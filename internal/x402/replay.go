package x402

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"
)

// probeSize is the one read past the limit that tells a whole body from one that grows on
const probeSize = 32 << 10

// Replay is a request body kept for one paid retry
type Replay struct {
	// Kept is the body read before the stop, set once Wait returns
	Kept []byte
	// Sum is the SHA-256 of Kept
	Sum [32]byte
	// Mark is empty, body_slow or body_too_large
	Mark Code
	// Upstream yields the kept bytes, then the rest as it arrives, to one reader
	Upstream io.Reader

	body  io.Reader
	limit int
	timer *time.Timer
	// done closes once Kept, Sum and Mark are set
	done chan struct{}
	// exited closes once the keeping goroutine no longer reads body
	exited chan struct{}

	mu sync.Mutex
	// grown wakes Upstream when buf grows or the keeping stops
	grown *sync.Cond
	// buf is the body kept so far, in room the size of the slot from the start
	buf     []byte
	stopped bool
	slot    *Slot
	// err is the body's error before the stop, which Wait returns
	err error
	// tail is what the read in flight at the stop gave, which Upstream yields after buf
	tail []byte
	// tailErr is the body's last error, io.EOF at its end, nil while body has more
	tailErr error
}

// ReadReplay keeps up to limit bytes of body that arrive before deadline
func ReadReplay(body io.Reader, limit int64, deadline time.Time) *Replay {
	limit = max(limit, 0)
	r := &Replay{
		body:   body,
		limit:  int(limit),
		buf:    make([]byte, 0, limit),
		done:   make(chan struct{}),
		exited: make(chan struct{}),
	}
	r.grown = sync.NewCond(&r.mu)
	r.Upstream = &upstream{r: r}
	r.timer = time.AfterFunc(time.Until(deadline), func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.stop(CodeBodySlow)
	})
	go r.keep()
	return r
}

// Wait returns once Kept, Sum and Mark are set, at the end, the limit or the deadline
func (r *Replay) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return r.err
	default:
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FreeOnMark frees s as soon as the read is marked, at once when it already is
func (r *Replay) FreeOnMark(s *Slot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped {
		r.slot = s
	} else if r.Mark != "" {
		s.Free()
	}
}

// keep moves body into buf until the end, a byte past the limit or the stop at the deadline
func (r *Replay) keep() {
	defer close(r.exited)
	defer r.timer.Stop()
	room := r.buf[:r.limit]
	var probe []byte
	for n := 0; ; {
		p := room[n:]
		if n == r.limit {
			if probe == nil {
				probe = make([]byte, probeSize)
			}
			p = probe
		}
		k, err := r.body.Read(p)

		r.mu.Lock()
		switch {
		case r.stopped:
			r.tail, r.tailErr = p[:k], err
		case n == r.limit && k > 0:
			r.tail, r.tailErr = p[:k], err
			r.stop(CodeBodyTooLarge)
		default:
			n += k
			r.buf = room[:n]
			r.grown.Broadcast()
			if err != nil {
				r.tailErr = err
				if !errors.Is(err, io.EOF) {
					r.err = err
				}
				r.stop("")
			}
		}
		stopped := r.stopped
		r.mu.Unlock()
		if stopped {
			return
		}
	}
}

// stop ends the keeping once, with r.mu held
func (r *Replay) stop(mark Code) {
	if r.stopped {
		return
	}
	r.stopped = true
	r.Kept = r.buf[:len(r.buf):len(r.buf)]
	r.Sum = sha256.Sum256(r.Kept)
	r.Mark = mark
	if mark != "" {
		r.slot.Free()
	}
	r.grown.Broadcast()
	close(r.done)
}

// upstream is Replay.Upstream
type upstream struct {
	r *Replay
	// sent counts the bytes of buf yielded, then tailSent those of tail
	sent, tailSent int
}

func (u *upstream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r := u.r
	r.mu.Lock()
	for u.sent == len(r.buf) && !r.stopped {
		r.grown.Wait()
	}
	if u.sent < len(r.buf) {
		kept := r.buf[u.sent:]
		r.mu.Unlock()
		n := copy(p, kept)
		u.sent += n
		return n, nil
	}
	r.mu.Unlock()

	<-r.exited
	if u.tailSent < len(r.tail) {
		n := copy(p, r.tail[u.tailSent:])
		u.tailSent += n
		return n, nil
	}
	if r.tailErr != nil {
		return 0, r.tailErr
	}
	return r.body.Read(p)
}
