package x402

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"
)

// chunkSize is the size of each body read, the only room a Replay holds outside its slot
const chunkSize = 4 << 10

// Replay is a request body kept for one paid retry
type Replay struct {
	// Kept is the paid retry's body, read only after Wait returns nil, nil after a mark or error
	Kept []byte
	// Sum is the SHA-256 of Kept, zero when Kept is nil
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
	// closed closes once Close ends Upstream
	closed chan struct{}

	mu sync.Mutex
	// grown wakes Upstream when buf grows, the keeping stops or Close is called
	grown *sync.Cond
	// buf is the body kept so far, in room the size of the slot until a mark trims it to its length
	buf []byte
	// sent counts the bytes of buf Upstream yielded
	sent    int
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
		closed: make(chan struct{}),
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

// Wait returns once Kept, Sum and Mark are set, with the body's error when it failed first
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

// Close ends Upstream, whose reads then give io.ErrClosedPipe, and leaves Kept as it is
func (r *Replay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed() {
		return
	}
	close(r.closed)
	if r.stopped {
		r.buf = nil
		r.release()
	}
	r.grown.Broadcast()
}

// isClosed reports whether Close was called
func (r *Replay) isClosed() bool {
	select {
	case <-r.closed:
		return true
	default:
		return false
	}
}

// FreeOnMark frees s at a mark, past its kept bytes until sent or Close, and never an unmarked s
func (r *Replay) FreeOnMark(s *Slot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// a slot after the first stays the caller's to free
	if r.slot != nil {
		return
	}
	r.slot = s
	r.release()
}

// release gives back the room a marked read no longer holds, in memory and slot, with r.mu held
func (r *Replay) release() {
	if r.Mark == "" {
		return
	}
	if r.buf == nil {
		r.slot.Free()
		return
	}
	if cap(r.buf) > len(r.buf) {
		r.buf = append(make([]byte, 0, len(r.buf)), r.buf...)
	}
	r.slot.shrink(int64(len(r.buf)))
}

// keep moves body into buf a chunk at a time, so the read in flight at a stop holds no slot room
func (r *Replay) keep() {
	defer close(r.exited)
	defer r.timer.Stop()
	chunk := make([]byte, chunkSize)
	for n := 0; ; {
		p := chunk
		if room := r.limit - n; room > 0 {
			p = chunk[:min(room, chunkSize)]
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
			r.buf = append(r.buf, p[:k]...)
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
	r.Mark = mark
	if mark == "" && r.err == nil {
		r.Kept = r.buf[:len(r.buf):len(r.buf)]
		r.Sum = sha256.Sum256(r.Kept)
	}
	if r.isClosed() || (mark != "" && r.sent == len(r.buf)) {
		r.buf = nil
	}
	r.release()
	r.grown.Broadcast()
	close(r.done)
}

// upstream is Replay.Upstream
type upstream struct {
	r *Replay
	// past is set once every kept byte is yielded after the stop
	past bool
}

func (u *upstream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r := u.r
	if !u.past {
		if n, err := u.readKept(p); n > 0 || err != nil {
			return n, err
		}
	}

	select {
	case <-r.exited:
	case <-r.closed:
	}
	if r.isClosed() {
		return 0, io.ErrClosedPipe
	}
	if len(r.tail) > 0 {
		n := copy(p, r.tail)
		r.tail = r.tail[n:]
		return n, nil
	}
	if r.tailErr != nil {
		return 0, r.tailErr
	}
	return r.body.Read(p)
}

// readKept yields kept bytes as they land, and lets go of buf with its last byte after the stop
func (u *upstream) readKept(p []byte) (int, error) {
	r := u.r
	r.mu.Lock()
	for r.sent == len(r.buf) && !r.stopped && !r.isClosed() {
		r.grown.Wait()
	}
	if r.isClosed() {
		r.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if r.buf == nil {
		u.past = true
		r.mu.Unlock()
		return 0, nil
	}
	kept := r.buf[r.sent:]
	n := min(len(p), len(kept))
	r.sent += n
	if r.stopped && n == len(kept) {
		u.past = true
		r.buf = nil
		r.release()
	}
	r.mu.Unlock()
	copy(p, kept[:n])
	return n, nil
}
