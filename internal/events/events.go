// Package events follows the router's edge event stream and reconnects from its cursor, DP 4.2
package events

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

const (
	// upAfter is how long a silent stream must stay open to count as back
	upAfter    = time.Second
	minBackoff = 250 * time.Millisecond
	maxBackoff = 10 * time.Second
)

// Stream is one open event stream
type Stream interface {
	// Recv returns the next cursor and event, the event is nil when only the cursor moved
	Recv() (cursor string, ev *routerv1.EdgeEvent, err error)
	Close() error
}

// Open starts a stream after cursor, an empty cursor starts from now
type Open func(ctx context.Context, cursor string) (Stream, error)

// Watcher keeps one event stream open and hands each event on in order
type Watcher struct {
	open   Open
	on     func(*routerv1.EdgeEvent)
	resync func()
	// down can run alongside on, from the timer that marks a silent stream up
	down func(bool)

	// told serializes calls to down, and reported is the state down last heard
	told     sync.Mutex
	reported bool

	mu     sync.Mutex
	cursor string
	isDown bool
	// stream counts streams, so a late timer of an ended one changes nothing
	stream uint64
	up     bool
	// gap is set when events may have been missed without a cursor to resume from
	gap bool
}

// NewWatcher calls on per event, resync for a lease check and down as the stream drops or returns
func NewWatcher(
	open Open, on func(*routerv1.EdgeEvent), resync func(), down func(bool),
) *Watcher {
	return &Watcher{open: open, on: on, resync: resync, down: down}
}

// Cursor is the position after the last event handed on
func (w *Watcher) Cursor() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cursor
}

// Run follows the stream until ctx ends, reconnecting with backoff
func (w *Watcher) Run(ctx context.Context) {
	backoff := minBackoff
	for ctx.Err() == nil {
		cursor := w.Cursor()
		s, err := w.open(ctx, cursor)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			w.setDown()
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		w.mu.Lock()
		gap := cursor == "" && w.gap
		w.gap = false
		w.mu.Unlock()
		if gap {
			w.resync()
		}

		up := w.receive(s)
		_ = s.Close()
		if ctx.Err() != nil {
			return
		}
		w.setDown()
		if up {
			backoff = minBackoff
		}
		if !sleep(ctx, backoff) {
			return
		}
		if !up {
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

// receive hands on events until the stream fails and reports whether it ever came up
func (w *Watcher) receive(s Stream) bool {
	w.mu.Lock()
	w.stream++
	n := w.stream
	w.mu.Unlock()
	t := time.AfterFunc(upAfter, func() { w.markUp(n) })
	defer t.Stop()

	for {
		cursor, ev, err := s.Recv()
		if err != nil {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.stream++
			up := w.up
			w.up = false
			return up
		}
		w.markUp(n)
		switch {
		case ev.GetResync() != nil:
			w.resync()
		case ev != nil:
			w.on(ev)
		}
		if cursor != "" {
			w.mu.Lock()
			w.cursor = cursor
			w.mu.Unlock()
		}
	}
}

func (w *Watcher) markUp(n uint64) {
	w.mu.Lock()
	if n != w.stream || w.up {
		w.mu.Unlock()
		return
	}
	w.up = true
	changed := w.isDown
	w.isDown = false
	w.mu.Unlock()
	if changed {
		w.report()
	}
}

func (w *Watcher) setDown() {
	w.mu.Lock()
	if w.cursor == "" {
		w.gap = true
	}
	changed := !w.isDown
	w.isDown = true
	w.mu.Unlock()
	if changed {
		w.report()
	}
}

// report calls down outside mu with the latest state, when it differs from the one last reported
func (w *Watcher) report() {
	w.told.Lock()
	defer w.told.Unlock()
	w.mu.Lock()
	d := w.isDown
	w.mu.Unlock()
	if d != w.reported {
		w.reported = d
		w.down(d)
	}
}

// sleep waits about d, a quarter either way, and reports false when ctx ended first
func sleep(ctx context.Context, d time.Duration) bool {
	d = d*3/4 + rand.N(d/2+1)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
