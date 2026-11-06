// Package usage reports the bytes each placement carried to the router, DP 4.3
package usage

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

const (
	// sendTimeout ends a report the router has not answered, its bytes go in the next one
	sendTimeout = 10 * time.Second
	// finalTimeout bounds the last report Run sends once its context ends
	finalTimeout = 5 * time.Second
)

// Send reports usage to the router and returns the bytes left and the pace by placement
type Send func(ctx context.Context, u []*routerv1.PlacementUsage) (
	remaining, pace map[string]uint64, err error)

// Reporter sends usage deltas every interval, or at once when one placement passes the threshold
type Reporter struct {
	send      Send
	every     time.Duration
	threshold int64
	flush     chan struct{}

	mu       sync.Mutex
	entries  map[string]*entry
	onAnswer func(placement string, remaining, pace uint64)
	// held keeps threshold reports back after a failed one, until the next interval
	held bool
}

type entry struct {
	in, out int64 // counted but not yet in a report
	// known is set once a figure for the bytes left came from the router or SetRemaining
	known     bool
	remaining uint64
	pace      uint64
	// set counts SetRemaining and Drop calls, so an answer to an older report keeps their figure
	set uint64
	// dropped keeps answers from bringing back a figure until the next SetRemaining
	dropped bool
}

// NewReporter reports every interval and once a placement's unsent bytes reach threshold
func NewReporter(send Send, every time.Duration, threshold int64) *Reporter {
	return &Reporter{
		send:      send,
		every:     every,
		threshold: threshold,
		flush:     make(chan struct{}, 1),
		entries:   map[string]*entry{},
	}
}

// OnAnswer runs per placement in each answer, and from Add when the local figure reaches zero
func (r *Reporter) OnAnswer(f func(placement string, remaining, pace uint64)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onAnswer = f
}

// Add counts bytes toward the sandbox (in) and from it (out)
func (r *Reporter) Add(placement string, in, out int64) {
	in, out = max(in, 0), max(out, 0)
	r.mu.Lock()
	e := r.entry(placement)
	e.in += in
	e.out += out
	cut := false
	if e.known && e.remaining > 0 {
		if spent := uint64(in + out); spent >= e.remaining {
			e.remaining = 0
			cut = true
		} else {
			e.remaining -= spent
		}
	}
	full := r.threshold > 0 && e.in+e.out >= r.threshold
	f, pace := r.onAnswer, e.pace
	r.mu.Unlock()

	if full {
		select {
		case r.flush <- struct{}{}:
		default:
		}
	}
	if cut && f != nil {
		f(placement, 0, pace)
	}
}

// SetRemaining sets the placement's bytes left from a resolve, a lease check or an event
func (r *Reporter) SetRemaining(placement string, remaining uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entry(placement)
	e.known = true
	e.remaining = remaining
	e.set++
	e.dropped = false
}

// Drop forgets the placement's figures once its unsent bytes are reported
func (r *Reporter) Drop(placement string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[placement]; ok {
		e.known = false
		e.set++
		e.dropped = true
		r.tidy(placement, e)
	}
}

// Run reports until ctx ends, then sends what is left once, and must not run twice at once
func (r *Reporter) Run(ctx context.Context) {
	tick := time.NewTicker(r.every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			last, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalTimeout)
			r.report(last)
			cancel()
			return
		case <-tick.C:
			r.mu.Lock()
			r.held = false
			r.mu.Unlock()
			r.reportFor(ctx)
		case <-r.flush:
			r.mu.Lock()
			held := r.held
			r.mu.Unlock()
			if !held {
				r.reportFor(ctx)
			}
		}
	}
}

func (r *Reporter) reportFor(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	r.report(ctx)
}

// answered is one OnAnswer call
type answered struct {
	placement       string
	remaining, pace uint64
}

func (r *Reporter) report(ctx context.Context) {
	r.mu.Lock()
	var batch []*routerv1.PlacementUsage
	set := map[string]uint64{}
	for id, e := range r.entries {
		if e.in+e.out == 0 {
			continue
		}
		batch = append(batch, &routerv1.PlacementUsage{
			PlacementId: id, BytesIn: uint64(e.in), BytesOut: uint64(e.out),
		})
		set[id] = e.set
		e.in, e.out = 0, 0
	}
	r.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	slices.SortFunc(batch, func(a, b *routerv1.PlacementUsage) int {
		return cmp.Compare(a.GetPlacementId(), b.GetPlacementId())
	})

	remaining, pace, err := r.send(ctx, batch)

	r.mu.Lock()
	if err != nil {
		for _, u := range batch {
			e, ok := r.entries[u.GetPlacementId()]
			if !ok {
				// Only Drop deletes an entry while its bytes are out
				e = &entry{dropped: true}
				r.entries[u.GetPlacementId()] = e
			}
			e.in += int64(u.GetBytesIn())
			e.out += int64(u.GetBytesOut())
		}
		r.held = true
		r.mu.Unlock()
		return
	}
	var calls []answered
	for _, u := range batch {
		id := u.GetPlacementId()
		e, ok := r.entries[id]
		if !ok {
			continue
		}
		left, ok := remaining[id]
		if !ok || e.dropped {
			e.known = false
			r.tidy(id, e)
			continue
		}
		if p, ok := pace[id]; ok {
			e.pace = p
		}
		if e.set == set[id] {
			e.known = true
			e.remaining = left - min(left, uint64(e.in+e.out))
		}
		calls = append(calls, answered{id, e.remaining, e.pace})
	}
	f := r.onAnswer
	r.mu.Unlock()
	if f == nil {
		return
	}
	for _, c := range calls {
		f(c.placement, c.remaining, c.pace)
	}
}

func (r *Reporter) entry(placement string) *entry {
	e, ok := r.entries[placement]
	if !ok {
		e = &entry{}
		r.entries[placement] = e
	}
	return e
}

// tidy deletes an entry holding neither a figure nor unsent bytes
func (r *Reporter) tidy(placement string, e *entry) {
	if !e.known && e.in+e.out == 0 {
		delete(r.entries, placement)
	}
}

func (r *Reporter) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
