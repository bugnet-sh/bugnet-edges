package preview

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/pages"
)

// wsRetry is the Retry-After for a placement whose WebSockets are all open
const wsRetry = 10 * time.Second

// limits holds DP 8.2.8's per-placement queue, rate and WebSockets, and the edge-wide Boat limit
type limits struct {
	wait time.Duration
	most int
	boat *rate.Limiter

	mu sync.Mutex
	// gates is keyed by lease, so a placement's next lease starts with fresh figures
	gates map[*lease.Lease]*gate
}

// gate is one placement's request slots, waiting count, request rate and WebSockets
type gate struct {
	slots   chan struct{} // nil for no limit
	waiting atomic.Int64
	rate    *rate.Limiter

	mu        sync.Mutex
	ws, wsMax int
}

// newLimits waits wait for a slot with most waiting, and paces Boat routes at perMinute
func newLimits(wait time.Duration, most, boatPerMinute int) *limits {
	l := &limits{wait: wait, most: most, gates: map[*lease.Lease]*gate{}}
	if boatPerMinute > 0 {
		l.boat = boatLimiter(boatPerMinute)
	}
	return l
}

// boatLimiter allows perMinute a minute with a tenth of it as burst, so no minute passes 1.1 times
func boatLimiter(perMinute int) *rate.Limiter {
	return rate.NewLimiter(rate.Limit(float64(perMinute)/60), max(perMinute/10, 1))
}

func (l *limits) gate(rt *route) *gate {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g, ok := l.gates[rt.lease]; ok {
		return g
	}
	b := rt.budget
	g := &gate{rate: rate.NewLimiter(rate.Inf, 0), wsMax: int(b.GetWebsockets())}
	if b.GetQueuedRequests() > 0 {
		g.slots = make(chan struct{}, b.GetQueuedRequests())
	}
	if b.GetRequestsPerSecond() > 0 {
		g.rate = rate.NewLimiter(rate.Limit(b.GetRequestsPerSecond()),
			int(max(b.GetRequestsBurst(), 1)))
	}
	l.gates[rt.lease] = g
	context.AfterFunc(rt.lease.Context(), func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.gates, rt.lease)
	})
	return g
}

// admit waits for the request's turn and returns its release, or the page that refuses it
func (l *limits) admit(ctx context.Context, rt *route, upgrade bool) (func(), pages.Page, bool) {
	g := l.gate(rt)
	var undo []func()
	release := func() {
		for _, f := range undo {
			f()
		}
	}
	if upgrade {
		if !g.openWS() {
			return nil, pages.SlowDown.RetryAfter(wsRetry), false
		}
		undo = append(undo, g.closeWS)
	}
	if int(g.waiting.Add(1)) > l.most {
		g.waiting.Add(-1)
		release()
		return nil, pages.Busy, false
	}
	defer g.waiting.Add(-1)
	wctx, cancel := context.WithTimeout(ctx, l.wait)
	defer cancel()
	refuse := func() (func(), pages.Page, bool) {
		release()
		if reason := lease.Reason(ctx); reason != "" {
			return nil, byLease(reason), false
		}
		return nil, pages.Busy, false
	}
	if g.rate.Wait(wctx) != nil {
		return refuse()
	}
	if rt.boat && l.boat != nil && l.boat.Wait(wctx) != nil {
		return refuse()
	}
	// A WebSocket holds no request slot, since it stays open for as long as the page does
	if !upgrade && g.slots != nil {
		select {
		case g.slots <- struct{}{}:
			undo = append(undo, func() { <-g.slots })
		case <-wctx.Done():
			return refuse()
		}
	}
	return release, pages.Page{}, true
}

func (g *gate) openWS() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.wsMax > 0 && g.ws >= g.wsMax {
		return false
	}
	g.ws++
	return true
}

func (g *gate) closeWS() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ws--
}

// byLease is the page for a request its lease or preview child ended
func byLease(reason string) pages.Page {
	switch reason {
	case lease.ReasonBudget:
		return pages.BudgetSpent
	case lease.ReasonRevoked:
		return pages.Revoked
	}
	return pages.Ended
}
