package sessionsroute

import (
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/oynozan/bugnet-edges/internal/strangers"
)

const (
	// idHot is how long an id past its wrong key limit sends one router call a second
	idHot = time.Minute
	// goodFor keeps a pair the router accepted out of every stranger limit, refreshed on each use
	goodFor = 10 * time.Minute
	// maxIDs and maxGood bound the tables, past them an arbitrary entry gives way
	maxIDs     = 100_000
	maxGood    = 100_000
	sweepEvery = time.Minute
)

// clientKey is the address the per-IP limits count by: an IPv4 address, or an IPv6 one's /64
func clientKey(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// idGuard spaces the router calls for one id once its wrong keys pass perMinute, SP 7.4
type idGuard struct {
	perSecond, burst float64

	mu    sync.Mutex
	ids   map[string]*idEntry
	swept time.Time
}

type idEntry struct {
	tokens   float64
	at       time.Time
	hotUntil time.Time
	askedAt  time.Time
}

// newIDGuard limits each id to perMinute wrong keys a minute, 0 or less limits none
func newIDGuard(perMinute int) *idGuard {
	if perMinute <= 0 {
		return &idGuard{}
	}
	n := float64(perMinute)
	return &idGuard{perSecond: n / 60, burst: n, ids: map[string]*idEntry{}, swept: time.Now()}
}

// failed counts a wrong key for id, making it hot once past the limit
func (g *idGuard) failed(id string) {
	if g.ids == nil {
		return
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e, ok := g.ids[id]
	if !ok {
		g.makeRoom(now)
		e = &idEntry{tokens: g.burst, at: now}
		g.ids[id] = e
	}
	g.refill(e, now)
	if e.tokens < 1 {
		// The call that made it hot was this second's one
		if !now.Before(e.hotUntil) {
			e.askedAt = now
		}
		e.hotUntil = now.Add(idHot)
		return
	}
	e.tokens--
}

// mayAsk reports whether a call for id may go to the router, once a second for a hot id
func (g *idGuard) mayAsk(id string) bool {
	if g.ids == nil {
		return true
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e, ok := g.ids[id]
	if !ok || !now.Before(e.hotUntil) {
		return true
	}
	if !e.askedAt.IsZero() && now.Sub(e.askedAt) < strangers.AskEvery {
		return false
	}
	e.askedAt = now
	return true
}

func (g *idGuard) refill(e *idEntry, now time.Time) {
	if elapsed := now.Sub(e.at).Seconds(); elapsed > 0 {
		e.tokens = min(g.burst, e.tokens+elapsed*g.perSecond)
	}
	e.at = now
}

func (g *idGuard) makeRoom(now time.Time) {
	if len(g.ids) < maxIDs {
		return
	}
	g.sweep(now)
	for k := range g.ids {
		if len(g.ids) < maxIDs {
			return
		}
		delete(g.ids, k)
	}
}

func (g *idGuard) sweepDue(now time.Time) {
	if now.Sub(g.swept) >= sweepEvery {
		g.sweep(now)
	}
}

// sweep drops every id whose bucket is full again and which is no longer hot
func (g *idGuard) sweep(now time.Time) {
	g.swept = now
	for k, e := range g.ids {
		g.refill(e, now)
		if e.tokens >= g.burst && !now.Before(e.hotUntil) {
			delete(g.ids, k)
		}
	}
}

// goodPairs holds the SHA-256 of each (id, key) the router accepted, so a right key is never
// blocked by the limits strangers share with it
type goodPairs struct {
	mu    sync.Mutex
	until map[[32]byte]time.Time
	swept time.Time
}

func newGoodPairs() *goodPairs {
	return &goodPairs{until: map[[32]byte]time.Time{}, swept: time.Now()}
}

func (g *goodPairs) has(sum [32]byte) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.until[sum]
	return ok && now.Before(until)
}

func (g *goodPairs) add(sum [32]byte) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.swept) >= sweepEvery {
		g.sweep(now)
	}
	if _, ok := g.until[sum]; !ok && len(g.until) >= maxGood {
		g.sweep(now)
		for k := range g.until {
			if len(g.until) < maxGood {
				break
			}
			delete(g.until, k)
		}
	}
	g.until[sum] = now.Add(goodFor)
}

func (g *goodPairs) remove(sum [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.until, sum)
}

func (g *goodPairs) sweep(now time.Time) {
	g.swept = now
	for k, until := range g.until {
		if !now.Before(until) {
			delete(g.until, k)
		}
	}
}
