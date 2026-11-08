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
	// maxIDs, maxOffenders and maxGood bound the tables, past them an arbitrary entry gives way
	maxIDs       = 100_000
	maxOffenders = 200_000
	maxGood      = 100_000
	sweepEvery   = time.Minute
	// fullSweepEvery spaces a full table's sweeps, between them an arbitrary entry gives way
	fullSweepEvery = time.Second
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

// idGuard spaces the router calls for a hot id, but only from addresses that sent it a wrong key
type idGuard struct {
	perSecond, burst float64
	now              func() time.Time

	mu        sync.Mutex
	ids       map[string]*idEntry
	offenders map[offender]time.Time // until when an address counts as one for an id
	swept     time.Time
	fullSwept time.Time
}

type idEntry struct {
	tokens   float64
	at       time.Time
	hotUntil time.Time
	askedAt  time.Time
}

// offender is an address, IPv4 or an IPv6 /64, that sent a wrong key for an id
type offender struct {
	id string
	ip netip.Addr
}

// newIDGuard limits each id to perMinute wrong keys a minute, 0 or less limits none
func newIDGuard(perMinute int, now func() time.Time) *idGuard {
	if perMinute <= 0 {
		return &idGuard{}
	}
	if now == nil {
		now = time.Now
	}
	n := float64(perMinute)
	return &idGuard{perSecond: n / 60, burst: n, now: now, ids: map[string]*idEntry{},
		offenders: map[offender]time.Time{}, swept: now()}
}

// failed counts a wrong key for id from ip, making the id hot once past the limit
func (g *idGuard) failed(id string, ip netip.Addr) {
	if g.ids == nil {
		return
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	o := offender{id: id, ip: ip}
	if _, ok := g.offenders[o]; !ok {
		g.makeRoom(now, len(g.offenders) >= maxOffenders)
		evict(g.offenders, maxOffenders)
	}
	g.offenders[o] = now.Add(idHot)
	e, ok := g.ids[id]
	if !ok {
		g.makeRoom(now, len(g.ids) >= maxIDs)
		evict(g.ids, maxIDs)
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

// mayAsk reports whether a call for id from ip may go to the router, an address that sent the
// hot id a wrong key sharing one call a second and every other address never held
func (g *idGuard) mayAsk(id string, ip netip.Addr) bool {
	if g.ids == nil {
		return true
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e, ok := g.ids[id]
	if !ok || !now.Before(e.hotUntil) {
		return true
	}
	if until, ok := g.offenders[offender{id: id, ip: ip}]; !ok || !now.Before(until) {
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

// makeRoom sweeps out the expired entries of a full table, at most once a second
func (g *idGuard) makeRoom(now time.Time, full bool) {
	if full && now.Sub(g.fullSwept) >= fullSweepEvery {
		g.fullSwept = now
		g.sweep(now)
	}
}

// evict drops arbitrary entries of m until it has room for one more
func evict[K comparable, V any](m map[K]V, limit int) {
	for k := range m {
		if len(m) < limit {
			return
		}
		delete(m, k)
	}
}

func (g *idGuard) sweepDue(now time.Time) {
	if now.Sub(g.swept) >= sweepEvery {
		g.sweep(now)
	}
}

// sweep drops every id whose bucket is full again and which is no longer hot, and every
// offender whose wrong key is older than idHot
func (g *idGuard) sweep(now time.Time) {
	g.swept = now
	for k, e := range g.ids {
		g.refill(e, now)
		if e.tokens >= g.burst && !now.Before(e.hotUntil) {
			delete(g.ids, k)
		}
	}
	for o, until := range g.offenders {
		if !now.Before(until) {
			delete(g.offenders, o)
		}
	}
}

func (g *idGuard) size() (ids, offenders int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.ids), len(g.offenders)
}

// goodPairs holds the SHA-256 of each (id, key) the router accepted, so a right key is never
// blocked by the limits strangers share with it
type goodPairs struct {
	mu        sync.Mutex
	until     map[[32]byte]time.Time
	swept     time.Time
	fullSwept time.Time
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
		if now.Sub(g.fullSwept) >= fullSweepEvery {
			g.fullSwept = now
			g.sweep(now)
		}
		evict(g.until, maxGood)
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
