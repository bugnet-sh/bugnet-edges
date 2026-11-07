// Package strangers limits what a client without a valid token can make the edge binaries do
package strangers

import (
	"net/netip"
	"sync"
	"time"
)

// Mark and Unknown are DP 4.5's mark on an address past the limit and life of a failed token
const (
	Mark    = 10 * time.Minute
	Unknown = 10 * time.Second
)

const (
	// maxAddrs matches HAProxy's per-source tables, past it an arbitrary address gives way
	maxAddrs   = 200_000
	maxUnknown = 100_000
	sweepEvery = time.Minute
	// fullSweepEvery spaces a full table's sweeps, between them one arbitrary entry gives way
	fullSweepEvery = time.Second
	askEvery       = time.Second
)

// Guard applies the token failure rule of one route, DP 4.5
type Guard struct {
	mark, unknownTTL time.Duration

	mu sync.Mutex
	// ips is nil when failed tokens are not limited
	ips        *addrs
	unknown    map[[32]byte]time.Time
	maxUnknown int
	swept      time.Time
}

// NewGuard marks an address for mark past perMinute failed tokens a minute, 0 or less marks none
func NewGuard(perMinute int, mark, unknownTTL time.Duration) *Guard {
	now := time.Now()
	g := &Guard{
		mark:       mark,
		unknownTTL: unknownTTL,
		unknown:    map[[32]byte]time.Time{},
		maxUnknown: maxUnknown,
		swept:      now,
	}
	if perMinute > 0 {
		g.ips = newAddrs(perMinute, now)
	}
	return g
}

// Marked reports whether unknown tokens from ip get 429
func (g *Guard) Marked(ip netip.Addr) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e := g.ips.find(ip, now)
	return e != nil && now.Before(e.markedUntil)
}

// Failed counts a token from ip that did not resolve, marking ip once past the limit
func (g *Guard) Failed(ip netip.Addr) {
	if g.ips == nil {
		return
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e := g.ips.get(ip, now)
	if !g.ips.take(e, now) {
		e.markedUntil = now.Add(g.mark)
	}
}

// MayAsk reports whether a token from ip may go to the router, once a second for a marked ip
func (g *Guard) MayAsk(ip netip.Addr) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	e := g.ips.find(ip, now)
	if e == nil || !now.Before(e.markedUntil) {
		return true
	}
	if !e.askedAt.IsZero() && now.Sub(e.askedAt) < askEvery {
		return false
	}
	e.askedAt = now
	return true
}

// KnownUnknown reports whether the token with this SHA-256 failed within the unknown TTL
func (g *Guard) KnownUnknown(tokenSHA [32]byte) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	until, ok := g.unknown[tokenSHA]
	return ok && now.Before(until)
}

// RememberUnknown keeps the token with this SHA-256 as unknown for the unknown TTL
func (g *Guard) RememberUnknown(tokenSHA [32]byte) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepDue(now)
	if _, ok := g.unknown[tokenSHA]; !ok && len(g.unknown) >= g.maxUnknown {
		if now.Sub(g.swept) >= fullSweepEvery {
			g.sweepUnknown(now)
		}
		for k := range g.unknown {
			if len(g.unknown) < g.maxUnknown {
				break
			}
			delete(g.unknown, k)
		}
	}
	g.unknown[tokenSHA] = now.Add(g.unknownTTL)
}

func (g *Guard) sweepDue(now time.Time) {
	if now.Sub(g.swept) >= sweepEvery {
		g.sweepUnknown(now)
	}
}

func (g *Guard) sweepUnknown(now time.Time) {
	g.swept = now
	for k, until := range g.unknown {
		if !now.Before(until) {
			delete(g.unknown, k)
		}
	}
}

func (g *Guard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ips.len()
}

// PerIP allows each client address a number of requests a minute
type PerIP struct {
	mu  sync.Mutex
	ips *addrs
}

// NewPerIP allows perMinute requests a minute per address with that burst, 0 or less is no limit
func NewPerIP(perMinute int) *PerIP {
	if perMinute <= 0 {
		return &PerIP{}
	}
	return &PerIP{ips: newAddrs(perMinute, time.Now())}
}

// Allow counts one request from ip and reports whether it is within the limit
func (l *PerIP) Allow(ip netip.Addr) bool {
	if l.ips == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ips.take(l.ips.get(ip, now), now)
}

// addrs holds a token bucket per client address, forgetting full ones every minute
type addrs struct {
	perSecond, burst float64
	max              int
	m                map[netip.Addr]*entry
	swept            time.Time
}

type entry struct {
	tokens      float64
	at          time.Time
	markedUntil time.Time
	askedAt     time.Time
}

func newAddrs(perMinute int, now time.Time) *addrs {
	n := float64(max(perMinute, 0))
	return &addrs{
		perSecond: n / 60, burst: n, max: maxAddrs, m: map[netip.Addr]*entry{}, swept: now,
	}
}

func (a *addrs) len() int {
	if a == nil {
		return 0
	}
	return len(a.m)
}

// key folds an IPv4-mapped address into its IPv4 form and drops a zone
func key(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

func (a *addrs) find(ip netip.Addr, now time.Time) *entry {
	if a == nil {
		return nil
	}
	a.sweepDue(now)
	return a.m[key(ip)]
}

func (a *addrs) get(ip netip.Addr, now time.Time) *entry {
	a.sweepDue(now)
	k := key(ip)
	if e, ok := a.m[k]; ok {
		return e
	}
	if len(a.m) >= a.max {
		if now.Sub(a.swept) >= fullSweepEvery {
			a.sweep(now)
		}
		for k := range a.m {
			if len(a.m) < a.max {
				break
			}
			delete(a.m, k)
		}
	}
	e := &entry{tokens: a.burst, at: now}
	a.m[k] = e
	return e
}

// take spends one token from e's bucket, false when none is left
func (a *addrs) take(e *entry, now time.Time) bool {
	a.refill(e, now)
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

func (a *addrs) refill(e *entry, now time.Time) {
	if elapsed := now.Sub(e.at).Seconds(); elapsed > 0 {
		e.tokens = min(a.burst, e.tokens+elapsed*a.perSecond)
	}
	e.at = now
}

func (a *addrs) sweepDue(now time.Time) {
	if now.Sub(a.swept) >= sweepEvery {
		a.sweep(now)
	}
}

// sweep drops every address whose bucket is full again and whose mark has run out
func (a *addrs) sweep(now time.Time) {
	a.swept = now
	for k, e := range a.m {
		a.refill(e, now)
		if e.tokens >= a.burst && !now.Before(e.markedUntil) {
			delete(a.m, k)
		}
	}
}
