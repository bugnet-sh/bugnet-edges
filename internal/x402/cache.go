package x402

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Key is the cache key of XS 6.11
type Key struct {
	Placement, Method, Host, Target string
	BodySum                         [32]byte
}

// keyShown is what printing or logging a Key shows, since Target holds the query
const keyShown = "[x402 cache key]"

// Format prints no field of the key
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, keyShown) }

// LogValue keeps every field of the key out of slog
func (Key) LogValue() slog.Value { return slog.StringValue(keyShown) }

// Payload is one signed payment egress may resend, zeroed on drop
type Payload struct {
	Value                    []byte
	PaymentID, PaymentRef    string
	ServiceID                string
	AmountMicros, LeftMicros int64
	KeepUntil                time.Time
}

// payloadShown is what printing or logging a Payload shows
const payloadShown = "[x402 payload]"

// Format prints no field of the payload
func (Payload) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, payloadShown) }

// LogValue keeps every field of the payload out of slog
func (Payload) LogValue() slog.Value { return slog.StringValue(payloadShown) }

// End is how a paid attempt ended
type End int

const (
	// EndClean is a 2xx or 3xx answer with success true and a complete body
	EndClean End = iota
	// EndRejected is a 402 to the paid retry
	EndRejected
	// EndOther is every other end, which keeps the payload for a resend
	EndOther
)

// Cache keeps signed payloads in memory for resends and runs one paid attempt per key
type Cache struct {
	maxResends int
	now        func() time.Time

	mu     sync.Mutex
	places map[string]*place
}

// place is one placement's payloads and the keys its attempts hold
type place struct {
	entries map[Key]*entry
	held    map[Key]*Attempt
}

// entry is one cached payload
type entry struct {
	p       Payload
	resends int
	timer   *time.Timer
	// user is the unfinished attempt that attached or stored p and may still read it
	user *Attempt
	// dropped is set once p left the cache, so a user zeroes it at Finish
	dropped bool
}

// NewCache makes a cache that hands each payload out for at most maxResends resends
func NewCache(maxResends int, now func() time.Time) *Cache {
	return &Cache{maxResends: maxResends, now: now, places: map[string]*place{}}
}

// Has says whether a payload is cached for key, for the step 7 shortcut
func (c *Cache) Has(k Key) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.live(k) != nil
}

// live is the key's payload before its KeepUntil, dropping it from then on, with c.mu held
func (c *Cache) live(k Key) *entry {
	pl := c.places[k.Placement]
	if pl == nil {
		return nil
	}
	e := pl.entries[k]
	if e == nil {
		return nil
	}
	if !c.now().Before(e.p.KeepUntil) {
		c.drop(k, e)
		return nil
	}
	return e
}

// drop takes e out of the cache and zeroes it, unless its user may still read it, with c.mu held
func (c *Cache) drop(k Key, e *entry) {
	if pl := c.places[k.Placement]; pl != nil && pl.entries[k] == e {
		delete(pl.entries, k)
		c.tidy(k.Placement)
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	e.dropped = true
	if e.user == nil {
		clear(e.p.Value)
	}
}

// tidy forgets a placement with no payload and no attempt, with c.mu held
func (c *Cache) tidy(placement string) {
	if pl := c.places[placement]; pl != nil && len(pl.entries) == 0 && len(pl.held) == 0 {
		delete(c.places, placement)
	}
}

// DropPlacement zeroes and forgets every payload of a placement
func (c *Cache) DropPlacement(placement string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pl := c.places[placement]
	if pl == nil {
		return
	}
	for k, e := range pl.entries {
		c.drop(k, e)
	}
	for _, a := range pl.held {
		a.gone = true
	}
}

// Attempt is one paid attempt holding its key until Finish
type Attempt struct {
	c    *Cache
	k    Key
	done chan struct{}

	// e is the payload this attempt attached or stored
	e        *entry
	finished bool
	// gone is set when the placement was dropped while the attempt held its key
	gone bool
}

// Begin waits until no paid attempt for key is in flight in this process, then holds it
func (c *Cache) Begin(ctx context.Context, k Key) (*Attempt, error) {
	for {
		// A done ctx always wins, so a request past its deadline never starts a payment
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		pl := c.places[k.Placement]
		if pl == nil {
			pl = &place{entries: map[Key]*entry{}, held: map[Key]*Attempt{}}
			c.places[k.Placement] = pl
		}
		h := pl.held[k]
		if h == nil {
			a := &Attempt{c: c, k: k, done: make(chan struct{})}
			pl.held[k] = a
			c.mu.Unlock()
			return a, nil
		}
		c.mu.Unlock()
		select {
		case <-h.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Attach hands out the cached payload for one resend, readable until Finish, else nil
func (a *Attempt) Attach(enabled bool, listed func(serviceID string) bool) *Payload {
	if !enabled || listed == nil {
		return nil
	}
	c := a.c
	c.mu.Lock()
	e := c.live(a.k)
	if a.finished {
		e = nil
	}
	c.mu.Unlock()
	// listed runs without c.mu, so it may take the caller's own locks
	if e == nil || !listed(e.p.ServiceID) {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if a.finished || c.live(a.k) != e {
		return nil
	}
	if e.resends >= c.maxResends {
		c.drop(a.k, e)
		return nil
	}
	e.resends++
	a.use(e)
	if e.resends == c.maxResends {
		c.drop(a.k, e)
	}
	p := e.p
	return &p
}

// Store keeps a fresh payload under the held key, owning p.Value from then on
func (a *Attempt) Store(p Payload) {
	c := a.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.finished {
		clear(p.Value)
		return
	}
	pl := c.places[a.k.Placement]
	if old := pl.entries[a.k]; old != nil {
		c.drop(a.k, old)
	}
	e := &entry{p: p}
	a.use(e)
	if a.gone || !c.now().Before(p.KeepUntil) {
		e.dropped = true
		return
	}
	pl.entries[a.k] = e
	k := a.k
	e.timer = time.AfterFunc(p.KeepUntil.Sub(c.now()), func() { c.expire(k, e) })
}

// expire zeroes a payload nobody asked for by its KeepUntil, else waits for the rest
func (c *Cache) expire(k Key, e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live(k) == e {
		e.timer.Reset(e.p.KeepUntil.Sub(c.now()))
	}
}

// use makes e the attempt's payload, zeroing a dropped one it used before, with c.mu held
func (a *Attempt) use(e *entry) {
	if old := a.e; old != nil && old != e {
		old.user = nil
		if old.dropped {
			clear(old.p.Value)
		}
	}
	a.e = e
	if e != nil {
		e.user = a
	}
}

// Finish records the end and releases the key, clean and rejected drop the payload
func (a *Attempt) Finish(end End) {
	c := a.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.finished {
		return
	}
	a.finished = true
	a.use(nil)
	pl := c.places[a.k.Placement]
	if e := pl.entries[a.k]; e != nil && (end == EndClean || end == EndRejected) {
		c.drop(a.k, e)
	}
	delete(pl.held, a.k)
	c.tidy(a.k.Placement)
	close(a.done)
}
