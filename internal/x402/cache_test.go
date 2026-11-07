package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cacheStart is the injected clock's first reading
var cacheStart = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// cacheClock is a clock a test moves by hand
type cacheClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *cacheClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *cacheClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newTestCache is a cache allowing three resends on a clock at cacheStart
func newTestCache() (*Cache, *cacheClock) {
	clk := &cacheClock{t: cacheStart}
	return NewCache(3, clk.now), clk
}

// cacheKey is a paid search on placement
func cacheKey(placement string) Key {
	return Key{
		Placement: placement,
		Method:    "GET",
		Host:      "api.example.com",
		Target:    "/search?q=weather%20in%20Paris",
		BodySum:   sha256.Sum256(nil),
	}
}

// signed is a fresh payload kept 45 s after cacheStart
func signed(value string) Payload {
	return Payload{
		Value:        []byte(value),
		PaymentID:    "pay_0001",
		PaymentRef:   "ref_0001",
		ServiceID:    "xs_aaaaaaaaaaaaaaaa",
		AmountMicros: 1000,
		LeftMicros:   9000,
		KeepUntil:    cacheStart.Add(45 * time.Second),
	}
}

// listed accepts every service
func listed(string) bool { return true }

// begin holds k, failing the test when it takes more than a second
func begin(t *testing.T, c *Cache, k Key) *Attempt {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := c.Begin(ctx, k)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	return a
}

// store keeps p under k through one attempt that ends unclean
func store(t *testing.T, c *Cache, k Key, p Payload) {
	t.Helper()
	a := begin(t, c, k)
	a.Store(p)
	a.Finish(EndOther)
}

// resend attaches k's payload in one attempt that ends unclean
func resend(t *testing.T, c *Cache, k Key) *Payload {
	t.Helper()
	a := begin(t, c, k)
	defer a.Finish(EndOther)
	return a.Attach(true, listed)
}

// zeroed reports whether every byte of b is zero
func zeroed(b []byte) bool {
	return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b)
}

// placements counts the placements the cache still tracks
func placements(c *Cache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.places)
}

func TestKeyFields(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	store(t, c, k, signed("base"))

	other := []Key{k, k, k, k, k}
	other[0].Placement = "pl_b"
	other[1].Method = "POST"
	other[2].Host = "api2.example.com"
	other[3].Target = "/search?q=weather%20in%20Rome"
	other[4].BodySum = sha256.Sum256([]byte("{}"))
	for i, o := range other {
		eq(t, c.Has(o), false)
		store(t, c, o, signed(fmt.Sprintf("other-%d", i)))
		eq(t, c.Has(o), true)
	}
	eq(t, c.Has(k), true)
	eq(t, string(resend(t, c, k).Value), "base")
	for i, o := range other {
		eq(t, string(resend(t, c, o).Value), fmt.Sprintf("other-%d", i))
	}
}

func TestThreeResendsThenDropped(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)
	for i := range 3 {
		a := begin(t, c, k)
		got := a.Attach(true, listed)
		if got == nil {
			t.Fatalf("resend %d got nothing", i+1)
		}
		eq(t, string(got.Value), "payload")
		eq(t, got.PaymentID, p.PaymentID)
		eq(t, got.PaymentRef, p.PaymentRef)
		eq(t, got.ServiceID, p.ServiceID)
		eq(t, got.AmountMicros, p.AmountMicros)
		eq(t, got.LeftMicros, p.LeftMicros)
		eq(t, got.KeepUntil, p.KeepUntil)
		a.Finish(EndOther)
	}
	eq(t, c.Has(k), false)
	eq(t, resend(t, c, k), (*Payload)(nil))
	eq(t, zeroed(p.Value), true)
}

func TestLastResendDropsAtOnce(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	store(t, c, k, signed("payload"))
	resend(t, c, k)
	resend(t, c, k)

	a := begin(t, c, k)
	got := a.Attach(true, listed)
	eq(t, c.Has(k), false)
	eq(t, string(got.Value), "payload")
	a.Finish(EndOther)
	eq(t, zeroed(got.Value), true)
}

func TestDropAtKeepUntil(t *testing.T) {
	c, clk := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)

	clk.set(p.KeepUntil.Add(-time.Nanosecond))
	eq(t, c.Has(k), true)
	eq(t, string(resend(t, c, k).Value), "payload")

	clk.set(p.KeepUntil.Add(time.Nanosecond))
	eq(t, resend(t, c, k), (*Payload)(nil))
	eq(t, c.Has(k), false)
	eq(t, zeroed(p.Value), true)
}

func TestDropAtKeepUntilExactly(t *testing.T) {
	c, clk := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)
	clk.set(p.KeepUntil)
	eq(t, c.Has(k), false)
	eq(t, zeroed(p.Value), true)
}

func TestKeepUntilDropsUnasked(t *testing.T) {
	c := NewCache(3, time.Now)
	k := cacheKey("pl_a")
	p := signed("payload")
	p.KeepUntil = time.Now().Add(20 * time.Millisecond)
	store(t, c, k, p)
	for deadline := time.Now().Add(time.Second); placements(c) > 0; {
		if time.Now().After(deadline) {
			t.Fatal("payload still kept a second after its KeepUntil")
		}
		time.Sleep(5 * time.Millisecond)
	}
	eq(t, zeroed(p.Value), true)
}

// laggingClock is the real clock minus a lag a test sets
type laggingClock struct{ lag atomic.Int64 }

func (c *laggingClock) now() time.Time {
	return time.Now().Add(-time.Duration(c.lag.Load()))
}

func TestKeepUntilWaitsForALaggingClock(t *testing.T) {
	var clk laggingClock
	c := NewCache(3, clk.now)
	k := cacheKey("pl_a")
	p := signed("payload")
	p.KeepUntil = time.Now().Add(20 * time.Millisecond)
	store(t, c, k, p)
	clk.lag.Store(int64(30 * time.Millisecond))
	for deadline := time.Now().Add(time.Second); placements(c) > 0; {
		if time.Now().After(deadline) {
			t.Fatal("payload still kept a second after the lagging clock passed its KeepUntil")
		}
		time.Sleep(5 * time.Millisecond)
	}
	eq(t, zeroed(p.Value), true)
}

func TestStoreAfterKeepUntilKeepsNothing(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	p.KeepUntil = cacheStart

	a := begin(t, c, k)
	a.Store(p)
	eq(t, c.Has(k), false)
	eq(t, string(p.Value), "payload")
	a.Finish(EndOther)
	eq(t, zeroed(p.Value), true)
	eq(t, placements(c), 0)
}

// dropEnds are the ends that drop the payload, by name
var dropEnds = []struct {
	name string
	end  End
}{{"clean", EndClean}, {"rejected", EndRejected}}

func TestCleanAndRejectedDrop(t *testing.T) {
	for _, d := range dropEnds {
		end := d.end
		t.Run(d.name, func(t *testing.T) {
			c, _ := newTestCache()
			k := cacheKey("pl_a")
			p := signed("payload")
			a := begin(t, c, k)
			a.Store(p)
			a.Finish(end)
			eq(t, c.Has(k), false)
			eq(t, zeroed(p.Value), true)
			eq(t, resend(t, c, k), (*Payload)(nil))
			eq(t, placements(c), 0)
		})
	}
}

func TestResendThenCleanDrops(t *testing.T) {
	for _, d := range dropEnds {
		end := d.end
		t.Run(d.name, func(t *testing.T) {
			c, _ := newTestCache()
			k := cacheKey("pl_a")
			store(t, c, k, signed("payload"))
			a := begin(t, c, k)
			got := a.Attach(true, listed)
			a.Finish(end)
			eq(t, c.Has(k), false)
			eq(t, zeroed(got.Value), true)
		})
	}
}

func TestOtherEndsKeep(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)
	eq(t, c.Has(k), true)
	eq(t, string(resend(t, c, k).Value), "payload")
	eq(t, c.Has(k), true)
	eq(t, string(p.Value), "payload")

	a := begin(t, c, k)
	a.Finish(EndOther)
	eq(t, c.Has(k), true)
}

func TestDroppedPayloadZeroed(t *testing.T) {
	k := cacheKey("pl_a")
	for _, tc := range []struct {
		name string
		drop func(t *testing.T, c *Cache, clk *cacheClock)
	}{
		{"clean", func(t *testing.T, c *Cache, _ *cacheClock) {
			begin(t, c, k).Finish(EndClean)
		}},
		{"rejected", func(t *testing.T, c *Cache, _ *cacheClock) {
			begin(t, c, k).Finish(EndRejected)
		}},
		{"last resend", func(t *testing.T, c *Cache, _ *cacheClock) {
			for range 3 {
				resend(t, c, k)
			}
		}},
		{"keep until", func(_ *testing.T, c *Cache, clk *cacheClock) {
			clk.set(cacheStart.Add(time.Hour))
			c.Has(k)
		}},
		{"placement", func(_ *testing.T, c *Cache, _ *cacheClock) {
			c.DropPlacement(k.Placement)
		}},
		{"replaced", func(t *testing.T, c *Cache, _ *cacheClock) {
			store(t, c, k, signed("fresh"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, clk := newTestCache()
			p := signed("payload")
			kept := p.Value
			store(t, c, k, p)
			tc.drop(t, c, clk)
			eq(t, zeroed(kept), true)
		})
	}
}

func TestPayloadInUseZeroedAtFinish(t *testing.T) {
	c, clk := newTestCache()
	k := cacheKey("pl_a")
	store(t, c, k, signed("payload"))

	a := begin(t, c, k)
	got := a.Attach(true, listed)
	c.DropPlacement(k.Placement)
	clk.set(cacheStart.Add(time.Hour))
	c.Has(k)
	eq(t, string(got.Value), "payload")
	a.Finish(EndOther)
	eq(t, zeroed(got.Value), true)
	eq(t, placements(c), 0)
}

func TestStoreAfterDropPlacementKeepsNothing(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	a := begin(t, c, k)
	c.DropPlacement(k.Placement)

	p := signed("payload")
	a.Store(p)
	eq(t, c.Has(k), false)
	eq(t, string(p.Value), "payload")
	a.Finish(EndOther)
	eq(t, zeroed(p.Value), true)
	eq(t, placements(c), 0)
}

func TestOnePaidAttemptPerKey(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	first := begin(t, c, k)

	got := make(chan *Attempt, 1)
	go func() {
		a, err := c.Begin(context.Background(), k)
		if err != nil {
			t.Errorf("second begin: %v", err)
		}
		got <- a
	}()
	select {
	case <-got:
		t.Fatal("a second Begin returned while the first held the key")
	case <-time.After(50 * time.Millisecond):
	}
	first.Finish(EndOther)
	select {
	case a := <-got:
		a.Finish(EndOther)
	case <-time.After(time.Second):
		t.Fatal("the second Begin still waits after the first Finish")
	}
}

func TestBeginCancelledWhileWaiting(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	first := begin(t, c, k)

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		a, err := c.Begin(ctx, k)
		if a != nil {
			t.Error("a cancelled Begin holds the key")
		}
		errs <- err
	}()
	select {
	case err := <-errs:
		t.Fatalf("Begin returned %v while the key was held", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := within(errs); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}

	first.Finish(EndOther)
	begin(t, c, k).Finish(EndOther)
	eq(t, placements(c), 0)
}

func TestBeginDeadlinePassesWhileWaiting(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	first := begin(t, c, k)
	defer first.Finish(EndOther)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	a, err := c.Begin(ctx, k)
	eq(t, a, (*Attempt)(nil))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
}

func TestBeginWithADoneContextHoldsNothing(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 100 {
		a, err := c.Begin(ctx, k)
		eq(t, a, (*Attempt)(nil))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	}
	begin(t, c, k).Finish(EndOther)
}

func TestTwoKeysNeverWait(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	held := begin(t, c, k)
	defer held.Finish(EndOther)

	other := k
	other.Target = "/search?q=weather%20in%20Rome"
	begin(t, c, other).Finish(EndOther)
	begin(t, c, cacheKey("pl_b")).Finish(EndOther)
}

func TestIdenticalRequestsTakeTurns(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	var inside, most int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			a, err := c.Begin(context.Background(), k)
			if err != nil {
				t.Errorf("begin: %v", err)
				return
			}
			mu.Lock()
			inside++
			most = max(most, inside)
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			a.Finish(EndOther)
		})
	}
	wg.Wait()
	eq(t, most, 1)
}

func TestFinishTwiceReleasesOnce(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	first := begin(t, c, k)
	first.Finish(EndOther)
	second := begin(t, c, k)
	first.Finish(EndOther)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Begin(ctx, k); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a third Begin got %v while the second held the key", err)
	}
	second.Finish(EndOther)
}

func TestFinishedAttemptAttachesAndStoresNothing(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	store(t, c, k, signed("payload"))

	a := begin(t, c, k)
	a.Finish(EndOther)
	eq(t, a.Attach(true, listed), (*Payload)(nil))
	p := signed("late")
	a.Store(p)
	eq(t, zeroed(p.Value), true)
	eq(t, string(resend(t, c, k).Value), "payload")
}

func TestAttachNeedsEnabledAndListed(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)

	var asked []string
	only := func(id string) func(string) bool {
		return func(serviceID string) bool {
			asked = append(asked, serviceID)
			return serviceID == id
		}
	}
	a := begin(t, c, k)
	eq(t, a.Attach(false, listed), (*Payload)(nil))
	eq(t, a.Attach(true, only("xs_bbbbbbbbbbbbbbbb")), (*Payload)(nil))
	eq(t, a.Attach(true, nil), (*Payload)(nil))
	a.Finish(EndOther)
	eq(t, asked, []string{p.ServiceID})
	eq(t, c.Has(k), true)

	for range 3 {
		a := begin(t, c, k)
		eq(t, string(a.Attach(true, only(p.ServiceID)).Value), "payload")
		a.Finish(EndOther)
	}
	eq(t, c.Has(k), false)
}

func TestAttachRechecksAfterListed(t *testing.T) {
	c, _ := newTestCache()
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)

	a := begin(t, c, k)
	got := a.Attach(true, func(string) bool {
		c.DropPlacement(k.Placement)
		return true
	})
	eq(t, got, (*Payload)(nil))
	eq(t, zeroed(p.Value), true)
	a.Finish(EndOther)
}

func TestNoResendsAllowed(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	c := NewCache(0, clk.now)
	k := cacheKey("pl_a")
	p := signed("payload")
	store(t, c, k, p)
	eq(t, resend(t, c, k), (*Payload)(nil))
	eq(t, c.Has(k), false)
	eq(t, zeroed(p.Value), true)
}

func TestDropPlacementZeroesAll(t *testing.T) {
	c, _ := newTestCache()
	a1, a2, b := cacheKey("pl_a"), cacheKey("pl_a"), cacheKey("pl_b")
	a2.Method = "POST"
	pa1, pa2, pb := signed("a1"), signed("a2"), signed("b")
	store(t, c, a1, pa1)
	store(t, c, a2, pa2)
	store(t, c, b, pb)

	c.DropPlacement("pl_a")
	eq(t, c.Has(a1), false)
	eq(t, c.Has(a2), false)
	eq(t, zeroed(pa1.Value), true)
	eq(t, zeroed(pa2.Value), true)
	eq(t, c.Has(b), true)
	eq(t, string(pb.Value), "b")
	eq(t, placements(c), 1)
	c.DropPlacement("pl_none")
}

func TestPayloadNeverPrinted(t *testing.T) {
	p := signed("c2lnbmVkLXRyYW5zYWN0aW9u")
	k := cacheKey("pl_a")
	secrets := []string{
		string(p.Value),
		base64.StdEncoding.EncodeToString(p.Value),
		hex.EncodeToString(p.Value),
		fmt.Sprintf("%d", p.Value),
		p.PaymentRef,
		p.PaymentID,
		"weather",
		hex.EncodeToString(k.BodySum[:]),
	}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		out = append(out, fmt.Sprintf(verb, p), fmt.Sprintf(verb, &p), fmt.Sprintf(verb, k))
	}
	var logs bytes.Buffer
	for _, log := range []*slog.Logger{
		slog.New(slog.NewJSONHandler(&logs, nil)),
		slog.New(slog.NewTextHandler(&logs, nil)),
	} {
		log.Info("paid", "payload", p, "ptr", &p, "key", k)
	}
	out = append(out, logs.String())
	for _, o := range out {
		for _, s := range secrets {
			if strings.Contains(o, s) {
				t.Fatalf("%q holds %q", o, s)
			}
		}
	}
}
