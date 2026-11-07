package x402

import (
	"sync"
	"testing"
	"time"
)

// left is what a host's bucket holds now
func left(h *HostRate, host string) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tokens(host, h.now())
}

// unpaidCall admits one request and ends it free with an answer, failing when it is refused
func unpaidCall(t *testing.T, h *HostRate, host, placement string) {
	t.Helper()
	if !h.Admit(host, placement, false) {
		t.Fatalf("%s refused on %s", placement, host)
	}
	h.Ended(host, true, EventFree, false)
}

func TestHostRateCountsUnpaidEnds(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(600, 20, clk.now)
	const a, b = "a.example.com", "b.example.com"

	for range 600 {
		unpaidCall(t, h, a, "pl_a")
	}
	eq(t, left(h, a), 0.0)
	eq(t, h.Admit(a, "pl_a", false), false)
	eq(t, h.Admit(a, "pl_a", true), false)
	eq(t, left(h, a), 0.0)

	for i := range 20 {
		if !h.Admit(a, "pl_b", false) {
			t.Fatalf("pl_b's request %d refused within the floor", i+1)
		}
	}
	eq(t, h.Admit(a, "pl_b", false), false)

	for i := range 1000 {
		if !h.Admit(b, "pl_c", false) {
			t.Fatalf("pl_c's paid request %d refused", i+1)
		}
		status := EventPaid
		if i%2 == 1 {
			status = EventUncertain
		}
		h.Ended(b, true, status, false)
	}
	eq(t, left(h, b), 600.0)

	h.Ended(b, true, EventPaymentFailed, false)
	eq(t, left(h, b), 599.0)
	h.Ended(b, false, EventFree, false)
	eq(t, left(h, b), 599.0)

	eq(t, h.Admit(b, "pl_c", true), true)
	eq(t, left(h, b), 598.0)
	h.Ended(b, true, EventPaymentFailed, true)
	eq(t, left(h, b), 598.0)

	clk.set(cacheStart.Add(time.Minute))
	eq(t, h.Admit(a, "pl_a", false), true)
}

func TestHostRateFloorIsTheSetting(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(10, 5, clk.now)
	const host = "api.example.com"

	// fill keeps the bucket empty, as an attacker's placement does
	fill := func() {
		t.Helper()
		for range 10 {
			unpaidCall(t, h, host, "pl_attacker")
		}
		eq(t, left(h, host), 0.0)
	}

	fill()
	for i := range 5 {
		if !h.Admit(host, "pl_a", false) {
			t.Fatalf("request %d refused within the floor", i+1)
		}
	}
	eq(t, h.Admit(host, "pl_a", false), false)

	clk.set(cacheStart.Add(time.Minute))
	fill()
	for i := range 5 {
		if !h.Admit(host, "pl_a", false) {
			t.Fatalf("request %d of the next minute refused within the floor", i+1)
		}
	}
	eq(t, h.Admit(host, "pl_a", false), false)
}

func TestHostRateFloorWindowStartsAtFirstRequest(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(10, 2, clk.now)
	const host = "api.example.com"

	// drain puts the bucket at its deepest debt, as a steady attacker does
	drain := func(after time.Duration) {
		clk.set(cacheStart.Add(after))
		for range 30 {
			h.Ended(host, true, EventFree, false)
		}
		if l := left(h, host); l > -9 {
			t.Fatalf("the bucket holds %v after the drain", l)
		}
	}

	drain(0)
	drain(10 * time.Second)
	eq(t, h.Admit(host, "pl_a", false), true)
	eq(t, h.Admit(host, "pl_a", false), true)
	eq(t, h.Admit(host, "pl_a", false), false)

	// The sweep at 60 s keeps the window, which ends at 70 s
	drain(60 * time.Second)
	eq(t, h.Admit(host, "pl_a", false), false)
	drain(70 * time.Second)
	eq(t, h.Admit(host, "pl_a", false), true)
}

func TestHostRateDebtIsBounded(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(600, 1, clk.now)
	const host = "api.example.com"

	for range 2000 {
		h.Ended(host, true, EventFree, false)
	}
	eq(t, left(h, host), -600.0)

	clk.set(cacheStart.Add(time.Minute))
	eq(t, h.Admit(host, "pl_a", false), true)
	eq(t, h.Admit(host, "pl_a", false), false)

	clk.set(cacheStart.Add(time.Minute + 200*time.Millisecond))
	eq(t, h.Admit(host, "pl_a", false), true)
}

func TestHostRateForgetsIdleState(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(600, 20, clk.now)
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		for _, pl := range []string{"pl_a", "pl_b"} {
			unpaidCall(t, h, host, pl)
		}
	}
	eq(t, len(h.windows), 6)
	eq(t, len(h.buckets), 3)

	clk.set(cacheStart.Add(2 * time.Minute))
	unpaidCall(t, h, "d.example.com", "pl_a")
	eq(t, len(h.windows), 1)
	eq(t, len(h.buckets), 1)
}

func TestHostRateConcurrentUse(t *testing.T) {
	clk := &cacheClock{t: cacheStart}
	h := NewHostRate(1000, 20, clk.now)
	const host = "api.example.com"
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if h.Admit(host, "pl_a", false) {
					h.Ended(host, true, EventFree, false)
				}
			}
		})
	}
	wg.Wait()
	eq(t, left(h, host), 200.0)
}
