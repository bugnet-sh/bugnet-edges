package strangers

import (
	"net/netip"
	"sync"
	"testing"
)

func TestConnsCapsEachAddress(t *testing.T) {
	c := NewConns(2)
	r1, ok1 := c.Acquire(ip)
	_, ok2 := c.Acquire(ip)
	_, ok3 := c.Acquire(ip)
	eq(t, []bool{ok1, ok2, ok3}, []bool{true, true, false})
	_, ok := c.Acquire(other)
	eq(t, ok, true)

	// An IPv4-mapped address shares its IPv4 address's slots
	_, ok = c.Acquire(netip.MustParseAddr("::ffff:203.0.113.9"))
	eq(t, ok, false)

	r1()
	r1()
	_, ok = c.Acquire(ip)
	eq(t, ok, true)
	_, ok = c.Acquire(ip)
	eq(t, ok, false)
}

func TestConnsForgetsAnAddressWithNothingOpen(t *testing.T) {
	c := NewConns(16)
	release, _ := c.Acquire(ip6)
	eq(t, c.size(), 1)
	release()
	eq(t, c.size(), 0)
}

func TestConnsHoldsUnderRaces(t *testing.T) {
	c := NewConns(16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	most, open := 0, 0
	for range 64 {
		wg.Go(func() {
			for range 100 {
				release, ok := c.Acquire(ip)
				if !ok {
					continue
				}
				mu.Lock()
				open++
				most = max(most, open)
				open--
				mu.Unlock()
				release()
			}
		})
	}
	wg.Wait()
	eq(t, most <= 16, true)
	eq(t, c.size(), 0)
}
