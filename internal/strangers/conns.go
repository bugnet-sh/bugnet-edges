package strangers

import (
	"net/netip"
	"sync"
)

// Conns caps the connections each client address holds open at once, DP 4.5
type Conns struct {
	limit int

	mu   sync.Mutex
	open map[netip.Addr]int
}

// NewConns allows each address limit open connections, 0 or less is no limit
func NewConns(limit int) *Conns {
	return &Conns{limit: limit, open: map[netip.Addr]int{}}
}

// Acquire takes one of ip's slots and returns its release, false when every slot is taken
func (c *Conns) Acquire(ip netip.Addr) (release func(), ok bool) {
	if c.limit <= 0 {
		return func() {}, true
	}
	k := key(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[k] >= c.limit {
		return nil, false
	}
	c.open[k]++
	var once sync.Once
	return func() { once.Do(func() { c.release(k) }) }, true
}

func (c *Conns) release(k netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[k]--; c.open[k] <= 0 {
		delete(c.open, k)
	}
}

func (c *Conns) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}
