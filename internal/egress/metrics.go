package egress

import (
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
)

// topHosts is how many custom hosts the metrics tell apart (DP 10.5)
const topHosts = 1000

type proxyMetrics struct {
	tunnels       *metrics.Gauge
	tunnelRefused *metrics.Counter
	refusedSNI    *metrics.Counter
	bytes         *metrics.Counter
	requests      *metrics.Counter
}

func newProxyMetrics(r *metrics.Registry) *proxyMetrics {
	return &proxyMetrics{
		tunnels: r.Gauge("egress_tunnels", "Tunnels open now"),
		tunnelRefused: r.Counter("egress_tunnel_refused_total", "Tunnel upgrades refused",
			"status"),
		refusedSNI: r.Counter("egress_inner_handshakes_refused_total",
			"Inner handshakes refused for their server name"),
		bytes: r.Counter("egress_tunnel_bytes_total", "Bytes carried by tunnels", "direction"),
		requests: r.Counter("egress_requests_total", "Requests served inside tunnels",
			"kind", "status", "swapped"),
	}
}

// customRates limits and counts the requests to hosts outside every preset, all placements together
type customRates struct {
	perMinute int
	now       func() time.Time

	mu    sync.Mutex
	hosts map[string]*customHost
}

type customHost struct {
	limiter  *rate.Limiter
	requests uint64
	bytes    uint64
}

func newCustomRates(perMinute int, now func() time.Time) *customRates {
	return &customRates{perMinute: perMinute, now: now, hosts: map[string]*customHost{}}
}

// allow counts one request to host, false past the per-minute limit
func (c *customRates) allow(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.hosts[host]
	if h == nil {
		if len(c.hosts) >= topHosts {
			c.evictLocked()
		}
		h = &customHost{limiter: rate.NewLimiter(rate.Limit(float64(c.perMinute)/60), c.perMinute)}
		c.hosts[host] = h
	}
	h.requests++
	return h.limiter.AllowN(c.now(), 1)
}

func (c *customRates) addBytes(host string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.hosts[host]; h != nil && n > 0 {
		h.bytes += uint64(n)
	}
}

// evictLocked drops the host with the fewest requests, so the busiest stay
func (c *customRates) evictLocked() {
	least, count := "", ^uint64(0)
	for name, h := range c.hosts {
		if h.requests < count {
			least, count = name, h.requests
		}
	}
	delete(c.hosts, least)
}

// export registers the counts of the busiest custom hosts
func (c *customRates) export(r *metrics.Registry) {
	r.GaugeFunc("egress_custom_host_requests", "Requests to the busiest custom hosts",
		[]string{"host"}, func(emit func(float64, ...string)) {
			c.each(func(h string, x *customHost) { emit(float64(x.requests), h) })
		})
	r.GaugeFunc("egress_custom_host_bytes", "Response bytes of the busiest custom hosts",
		[]string{"host"}, func(emit func(float64, ...string)) {
			c.each(func(h string, x *customHost) { emit(float64(x.bytes), h) })
		})
}

func (c *customRates) each(f func(host string, h *customHost)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.hosts))
	for n := range c.hosts {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		f(n, c.hosts[n])
	}
}
