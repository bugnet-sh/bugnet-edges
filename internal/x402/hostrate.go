package x402

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// HostRate is one bucket per host across placements, filled only by ends without a payment
type HostRate struct {
	perMinute, floor int
	now              func() time.Time

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	windows map[floorKey]*floorWindow
	swept   time.Time
}

// floorKey names one placement's requests to one host
type floorKey struct{ host, placement string }

// floorWindow counts the requests admitted in the minute from start
type floorWindow struct {
	start time.Time
	n     int
}

// NewHostRate holds perMinute unpaid requests a host and passes floor a minute per placement
func NewHostRate(perMinute, floor int, now func() time.Time) *HostRate {
	return &HostRate{
		perMinute: perMinute,
		floor:     floor,
		now:       now,
		buckets:   map[string]*rate.Limiter{},
		windows:   map[floorKey]*floorWindow{},
	}
}

// Admit says whether a request may be sent, a resend is counted here
func (h *HostRate) Admit(host, placement string, resend bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Read under the lock, so the buckets see times in order
	now := h.now()
	h.sweep(now)
	k := floorKey{host, placement}
	w := h.windows[k]
	if w == nil || !now.Before(w.start.Add(time.Minute)) {
		w = &floorWindow{start: now}
		h.windows[k] = w
	}
	if w.n >= h.floor && h.tokens(host, now) < 1 {
		return false
	}
	w.n++
	if resend {
		h.spend(host, now)
	}
	return true
}

// Ended spends a token when the answer started and the end's status carries no payment
func (h *HostRate) Ended(host string, answered bool, status string, resend bool) {
	// A cached resend spent its token at Admit
	if resend || !answered || !UnpaidEnd(status) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.sweep(now)
	h.spend(host, now)
}

// tokens is what the host's bucket holds, full when it has none, with h.mu held
func (h *HostRate) tokens(host string, now time.Time) float64 {
	if b := h.buckets[host]; b != nil {
		return b.TokensAt(now)
	}
	return float64(h.perMinute)
}

// spend takes one token, into a debt of at most one minute's refill, with h.mu held
func (h *HostRate) spend(host string, now time.Time) {
	b := h.buckets[host]
	if b == nil {
		b = rate.NewLimiter(rate.Limit(float64(h.perMinute)/60), h.perMinute)
		h.buckets[host] = b
	}
	if b.TokensAt(now)-1 >= -float64(h.perMinute) {
		b.ReserveN(now, 1)
	}
}

// sweep forgets past windows and full buckets once a minute, with h.mu held
func (h *HostRate) sweep(now time.Time) {
	if now.Sub(h.swept) < time.Minute {
		return
	}
	h.swept = now
	for k, w := range h.windows {
		if !now.Before(w.start.Add(time.Minute)) {
			delete(h.windows, k)
		}
	}
	for host, b := range h.buckets {
		if b.TokensAt(now) >= float64(h.perMinute) {
			delete(h.buckets, host)
		}
	}
}
