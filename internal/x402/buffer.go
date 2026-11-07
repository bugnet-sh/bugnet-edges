package x402

import (
	"sync"
	"sync/atomic"

	"github.com/oynozan/bugnet-edges/internal/metrics"
)

// Buffers is the process-wide body budget, split per placement
type Buffers struct {
	budget, perPlacement int64

	mu    sync.Mutex
	total int64
	held  map[string]int64
}

// NewBuffers makes a budget of budget bytes, at most perPlacement of them for one placement
func NewBuffers(budget, perPlacement int64) *Buffers {
	return &Buffers{budget: budget, perPlacement: perPlacement, held: map[string]int64{}}
}

// Slot is the room one request holds for its body
type Slot struct {
	b         *Buffers
	placement string
	n         int64
	freed     atomic.Bool
}

// Take reserves n bytes for placement, false when either limit lacks room
func (b *Buffers) Take(placement string, n int64) (*Slot, bool) {
	if n < 0 {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	held := b.held[placement]
	if n > b.perPlacement-held || n > b.budget-b.total {
		return nil, false
	}
	b.total += n
	if n > 0 {
		b.held[placement] = held + n
	}
	return &Slot{b: b, placement: placement, n: n}, true
}

// Held is what one placement holds, for tests and the gauge
func (b *Buffers) Held(placement string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held[placement]
}

// Total is what every placement holds together
func (b *Buffers) Total() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

// Export registers the gauge egress_x402_buffer_bytes, which reads Total at each scrape
func (b *Buffers) Export(r *metrics.Registry) {
	r.GaugeFunc("egress_x402_buffer_bytes", "Request body bytes held for x402 paid retries",
		nil, func(emit func(float64, ...string)) { emit(float64(b.Total())) })
}

// Free gives the slot's room back once, however often it is called
func (s *Slot) Free() {
	if s == nil || !s.freed.CompareAndSwap(false, true) {
		return
	}
	b := s.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total -= s.n
	if held := b.held[s.placement] - s.n; held > 0 {
		b.held[s.placement] = held
	} else {
		delete(b.held, s.placement)
	}
}

// SlotSize is min(length, limit), limit when length is unknown, false when length is over limit
func SlotSize(contentLength, limit int64) (int64, bool) {
	switch {
	case contentLength < 0:
		return limit, true
	case contentLength > limit:
		return 0, false
	}
	return contentLength, true
}
