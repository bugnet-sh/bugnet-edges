package x402

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
)

const (
	kib = int64(1 << 10)
	mib = int64(1 << 20)
)

// take reserves n bytes for placement, failing the test when there is no room
func take(t *testing.T, b *Buffers, placement string, n int64) *Slot {
	t.Helper()
	s, ok := b.Take(placement, n)
	if !ok {
		t.Fatalf("no room for %d bytes of %s", n, placement)
	}
	return s
}

func TestSlotSize(t *testing.T) {
	for _, c := range []struct {
		length, want int64
		ok           bool
	}{
		{300 * kib, 300 * kib, true},
		{-1, mib, true},
		{mib, mib, true},
		{mib + 1, 0, false},
		{0, 0, true},
	} {
		got, ok := SlotSize(c.length, mib)
		eq(t, ok, c.ok)
		eq(t, got, c.want)
	}
}

func TestPerPlacementCap4MiB(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	for range 4 {
		take(t, b, "pl_a", mib)
	}
	_, ok := b.Take("pl_a", mib)
	eq(t, ok, false)
	eq(t, b.Held("pl_a"), 4*mib)

	take(t, b, "pl_b", mib)
	eq(t, b.Held("pl_b"), mib)
	eq(t, b.Total(), 5*mib)
}

func TestBudget256MiB(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	var first *Slot
	for i := range 64 {
		for j := range 4 {
			s := take(t, b, "pl_"+strconv.Itoa(i), mib)
			if i == 0 && j == 0 {
				first = s
			}
		}
	}
	eq(t, b.Total(), 256*mib)
	_, ok := b.Take("pl_64", mib)
	eq(t, ok, false)
	eq(t, b.Held("pl_64"), int64(0))

	first.Free()
	take(t, b, "pl_64", mib)
	eq(t, b.Total(), 256*mib)
}

func TestFreeIsIdempotent(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	s := take(t, b, "pl_a", mib)
	s.Free()
	s.Free()
	eq(t, b.Held("pl_a"), int64(0))
	eq(t, b.Total(), int64(0))

	take(t, b, "pl_a", 4*mib)
	_, ok := b.Take("pl_a", 1)
	eq(t, ok, false)

	var none *Slot
	none.Free()
}

func TestShrinkOfAFreedSlot(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	s := take(t, b, "pl_a", mib)
	s.Free()
	s.shrink(10)
	eq(t, b.Held("pl_a"), int64(0))
	eq(t, b.Total(), int64(0))
}

func TestTakeRefusesBadSizes(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	_, ok := b.Take("pl_a", -1)
	eq(t, ok, false)
	_, ok = b.Take("pl_a", 4*mib+1)
	eq(t, ok, false)

	empty := take(t, b, "pl_a", 0)
	eq(t, b.Held("pl_a"), int64(0))
	empty.Free()
	eq(t, b.Total(), int64(0))
}

func TestTakeAndFreeConcurrently(t *testing.T) {
	b := NewBuffers(8*mib, 4*mib)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			placement := "pl_" + strconv.Itoa(g%4)
			for range 200 {
				s, ok := b.Take(placement, mib)
				if held := b.Held(placement); held > 4*mib {
					t.Errorf("%s holds %d bytes", placement, held)
				}
				if total := b.Total(); total > 8*mib {
					t.Errorf("the process holds %d bytes", total)
				}
				if ok {
					s.Free()
					s.Free()
				}
			}
		})
	}
	wg.Wait()
	eq(t, b.Total(), int64(0))
	for i := range 4 {
		eq(t, b.Held("pl_"+strconv.Itoa(i)), int64(0))
	}
}

func TestBufferGaugeReadsTheProcessTotal(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)
	reg := metrics.New()
	b.Export(reg)
	take(t, b, "pl_a", mib)
	take(t, b, "pl_b", 300*kib)

	var out strings.Builder
	if _, err := reg.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	want := "egress_x402_buffer_bytes " + strconv.FormatFloat(float64(mib+300*kib), 'g', -1, 64)
	if !strings.Contains(out.String(), "# TYPE egress_x402_buffer_bytes gauge\n"+want+"\n") {
		t.Fatalf("no %q in\n%s", want, out.String())
	}
}
