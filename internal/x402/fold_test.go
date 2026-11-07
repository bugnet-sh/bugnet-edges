package x402

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	eventHost = "api.example.com"
	svcA      = "xs_aaaaaaaaaaaaaaaa"
	svcB      = "xs_bbbbbbbbbbbbbbbb"
)

// eventAt is sec seconds past cacheStart, which starts a minute
func eventAt(sec int) time.Time {
	return cacheStart.Add(time.Duration(sec) * time.Second)
}

// eventCall is one request's event on eventHost under svcA
func eventCall(status string, reason Code, at time.Time) *routerv1.X402Event {
	return &routerv1.X402Event{
		At: timestamppb.New(at), Host: eventHost, Method: "GET", Path: "/v1/auto/x",
		Status: status, Reason: string(reason), ServiceId: svcA, HttpStatus: 403,
		BytesOut: 10, BytesIn: 20,
	}
}

// sink records each batch it is handed and answers through answer, OK when answer is nil
type sink struct {
	batches chan *routerv1.AppendX402EventsRequest

	mu     sync.Mutex
	calls  int
	answer func(ctx context.Context, call int) (*routerv1.AppendX402EventsResponse, error)
}

func (s *sink) send(
	ctx context.Context, r *routerv1.AppendX402EventsRequest,
) (*routerv1.AppendX402EventsResponse, error) {
	// A real client sends nothing on a context that has ended
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.calls++
	call, answer := s.calls, s.answer
	s.mu.Unlock()
	s.batches <- proto.CloneOf(r)
	if answer == nil {
		return &routerv1.AppendX402EventsResponse{}, nil
	}
	return answer(ctx, call)
}

func (s *sink) answerWith(
	f func(ctx context.Context, call int) (*routerv1.AppendX402EventsResponse, error),
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer = f
}

// drain takes every batch sent so far
func (s *sink) drain() []*routerv1.AppendX402EventsRequest {
	var out []*routerv1.AppendX402EventsRequest
	for {
		select {
		case b := <-s.batches:
			out = append(out, b)
		default:
			return out
		}
	}
}

// next waits a second at most for the next batch
func (s *sink) next(t *testing.T) *routerv1.AppendX402EventsRequest {
	t.Helper()
	select {
	case b := <-s.batches:
		return b
	case <-time.After(time.Second):
		t.Fatal("no batch within a second")
		return nil
	}
}

// none checks that no batch arrives within d
func (s *sink) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case b := <-s.batches:
		t.Fatalf("unexpected batch of %d events", len(b.GetEvents()))
	case <-time.After(d):
	}
}

// eventsOf lists the events of batches in the order they were sent
func eventsOf(bs []*routerv1.AppendX402EventsRequest) []*routerv1.X402Event {
	var out []*routerv1.X402Event
	for _, b := range bs {
		out = append(out, b.GetEvents()...)
	}
	return out
}

// newTestEvents makes Events on a clock at cacheStart, with services on all but pl_none
func newTestEvents(t *testing.T) (*Events, *sink, *cacheClock, *logBuf) {
	t.Helper()
	s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 1024)}
	clk := &cacheClock{t: cacheStart}
	logs := &logBuf{}
	e := NewEvents(s.send, 2*time.Second, clk.now, slog.New(slog.NewJSONHandler(logs, nil)))
	e.SetServices(func(placement string) bool { return placement != "pl_none" })
	return e, s, clk, logs
}

// flushed runs one flush and lists the events it sent, all of them for placement
func flushed(t *testing.T, e *Events, s *sink, placement string) []*routerv1.X402Event {
	t.Helper()
	e.flushAll(context.Background())
	bs := s.drain()
	for _, b := range bs {
		eq(t, b.GetPlacementId(), placement)
	}
	return eventsOf(bs)
}

func TestFoldFirstAtOnceRestAtClose(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	var refs []string
	for i, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		ev := eventCall(EventRefusedRequest, CodePathNotEnabled, eventAt(5+i))
		ev.Method = m
		ev.BytesOut, ev.BytesIn = uint64(10*(i+1)), uint64(100*(i+1))
		ev.Ref = NewRef()
		refs = append(refs, ev.Ref)
		e.Add("pl_a", ev)
	}

	clk.set(eventAt(30))
	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 1)
	first := got[0]
	eq(t, []any{first.GetCount(), first.GetMethod(), first.GetRef(), first.GetBytesOut(),
		first.GetBytesIn(), first.GetAt().AsTime()},
		[]any{uint32(1), "GET", refs[0], uint64(10), uint64(100), eventAt(5)})

	clk.set(eventAt(59))
	eq(t, len(flushed(t, e, s, "pl_a")), 0)

	clk.set(eventAt(60))
	got = flushed(t, e, s, "pl_a")
	eq(t, len(got), 1)
	rest := got[0]
	eq(t, []any{rest.GetCount(), rest.GetBytesOut(), rest.GetBytesIn(), rest.GetAt().AsTime(),
		rest.GetMethod(), rest.GetRef()},
		[]any{uint32(4), uint64(20 + 30 + 40 + 50), uint64(200 + 300 + 400 + 500), eventAt(9),
			"POST", refs[1]})
	eq(t, []any{rest.GetHost(), rest.GetServiceId(), rest.GetStatus(), rest.GetReason(),
		rest.GetPath()},
		[]any{eventHost, svcA, EventRefusedRequest, string(CodePathNotEnabled), "/v1/auto/x"})

	clk.set(eventAt(120))
	eq(t, len(flushed(t, e, s, "pl_a")), 0)
}

func TestFoldTakesTheNewestAt(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	for _, sec := range []int{5, 40, 20} {
		e.Add("pl_a", eventCall(EventFree, "", eventAt(sec)))
	}
	clk.set(eventAt(60))
	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 2)
	eq(t, got[1].GetAt().AsTime(), eventAt(40))
	eq(t, got[1].GetCount(), uint32(2))
}

func TestMoneyRowsNeverFold(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	var refs []string
	for range 3 {
		for _, ev := range []*routerv1.X402Event{
			eventCall(EventPaid, "", eventAt(5)),
			eventCall(EventUncertain, CodePaidNoAnswer, eventAt(5)),
			eventCall(EventPaymentFailed, CodePaymentRejected, eventAt(5)),
			eventCall(EventNotPaid, CodePaymentsUnavailable, eventAt(5)),
		} {
			if ev.GetStatus() == EventNotPaid {
				ev.AmountMicros = 1
			}
			ev.Ref = NewRef()
			refs = append(refs, ev.Ref)
			e.Add("pl_a", ev)
		}
	}

	clk.set(eventAt(30))
	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 12)
	var sent []string
	for _, ev := range got {
		eq(t, ev.GetCount(), uint32(1))
		sent = append(sent, ev.GetRef())
	}
	slices.Sort(refs)
	slices.Sort(sent)
	eq(t, sent, refs)

	clk.set(eventAt(60))
	eq(t, len(flushed(t, e, s, "pl_a")), 0)
}

func TestFoldKeyHoldsServiceID(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	for range 2 {
		for _, svc := range []string{svcA, svcB} {
			ev := eventCall(EventRefusedRequest, CodePathNotEnabled, eventAt(5))
			ev.ServiceId = svc
			e.Add("pl_a", ev)
		}
	}
	clk.set(eventAt(30))
	byService := func(evs []*routerv1.X402Event) map[string]uint32 {
		m := map[string]uint32{}
		for _, ev := range evs {
			m[ev.GetServiceId()] += ev.GetCount()
		}
		return m
	}
	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 2)
	eq(t, byService(got), map[string]uint32{svcA: 1, svcB: 1})

	clk.set(eventAt(60))
	got = flushed(t, e, s, "pl_a")
	eq(t, len(got), 2)
	eq(t, byService(got), map[string]uint32{svcA: 1, svcB: 1})
}

func TestFoldKeyHoldsHostStatusAndReason(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	other := eventCall(EventRefusedRequest, CodePathNotEnabled, eventAt(5))
	other.Host = "other.example.com"
	for _, ev := range []*routerv1.X402Event{
		eventCall(EventRefusedRequest, CodePathNotEnabled, eventAt(5)),
		eventCall(EventRefusedRequest, CodeMethodNotEnabled, eventAt(5)),
		eventCall(EventRefusedCap, CodeUnpaidCap, eventAt(5)),
		other,
	} {
		e.Add("pl_a", ev)
	}
	clk.set(eventAt(30))
	eq(t, len(flushed(t, e, s, "pl_a")), 4)
	clk.set(eventAt(60))
	eq(t, len(flushed(t, e, s, "pl_a")), 0)
}

func TestFoldPerPlacement(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
	e.Add("pl_b", eventCall(EventFree, "", eventAt(5)))
	clk.set(eventAt(30))
	e.flushAll(context.Background())
	var placements []string
	for _, b := range s.drain() {
		placements = append(placements, b.GetPlacementId())
		eq(t, len(b.GetEvents()), 1)
		eq(t, b.GetEvents()[0].GetCount(), uint32(1))
	}
	slices.Sort(placements)
	eq(t, placements, []string{"pl_a", "pl_b"})
}

func TestFoldWindowIsTheMinuteOfAt(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	e.Add("pl_a", eventCall(EventFree, "", eventAt(50)))
	e.Add("pl_a", eventCall(EventFree, "", eventAt(65)))
	clk.set(eventAt(70))
	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 2)
	for _, ev := range got {
		eq(t, ev.GetCount(), uint32(1))
	}

	// A call from a minute already closed is sent at the next flush, never held
	e.Add("pl_a", eventCall(EventFree, "", eventAt(58)))
	e.Add("pl_a", eventCall(EventFree, "", eventAt(57)))
	e.Add("pl_a", eventCall(EventFree, "", eventAt(59)))
	got = flushed(t, e, s, "pl_a")
	eq(t, len(got), 2)
	eq(t, []any{got[0].GetCount(), got[0].GetAt().AsTime()}, []any{uint32(1), eventAt(58)})
	eq(t, []any{got[1].GetCount(), got[1].GetAt().AsTime()}, []any{uint32(2), eventAt(59)})
}

func TestAddKeepsItsOwnCopy(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	ev := eventCall(EventFree, "", eventAt(5))
	ev.Ref = "not a ref"
	ev.Count = 7
	e.Add("pl_a", ev)
	ev.Host = "changed.example.com"

	kept := eventCall(EventFree, "", eventAt(6))
	kept.Ref = NewRef()
	kept.ServiceId = svcB
	e.Add("pl_a", kept)

	noAt := eventCall(EventFree, "", time.Time{})
	noAt.At = nil
	noAt.ServiceId = "xs_cccccccccccccccc"
	clk.set(eventAt(9))
	e.Add("pl_a", noAt)

	// Refs of 16 characters with one outside a-z and 2-7
	bad := []string{"ABCDEFGHIJKLMNOP", "0000000000000000", "abcdefghijklmno1",
		"abcdefghijklmno8", "abcdefghijklmn-z"}
	for i, ref := range bad {
		ev := eventCall(EventFree, "", eventAt(7))
		ev.Ref, ev.ServiceId = ref, fmt.Sprintf("xs_bad%013d", i)
		e.Add("pl_a", ev)
	}

	got := flushed(t, e, s, "pl_a")
	eq(t, len(got), 3+len(bad))
	eq(t, got[0].GetHost(), eventHost)
	eq(t, got[0].GetCount(), uint32(1))
	eq(t, got[1].GetRef(), kept.GetRef())
	eq(t, got[2].GetAt().AsTime(), eventAt(9))
	refShape := regexp.MustCompile(`^[a-z2-7]{16}$`)
	for i, ev := range append([]*routerv1.X402Event{got[0]}, got[3:]...) {
		if !refShape.MatchString(ev.GetRef()) || (i > 0 && ev.GetRef() == bad[i-1]) {
			t.Fatalf("Add kept the ref %q", ev.GetRef())
		}
	}
}

func TestIdlePlacementsForgotten(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	for range 3 {
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
	}
	e.RefusedHost("pl_a", "x.example.com", eventAt(5))
	e.RefusedHost("pl_a", "bad_name", eventAt(5))
	clk.set(eventAt(60))
	eq(t, len(flushed(t, e, s, "pl_a")), 4)
	e.mu.Lock()
	defer e.mu.Unlock()
	eq(t, len(e.places), 0)
}

func TestRefusedHostNames(t *testing.T) {
	t.Run("a name is lower-cased and has no method or path", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		e.RefusedHost("pl_a", "API.Example.COM", eventAt(5))
		clk.set(eventAt(30))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 1)
		ev := got[0]
		eq(t, []any{ev.GetHost(), ev.GetMethod(), ev.GetPath(), ev.GetStatus(), ev.GetReason(),
			ev.GetCount(), ev.GetAt().AsTime(), isRef(ev.GetRef())},
			[]any{"api.example.com", "", "", EventRefusedHost, "", uint32(1), eventAt(5), true})
	})

	t.Run("a name folds like any row", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		for i := range 4 {
			e.RefusedHost("pl_a", "api.example.com", eventAt(5+i))
		}
		clk.set(eventAt(60))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 2)
		eq(t, []any{got[0].GetCount(), got[1].GetCount(), got[1].GetHost(),
			got[1].GetAt().AsTime()}, []any{uint32(1), uint32(3), "api.example.com", eventAt(8)})
	})

	t.Run("other characters go to the empty-host row at the close", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		for _, name := range []string{
			"evil_name", "bücher.example", "Kelvin.example", "", "a b.example",
		} {
			e.RefusedHost("pl_a", name, eventAt(5))
		}
		clk.set(eventAt(30))
		eq(t, len(flushed(t, e, s, "pl_a")), 0)
		clk.set(eventAt(60))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 1)
		eq(t, []any{got[0].GetHost(), got[0].GetMethod(), got[0].GetPath(), got[0].GetStatus(),
			got[0].GetReason(), got[0].GetCount()},
			[]any{"", "", "", EventRefusedHost, "", uint32(5)})
	})

	t.Run("11 names give 10 named rows and one empty-host row", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		for i := range 11 {
			e.RefusedHost("pl_a", fmt.Sprintf("n%d.example.com", i), eventAt(5))
		}
		e.RefusedHost("pl_a", "n0.example.com", eventAt(6))
		clk.set(eventAt(30))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 10)
		for _, ev := range got {
			eq(t, ev.GetHost() != "" && ev.GetHost() != "n10.example.com", true)
		}
		clk.set(eventAt(60))
		got = flushed(t, e, s, "pl_a")
		eq(t, len(got), 2)
		hosts := map[string]uint32{}
		for _, ev := range got {
			hosts[ev.GetHost()] = ev.GetCount()
		}
		eq(t, hosts, map[string]uint32{"": 1, "n0.example.com": 1})
	})

	t.Run("each minute has its own 10 names", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		for i := range 10 {
			e.RefusedHost("pl_a", fmt.Sprintf("n%d.example.com", i), eventAt(5))
		}
		for i := range 10 {
			e.RefusedHost("pl_a", fmt.Sprintf("m%d.example.com", i), eventAt(65))
		}
		clk.set(eventAt(70))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 20)
		for _, ev := range got {
			eq(t, ev.GetHost() != "", true)
		}
	})

	t.Run("a long name is cut to 63", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		name := strings.Repeat("a", 70) + ".example.com"
		e.RefusedHost("pl_a", name, eventAt(5))
		clk.set(eventAt(30))
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 1)
		eq(t, got[0].GetHost(), name[:63])
	})

	t.Run("a placement without x402 services writes nothing", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		e.RefusedHost("pl_none", "api.example.com", eventAt(5))
		e.RefusedHost("pl_none", "evil_name", eventAt(5))
		clk.set(eventAt(60))
		eq(t, len(flushed(t, e, s, "pl_none")), 0)
	})

	t.Run("no services check writes nothing", func(t *testing.T) {
		s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 16)}
		clk := &cacheClock{t: cacheStart}
		e := NewEvents(s.send, 2*time.Second, clk.now, nil)
		e.RefusedHost("pl_a", "api.example.com", eventAt(5))
		clk.set(eventAt(60))
		eq(t, len(flushed(t, e, s, "pl_a")), 0)
	})

	t.Run("a zero time is the clock", func(t *testing.T) {
		e, s, clk, _ := newTestEvents(t)
		clk.set(eventAt(7))
		e.RefusedHost("pl_a", "api.example.com", time.Time{})
		got := flushed(t, e, s, "pl_a")
		eq(t, len(got), 1)
		eq(t, got[0].GetAt().AsTime(), eventAt(7))
	})
}
