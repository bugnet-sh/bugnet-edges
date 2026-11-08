package x402

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// runEvents runs e.Run until the test ends, ticking only when the test sends on the channel
func runEvents(t *testing.T, e *Events) (tick chan time.Time, stop func()) {
	t.Helper()
	tick = make(chan time.Time)
	e.tick = tick
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("Run did not return within 2 s of its context ending")
			}
		})
	}
	t.Cleanup(stop)
	return tick, stop
}

// paidCall is a paid request's event on host
func paidCall(host string, at time.Time) *routerv1.X402Event {
	ev := eventCall(EventPaid, "", at)
	ev.Host, ev.AmountMicros, ev.HttpStatus = host, 10000, 200
	return ev
}

// unavailable fails every send as a router that is down
func unavailable(context.Context, int) (*routerv1.AppendX402EventsResponse, error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("router down"))
}

// refsOf lists the refs of events in order
func refsOf(evs []*routerv1.X402Event) []string {
	var out []string
	for _, ev := range evs {
		out = append(out, ev.GetRef())
	}
	return out
}

func TestFlushEvery2sOrAt50(t *testing.T) {
	t.Run("a tick sends the queue", func(t *testing.T) {
		e, s, _, _ := newTestEvents(t)
		tick, _ := runEvents(t, e)
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		s.none(t, 50*time.Millisecond)
		tick <- time.Now()
		b := s.next(t)
		eq(t, b.GetPlacementId(), "pl_a")
		eq(t, len(b.GetEvents()), 1)
	})

	t.Run("50 rows send at once", func(t *testing.T) {
		e, s, _, _ := newTestEvents(t)
		runEvents(t, e)
		for i := range 49 {
			e.Add("pl_a", paidCall(fmt.Sprintf("h%d.example.com", i), eventAt(5)))
		}
		e.Add("pl_b", paidCall(eventHost, eventAt(5)))
		s.none(t, 50*time.Millisecond)
		e.Add("pl_a", paidCall(eventHost, eventAt(5)))
		b := s.next(t)
		eq(t, b.GetPlacementId(), "pl_a")
		eq(t, len(b.GetEvents()), 50)
		s.none(t, 50*time.Millisecond)
	})

	t.Run("the ticker runs at the flush interval", func(t *testing.T) {
		s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 16)}
		e := NewEvents(s.send, 20*time.Millisecond, time.Now, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			e.Run(ctx)
			close(done)
		}()
		defer func() {
			cancel()
			<-done
		}()
		e.Add("pl_a", eventCall(EventFree, "", time.Now()))
		eq(t, len(s.next(t).GetEvents()), 1)
	})

	t.Run("2 s is the default interval", func(t *testing.T) {
		d := time.Duration(Defaults().EventFlushInterval)
		eq(t, NewEvents(nil, d, nil, nil).flush, 2*time.Second)
		eq(t, NewEvents(nil, 0, nil, nil).flush, 2*time.Second)
	})
}

func TestRunClosesTheMinute(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	tick, _ := runEvents(t, e)
	for i := range 3 {
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5+i)))
	}
	clk.set(eventAt(30))
	tick <- time.Now()
	eq(t, s.next(t).GetEvents()[0].GetCount(), uint32(1))
	clk.set(eventAt(60))
	tick <- time.Now()
	eq(t, s.next(t).GetEvents()[0].GetCount(), uint32(2))
}

func TestRunFlushesAtTheMinuteClose(t *testing.T) {
	eq(t, untilMinute(eventAt(0)), time.Minute)
	eq(t, untilMinute(eventAt(59).Add(900*time.Millisecond)), 100*time.Millisecond)

	e, s, _, _ := newTestEvents(t)
	for i := range 3 {
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5+i)))
	}
	// The clock runs in real time from 500 ms before the minute ends, and nothing ticks
	start := time.Now()
	e.now = func() time.Time { return eventAt(59).Add(500*time.Millisecond + time.Since(start)) }
	runEvents(t, e)
	b := s.next(t)
	var counts []uint32
	for _, ev := range b.GetEvents() {
		counts = append(counts, ev.GetCount())
	}
	eq(t, counts, []uint32{1, 2})
}

// minuteTimers stands in for Run's minute timer, giving the test each one Run arms and its wait
type minuteTimers struct {
	armed chan chan time.Time
	waits chan time.Duration
}

func (m *minuteTimers) after(d time.Duration) <-chan time.Time {
	c := make(chan time.Time, 1)
	m.waits <- d
	m.armed <- c
	return c
}

// next is the timer Run arms next, failing the test when Run arms none within a second
func (m *minuteTimers) next(t *testing.T) chan time.Time {
	t.Helper()
	select {
	case c := <-m.armed:
		eq(t, <-m.waits, time.Minute)
		return c
	case <-time.After(time.Second):
		t.Fatal("Run armed no minute timer within a second")
		return nil
	}
}

func TestRunFlushesAtEachMinuteClose(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	timers := &minuteTimers{armed: make(chan chan time.Time, 4), waits: make(chan time.Duration, 4)}
	e.minuteAfter = timers.after
	runEvents(t, e)
	for minute := range 2 {
		timer := timers.next(t)
		for i := range 3 {
			e.Add("pl_a", eventCall(EventFree, "", eventAt(60*minute+5+i)))
		}
		s.none(t, 50*time.Millisecond)
		clk.set(eventAt(60 * (minute + 1)))
		timer <- time.Now()
		var counts []uint32
		for _, ev := range s.next(t).GetEvents() {
			counts = append(counts, ev.GetCount())
		}
		eq(t, counts, []uint32{1, 2})
	}
}

func TestBatchesHoldAtMost50(t *testing.T) {
	e, s, clk, _ := newTestEvents(t)
	for i := range 55 {
		ev := eventCall(EventFree, "", eventAt(5))
		ev.Host = fmt.Sprintf("free%d.example.com", i)
		e.Add("pl_a", ev)
	}
	for i := range 60 {
		e.Add("pl_a", paidCall(fmt.Sprintf("paid%d.example.com", i), eventAt(5)))
	}
	clk.set(eventAt(30))
	e.flushAll(context.Background())
	bs := s.drain()
	var sizes []int
	for _, b := range bs {
		eq(t, b.GetPlacementId(), "pl_a")
		sizes = append(sizes, len(b.GetEvents()))
	}
	eq(t, sizes, []int{50, 50, 15})
	evs := eventsOf(bs)
	for i, ev := range evs {
		eq(t, CanInvolveMoney(ev), i < 60)
	}
}

func TestRetryRules(t *testing.T) {
	t.Run("a row that cannot involve money is dropped after 3 retries", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		s.answerWith(unavailable)
		ev := eventCall(EventFree, "", eventAt(5))
		ev.Ref = NewRef()
		e.Add("pl_a", ev)
		var tries []string
		for i := range 6 {
			clk.set(eventAt(10 + 2*i))
			tries = append(tries, refsOf(flushed(t, e, s, "pl_a"))...)
		}
		eq(t, tries, []string{ev.Ref, ev.Ref, ev.Ref, ev.Ref})
		drops := logs.records(t, msgEventDropped)
		eq(t, len(drops), 1)
		eq(t, []any{drops[0]["why"], drops[0]["level"]}, []any{"tries", "WARN"})
	})

	t.Run("a money row is retried for 5 minutes", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		s.answerWith(unavailable)
		ev := paidCall(eventHost, eventAt(1))
		ev.Ref = NewRef()
		clk.set(eventAt(1))
		e.Add("pl_a", ev)
		var tries []string
		for _, d := range []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute,
			4 * time.Minute, 5*time.Minute - time.Second} {
			clk.set(eventAt(1).Add(d))
			tries = append(tries, refsOf(flushed(t, e, s, "pl_a"))...)
		}
		eq(t, len(tries), 6)
		eq(t, len(logs.records(t, msgEventDropped)), 0)

		clk.set(eventAt(1).Add(5 * time.Minute))
		tries = append(tries, refsOf(flushed(t, e, s, "pl_a"))...)
		clk.set(eventAt(1).Add(5*time.Minute + 2*time.Second))
		tries = append(tries, refsOf(flushed(t, e, s, "pl_a"))...)
		eq(t, len(tries), 7)
		for _, r := range tries {
			eq(t, r, ev.Ref)
		}
		drops := logs.records(t, msgEventDropped)
		eq(t, len(drops), 1)
		eq(t, []any{drops[0]["why"], drops[0]["level"]}, []any{"retry_window", "ERROR"})
	})

	t.Run("InvalidArgument drops the batch at once", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		s.answerWith(func(context.Context, int) (*routerv1.AppendX402EventsResponse, error) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown"))
		})
		e.Add("pl_a", paidCall(eventHost, eventAt(5)))
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		clk.set(eventAt(10))
		eq(t, len(flushed(t, e, s, "pl_a")), 2)
		clk.set(eventAt(12))
		eq(t, len(flushed(t, e, s, "pl_a")), 0)
		drops := logs.records(t, msgEventDropped)
		eq(t, len(drops), 2)
		for _, d := range drops {
			eq(t, []any{d["why"], d["code"]}, []any{"invalid_argument", "invalid_argument"})
		}
	})

	t.Run("a rejected index is logged and never resent", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		s.answerWith(func(context.Context, int) (*routerv1.AppendX402EventsResponse, error) {
			return &routerv1.AppendX402EventsResponse{Rejected: []uint32{1, 9}}, nil
		})
		for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
			e.Add("pl_a", paidCall(h, eventAt(5)))
		}
		clk.set(eventAt(10))
		eq(t, len(flushed(t, e, s, "pl_a")), 3)
		clk.set(eventAt(12))
		eq(t, len(flushed(t, e, s, "pl_a")), 0)
		drops := logs.records(t, msgEventDropped)
		eq(t, len(drops), 1)
		eq(t, []any{drops[0]["why"], drops[0]["host"]}, []any{"rejected", "b.example.com"})
		var sent []any
		for _, r := range logs.records(t, msgEventSent) {
			sent = append(sent, r["host"])
		}
		eq(t, sent, []any{"a.example.com", "c.example.com"})
	})

	t.Run("a resend reuses every ref, a folded row's too", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		s.answerWith(func(
			ctx context.Context, call int,
		) (*routerv1.AppendX402EventsResponse, error) {
			if call < 3 {
				return unavailable(ctx, call)
			}
			return &routerv1.AppendX402EventsResponse{}, nil
		})
		for range 3 {
			e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		}
		e.Add("pl_a", paidCall(eventHost, eventAt(5)))
		clk.set(eventAt(60))
		first := refsOf(flushed(t, e, s, "pl_a"))
		eq(t, len(first), 3)
		for range 2 {
			clk.set(clk.now().Add(2 * time.Second))
			again := refsOf(flushed(t, e, s, "pl_a"))
			slices.Sort(first)
			slices.Sort(again)
			eq(t, again, first)
		}
		clk.set(clk.now().Add(2 * time.Second))
		eq(t, len(flushed(t, e, s, "pl_a")), 0)
		eq(t, len(logs.records(t, msgEventSent)), 3)
	})

	t.Run("a flush on a context already ended counts no try", func(t *testing.T) {
		e, s, clk, logs := newTestEvents(t)
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		cut, cancel := context.WithCancel(context.Background())
		cancel()
		for range 6 {
			e.flushAll(cut)
		}
		eq(t, len(s.drain()), 0)
		clk.set(eventAt(10))
		eq(t, len(flushed(t, e, s, "pl_a")), 1)
		eq(t, len(logs.records(t, msgEventDropped)), 0)
	})

	t.Run("a send in flight when Run ends counts no try", func(t *testing.T) {
		e, s, _, logs := newTestEvents(t)
		s.answerWith(func(
			ctx context.Context, call int,
		) (*routerv1.AppendX402EventsResponse, error) {
			switch {
			case call < 4:
				return unavailable(ctx, call)
			case call == 4:
				return hang(ctx, call)
			}
			return &routerv1.AppendX402EventsResponse{}, nil
		})
		tick, stop := runEvents(t, e)
		e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		// Three failed sends leave the row one try from its drop, and the fourth hangs
		for range 4 {
			tick <- time.Now()
			s.next(t)
		}
		stop()
		eq(t, len(s.drain()), 1)
		eq(t, len(logs.records(t, msgEventSent)), 1)
		eq(t, len(logs.records(t, msgEventDropped)), 0)
	})
}

func TestFlushOnShutdown(t *testing.T) {
	t.Run("every row and open window goes out once", func(t *testing.T) {
		e, s, _, _ := newTestEvents(t)
		_, stop := runEvents(t, e)
		for range 5 {
			e.Add("pl_a", eventCall(EventFree, "", eventAt(5)))
		}
		e.RefusedHost("pl_a", "bad_name", eventAt(6))
		e.Add("pl_a", paidCall(eventHost, eventAt(7)))
		stop()
		evs := eventsOf(s.drain())
		type seen struct {
			host, status string
			count        uint32
		}
		var got []seen
		for _, ev := range evs {
			got = append(got, seen{ev.GetHost(), ev.GetStatus(), ev.GetCount()})
		}
		slices.SortFunc(got, func(a, b seen) int {
			return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
		})
		eq(t, got, []seen{
			{"", EventRefusedHost, 1},
			{eventHost, EventFree, 1},
			{eventHost, EventFree, 4},
			{eventHost, EventPaid, 1},
		})
	})

	t.Run("a router that never answers holds the end one interval at most", func(t *testing.T) {
		s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 64)}
		s.answerWith(hang)
		logs := &logBuf{}
		e := NewEvents(s.send, 50*time.Millisecond, time.Now,
			slog.New(slog.NewJSONHandler(logs, nil)))
		e.tick = make(chan time.Time)
		e.Add("pl_a", paidCall(eventHost, time.Now()))
		for i := range 39 {
			e.Add(fmt.Sprintf("pl_%d", i), eventCall(EventFree, "", time.Now()))
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		e.Run(ctx)
		if took := time.Since(start); took > time.Second {
			t.Fatalf("Run took %v to end", took)
		}
		drops := logs.records(t, msgEventDropped)
		eq(t, len(drops), 40)
		for _, d := range drops {
			eq(t, d["why"], "shutdown")
		}
	})
}

// hang answers only when the call's context ends
func hang(ctx context.Context, _ int) (*routerv1.AppendX402EventsResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSendCutAtTheFlushInterval(t *testing.T) {
	s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 16)}
	s.answerWith(func(ctx context.Context, call int) (*routerv1.AppendX402EventsResponse, error) {
		if call == 1 {
			return hang(ctx, call)
		}
		return &routerv1.AppendX402EventsResponse{}, nil
	})
	e := NewEvents(s.send, 50*time.Millisecond, time.Now, nil)
	e.Add("pl_a", paidCall(eventHost, time.Now()))
	done := make(chan struct{})
	go func() {
		e.flushAll(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a flush the router never answers was not cut")
	}
	first := eventsOf(s.drain())
	e.flushAll(context.Background())
	again := eventsOf(s.drain())
	eq(t, len(first), 1)
	eq(t, refsOf(again), refsOf(first))
}

func TestSlowPlacementHoldsNoOther(t *testing.T) {
	s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 16)}
	release := make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	t.Cleanup(free)
	s.answerWith(func(ctx context.Context, _ int) (*routerv1.AppendX402EventsResponse, error) {
		select {
		case <-release:
			return &routerv1.AppendX402EventsResponse{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	// Every send waits for the test, so one placement at a time starts a single send in 1 s
	e := NewEvents(s.send, 1500*time.Millisecond, time.Now, nil)
	for i := range sendWorkers {
		e.Add(fmt.Sprintf("pl_%d", i), paidCall(eventHost, time.Now()))
	}
	done := make(chan struct{})
	go func() {
		e.flushAll(context.Background())
		close(done)
	}()
	var started []string
	for range sendWorkers {
		started = append(started, s.next(t).GetPlacementId())
	}
	free()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the flush did not end once the router answered")
	}
	slices.Sort(started)
	eq(t, len(slices.Compact(started)), sendWorkers)
}

func TestRoundEndsWithinOneInterval(t *testing.T) {
	s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 64)}
	s.answerWith(hang)
	logs := &logBuf{}
	e := NewEvents(s.send, 100*time.Millisecond, time.Now,
		slog.New(slog.NewJSONHandler(logs, nil)))
	const placements = sendWorkers + 1
	for i := range placements {
		e.Add(fmt.Sprintf("pl_%d", i), eventCall(EventFree, "", time.Now()))
	}
	for range 4 {
		start := time.Now()
		e.flushAll(context.Background())
		if took := time.Since(start); took > 500*time.Millisecond {
			t.Fatalf("a round on a router that never answers took %v", took)
		}
	}
	// Each round had time for sendWorkers sends, and a row it never started keeps its try
	drops := len(logs.records(t, msgEventDropped))
	if drops == 0 || drops >= placements {
		t.Fatalf("%d of %d rows dropped after 4 rounds", drops, placements)
	}
	s.answerWith(nil)
	e.flushAll(context.Background())
	eq(t, len(logs.records(t, msgEventSent))+drops, placements)
}

func TestNoSendStartsInARoundsLastQuarter(t *testing.T) {
	s := &sink{batches: make(chan *routerv1.AppendX402EventsRequest, 64)}
	// Each send answers 50 ms before the round's budget of 400 ms ends
	s.answerWith(func(ctx context.Context, _ int) (*routerv1.AppendX402EventsResponse, error) {
		deadline, _ := ctx.Deadline()
		select {
		case <-time.After(time.Until(deadline) - 50*time.Millisecond):
			return &routerv1.AppendX402EventsResponse{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	logs := &logBuf{}
	e := NewEvents(s.send, 400*time.Millisecond, time.Now,
		slog.New(slog.NewJSONHandler(logs, nil)))
	const placements = sendWorkers + 1
	for i := range placements {
		e.Add(fmt.Sprintf("pl_%d", i), eventCall(EventFree, "", time.Now()))
	}
	e.flushAll(context.Background())
	eq(t, len(s.drain()), sendWorkers)
	eq(t, len(logs.records(t, msgEventSent)), sendWorkers)

	s.answerWith(nil)
	e.flushAll(context.Background())
	eq(t, len(s.drain()), 1)
	eq(t, len(logs.records(t, msgEventSent)), placements)
	eq(t, len(logs.records(t, msgEventDropped)), 0)

	for _, c := range []struct {
		left time.Duration
		want bool
	}{{150 * time.Millisecond, true}, {75 * time.Millisecond, false}, {0, false}} {
		budget, cancel := context.WithTimeout(context.Background(), c.left)
		eq(t, e.mayStart(budget), c.want)
		cancel()
	}
}

func TestEventLogsHoldNoSecrets(t *testing.T) {
	e, s, clk, logs := newTestEvents(t)
	const placement = "pl_secretplacement01"
	s.answerWith(func(_ context.Context, call int) (*routerv1.AppendX402EventsResponse, error) {
		switch call {
		case 1:
			return &routerv1.AppendX402EventsResponse{Rejected: []uint32{1}}, nil
		case 2:
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("too many"))
		}
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	})

	var secrets []string
	add := func(ev *routerv1.X402Event) {
		ev.Ref, ev.PaymentRef = NewRef(), NewRef()
		secrets = append(secrets, ev.Ref, ev.PaymentRef, ev.Path)
		e.Add(placement, ev)
	}
	paid := offered()
	paid.Status, paid.Reason, paid.AmountMicros = EventPaid, "", 10000
	paid.Path, paid.ServiceId = "/v1/private/search-path", "xs_secretservice0001"
	add(paid)
	free := eventCall(EventFree, "", eventAt(5))
	free.Path = "/v1/another/secret-path"
	add(free)
	e.RefusedHost(placement, "refused.example.com", eventAt(5))
	clk.set(eventAt(10))
	e.flushAll(context.Background())

	again := offered()
	again.Status, again.AmountMicros, again.Path = EventPaymentFailed, 10000, "/v1/third/path"
	add(again)
	e.flushAll(context.Background())

	secrets = append(secrets, placement, testPayTo, "xs_secretservice0001", USDCMint,
		SolanaMainnet)
	text := logs.String()
	for _, v := range secrets {
		if strings.Contains(text, v) {
			t.Fatalf("event logs hold %q:\n%s", v, text)
		}
	}

	allowed := map[string]bool{"time": true, "level": true, "msg": true, "placement": true,
		"host": true, "method": true, "status": true, "reason": true, "amount_micros": true,
		"bytes_out": true, "bytes_in": true, "count": true, "why": true, "code": true}
	var lines int
	for _, msg := range []string{msgEventSent, msgEventDropped} {
		for _, r := range logs.records(t, msg) {
			lines++
			eq(t, r["placement"], any(PlacementHash(placement)))
			for k := range r {
				if !allowed[k] {
					t.Fatalf("event log line has the field %q", k)
				}
			}
		}
	}
	eq(t, lines, 4)
	eq(t, strings.Count(text, "\n"), 4)
}

// appendClient answers AppendX402Events with res or err and keeps the request
type appendClient struct {
	routerv1connect.EgressServiceClient
	got *routerv1.AppendX402EventsRequest
	res *routerv1.AppendX402EventsResponse
	err error
}

func (a *appendClient) AppendX402Events(
	_ context.Context, r *connect.Request[routerv1.AppendX402EventsRequest],
) (*connect.Response[routerv1.AppendX402EventsResponse], error) {
	a.got = r.Msg
	if a.err != nil {
		return nil, a.err
	}
	return connect.NewResponse(a.res), nil
}

func TestEventsSendCallsTheRouter(t *testing.T) {
	c := &appendClient{res: &routerv1.AppendX402EventsResponse{Rejected: []uint32{2}}}
	req := &routerv1.AppendX402EventsRequest{
		PlacementId: "pl_a", Events: []*routerv1.X402Event{eventCall(EventFree, "", eventAt(5))},
	}
	res, err := EventsSend(c)(context.Background(), req)
	eq(t, err, nil)
	eq(t, res.GetRejected(), []uint32{2})
	eq(t, c.got == req, true)

	c.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if _, err := EventsSend(c)(context.Background(), req); err == nil {
		t.Fatal("a refused batch gave no error")
	}
}
