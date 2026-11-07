package x402

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

const unpaidHost = "api.example.com"

// unpaidCaps are XS 6.8's per-placement caps
var unpaidCaps = Caps{Requests: 300, Bytes: 50 * uint64(mib)}

// ownOf is a host's own count, zero when the counters know none
func ownOf(c *Counters, placement, host string) Unpaid {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pl := c.places[placement]; pl != nil {
		if hu := pl.hosts[host]; hu != nil {
			return hu.own
		}
	}
	return Unpaid{}
}

// known says whether the counters still hold a placement
func known(c *Counters, placement string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.places[placement]
	return ok
}

// plain turns reported deltas into maps a test compares
func plain(d map[string]*routerv1.X402UnpaidByHost) map[string]map[string]Unpaid {
	if d == nil {
		return nil
	}
	out := map[string]map[string]Unpaid{}
	for p, byHost := range d {
		out[p] = map[string]Unpaid{}
		for h, u := range byHost.GetHosts() {
			out[p][h] = Unpaid{Requests: u.GetRequests(), Bytes: u.GetBytes()}
		}
	}
	return out
}

// add counts n requests of size bytes each to one host
func add(c *Counters, placement, host string, n int, size int64) {
	for range n {
		c.AddRequest(placement, host)
		c.AddBytes(placement, host, size, unpaidCaps)
	}
}

// okSend accepts every report
func okSend(context.Context, map[string]*routerv1.X402UnpaidByHost) error { return nil }

// failSend refuses every report
func failSend(context.Context, map[string]*routerv1.X402UnpaidByHost) error {
	return errors.New("router down")
}

func TestRequestCap300(t *testing.T) {
	c := NewCounters()
	for range 299 {
		c.AddRequest("pl_a", unpaidHost)
	}
	eq(t, c.Over("pl_a", unpaidHost, unpaidCaps), false)
	c.AddRequest("pl_a", unpaidHost)
	eq(t, c.Over("pl_a", unpaidHost, unpaidCaps), true)

	eq(t, c.Over("pl_a", "other.example.com", unpaidCaps), false)
	eq(t, c.Over("pl_b", unpaidHost, unpaidCaps), false)
}

func TestByteCap50MiB(t *testing.T) {
	c := NewCounters()
	eq(t, c.AddBytes("pl_a", unpaidHost, 50*mib-1, unpaidCaps), false)
	eq(t, c.Over("pl_a", unpaidHost, unpaidCaps), false)
	eq(t, c.AddBytes("pl_a", unpaidHost, 1, unpaidCaps), true)
	eq(t, c.Over("pl_a", unpaidHost, unpaidCaps), true)

	eq(t, c.AddBytes("pl_b", unpaidHost, -5, unpaidCaps), false)
	eq(t, ownOf(c, "pl_b", unpaidHost), Unpaid{})
}

func TestZeroCapsAreReached(t *testing.T) {
	c := NewCounters()
	eq(t, c.Over("pl_a", unpaidHost, Caps{}), true)
	eq(t, c.Over("pl_a", unpaidHost, Caps{Requests: 300}), true)
}

func TestCountsSaturate(t *testing.T) {
	c := NewCounters()
	c.Merge("pl_a", map[string]Unpaid{unpaidHost: {Requests: ^uint32(0), Bytes: ^uint64(0)}})
	c.AddRequest("pl_a", unpaidHost)
	c.AddBytes("pl_a", unpaidHost, 10, unpaidCaps)
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{Requests: ^uint32(0), Bytes: ^uint64(0)})
}

func TestMergeTakesTheMax(t *testing.T) {
	c := NewCounters()
	add(c, "pl_a", unpaidHost, 7, 100)
	c.report(context.Background(), okSend)
	add(c, "pl_a", unpaidHost, 3, 100)
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{10, 1000})
	c.Merge("pl_a", map[string]Unpaid{unpaidHost: {25, 2500}})
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{28, 2800})

	add(c, "pl_b", unpaidHost, 37, 100)
	c.report(context.Background(), okSend)
	add(c, "pl_b", unpaidHost, 3, 100)
	c.Merge("pl_b", map[string]Unpaid{unpaidHost: {25, 2500}})
	eq(t, ownOf(c, "pl_b", unpaidHost), Unpaid{40, 4000})

	c.Merge("pl_b", map[string]Unpaid{"other.example.com": {5, 50}})
	eq(t, ownOf(c, "pl_b", "other.example.com"), Unpaid{5, 50})
	eq(t, ownOf(c, "pl_b", unpaidHost), Unpaid{40, 4000})

	// Each count takes its own max
	c.Merge("pl_b", map[string]Unpaid{unpaidHost: {1, 9000}})
	eq(t, ownOf(c, "pl_b", unpaidHost), Unpaid{40, 9300})
}

func TestMergeCountsAReportStillOut(t *testing.T) {
	c := NewCounters()
	add(c, "pl_a", unpaidHost, 4, 10)
	out := c.Take()
	add(c, "pl_a", unpaidHost, 2, 10)
	c.Merge("pl_a", map[string]Unpaid{unpaidHost: {25, 250}})
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{31, 310})
	c.Restore(out)
	eq(t, plain(c.Take()), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {6, 60}}})
}

func TestDeltasSinceLastSuccessfulReport(t *testing.T) {
	c := NewCounters()
	add(c, "pl_a", unpaidHost, 5, 40)
	d := c.Take()
	eq(t, plain(d), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {5, 200}}})
	eq(t, c.Take() == nil, true)
	c.Restore(d)
	add(c, "pl_a", unpaidHost, 2, 40)
	c.AddBytes("pl_a", "other.example.com", 9, unpaidCaps)
	eq(t, plain(c.Take()), map[string]map[string]Unpaid{"pl_a": {
		unpaidHost:          {7, 280},
		"other.example.com": {0, 9},
	}})

	add(c, "pl_a", unpaidHost, 1, 1)
	c.report(context.Background(), failSend)
	c.report(context.Background(), okSend)
	eq(t, c.Take() == nil, true)
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{8, 281})
}

// summingRouter keeps the totals of every report, as router-api does
type summingRouter struct {
	mu    sync.Mutex
	total map[string]map[string]Unpaid
}

func (r *summingRouter) send(_ context.Context, d map[string]*routerv1.X402UnpaidByHost) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p, byHost := range plain(d) {
		if r.total[p] == nil {
			r.total[p] = map[string]Unpaid{}
		}
		for h, u := range byHost {
			t := r.total[p][h]
			r.total[p][h] = Unpaid{t.Requests + u.Requests, t.Bytes + u.Bytes}
		}
	}
	return nil
}

func (r *summingRouter) used(placement string) map[string]Unpaid {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]Unpaid{}
	for h, u := range r.total[placement] {
		out[h] = u
	}
	return out
}

func TestTwoProcessesNeverOverwrite(t *testing.T) {
	r := &summingRouter{total: map[string]map[string]Unpaid{}}
	a, b := NewCounters(), NewCounters()
	add(a, "pl_a", unpaidHost, 5, 100)
	add(b, "pl_a", unpaidHost, 7, 100)
	a.report(context.Background(), r.send)
	b.report(context.Background(), r.send)
	a.Merge("pl_a", r.used("pl_a"))
	b.Merge("pl_a", r.used("pl_a"))
	eq(t, ownOf(a, "pl_a", unpaidHost), Unpaid{12, 1200})
	eq(t, ownOf(b, "pl_a", unpaidHost), Unpaid{12, 1200})

	add(a, "pl_a", unpaidHost, 3, 100)
	add(b, "pl_a", unpaidHost, 1, 100)
	b.report(context.Background(), r.send)
	a.Merge("pl_a", r.used("pl_a"))
	eq(t, ownOf(a, "pl_a", unpaidHost), Unpaid{16, 1600})

	restarted := NewCounters()
	restarted.Merge("pl_a", r.used("pl_a"))
	eq(t, ownOf(restarted, "pl_a", unpaidHost), Unpaid{13, 1300})
}

// fakeEgressClient records each ReportEgressUsage request
type fakeEgressClient struct {
	routerv1connect.EgressServiceClient
	reqs chan *routerv1.ReportEgressUsageRequest
	err  error
}

func (f *fakeEgressClient) ReportEgressUsage(
	_ context.Context, r *connect.Request[routerv1.ReportEgressUsageRequest],
) (*connect.Response[routerv1.ReportEgressUsageResponse], error) {
	f.reqs <- r.Msg
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&routerv1.ReportEgressUsageResponse{}), nil
}

// next waits for the next report or fails the test after a second
func (f *fakeEgressClient) next(t *testing.T) *routerv1.ReportEgressUsageRequest {
	t.Helper()
	select {
	case r := <-f.reqs:
		return r
	case <-time.After(time.Second):
		t.Fatal("no report within a second")
		return nil
	}
}

func TestUnpaidSendLeavesUsageEmpty(t *testing.T) {
	f := &fakeEgressClient{reqs: make(chan *routerv1.ReportEgressUsageRequest, 1)}
	d := map[string]*routerv1.X402UnpaidByHost{"pl_a": {Hosts: map[string]*routerv1.X402Unpaid{
		unpaidHost: {Requests: 2, Bytes: 30},
	}}}
	eq(t, UnpaidSend(f, "egress-test")(context.Background(), d), nil)
	r := f.next(t)
	eq(t, r.GetReporterId(), "egress-test")
	eq(t, len(r.GetUsage()), 0)
	eq(t, plain(r.GetX402Unpaid()), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {2, 30}}})

	f.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if err := UnpaidSend(f, "egress-test")(context.Background(), d); err == nil {
		t.Fatal("a refused report gave no error")
	}
}

func TestRunReportsEvery5s(t *testing.T) {
	t.Run("one tick sends once and nothing sends nothing", func(t *testing.T) {
		f := &fakeEgressClient{reqs: make(chan *routerv1.ReportEgressUsageRequest, 16)}
		c := NewCounters()
		add(c, "pl_a", unpaidHost, 3, 10)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			c.RunReports(ctx, UnpaidSend(f, "egress-test"), 20*time.Millisecond)
			close(done)
		}()
		r := f.next(t)
		eq(t, len(r.GetUsage()), 0)
		eq(t, plain(r.GetX402Unpaid()), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {3, 30}}})

		time.Sleep(100 * time.Millisecond)
		cancel()
		<-done
		eq(t, len(f.reqs), 0)
	})

	t.Run("the end of ctx sends the rest once", func(t *testing.T) {
		f := &fakeEgressClient{reqs: make(chan *routerv1.ReportEgressUsageRequest, 16)}
		c := NewCounters()
		add(c, "pl_a", unpaidHost, 2, 10)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.RunReports(ctx, UnpaidSend(f, "egress-test"), time.Hour)
		eq(t, plain(f.next(t).GetX402Unpaid()),
			map[string]map[string]Unpaid{"pl_a": {unpaidHost: {2, 20}}})
		eq(t, len(f.reqs), 0)
		eq(t, c.Take() == nil, true)
	})

	t.Run("a failed last send keeps its deltas", func(t *testing.T) {
		c := NewCounters()
		add(c, "pl_a", unpaidHost, 2, 10)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.RunReports(ctx, failSend, time.Hour)
		eq(t, plain(c.Take()), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {2, 20}}})
	})

	t.Run("a failed send goes out with the next tick", func(t *testing.T) {
		var calls atomic.Int32
		got := make(chan map[string]map[string]Unpaid, 4)
		send := func(_ context.Context, d map[string]*routerv1.X402UnpaidByHost) error {
			if calls.Add(1) == 1 {
				return errors.New("router down")
			}
			got <- plain(d)
			return nil
		}
		c := NewCounters()
		add(c, "pl_a", unpaidHost, 2, 10)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go c.RunReports(ctx, send, 20*time.Millisecond)
		select {
		case d := <-got:
			eq(t, d, map[string]map[string]Unpaid{"pl_a": {unpaidHost: {2, 20}}})
		case <-time.After(time.Second):
			t.Fatal("the restored deltas were never sent")
		}
	})

	t.Run("a send the router never answers ends within the interval", func(t *testing.T) {
		var calls atomic.Int32
		got := make(chan map[string]map[string]Unpaid, 4)
		waited := make(chan time.Duration, 1)
		send := func(ctx context.Context, d map[string]*routerv1.X402UnpaidByHost) error {
			if calls.Add(1) == 1 {
				start := time.Now()
				<-ctx.Done()
				waited <- time.Since(start)
				return ctx.Err()
			}
			got <- plain(d)
			return nil
		}
		c := NewCounters()
		add(c, "pl_a", unpaidHost, 1, 10)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go c.RunReports(ctx, send, 50*time.Millisecond)
		select {
		case w := <-waited:
			if w > 500*time.Millisecond {
				t.Fatalf("the send waited %v", w)
			}
		case <-time.After(time.Second):
			t.Fatal("the stalled send was never cut")
		}
		select {
		case d := <-got:
			eq(t, d, map[string]map[string]Unpaid{"pl_a": {unpaidHost: {1, 10}}})
		case <-time.After(time.Second):
			t.Fatal("the cut send's deltas were never sent again")
		}
	})
}

func TestDropAfterLastReport(t *testing.T) {
	c := NewCounters()
	caps := Caps{Requests: 3, Bytes: 50 * uint64(mib)}

	add(c, "pl_a", unpaidHost, 3, 10)
	c.Drop("pl_a")
	eq(t, known(c, "pl_a"), true)
	eq(t, c.Over("pl_a", unpaidHost, caps), true)
	c.report(context.Background(), failSend)
	eq(t, known(c, "pl_a"), true)
	c.report(context.Background(), okSend)
	eq(t, known(c, "pl_a"), false)
	eq(t, c.Over("pl_a", unpaidHost, caps), false)

	add(c, "pl_b", unpaidHost, 1, 10)
	c.report(context.Background(), okSend)
	c.Drop("pl_b")
	eq(t, known(c, "pl_b"), false)

	add(c, "pl_c", unpaidHost, 1, 10)
	out := c.Take()
	c.Drop("pl_c")
	eq(t, known(c, "pl_c"), true)
	c.Restore(out)
	eq(t, known(c, "pl_c"), true)
	c.report(context.Background(), okSend)
	eq(t, known(c, "pl_c"), false)

	add(c, "pl_d", unpaidHost, 1, 10)
	c.Drop("pl_d")
	c.Merge("pl_d", nil)
	c.report(context.Background(), okSend)
	eq(t, known(c, "pl_d"), true)
	eq(t, ownOf(c, "pl_d", unpaidHost), Unpaid{1, 10})

	c.Drop("pl_unknown")
	eq(t, known(c, "pl_unknown"), false)
}

func TestRestoreOfAForgottenPlacement(t *testing.T) {
	c := NewCounters()
	c.Restore(map[string]*routerv1.X402UnpaidByHost{"pl_a": {Hosts: map[string]*routerv1.X402Unpaid{
		unpaidHost: {Requests: 2, Bytes: 5},
	}}})
	eq(t, plain(c.Take()), map[string]map[string]Unpaid{"pl_a": {unpaidHost: {2, 5}}})
	c.Restore(map[string]*routerv1.X402UnpaidByHost{"pl_a": {Hosts: map[string]*routerv1.X402Unpaid{
		unpaidHost: {Requests: 2, Bytes: 5},
	}}})
	c.report(context.Background(), okSend)
	eq(t, known(c, "pl_a"), false)
}

func TestCountersConcurrentUse(t *testing.T) {
	c := NewCounters()
	r := &summingRouter{total: map[string]map[string]Unpaid{}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { add(c, "pl_a", unpaidHost, 100, 1) })
	}
	wg.Go(func() {
		for range 50 {
			c.report(context.Background(), r.send)
		}
	})
	wg.Wait()
	c.report(context.Background(), r.send)
	eq(t, r.used("pl_a")[unpaidHost], Unpaid{800, 800})
	eq(t, ownOf(c, "pl_a", unpaidHost), Unpaid{800, 800})
}

func TestCountsRequest(t *testing.T) {
	for _, c := range []struct {
		reached bool
		status  string
		reason  Code
		want    bool
	}{
		{true, EventFree, "", true},
		{true, EventSelfPaid, "", true},
		{false, EventRefusedCap, CodeUnpaidCap, false},
		{false, EventRefusedRequest, CodePathRefused, false},
		{true, EventPaid, "", false},
		{true, EventUncertain, "", false},
		{true, EventUncertain, CodePaidNoAnswer, false},
		{true, EventPaymentFailed, CodePaymentRejected, true},
		{true, EventRefusedRequest, CodeBodySlow, true},
		{true, EventRefusedRequest, CodeFirstAnswerSlow, true},
		{true, EventUpstreamError, CodeUpstreamUnreachable, true},
		{false, EventUpstreamError, CodeUpstreamUnreachable, false},
		{true, EventRefusedNetwork, CodeNotX402, true},
		{true, EventRefusedPrice, CodePriceAboveMax, true},
	} {
		eq(t, CountsRequest(c.reached, c.status, c.reason), c.want)
	}

	// XS 6.8's own limits, which never use up the request cap
	own := map[Code]bool{
		CodeAllowanceSpent: true, CodeRateCap: true, CodeTooManyOpenPayments: true,
		CodePaytoDailyCap: true, CodeOutflowCap: true, CodeOutflowPaused: true,
		CodeX402Disabled: true, CodePaymentsUnavailable: true, CodeBufferBusy: true,
	}
	for _, r := range refusals {
		want := !own[r.Code] && UnpaidEnd(r.EventStatus)
		eq(t, CountsRequest(true, r.EventStatus, r.Code), want)
	}
}

func TestUnpaidEnd(t *testing.T) {
	for status, want := range map[string]bool{
		EventPaid: false, EventUncertain: false, EventPaymentFailed: true, EventFree: true,
		EventSelfPaid: true, EventRefusedCap: true, EventNotPaid: true, "": true,
	} {
		eq(t, UnpaidEnd(status), want)
	}
}
