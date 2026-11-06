package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

const mib = 1 << 20

// router is a fake ReportEdgeUsage that records each report and answers from its fields
type router struct {
	mu        sync.Mutex
	reports   [][]usage
	at        []time.Duration
	start     time.Time
	remaining map[string]uint64
	pace      map[string]uint64
	err       error
	// hold, when set, keeps each report waiting until it is closed
	hold chan struct{}
}

// usage is one PlacementUsage as plain values
type usage struct {
	ID      string
	In, Out uint64
}

func newRouter() *router {
	return &router{start: time.Now(), remaining: map[string]uint64{}, pace: map[string]uint64{}}
}

func (r *router) send(
	ctx context.Context, u []*routerv1.PlacementUsage,
) (map[string]uint64, map[string]uint64, error) {
	r.mu.Lock()
	hold := r.hold
	r.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var got []usage
	for _, x := range u {
		got = append(got, usage{x.GetPlacementId(), x.GetBytesIn(), x.GetBytesOut()})
	}
	r.reports = append(r.reports, got)
	r.at = append(r.at, time.Since(r.start))
	if r.err != nil {
		return nil, nil, r.err
	}
	return clone(r.remaining), clone(r.pace), nil
}

func clone(m map[string]uint64) map[string]uint64 {
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func (r *router) seen() ([][]usage, []time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]usage(nil), r.reports...), append([]time.Duration(nil), r.at...)
}

func (r *router) set(f func(r *router)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

// answer is one OnAnswer call
type answer struct {
	ID              string
	Remaining, Pace uint64
}

// answers records every OnAnswer call
type answers struct {
	mu  sync.Mutex
	got []answer
}

func (a *answers) on(id string, remaining, pace uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, answer{id, remaining, pace})
}

func (a *answers) take() []answer {
	a.mu.Lock()
	defer a.mu.Unlock()
	got := a.got
	a.got = nil
	return got
}

// start runs a reporter every 5 s with an 8 MiB threshold until the test ends
func start(t *testing.T, r *router) (*Reporter, *answers, context.CancelFunc) {
	t.Helper()
	rep := NewReporter(r.send, 5*time.Second, 8*mib)
	a := &answers{}
	rep.OnAnswer(a.on)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return rep, a, func() {
		cancel()
		<-done
	}
}

func TestReporterFlushesAtThreshold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		rep, _, _ := start(t, r)
		rep.Add("p1", 4*mib, 0)
		rep.Add("p2", 0, 7*mib)
		synctest.Wait()
		reports, _ := r.seen()
		eq(t, len(reports), 0)

		rep.Add("p1", 1*mib, 3*mib)
		synctest.Wait()
		reports, at := r.seen()
		eq(t, reports, [][]usage{{{"p1", 5 * mib, 3 * mib}, {"p2", 0, 7 * mib}}})
		eq(t, at, []time.Duration{0})
	})
}

func TestReporterEveryInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		rep, _, _ := start(t, r)
		rep.Add("p1", 10, 20)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		rep.Add("p1", 1, 0)
		rep.Add("p2", 0, 2)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		reports, at := r.seen()
		eq(t, reports, [][]usage{{{"p1", 10, 20}}, {{"p1", 1, 0}, {"p2", 0, 2}}})
		eq(t, at, []time.Duration{5 * time.Second, 10 * time.Second})
	})
}

func TestReporterAnswersEachPlacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.remaining = map[string]uint64{"p1": 100 * mib, "p2": 0}
		r.pace = map[string]uint64{"p1": 5 * mib}
		rep, a, _ := start(t, r)
		rep.Add("p2", 1, 1)
		rep.Add("p1", 1, 1)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 100 * mib, 5 * mib}, {"p2", 0, 0}})
	})
}

func TestReporterKeepsLastRemainingWhileRouterDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.remaining = map[string]uint64{"p1": 10 * mib}
		r.pace = map[string]uint64{"p1": 5 * mib}
		rep, a, _ := start(t, r)
		rep.Add("p1", 1, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 10 * mib, 5 * mib}})

		r.set(func(r *router) { r.err = errors.New("router unreachable") })
		rep.Add("p1", 6*mib, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, a.take(), []answer(nil))

		rep.Add("p1", 0, 4*mib-1)
		synctest.Wait()
		eq(t, a.take(), []answer(nil))
		rep.Add("p1", 0, 1)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 0, 5 * mib}})
		rep.Add("p1", 0, 1)
		eq(t, a.take(), []answer(nil))

		// Nothing counted while the router was down is lost
		r.set(func(r *router) {
			r.err = nil
			r.remaining = map[string]uint64{"p1": 0}
		})
		time.Sleep(5 * time.Second)
		synctest.Wait()
		reports, _ := r.seen()
		eq(t, reports[len(reports)-1], []usage{{"p1", 6 * mib, 4*mib + 1}})
		eq(t, a.take(), []answer{{"p1", 0, 5 * mib}})
	})
}

func TestReporterRetriesOncePerIntervalWhileRouterDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.err = errors.New("router unreachable")
		rep, _, _ := start(t, r)
		rep.Add("p1", 9*mib, 0)
		synctest.Wait()
		for range 10 {
			rep.Add("p1", 9*mib, 0)
			synctest.Wait()
		}
		_, at := r.seen()
		eq(t, at, []time.Duration{0})
		time.Sleep(5 * time.Second)
		synctest.Wait()
		reports, at := r.seen()
		eq(t, at, []time.Duration{0, 5 * time.Second})
		eq(t, reports[1], []usage{{"p1", 99 * mib, 0}})
	})
}

func TestReporterAnswerCountsBytesSinceTheReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.remaining = map[string]uint64{"p1": 50 * mib}
		hold := make(chan struct{})
		r.hold = hold
		rep, a, _ := start(t, r)
		rep.Add("p1", 8*mib, 0)
		synctest.Wait()
		rep.Add("p1", 0, 3*mib)
		close(hold)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 47 * mib, 0}})

		// The local figure goes on counting down from there
		r.set(func(r *router) { r.hold = make(chan struct{}) })
		rep.Add("p1", 0, 47*mib)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 0, 0}})
	})
}

func TestReporterForgetsEndedPlacements(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.remaining = map[string]uint64{"p1": 1 * mib}
		rep, a, _ := start(t, r)
		rep.Add("p1", 1, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, a.take(), []answer{{"p1", 1 * mib, 0}})

		r.set(func(r *router) { r.remaining = map[string]uint64{} })
		rep.Add("p1", 1, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, a.take(), []answer(nil))
		eq(t, rep.size(), 0)
		rep.Add("p1", 0, 2*mib)
		synctest.Wait()
		eq(t, a.take(), []answer(nil))
	})
}

func TestReporterSetRemainingCutsWithoutAnAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.err = errors.New("router unreachable")
		rep, a, _ := start(t, r)
		rep.SetRemaining("p1", 2*mib)
		rep.Add("p1", 1*mib, 0)
		eq(t, a.take(), []answer(nil))
		rep.Add("p1", 0, 1*mib)
		eq(t, a.take(), []answer{{"p1", 0, 0}})
	})
}

func TestReporterDropKeepsBytesToSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		rep, a, _ := start(t, r)
		rep.SetRemaining("p1", 1*mib)
		rep.SetRemaining("p2", 1*mib)
		rep.Add("p1", 5, 0)
		rep.Drop("p1")
		rep.Drop("p2")
		eq(t, rep.size(), 1)
		rep.Add("p1", 0, 2*mib)
		eq(t, a.take(), []answer(nil))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		reports, _ := r.seen()
		eq(t, reports, [][]usage{{{"p1", 5, 2 * mib}}})
		eq(t, rep.size(), 0)
	})
}

func TestReporterSendsWhatIsLeftWhenStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		rep, _, stop := start(t, r)
		rep.Add("p1", 3, 4)
		time.Sleep(time.Second)
		stop()
		reports, at := r.seen()
		eq(t, reports, [][]usage{{{"p1", 3, 4}}})
		eq(t, at, []time.Duration{time.Second})
	})
}

func TestReporterGivesUpOnAHungReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.hold = make(chan struct{})
		rep, _, _ := start(t, r)
		rep.Add("p1", 8*mib, 0)
		synctest.Wait()
		r.set(func(r *router) { r.hold = nil })
		time.Sleep(sendTimeout)
		synctest.Wait()
		reports, at := r.seen()
		eq(t, reports, [][]usage{{{"p1", 8 * mib, 0}}})
		eq(t, at, []time.Duration{sendTimeout})
	})
}

// edgeClient answers ReportEdgeUsage and records the request
type edgeClient struct {
	routerv1connect.EdgeServiceClient
	got *routerv1.ReportEdgeUsageRequest
}

func (c *edgeClient) ReportEdgeUsage(
	_ context.Context, req *connect.Request[routerv1.ReportEdgeUsageRequest],
) (*connect.Response[routerv1.ReportEdgeUsageResponse], error) {
	c.got = req.Msg
	return connect.NewResponse(&routerv1.ReportEdgeUsageResponse{
		BytesRemaining: map[string]uint64{"p1": 7},
		BytesPerSecond: map[string]uint64{"p1": 5},
	}), nil
}

type sshClient struct {
	routerv1connect.SshGatewayServiceClient
	got *routerv1.ReportSshUsageRequest
}

func (c *sshClient) ReportSshUsage(
	_ context.Context, req *connect.Request[routerv1.ReportSshUsageRequest],
) (*connect.Response[routerv1.ReportSshUsageResponse], error) {
	c.got = req.Msg
	return connect.NewResponse(&routerv1.ReportSshUsageResponse{
		BytesRemaining: map[string]uint64{"p1": 8},
		BytesPerSecond: map[string]uint64{"p1": 4},
	}), nil
}

type egressClient struct {
	routerv1connect.EgressServiceClient
	got *routerv1.ReportEgressUsageRequest
	err error
}

func (c *egressClient) ReportEgressUsage(
	_ context.Context, req *connect.Request[routerv1.ReportEgressUsageRequest],
) (*connect.Response[routerv1.ReportEgressUsageResponse], error) {
	c.got = req.Msg
	if c.err != nil {
		return nil, c.err
	}
	return connect.NewResponse(&routerv1.ReportEgressUsageResponse{
		BytesRemaining: map[string]uint64{"p1": 9},
	}), nil
}

func TestSendsCallEachService(t *testing.T) {
	u := []*routerv1.PlacementUsage{{PlacementId: "p1", BytesIn: 1, BytesOut: 2}}

	edge := &edgeClient{}
	remaining, pace, err := EdgeSend(edge, "edge-1")(t.Context(), u)
	eq(t, err, nil)
	eq(t, remaining, map[string]uint64{"p1": 7})
	eq(t, pace, map[string]uint64{"p1": 5})
	eq(t, edge.got.GetReporterId(), "edge-1")
	eq(t, edge.got.GetUsage()[0].GetBytesOut(), uint64(2))

	ssh := &sshClient{}
	remaining, pace, err = SSHSend(ssh, "ssh-1")(t.Context(), u)
	eq(t, err, nil)
	eq(t, remaining, map[string]uint64{"p1": 8})
	eq(t, pace, map[string]uint64{"p1": 4})
	eq(t, ssh.got.GetReporterId(), "ssh-1")
	eq(t, ssh.got.GetUsage()[0].GetBytesIn(), uint64(1))

	egress := &egressClient{}
	remaining, pace, err = EgressSend(egress, "egress-1")(t.Context(), u)
	eq(t, err, nil)
	eq(t, remaining, map[string]uint64{"p1": 9})
	eq(t, pace, map[string]uint64(nil))
	eq(t, egress.got.GetReporterId(), "egress-1")

	egress.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	_, _, err = EgressSend(egress, "egress-1")(t.Context(), u)
	eq(t, connect.CodeOf(err), connect.CodeUnavailable)
}
