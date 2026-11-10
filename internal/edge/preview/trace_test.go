package preview

import (
	"net/http"
	"strings"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

const (
	testHandle    = "sbx_incf5d4j2g46mypgm6wajtyic5"
	testPlacement = "3f6c1d52-8b8e-4b6e-9d5b-0e1f2a3b4c5d"
	routerSpanID  = "00f067aa0ba902b7"
)

// tracedHarness is a harness whose router answers an order_traceparent in the handle's trace
func tracedHarness(
	t *testing.T, change ...func(*Deps),
) (*harness, *telemetrytest.Telemetry, string) {
	t.Helper()
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	x := newHarnessWith(t, tel.Telemetry, change...)
	tid, _ := telemetrytest.OrderIDs(testHandle)
	x.router.set(func(f *fakeRouter) {
		f.orderTP = telemetrytest.Traceparent(tid, routerSpanID)
		f.placement = testPlacement
	})
	return x, tel, tid
}

// revoke turns the first preview off, which ends its route span
func (x *harness) revoke() {
	x.router.set(func(*fakeRouter) { x.pv.revoked = true })
	x.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PreviewRevoked{
		PreviewRevoked: &routerv1.PreviewRevoked{PlacementId: testPlacement, PreviewId: firstID},
	}}
}

func TestStrangersMakeNoSpans(t *testing.T) {
	x, tel, _ := tracedHarness(t)
	for i := range 100 {
		x.get(t, at("/"), headerName, newToken())
		x.get(t, "https://"+secondID+"."+domain+"/", headerName, newToken())
		x.get(t, at("/"), headerName, "bnp_"+strings.Repeat("a", i%40))
	}
	eq(t, len(tel.Flushed(t)), 0)
}

func TestPreviewRouteSpanCounts(t *testing.T) {
	x, tel, tid := tracedHarness(t)
	x.gate.listen(5173)
	x.gate.set(func(g *fakeGate) {
		g.app = func(port int, w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/missing":
				w.WriteHeader(http.StatusNotFound)
			case "/boom":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				defaultApp(port, w, r)
			}
		}
	})
	get := func(path string) int {
		res, _ := x.get(t, at(path), headerName, x.pv.token)
		return res.StatusCode
	}
	eq(t, get("/"), 200)
	eq(t, get("/"), 200)
	eq(t, get("/missing"), 404)
	eq(t, get("/boom"), 500)
	w := x.openWS(t, x.pv, host)
	_ = w.conn.Close()
	x.gate.portClosed(5173)
	eq(t, get("/"), http.StatusBadGateway)
	x.revoke()
	within(t, "the route span", func() bool {
		return len(telemetrytest.Named(tel.Flushed(t), "edge.preview.route")) == 1
	})
	s := telemetrytest.Only(t, tel.Flushed(t), "edge.preview.route")
	eq(t, s.TraceID, tid)
	eq(t, s.ParentID, routerSpanID)
	eq[any](t, s.Attrs["bugnet.preview_id"], firstID)
	eq[any](t, s.Attrs["bugnet.port"], int64(5173))
	eq[any](t, s.Attrs["bugnet.placement_id"], testPlacement)
	eq[any](t, s.Attrs["bugnet.requests"], int64(6))
	eq[any](t, s.Attrs["bugnet.responses_4xx"], int64(1))
	eq[any](t, s.Attrs["bugnet.responses_5xx"], int64(2))
	eq[any](t, s.Attrs["bugnet.gate_errors"], int64(1))
	eq[any](t, s.Attrs["bugnet.websockets"], int64(1))
	eq[any](t, s.Attrs["bugnet.end_cause"], "revoked")
	if n, _ := s.Attrs["bugnet.bytes_out"].(int64); n <= 0 {
		t.Fatalf("bytes_out is %v", s.Attrs["bugnet.bytes_out"])
	}
}

func TestPreviewRouteSpanEndsWhenTheRouteIsReplaced(t *testing.T) {
	// A short ttl makes the next request resolve again, which replaces the cached route
	x, tel, _ := tracedHarness(t, func(d *Deps) { d.RouteTTL = time.Nanosecond })
	x.get(t, at("/"), headerName, x.pv.token)
	x.get(t, at("/"), headerName, x.pv.token)
	within(t, "the first route span", func() bool {
		return len(telemetrytest.Named(tel.Flushed(t), "edge.preview.route")) == 1
	})
	s := telemetrytest.Only(t, tel.Flushed(t), "edge.preview.route")
	eq[any](t, s.Attrs["bugnet.end_cause"], "deadline")
}

func TestRepairSpanIsUnderTheRoute(t *testing.T) {
	x, tel, _ := tracedHarness(t)
	x.gate.set(func(g *fakeGate) { g.provider = true })
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusBadGateway)
	within(t, "the repair span", func() bool {
		spans := tel.Flushed(t)
		return len(telemetrytest.Named(spans, "edge.preview.repair")) == 1 &&
			len(telemetrytest.Named(spans, "edge.preview.route")) == 1
	})
	spans := tel.Flushed(t)
	route := telemetrytest.Only(t, spans, "edge.preview.route")
	repair := telemetrytest.Only(t, spans, "edge.preview.repair")
	eq(t, repair.ParentID, route.SpanID)
	eq[any](t, repair.Attrs["bugnet.repaired"], true)
	call := telemetrytest.Only(t, spans, "bugnet.router.v1.EdgeService/RepairPreview")
	eq(t, call.ParentID, repair.SpanID)
}

func TestGateRequestsCarryNoBugnetTrace(t *testing.T) {
	x, _, _ := tracedHarness(t)
	x.get(t, at("/"), headerName, x.pv.token)
	seen := x.gate.last().header
	for _, h := range []string{"Traceparent", "Tracestate", "Baggage"} {
		eq(t, seen.Get(h), "")
	}
	// A visitor's own header passes unchanged
	own := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	x.get(t, at("/"), headerName, x.pv.token, "Traceparent", own, "Tracestate", "a=b")
	seen = x.gate.last().header
	eq(t, seen.Get("Traceparent"), own)
	eq(t, seen.Get("Tracestate"), "a=b")
}

func TestEmptyOrderTraceparentMakesNoSession(t *testing.T) {
	x, tel, _ := tracedHarness(t)
	x.router.set(func(f *fakeRouter) { f.orderTP = "" })
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, 200)
	x.revoke()
	time.Sleep(200 * time.Millisecond)
	eq(t, len(tel.Flushed(t)), 0)
}
