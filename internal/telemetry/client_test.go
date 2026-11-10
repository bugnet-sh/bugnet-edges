package telemetry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

const (
	testHandle   = "sbx_incf5d4j2g46mypgm6wajtyic5"
	routerSpanID = "00f067aa0ba902b7"
	edgeToken    = "edge-token-0123456789abcdefghijklmnop"
)

// router is an EdgeService that records the traceparent and tracestate each call carried
type router struct {
	routerv1connect.UnimplementedEdgeServiceHandler

	mu      sync.Mutex
	headers map[string][2]string
	failure error
}

func (r *router) note(name string, h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headers == nil {
		r.headers = map[string][2]string{}
	}
	r.headers[name] = [2]string{h.Get("Traceparent"), h.Get("Tracestate")}
}

func (r *router) carried(name string) [2]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headers[name]
}

func (r *router) ResolvePreview(
	_ context.Context, req *connect.Request[routerv1.ResolvePreviewRequest],
) (*connect.Response[routerv1.ResolvePreviewResponse], error) {
	r.note("ResolvePreview", req.Header())
	if r.failure != nil {
		return nil, r.failure
	}
	return connect.NewResponse(&routerv1.ResolvePreviewResponse{}), nil
}

func (r *router) CheckEdgeLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEdgeLeasesRequest],
) (*connect.Response[routerv1.CheckEdgeLeasesResponse], error) {
	r.note("CheckEdgeLeases", req.Header())
	return connect.NewResponse(&routerv1.CheckEdgeLeasesResponse{}), nil
}

func (r *router) ReadTransfer(
	_ context.Context, req *connect.Request[routerv1.ReadTransferRequest],
	out *connect.ServerStream[routerv1.ReadTransferResponse],
) error {
	r.note("ReadTransfer", req.Header())
	if r.failure != nil {
		return r.failure
	}
	return out.Send(&routerv1.ReadTransferResponse{Data: []byte("x"), Verified: true})
}

func (r *router) WriteTransfer(
	_ context.Context, in *connect.ClientStream[routerv1.WriteTransferRequest],
) (*connect.Response[routerv1.WriteTransferResponse], error) {
	r.note("WriteTransfer", in.RequestHeader())
	for in.Receive() {
	}
	return connect.NewResponse(&routerv1.WriteTransferResponse{}), nil
}

// rig is a router behind h2c and a client of it with the interceptor
type rig struct {
	r      *router
	tel    *telemetrytest.Telemetry
	client routerv1connect.EdgeServiceClient
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &router{}
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEdgeServiceHandler(r))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	return &rig{r: r, tel: tel, client: routerv1connect.NewEdgeServiceClient(
		routerclient.New(srv.URL, edgeToken), srv.URL, routerclient.Options(tel.Telemetry)...)}
}

// session starts a span in the handle's order trace, as an edge does after the router's answer
func (g *rig) session(t *testing.T, name string) (context.Context, trace.Span, string) {
	t.Helper()
	tid, _ := telemetrytest.OrderIDs(testHandle)
	ctx, span := g.tel.Session(t.Context(), telemetrytest.Traceparent(tid, routerSpanID), name,
		time.Now())
	return ctx, span, tid
}

func TestSessionStartsUnderTheRoutersSpanBackdated(t *testing.T) {
	g := newRig(t)
	start := time.Now().Add(-3 * time.Second).Truncate(time.Millisecond)
	tid, _ := telemetrytest.OrderIDs(testHandle)
	_, span := g.tel.Session(t.Context(), telemetrytest.Traceparent(tid, routerSpanID),
		"edge.transfer", start)
	span.End()
	s := telemetrytest.Only(t, g.tel.Flushed(t), "edge.transfer")
	eq(t, s.TraceID, tid)
	eq(t, s.ParentID, routerSpanID)
	eq(t, s.Start.Equal(start), true)
}

func TestEmptyOrderTraceparentMakesNoSession(t *testing.T) {
	g := newRig(t)
	for _, tp := range []string{"", "garbage", "00-" + strings.Repeat("0", 32) +
		"-" + strings.Repeat("1", 16) + "-01", "01-4bf92f3577b34da6a3ce929d0e0e4736-" +
		routerSpanID + "-01"} {
		ctx, span := g.tel.Session(t.Context(), tp, "edge.transfer", time.Now())
		span.End()
		eq(t, trace.SpanContextFromContext(ctx).IsValid(), false)
	}
	// A name the allowlist refuses makes no span either
	tid, _ := telemetrytest.OrderIDs(testHandle)
	_, span := g.tel.Session(t.Context(), telemetrytest.Traceparent(tid, routerSpanID),
		"Bad Name", time.Now())
	span.End()
	eq(t, len(g.tel.Flushed(t)), 0)
}

func TestClientCallWithoutASpanSendsNothing(t *testing.T) {
	g := newRig(t)
	if _, err := g.client.ResolvePreview(t.Context(),
		connect.NewRequest(&routerv1.ResolvePreviewRequest{})); err != nil {
		t.Fatal(err)
	}
	eq(t, g.r.carried("ResolvePreview"), [2]string{})
	eq(t, len(g.tel.Flushed(t)), 0)
}

func TestClientSpanIsAChildAndInjectsItsContext(t *testing.T) {
	g := newRig(t)
	ctx, parent, tid := g.session(t, "edge.transfer")
	if _, err := g.client.ResolvePreview(ctx,
		connect.NewRequest(&routerv1.ResolvePreviewRequest{})); err != nil {
		t.Fatal(err)
	}
	parent.End()
	spans := g.tel.Flushed(t)
	c := telemetrytest.Only(t, spans, "bugnet.router.v1.EdgeService/ResolvePreview")
	eq(t, c.ParentID, telemetrytest.Only(t, spans, "edge.transfer").SpanID)
	eq(t, c.Kind.String(), "SPAN_KIND_CLIENT")
	eq[any](t, c.Attrs["rpc.system.name"], "connectrpc")
	eq[any](t, c.Attrs["rpc.method"], "bugnet.router.v1.EdgeService/ResolvePreview")
	eq[any](t, c.Attrs["rpc.response.status_code"], "OK")
	eq(t, g.r.carried("ResolvePreview")[0], "00-"+tid+"-"+c.SpanID+"-01")
}

func TestClientSpanStatusOnlyForServerFaults(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		code   string
		reason string
		fault  bool
	}{
		"not found": {refusal(connect.CodeNotFound, "TOKEN_UNKNOWN"), "NOT_FOUND",
			"TOKEN_UNKNOWN", false},
		"internal": {refusal(connect.CodeInternal, "BROKEN"), "INTERNAL", "BROKEN", true},
		"no reason": {connect.NewError(connect.CodeUnavailable, errors.New("down")),
			"UNAVAILABLE", "UNAVAILABLE", true},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t)
			g.r.failure = tc.err
			ctx, parent, _ := g.session(t, "edge.transfer")
			_, err := g.client.ResolvePreview(ctx,
				connect.NewRequest(&routerv1.ResolvePreviewRequest{}))
			eq(t, err != nil, true)
			parent.End()
			c := telemetrytest.Only(t, g.tel.Flushed(t),
				"bugnet.router.v1.EdgeService/ResolvePreview")
			eq[any](t, c.Attrs["rpc.response.status_code"], tc.code)
			eq[any](t, c.Attrs["error.type"], tc.reason)
			eq(t, c.StatusText != "", tc.fault)
			// The error's text never leaves
			eq(t, strings.Contains(c.StatusText, "sbx_"), false)
		})
	}
}

func refusal(code connect.Code, reason string) error {
	ce := connect.NewError(code, errors.New("provider said sbx_secret"))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: "bugnet.router"})
	ce.AddDetail(d)
	return ce
}

func TestNeverTracedCallsCarryNoHeaderAndMakeNoSpan(t *testing.T) {
	g := newRig(t)
	ctx, parent, _ := g.session(t, "edge.transfer")
	if _, err := g.client.CheckEdgeLeases(ctx,
		connect.NewRequest(&routerv1.CheckEdgeLeasesRequest{})); err != nil {
		t.Fatal(err)
	}
	parent.End()
	eq(t, g.r.carried("CheckEdgeLeases"), [2]string{})
	eq(t, len(telemetrytest.Named(g.tel.Flushed(t),
		"bugnet.router.v1.EdgeService/CheckEdgeLeases")), 0)
}

func TestServerStreamSpanEndsWhenTheStreamCloses(t *testing.T) {
	g := newRig(t)
	ctx, parent, tid := g.session(t, "edge.transfer")
	stream, err := g.client.ReadTransfer(ctx, connect.NewRequest(&routerv1.ReadTransferRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
	}
	eq(t, stream.Err(), nil)
	// The span stays open until the caller closes the stream
	eq(t, len(telemetrytest.Named(g.tel.Flushed(t),
		"bugnet.router.v1.EdgeService/ReadTransfer")), 0)
	_ = stream.Close()
	parent.End()
	spans := g.tel.Flushed(t)
	c := telemetrytest.Only(t, spans, "bugnet.router.v1.EdgeService/ReadTransfer")
	eq(t, c.ParentID, telemetrytest.Only(t, spans, "edge.transfer").SpanID)
	eq[any](t, c.Attrs["rpc.response.status_code"], "OK")
	eq(t, g.r.carried("ReadTransfer")[0], "00-"+tid+"-"+c.SpanID+"-01")
}

func TestServerStreamErrorIsRecorded(t *testing.T) {
	g := newRig(t)
	g.r.failure = refusal(connect.CodeFailedPrecondition, "FILE_CHANGED")
	ctx, parent, _ := g.session(t, "edge.transfer")
	stream, err := g.client.ReadTransfer(ctx, connect.NewRequest(&routerv1.ReadTransferRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
	}
	_ = stream.Close()
	parent.End()
	c := telemetrytest.Only(t, g.tel.Flushed(t), "bugnet.router.v1.EdgeService/ReadTransfer")
	eq[any](t, c.Attrs["rpc.response.status_code"], "FAILED_PRECONDITION")
	eq[any](t, c.Attrs["error.type"], "FILE_CHANGED")
	eq(t, c.StatusText, "")
}

func TestClientStreamSpanEndsAtCloseAndReceive(t *testing.T) {
	g := newRig(t)
	ctx, parent, tid := g.session(t, "edge.transfer")
	call := g.client.WriteTransfer(ctx)
	if err := call.Send(&routerv1.WriteTransferRequest{Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if _, err := call.CloseAndReceive(); err != nil {
		t.Fatal(err)
	}
	parent.End()
	spans := g.tel.Flushed(t)
	c := telemetrytest.Only(t, spans, "bugnet.router.v1.EdgeService/WriteTransfer")
	eq(t, c.ParentID, telemetrytest.Only(t, spans, "edge.transfer").SpanID)
	eq(t, g.r.carried("WriteTransfer")[0], "00-"+tid+"-"+c.SpanID+"-01")
}

func TestOffClientInterceptorAddsNothing(t *testing.T) {
	eq(t, len(routerclient.Options(telemetry.Off())), 0)
	var none *telemetry.Telemetry
	eq(t, len(routerclient.Options(none)), 0)
}
