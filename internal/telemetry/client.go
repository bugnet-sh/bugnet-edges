package telemetry

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

// NeverTraced lists the procedures that make no span and carry no header, DP 20.3.2
var NeverTraced = []string{
	"/bugnet.router.v1.EdgeService/ReportEdgeUsage",
	"/bugnet.router.v1.EdgeService/CheckEdgeLeases",
	"/bugnet.router.v1.EdgeService/WatchEdgeEvents",
	"/bugnet.router.v1.SshGatewayService/RenewSshConnection",
	"/bugnet.router.v1.SshGatewayService/CheckSshGrants",
	"/bugnet.router.v1.SshGatewayService/ReportSshUsage",
	"/bugnet.router.v1.SshGatewayService/WatchSshEvents",
	"/bugnet.router.v1.EgressService/ReportEgressUsage",
	"/bugnet.router.v1.EgressService/CheckEgressLeases",
	"/bugnet.router.v1.EgressService/WatchEgressEvents",
	"/bugnet.router.v1.EgressService/AppendX402Events",
}

// serverFaults are the Connect codes that mark a client span failed
var serverFaults = map[connect.Code]bool{
	connect.CodeUnknown: true, connect.CodeDeadlineExceeded: true, connect.CodeUnimplemented: true,
	connect.CodeInternal: true, connect.CodeUnavailable: true, connect.CodeDataLoss: true,
}

func neverTraced(proc string) bool {
	for _, p := range NeverTraced {
		if p == proc {
			return true
		}
	}
	return false
}

// ClientInterceptor injects ctx's span into calls to the router and records client spans
func (t *Telemetry) ClientInterceptor() connect.Interceptor { return client{t} }

type client struct{ t *Telemetry }

// headerCarrier lets the propagator write a Connect header
type headerCarrier struct {
	h interface{ Set(string, string) }
}

func (c headerCarrier) Get(string) string { return "" }
func (c headerCarrier) Set(k, v string)   { c.h.Set(k, v) }
func (c headerCarrier) Keys() []string    { return nil }

// start begins a client span under the span in ctx and writes its context into h, nil when the
// call is never traced, traces are off or ctx holds no span
func (c client) start(ctx context.Context, proc string, h interface{ Set(string, string) }) (
	context.Context, trace.Span) {
	if !c.t.Enabled() || neverTraced(proc) ||
		!trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, nil
	}
	name := strings.TrimPrefix(proc, "/")
	ctx, span := c.t.provider.Tracer(sessionScope).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attr.RPCSystem(), attr.RPCMethod(name)))
	propagation.TraceContext{}.Inject(ctx, headerCarrier{h})
	return ctx, span
}

func (c client) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, span := c.start(ctx, req.Spec().Procedure, req.Header())
		resp, err := next(ctx, req)
		if span != nil {
			finish(span, err)
		}
		return resp, err
	}
}

func (c client) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		// The headers are set on the connection before the first send
		_, span := c.start(ctx, spec.Procedure, conn.RequestHeader())
		if span == nil {
			return conn
		}
		return &streamConn{StreamingClientConn: conn, span: span}
	}
}

func (c client) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// streamConn ends its span once both directions are closed, with the first error either saw
type streamConn struct {
	connect.StreamingClientConn
	span trace.Span

	mu                 sync.Mutex
	reqClosed, resDone bool
	err                error
	ended              bool
}

func (s *streamConn) note(err error) {
	if err == nil || errors.Is(err, io.EOF) {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *streamConn) Send(m any) error {
	err := s.StreamingClientConn.Send(m)
	s.note(err)
	return err
}

func (s *streamConn) Receive(m any) error {
	err := s.StreamingClientConn.Receive(m)
	s.note(err)
	return err
}

func (s *streamConn) CloseRequest() error {
	err := s.StreamingClientConn.CloseRequest()
	s.mu.Lock()
	s.reqClosed = true
	s.mu.Unlock()
	s.maybeEnd()
	return err
}

func (s *streamConn) CloseResponse() error {
	err := s.StreamingClientConn.CloseResponse()
	s.mu.Lock()
	s.resDone = true
	s.mu.Unlock()
	s.maybeEnd()
	return err
}

func (s *streamConn) maybeEnd() {
	s.mu.Lock()
	if s.ended || !s.reqClosed || !s.resDone {
		s.mu.Unlock()
		return
	}
	s.ended = true
	err := s.err
	s.mu.Unlock()
	finish(s.span, err)
}

// finish sets the outcome on a client span and ends it
func finish(span trace.Span, err error) {
	code, reason := "OK", ""
	fault := false
	if err != nil {
		c, r := failure(err)
		code, reason, fault = strings.ToUpper(c.String()), r, serverFaults[c]
		if reason == "" {
			reason = code
		}
	}
	span.SetAttributes(attr.RPCStatus(code))
	if err != nil {
		span.SetAttributes(attr.ErrorType(reason))
		if fault {
			span.SetStatus(codes.Error, reason)
		}
	}
	span.End()
}

// failure reads the Connect code and the ErrorInfo reason of err
func failure(err error) (connect.Code, string) {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return connect.CodeUnknown, ""
	}
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if info, ok := v.(*errdetails.ErrorInfo); ok {
				return ce.Code(), info.GetReason()
			}
		}
	}
	return ce.Code(), ""
}
