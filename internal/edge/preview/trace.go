package preview

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

const tracerScope = "bugnet-edges/preview"

// routeTrace is an edge.preview.route span and the counts it ends with
type routeTrace struct {
	span trace.Span

	requests, resp4xx, resp5xx, gateErrors, websockets atomic.Int64
	bytesIn, bytesOut                                  atomic.Int64

	mu    sync.Mutex
	cause string
}

// begin starts the route's span under the router's answer, to end with the route's context
func (t *routeTrace) begin(
	alive context.Context, tel *telemetry.Telemetry, traceparent string, start time.Time,
	attrs ...attr.KeyValue,
) {
	_, t.span = tel.Session(context.Background(), traceparent, "edge.preview.route", start,
		attrs...)
	context.AfterFunc(alive, func() { t.end(alive) })
}

// setCause records why the cache let the route go, unless the lease already ended it
func (t *routeTrace) setCause(cause string) {
	t.mu.Lock()
	if t.cause == "" {
		t.cause = cause
	}
	t.mu.Unlock()
}

// end sets the counts and the end cause and ends the span
func (t *routeTrace) end(alive context.Context) {
	cause := leaseCause(lease.Reason(alive))
	t.mu.Lock()
	if cause == "" {
		cause = t.cause
	}
	t.mu.Unlock()
	if cause == "" {
		cause = "done"
	}
	t.span.SetAttributes(attr.Requests(t.requests.Load()), attr.Responses4xx(t.resp4xx.Load()),
		attr.Responses5xx(t.resp5xx.Load()), attr.GateErrors(t.gateErrors.Load()),
		attr.Websockets(t.websockets.Load()), attr.BytesIn(t.bytesIn.Load()),
		attr.BytesOut(t.bytesOut.Load()), attr.EndCause(cause))
	t.span.End()
}

// leaseCause is the end_cause a lease's reason says, empty for none
func leaseCause(reason string) string {
	switch reason {
	case lease.ReasonBudget:
		return "budget_spent"
	case lease.ReasonRevoked:
		return "revoked"
	case lease.ReasonExpired:
		return "deadline"
	case lease.ReasonEnded:
		return "ended"
	}
	return ""
}

// status counts one answer by its class
func (t *routeTrace) status(code int) {
	switch {
	case code >= 500:
		t.resp5xx.Add(1)
	case code >= 400:
		t.resp4xx.Add(1)
	}
}

// bg is a context for a call that outlives the request, holding the route's span
func (rt *route) bg() context.Context {
	if rt == nil || rt.trace.span == nil {
		return context.Background()
	}
	return trace.ContextWithSpan(context.Background(), rt.trace.span)
}
