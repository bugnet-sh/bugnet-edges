package telemetry

import (
	"context"
	"regexp"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

const sessionScope = "bugnet-edges/telemetry"

var reTraceparent = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// Session starts a span under the router's order_traceparent, backdated to start
func (t *Telemetry) Session(
	ctx context.Context, orderTraceparent, name string, start time.Time, attrs ...attr.KeyValue,
) (context.Context, trace.Span) {
	none := trace.SpanFromContext(context.Background())
	if !t.Enabled() || !reTraceparent.MatchString(orderTraceparent) || !attr.SpanNameOK(name) {
		return ctx, none
	}
	h := propagation.MapCarrier{"traceparent": orderTraceparent}
	parent := trace.SpanContextFromContext(
		propagation.TraceContext{}.Extract(context.Background(), h))
	if !parent.IsValid() {
		return ctx, none
	}
	ctx = trace.ContextWithRemoteSpanContext(ctx, parent)
	ctx, span := t.provider.Tracer(sessionScope).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindServer), trace.WithTimestamp(start),
		trace.WithAttributes(attrs...))
	return ctx, span
}
