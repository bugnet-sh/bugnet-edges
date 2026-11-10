package egress

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

// tunnelTrace holds an egress.tunnel span and the counts it ends with
type tunnelTrace struct {
	span trace.Span

	requests, swaps, refused atomic.Int64
	host                     atomic.Pointer[string]
	idled                    atomic.Bool
}

// note counts one request of the tunnel's inner connection
func (t *tunnelTrace) note(st *reqState) {
	t.requests.Add(1)
	if st.swap.did() {
		t.swaps.Add(1)
	}
	if st.refused {
		t.refused.Add(1)
	}
}

// end sets the counts and ends the span with cause
func (t *tunnelTrace) end(cause string, in, out int64) {
	attrs := []attr.KeyValue{attr.Requests(t.requests.Load()), attr.Swaps(t.swaps.Load()),
		attr.Refused(t.refused.Load()), attr.BytesIn(in), attr.BytesOut(out),
		attr.EndCause(cause)}
	if h := t.host.Load(); h != nil {
		attrs = append(attrs, attr.EgressHost(*h))
	}
	t.span.SetAttributes(attrs...)
	t.span.End()
}

// tunnelCause says why a tunnel ended, from its contexts and connection
func (s *Server) tunnelCause(ctx context.Context, t *tunnelTrace, handshook bool) string {
	switch reason := lease.Reason(ctx); {
	case reason == lease.ReasonBudget:
		return "budget_spent"
	case reason == lease.ReasonRevoked:
		return "revoked"
	case reason == lease.ReasonExpired:
		return "deadline"
	case reason != "":
		return "ended"
	case s.runCtx.Err() != nil:
		return "drain"
	case ctx.Err() != nil:
		// A moved source check closes the tunnel
		return "revoked"
	case t.idled.Load():
		return "idle"
	case !handshook:
		return "error"
	}
	return "client_closed"
}

// hostLabel is the host as the span shows it, custom for any host outside the presets
func hostLabel(kind hostKind, host string) string {
	if kind == kindPreset {
		return host
	}
	return "custom"
}
