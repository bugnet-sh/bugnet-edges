package sshgw

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

const tracerScope = "bugnet-edges/sshgw"

// connTrace is a connection's ssh.connection span and the counts it ends with
type connTrace struct {
	accepted time.Time
	span     trace.Span // nil until acquire has succeeded

	sessions, forwards, bytesIn, bytesOut atomic.Int64
}

// begin starts the span under the router's answer, backdated to the TCP accept
func (t *connTrace) begin(tel *telemetry.Telemetry, traceparent, placement string) {
	_, t.span = tel.Session(context.Background(), traceparent, "ssh.connection", t.accepted,
		attr.PlacementID(placement))
}

// end sets the counts and the end cause and ends the span, when one started
func (t *connTrace) end(reason string) {
	if t.span == nil {
		return
	}
	t.span.SetAttributes(attr.Sessions(t.sessions.Load()), attr.Forwards(t.forwards.Load()),
		attr.BytesIn(t.bytesIn.Load()), attr.BytesOut(t.bytesOut.Load()),
		attr.EndCause(endCause(reason)))
	t.span.End()
}

// endCause maps a close reason to DP 20.5.2's end_cause values
func endCause(reason string) string {
	switch reason {
	case "done":
		return "client_closed"
	case "revoked", "key_removed":
		return "revoked"
	case "deadline", "ended", "drain":
		return reason
	case "budget":
		return "budget_spent"
	case "keepalive", "upstream_keepalive":
		return "idle"
	case "upstream_gone":
		return "upstream_failed"
	}
	return "error"
}

// traced is the connection's context holding its span, the plain one before acquire
func (c *conn) traced() context.Context {
	if c.trace.span == nil {
		return c.ctx
	}
	return trace.ContextWithSpan(c.ctx, c.trace.span)
}

func transportName(up *routerv1.OpenSshUpstreamResponse) string {
	if _, ok := up.GetTransport().(*routerv1.OpenSshUpstreamResponse_Tcp); ok {
		return "tcp"
	}
	return "websocket"
}

// endUpstream ends an ssh.upstream span, failed with err's class and never its text
func endUpstream(span trace.Span, err error) {
	if err != nil {
		reason := dialReason(err)
		span.SetAttributes(attr.ErrorType(errorType(reason)))
		span.SetStatus(codes.Error, errorType(reason))
	}
	span.End()
}

// errorType is reason as an error.type word, upper case with underscores
func errorType(reason string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		}
		return '_'
	}, reason)
	if out == "" || out[0] < 'A' || out[0] > 'Z' {
		return "ERROR"
	}
	return out[:min(len(out), 64)]
}
