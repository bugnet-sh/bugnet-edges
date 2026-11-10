package sshgw

import (
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

const (
	testHandle    = "sbx_incf5d4j2g46mypgm6wajtyic5"
	testPlacement = "3f6c1d52-8b8e-4b6e-9d5b-0e1f2a3b4c5d"
	routerSpanID  = "00f067aa0ba902b7"
)

// tracedRig is a rig whose router answers an order_traceparent in the handle's trace
func tracedRig(t *testing.T) (*rig, *telemetrytest.Telemetry, string) {
	t.Helper()
	tel := telemetrytest.New(t, "bugnet-ssh", 1)
	tid, _ := telemetrytest.OrderIDs(testHandle)
	r := newRig(t, func(r *rig, cfg *Config) {
		cfg.Tracing = tel.Telemetry
		r.router.register(r.alias, testPlacement, r.user.PublicKey(), time.Now().Add(time.Hour))
		r.placement = testPlacement
		r.router.upstream = r.upstreamTo(r.up)
		r.router.orderTP = telemetrytest.Traceparent(tid, routerSpanID)
	})
	return r, tel, tid
}

func TestSshConnectionSpan(t *testing.T) {
	r, tel, tid := tracedRig(t)
	c := r.client()
	ch := rawSession(t, c)
	ok, err := ch.SendRequest("shell", true, nil)
	eq(t, err, nil)
	eq(t, ok, true)
	_ = ch.Close()
	_ = c.Close()
	waitFor(t, "the lease release", func() bool { return r.router.count(&r.router.releases) == 1 })
	waitFor(t, "the connection span", func() bool {
		return len(telemetrytest.Named(tel.Flushed(t), "ssh.connection")) == 1 &&
			len(telemetrytest.Named(tel.Flushed(t), "bugnet.router.v1.SshGatewayService/"+
				"ReleaseSshConnection")) == 1
	})
	spans := tel.Flushed(t)
	conn := telemetrytest.Only(t, spans, "ssh.connection")
	eq(t, conn.TraceID, tid)
	eq(t, conn.ParentID, routerSpanID)
	eq[any](t, conn.Attrs["bugnet.placement_id"], testPlacement)
	eq[any](t, conn.Attrs["bugnet.sessions"], int64(1))
	eq[any](t, conn.Attrs["bugnet.forwards"], int64(0))
	eq[any](t, conn.Attrs["bugnet.end_cause"], "client_closed")
	up := telemetrytest.Only(t, spans, "ssh.upstream")
	eq(t, up.ParentID, conn.SpanID)
	eq[any](t, up.Attrs["bugnet.transport"], "tcp")
	open := telemetrytest.Only(t, spans, "bugnet.router.v1.SshGatewayService/OpenSshUpstream")
	eq(t, open.ParentID, up.SpanID)
	rel := telemetrytest.Only(t, spans,
		"bugnet.router.v1.SshGatewayService/ReleaseSshConnection")
	eq(t, rel.ParentID, conn.SpanID)
	// The key check and the lease come before the span exists, so they carry no header
	eq(t, r.router.carried("AuthorizeSshKey"), []string{""})
	eq(t, r.router.carried("AcquireSshConnection"), []string{""})
	eq(t, len(telemetrytest.Named(spans,
		"bugnet.router.v1.SshGatewayService/AcquireSshConnection")), 0)
	got := r.router.carried("OpenSshUpstream")
	eq(t, strings.Split(got[0], "-")[1:3], []string{tid, open.SpanID})
}

func TestSshKeyQueryMakesNoSpan(t *testing.T) {
	r, tel, _ := tracedRig(t)
	// A key query reaches AuthorizeSshKey and no lease
	_, v := r.gw.authorize(t.Context(), r.alias, r.user.PublicKey(), "fp", netipAddr())
	eq(t, v, allowed)
	eq(t, r.router.count(&r.router.acquires), 0)
	eq(t, len(tel.Flushed(t)), 0)
}

func TestStrangersMakeNoSpans(t *testing.T) {
	r, tel, _ := tracedRig(t)
	for i := range 100 {
		other := newSigner(t)
		alias := "bn-" + strings.Repeat("x", 3+i%5)
		if c, err := r.dialAs(alias, other, nil); err == nil {
			_ = c.Close()
		}
	}
	eq(t, len(tel.Flushed(t)), 0)
}

func TestUpstreamSpanFails(t *testing.T) {
	r, tel, _ := tracedRig(t)
	r.router.mu.Lock()
	r.router.upstream = func(*routerv1.OpenSshUpstreamRequest, string) (
		*routerv1.OpenSshUpstreamResponse, error) {
		return nil, errInfo(connect.CodeUnavailable, "SSH_PREPARING")
	}
	r.router.mu.Unlock()
	c := r.client()
	waitFor(t, "the upstream attempt", func() bool {
		return r.router.count(&r.router.upstreams) == 1
	})
	_ = c.Close()
	waitFor(t, "the upstream span", func() bool {
		return len(telemetrytest.Named(tel.Flushed(t), "ssh.upstream")) == 1
	})
	up := telemetrytest.Only(t, tel.Flushed(t), "ssh.upstream")
	eq[any](t, up.Attrs["error.type"], "SSH_PREPARING")
	eq(t, up.StatusText, "SSH_PREPARING")
}

func TestEmptyOrderTraceparentMakesNoSession(t *testing.T) {
	r, tel, _ := tracedRig(t)
	r.router.mu.Lock()
	r.router.orderTP = ""
	r.router.mu.Unlock()
	c := r.client()
	rawSession(t, c)
	_ = c.Close()
	waitFor(t, "the lease release", func() bool { return r.router.count(&r.router.releases) == 1 })
	eq(t, len(tel.Flushed(t)), 0)
}
