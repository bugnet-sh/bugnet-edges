package egress

import (
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

const (
	testHandle   = "sbx_incf5d4j2g46mypgm6wajtyic5"
	routerSpanID = "00f067aa0ba902b7"
)

// traced makes the proxy export spans to a receiver, its router client carrying the interceptor
func traced(t *testing.T) (option, *telemetrytest.Telemetry, string) {
	t.Helper()
	tel := telemetrytest.New(t, "bugnet-egress", 1)
	tid, _ := telemetrytest.OrderIDs(testHandle)
	return func(cfg *Config, d *Deps) {
		d.Telemetry = tel.Telemetry
		var opts []connect.ClientOption
		if tel.Enabled() {
			opts = append(opts, connect.WithInterceptors(tel.ClientInterceptor()))
		}
		d.Router = routerv1connect.NewEgressServiceClient(
			http.DefaultClient, cfg.RouterURL, opts...)
	}, tel, tid
}

// closeTunnels ends every tunnel the client opened
func closeTunnels(c *http.Client) { c.Transport.(*http.Transport).CloseIdleConnections() }

func TestTunnelSpanHidesCustomHosts(t *testing.T) {
	opt, tel, tid := traced(t)
	h := start(t, opt)
	p, phs := h.placement(t,
		secretSpec{name: "RELAY", value: "relay_secret", hosts: []string{"relay.example"},
			custom: []string{"relay.example"}},
		secretSpec{name: "HF", value: "hf_secret", hosts: []string{"hf.example"}})
	p.resp.OrderTraceparent = telemetrytest.Traceparent(tid, routerSpanID)

	c := h.client(p.token)
	eq(t, get(t, c, "https://relay.example/", nil).StatusCode, http.StatusForbidden)
	eq(t, get(t, c, "https://relay.example/",
		map[string]string{"Authorization": "Bearer " + phs[0]}).StatusCode, 200)
	closeTunnels(c)
	c = h.client(p.token)
	eq(t, get(t, c, "https://hf.example/", nil).StatusCode, 200)
	closeTunnels(c)

	within(t, "both tunnel spans", func() bool {
		return len(telemetrytest.Named(tel.Flushed(t), "egress.tunnel")) == 2
	})
	spans := tel.Flushed(t)
	byHost := map[string]telemetrytest.Span{}
	for _, s := range telemetrytest.Named(spans, "egress.tunnel") {
		eq(t, s.TraceID, tid)
		eq(t, s.ParentID, routerSpanID)
		eq[any](t, s.Attrs["bugnet.placement_id"], p.id.String())
		eq[any](t, s.Attrs["bugnet.end_cause"], "client_closed")
		if n, _ := s.Attrs["bugnet.bytes_out"].(int64); n <= 0 {
			t.Fatalf("bytes_out is %v", s.Attrs["bugnet.bytes_out"])
		}
		byHost[s.Attrs["bugnet.egress_host"].(string)] = s
	}
	custom, preset := byHost["custom"], byHost["hf.example"]
	eq[any](t, custom.Attrs["bugnet.requests"], int64(2))
	eq[any](t, custom.Attrs["bugnet.swaps"], int64(1))
	eq[any](t, custom.Attrs["bugnet.refused"], int64(1))
	eq[any](t, preset.Attrs["bugnet.requests"], int64(1))
	eq[any](t, preset.Attrs["bugnet.swaps"], int64(0))
	eq[any](t, preset.Attrs["bugnet.refused"], int64(0))
	// No span says the custom host's name or a secret
	eq(t, telemetrytest.Scan(spans, map[string]string{
		"custom host": "relay.example", "value": "relay_secret", "placeholder": phs[0],
		"token": p.token,
	}), []string(nil))
}

func TestStrangersMakeNoSpans(t *testing.T) {
	opt, tel, _ := traced(t)
	h := start(t, opt)
	for range 100 {
		if _, _, err := h.tunnel(newToken(), "203.0.113.9"); err == nil {
			t.Fatal("an unknown token opened a tunnel")
		}
	}
	eq(t, len(tel.Flushed(t)), 0)
}

func TestEmptyOrderTraceparentMakesNoSession(t *testing.T) {
	opt, tel, _ := traced(t)
	h := start(t, opt)
	p, _ := h.placement(t, secretSpec{name: "HF", value: "hf_secret",
		hosts: []string{"hf.example"}})
	c := h.client(p.token)
	eq(t, get(t, c, "https://hf.example/", nil).StatusCode, 200)
	closeTunnels(c)
	// Stopping the proxy waits for every tunnel to end
	h.stop()
	eq(t, len(tel.Flushed(t)), 0)
}
