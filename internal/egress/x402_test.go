package egress

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

var sellerPin = x402.Encode58(bytes.Repeat([]byte{1}, 32))

// xenv is a proxy whose placement has x402 services on api.example
type xenv struct {
	h      *harness
	p      *fakePlacement
	cfg    *routerv1.X402Config
	stopEv func()
}

func paymentRequired(micros int64) string {
	return x402.EncodeRequired(x402.Required{Version: 2, Accepts: []x402.Entry{{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint, PayTo: sellerPin,
		AmountMicros: micros, AmountOK: true,
	}}}, "https://api.example/post/x", nil)
}

// seller answers the paths the x402 tests use
func seller(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Bugnet-X402-Status", "paid")
	switch {
	case strings.HasPrefix(r.RequestURI, "/free/big"):
		_, _ = w.Write(make([]byte, 3<<20))
	case strings.HasPrefix(r.RequestURI, "/free/drop"):
		c, _, _ := w.(http.Hijacker).Hijack()
		_ = c.Close()
	case strings.HasPrefix(r.RequestURI, "/free/paywall"):
		w.Header().Set("Payment-Required", "seller-own")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, "seller body")
	case strings.HasPrefix(r.RequestURI, "/post/v1only"):
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"x402Version":1,"accepts":[{"scheme":"exact"}]}`)
	case strings.HasPrefix(r.RequestURI, "/post/"):
		w.Header().Set("Payment-Required", paymentRequired(10000))
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, "seller body")
	default:
		w.Header().Set("X-Saw-Auth", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "free")
	}
}

func startX402(t *testing.T, mod func(*routerv1.X402Config), opts ...option) *xenv {
	t.Helper()
	var ev *x402.Events
	var counters *x402.Counters
	h := start(t, append([]option{func(_ *Config, d *Deps) {
		ev = x402.NewEvents(x402.EventsSend(d.Router), 20*time.Millisecond, time.Now, nil)
		counters = x402.NewCounters()
		d.Events, d.Counters = ev, counters
	}}, opts...)...)
	h.sell = seller
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ev.Run(ctx); close(done) }()
	go counters.RunReports(ctx, x402.UnpaidSend(
		routerClient(h), ReporterID), 20*time.Millisecond)
	ev.SetServices(h.server.HasX402)
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	cfg := &routerv1.X402Config{
		Enabled: true, AccountId: "order-1",
		Services: []*routerv1.X402Service{
			{ServiceId: "xs_free", Host: "api.example", Prefix: "/free/", Method: "GET",
				MaxPriceMicros: 10000, PayTo: sellerPin},
			{ServiceId: "xs_post", Host: "api.example", Prefix: "/post/", Method: "POST",
				MaxPriceMicros: 10000, PayTo: sellerPin},
		},
		UnpaidRequestsPerHost: 300, UnpaidBytesPerHost: 50 << 20,
	}
	if mod != nil {
		mod(cfg)
	}
	p, _ := h.placement(t)
	p.resp.X402 = cfg
	return &xenv{h: h, p: p, cfg: cfg, stopEv: stop}
}

func routerClient(h *harness) routerv1connect.EgressServiceClient { return h.server.router }

func (x *xenv) get(
	t *testing.T, c *http.Client, path string, hdr map[string]string,
) *http.Response {
	t.Helper()
	return get(t, c, "https://api.example"+path, hdr)
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestX402HostJoinsSNISetAndRefusedHostIsRecorded(t *testing.T) {
	x := startX402(t, nil)
	if _, err := x.h.inner(x.p.token, "api.example"); err != nil {
		t.Fatalf("the handshake to an x402 host failed: %v", err)
	}
	if _, err := x.h.inner(x.p.token, "other.example"); err == nil {
		t.Fatal("the handshake to a host outside the set passed")
	}
	x.stopEv()
	var refused int
	for _, e := range x.h.router.x402Events {
		if e.Status == x402.EventRefusedHost && e.Host == "other.example" {
			refused++
		}
	}
	eq(t, refused, 1)
}

func TestX402RequestRules(t *testing.T) {
	x := startX402(t, nil)
	c := x.h.client(x.p.token)
	upgrade := map[string]string{"Connection": "upgrade", "Upgrade": "websocket"}
	for _, tc := range map[string]struct {
		path   string
		hdr    map[string]string
		status int
		code   string
	}{
		"upgrade": {"/free/a", upgrade, 405, "upgrade_refused"},
		"dotdot":  {"/free/..;/x", nil, 400, "path_refused"},
		"double":  {"/free/%252e%252e/x", nil, 400, "path_refused"},
		"prefix":  {"/other/a", nil, 403, "path_not_enabled"},
		"free":    {"/free/a", nil, 200, ""},
	} {
		resp := x.get(t, c, tc.path, tc.hdr)
		eq(t, resp.StatusCode, tc.status)
		eq(t, resp.Header.Get(x402.HeaderError), tc.code)
		if tc.code != "" {
			eq(t, strings.Contains(body(t, resp), `"code":"`+tc.code+`"`), true)
		}
	}
	eq(t, x.h.seenCount(), 1)
}

func TestX402ForwardsTheTargetAndKeepsRealKeys(t *testing.T) {
	x := startX402(t, nil)
	for _, protos := range [][]string{{"http/1.1"}, {"h2", "http/1.1"}} {
		c := x.h.client(x.p.token, protos...)
		for _, target := range []string{"/free/a%20b%40c?x=%2F&y=1", "/free/x?"} {
			x.get(t, c, target, nil)
			eq(t, x.h.lastSeen().RequestURI, target)
		}
	}
	c := x.h.client(x.p.token)
	resp := x.get(t, c, "/free/a", map[string]string{"Authorization": "Bearer x402"})
	eq(t, resp.Header.Get("X-Saw-Auth"), "")
	resp = x.get(t, c, "/free/a", map[string]string{
		"Authorization": "Bearer sk-real", "Bugnet-Foo": "1", "Keep-Alive": "5"})
	eq(t, resp.Header.Get("X-Saw-Auth"), "Bearer sk-real")
	eq(t, x.h.lastSeen().Header.Get("Bugnet-Foo"), "")
	eq(t, x.h.lastSeen().Header.Get("Keep-Alive"), "")
	// The seller's own Bugnet header never reaches the code
	eq(t, resp.Header.Get("Bugnet-X402-Status"), "")
}

func TestX402SelfPaid402PassesUnchanged(t *testing.T) {
	x := startX402(t, nil)
	c := x.h.client(x.p.token)
	resp := x.get(t, c, "/free/paywall", map[string]string{"X-Payment": "abc"})
	eq(t, resp.StatusCode, 402)
	eq(t, resp.Header.Get("Payment-Required"), "seller-own")
	eq(t, resp.Header.Get(x402.HeaderError), "")
	eq(t, body(t, resp), "seller body")
	x.stopEv()
	eq(t, x.h.router.x402Events[0].Status, x402.EventSelfPaid)
}

func TestX402UnpaidCapsAndStreamCut(t *testing.T) {
	x := startX402(t, func(c *routerv1.X402Config) {
		c.UnpaidRequestsPerHost, c.UnpaidBytesPerHost = 3, 1<<20
	})
	c := x.h.client(x.p.token)
	for range 2 {
		eq(t, x.get(t, c, "/free/a", nil).StatusCode, 200)
	}
	// The third request streams 3 MiB, which the 1 MiB byte cap cuts
	resp := getStream(t, c, "https://api.example/free/big", nil)
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil || n >= 3<<20 {
		t.Fatalf("the answer was not cut: %d bytes, err %v", n, err)
	}
	resp = x.get(t, c, "/free/a", nil)
	eq(t, resp.StatusCode, 403)
	eq(t, resp.Header.Get(x402.HeaderError), "unpaid_cap")
	eq(t, x.h.seenCount(), 3)
	x.stopEv()
	var cut bool
	for _, e := range x.h.router.x402Events {
		cut = cut || e.StreamCut && e.Reason == "unpaid_cap" && e.Status == x402.EventRefusedCap
	}
	eq(t, cut, true)
}

func TestX402Refused402(t *testing.T) {
	x := startX402(t, nil)
	c := x.h.client(x.p.token)
	req := func(method, path string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest(method, "https://api.example"+path, nil)
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// A GET to a POST service keeps the seller's PAYMENT-REQUIRED and swaps the body
	resp := req("GET", "/post/x")
	eq(t, resp.StatusCode, 402)
	eq(t, resp.Header.Get(x402.HeaderError), "method_not_enabled")
	eq(t, resp.Header.Get("Payment-Required"), paymentRequired(10000))
	eq(t, resp.Header.Get("Content-Type"), "application/json")
	eq(t, strings.Contains(body(t, resp), "seller body"), false)
	resp = req("POST", "/post/v1only")
	eq(t, resp.Header.Get(x402.HeaderError), "version_unsupported")
	// A payable 402 fails closed until Payments is called
	resp = req("POST", "/post/x")
	eq(t, resp.StatusCode, 503)
	eq(t, resp.Header.Get(x402.HeaderError), "payments_unavailable")
	eq(t, resp.Header.Get("Retry-After"), "5")
}

func TestX402KillSwitch(t *testing.T) {
	x := startX402(t, func(c *routerv1.X402Config) { c.Enabled = false })
	c := x.h.client(x.p.token)
	eq(t, x.get(t, c, "/free/a", nil).StatusCode, 200)
	r, _ := http.NewRequest("POST", "https://api.example/post/x", nil)
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, resp.StatusCode, 402)
	eq(t, resp.Header.Get(x402.HeaderError), "x402_disabled")
}

func TestX402EventsAndUnpaidDeltasReported(t *testing.T) {
	x := startX402(t, nil)
	c := x.h.client(x.p.token)
	x.get(t, c, "/free/a", nil)
	x.get(t, c, "/free/paywall", map[string]string{"X-Payment": "abc"})
	x.get(t, c, "/other/a", nil)
	x.get(t, c, "/free/drop", nil)
	within(t, "the unpaid deltas", func() bool {
		x.h.router.mu.Lock()
		defer x.h.router.mu.Unlock()
		u := x.h.router.unpaid["api.example"]
		return u != nil && u.Requests >= 3
	})
	x.stopEv()
	var got []string
	for _, e := range x.h.router.x402Events {
		got = append(got, e.Status)
	}
	slices.Sort(got)
	eq(t, got, []string{x402.EventFree, x402.EventRefusedRequest, x402.EventSelfPaid,
		x402.EventUpstreamError})
}
