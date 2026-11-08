package egress

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// hfPlacement is a placement with one secret for hf.example, in the Authorization header
func hfPlacement(t *testing.T, h *harness, opts ...func(*secretSpec)) (*fakePlacement, string) {
	t.Helper()
	s := secretSpec{
		name: "HF_TOKEN", value: "hf_secret", hosts: []string{"hf.example"},
		headers: []string{"x-api-key"},
	}
	for _, o := range opts {
		o(&s)
	}
	p, phs := h.placement(t, s)
	return p, phs[0]
}

func TestInnerHandshakeRefusals(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	for _, sni := range []string{"", "203.0.113.5", "egress.bugnet.sh", "not-in-set.example",
		"hf.example.bugnet.sh", "preview.bugnet.sh"} {
		if _, err := h.inner(p.token, sni); err == nil {
			t.Errorf("the inner handshake for %q succeeded", sni)
		}
	}
	if _, err := h.inner(p.token, "hf.example"); err != nil {
		t.Fatalf("the inner handshake for a host in the set failed: %v", err)
	}
}

func TestSwap(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	c := h.client(p.token)
	seen := func(hdr map[string]string, path string) *http.Request {
		t.Helper()
		resp := get(t, c, "https://hf.example"+path, hdr)
		eq(t, resp.StatusCode, 200)
		return h.lastSeen()
	}
	eq(t, seen(map[string]string{"Authorization": "Bearer " + ph}, "/").Header.Get("Authorization"),
		"Bearer hf_secret")
	eq(t, seen(map[string]string{"Authorization": "token " + ph}, "/").Header.Get("Authorization"),
		"token hf_secret")
	eq(t, seen(map[string]string{"Authorization": "Custom-Scheme " + ph}, "/").
		Header.Get("Authorization"), "Custom-Scheme hf_secret")
	eq(t, seen(map[string]string{"Authorization": basic("x", ph)}, "/").Header.Get("Authorization"),
		basic("x", "hf_secret"))
	eq(t, seen(map[string]string{"Authorization": basic(ph, ph)}, "/").Header.Get("Authorization"),
		basic("hf_secret", "hf_secret"))
	eq(t, seen(map[string]string{"X-Api-Key": ph}, "/").Header.Get("X-Api-Key"), "hf_secret")
	// The URL, a cookie and an unlisted header are never scanned
	eq(t, seen(nil, "/q?k="+ph).URL.RawQuery, "k="+ph)
	eq(t, seen(map[string]string{"Cookie": "k=" + ph}, "/").Header.Get("Cookie"), "k="+ph)
	eq(t, seen(map[string]string{"X-Other": ph}, "/").Header.Get("X-Other"), ph)
}

func TestSwapOverHTTP2(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	c := h.client(p.token, "h2", "http/1.1")
	resp := get(t, c, "https://hf.example/", map[string]string{"Authorization": "Bearer " + ph})
	eq(t, resp.ProtoMajor, 2)
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
}

func TestNeverSwapped(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	_, otherPH := hfPlacement(t, h, func(s *secretSpec) { s.value = "other_secret" })
	// A second host on the same placement, which the secret does not allow
	p2, phs := h.placement(t,
		secretSpec{name: "A", value: "va", hosts: []string{"a.example"}},
		secretSpec{name: "B", value: "vb", hosts: []string{"b.example"}})
	cases := []struct {
		name, token, url, auth string
	}{
		{"another host", p2.token, "https://b.example/", "Bearer " + phs[0]},
		{"another placement", p.token, "https://hf.example/", "Bearer " + otherPH},
	}
	for _, tc := range cases {
		resp := get(t, h.client(tc.token), tc.url, map[string]string{"Authorization": tc.auth})
		eq(t, resp.StatusCode, 200)
		eq(t, h.lastSeen().Header.Get("Authorization"), tc.auth)
	}
	bad, badPH := hfPlacement(t, h, func(s *secretSpec) { s.value = "line\r\nInjected: 1" })
	resp := get(t, h.client(bad.token), "https://hf.example/",
		map[string]string{"Authorization": "Bearer " + badPH})
	eq(t, resp.StatusCode, 200)
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer "+badPH)
	eq(t, h.lastSeen().Header.Get("Injected"), "")
}

func TestEchoScrubbedFromResponseHeaders(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	c := h.client(p.token)
	resp := get(t, c, "https://hf.example/echo",
		map[string]string{"Authorization": "Bearer " + ph, "X-Api-Key": ph})
	eq(t, resp.Header.Get("X-Echo"), "Bearer "+ph)
	eq(t, resp.Header.Get("X-Api-Echo"), ph)
	resp = get(t, c, "https://hf.example/echo", map[string]string{"Authorization": basic("u", ph)})
	eq(t, strings.Contains(resp.Header.Get("X-Echo"), "hf_secret"), false)
	eq(t, strings.Contains(resp.Header.Get("X-Echo"), basic("u", "hf_secret")[6:]), false)
	eq(t, resp.Header.Get("X-Echo"), "Basic "+ph)
}

func TestRedirectPassedBack(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	resp := get(t, h.client(p.token), "https://hf.example/redirect", nil)
	eq(t, resp.StatusCode, http.StatusFound)
	eq(t, resp.Header.Get("Location"), "https://other.example/next")
	eq(t, h.seenCount(), 1)
}

func TestHostSNIMismatchIs421(t *testing.T) {
	h := start(t)
	p, _ := h.placement(t,
		secretSpec{name: "A", value: "va", hosts: []string{"a.example", "b.example"}})
	c := h.client(p.token)
	req, _ := http.NewRequest(http.MethodGet, "https://a.example/", nil)
	req.Host = "b.example"
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	eq(t, resp.StatusCode, http.StatusMisdirectedRequest)
	eq(t, h.seenCount(), 0)
}

func TestTraceIs405(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	for _, m := range []string{"TRACE", "TRACK"} {
		req, _ := http.NewRequest(m, "https://hf.example/", nil)
		resp, err := h.client(p.token).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		eq(t, resp.StatusCode, http.StatusMethodNotAllowed)
	}
	eq(t, h.seenCount(), 0)
}

func TestBugnetHeadersAreStrippedAndNoForwardedAreAdded(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	resp := get(t, h.client(p.token), "https://hf.example/",
		map[string]string{"Bugnet-Placement": "x", "Bugnet-Gate": "y",
			"X-Forwarded-For": "1.2.3.4"})
	eq(t, resp.StatusCode, 200)
	seen := h.lastSeen()
	eq(t, seen.Header.Get("Bugnet-Placement"), "")
	eq(t, seen.Header.Get("Bugnet-Gate"), "")
	eq(t, seen.Header.Get("X-Forwarded-For"), "")
	eq(t, seen.Header.Get("Forwarded"), "")
}

func TestWebSocketUpgradeIsPassedWithTheSwap(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	ctx, cancel := context.WithTimeout(t.Context(), shortWait)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "https://hf.example/ws", &websocket.DialOptions{
		HTTPClient: h.client(p.token),
		HTTPHeader: http.Header{"Authorization": {"Bearer " + ph}},
	})
	if err != nil {
		t.Fatalf("%v %v", err, resp)
	}
	defer func() { _ = ws.CloseNow() }()
	eq(t, resp.StatusCode, http.StatusSwitchingProtocols)
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
	if err := ws.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, string(msg), "hello")
}
