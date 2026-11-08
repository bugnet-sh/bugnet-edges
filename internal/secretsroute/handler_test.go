package secretsroute

import (
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

func TestJSONMatchesTheSpec(t *testing.T) {
	x := newHarness(t, 0)
	eq(t, x.call(t, "GET", "/v1/links/"+link, nil, pageHeaders).body, golden(t, "get_link.json"))
	eq(t, x.call(t, "PUT", "/v1/links/"+link+"/secret", submitBodyText(), pageHeaders).body,
		golden(t, "submit.json"))
	eq(t, x.call(t, "GET", "/v1/sealing-key", nil, bridgeHeaders).body,
		golden(t, "sealing_key.json"))
	r := x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), bridgeHeaders)
	eq(t, r.status, 200)
	eq(t, r.body, golden(t, "put.json"))
	eq(t, r.header.Get("Content-Type"), "application/json")
}

func TestRouterGetsTheDecodedCall(t *testing.T) {
	x := newHarness(t, 0)
	x.call(t, "PUT", "/v1/links/"+link+"/secret", submitBodyText(), pageHeaders)
	got := x.router.lastRequest().(*routerv1.SubmitSecretLinkRequest)
	eq(t, got.GetLinkToken(), link)
	eq(t, got.GetValue().GetBox(), []byte("sealed"))
	eq(t, got.GetValue().GetKeyId(), "k1")
	eq(t, got.GetClientIp(), "127.0.0.1")
	eq(t, got.GetSpec().GetHosts(), []string{"huggingface.co"})
	x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), bridgeHeaders)
	put := x.router.lastRequest().(*routerv1.PutBridgeSecretRequest)
	eq(t, put.GetPutGrant(), grant)
	eq(t, put.GetIdempotencyKey(), "idem-1")
	eq(t, put.GetClientIp(), "127.0.0.1")
}

func TestBodiesAreStrict(t *testing.T) {
	x := newHarness(t, 0)
	pad := b64("sealed") + "=="
	for name, body := range map[string]string{
		"unknown field": `{"spec":` + specJSONText + `,"extra":1}`,
		"not json":      `nope`,
		"trailing json": string(putBodyText()) + ` {}`,
		"padded box": `{"spec":` + specJSONText + `,"value":{"keyId":"k1","box":"` + pad +
			`"},"idempotencyKey":"i"}`,
		"std base64": `{"spec":` + specJSONText + `,"value":{"keyId":"k1","box":"+/+/"}}`,
	} {
		r := x.call(t, "PUT", "/v1/secrets/HF_TOKEN", []byte(body), bridgeHeaders)
		eq(t, [2]any{name, r.status}, [2]any{name, 400})
		if !contains(r.body, `"error":"invalid_body"`) {
			t.Fatalf("%s: %s", name, r.body)
		}
	}
	eq(t, x.router.count(), 0)
}

func TestBridgeRefusesBrowserHeaders(t *testing.T) {
	x := newHarness(t, 0)
	for _, h := range []headers{
		{"Origin": origin}, {"Origin": "null"}, {"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "none"}, {"Origin": origin, "Sec-Fetch-Site": "same-origin"},
	} {
		for _, call := range [][3]string{
			{"GET", "/v1/sealing-key", ""}, {"PUT", "/v1/secrets/HF_TOKEN", string(putBodyText())},
		} {
			r := x.call(t, call[0], call[1], []byte(call[2]), merge(bridgeHeaders, h))
			eq(t, r.status, 403)
			eq(t, r.body, `{"error":"browser_refused","message":"This call is not for browsers."}`)
		}
	}
	eq(t, x.router.count(), 0)
}

func TestPageNeedsItsOrigin(t *testing.T) {
	x := newHarness(t, 0)
	for name, h := range map[string]headers{
		"no origin":      merge(pageHeaders, headers{"Origin": ""}),
		"another origin": merge(pageHeaders, headers{"Origin": "https://x.example.test"}),
		"null origin":    merge(pageHeaders, headers{"Origin": "null"}),
		"http origin":    merge(pageHeaders, headers{"Origin": "http://" + host}),
		"same-site":      merge(pageHeaders, headers{"Sec-Fetch-Site": "same-site"}),
		"cross-site":     merge(pageHeaders, headers{"Sec-Fetch-Site": "cross-site"}),
	} {
		delete(h, "")
		if h["Origin"] == "" {
			delete(h, "Origin")
		}
		r := x.call(t, "GET", "/v1/links/"+link, nil, h)
		eq(t, [2]any{name, r.status}, [2]any{name, 403})
		if !contains(r.body, `"error":"origin_refused"`) {
			t.Fatalf("%s: %s", name, r.body)
		}
	}
	eq(t, x.router.count(), 0)
	// A request with no Sec-Fetch-Site header passes when the origin is right
	h := merge(pageHeaders, nil)
	delete(h, "Sec-Fetch-Site")
	eq(t, x.call(t, "GET", "/v1/links/"+link, nil, h).status, 200)
	h["Content-Type"] = "text/plain"
	eq(t, x.call(t, "GET", "/v1/links/"+link, nil, h).status, 400)
}

func TestPageCallsRefuseTheBridgeGrant(t *testing.T) {
	x := newHarness(t, 0)
	r := x.call(t, "GET", "/v1/sealing-key", nil, pageHeaders)
	eq(t, r.status, 403)
	eq(t, x.router.count(), 0)
}

func TestBodyOver128KiB(t *testing.T) {
	x := newHarness(t, 0)
	big := []byte(`{"spec":{"name":"` + strings.Repeat("a", 128<<10) + `"}}`)
	r := x.call(t, "PUT", "/v1/secrets/HF_TOKEN", big, bridgeHeaders)
	eq(t, r.status, 413)
	eq(t, x.call(t, "PUT", "/v1/links/"+link+"/secret", big, pageHeaders).status, 413)
	eq(t, x.router.count(), 0)
}

func TestPageLoadsWith600KiBCookie(t *testing.T) {
	x := newHarness(t, 0)
	cookie := headers{"Cookie": "a=" + strings.Repeat("c", 600<<10)}
	r := x.call(t, "GET", "/l/"+link, nil, cookie)
	eq(t, r.status, 200)
	eq(t, r.body, indexHTML)
	eq(t, x.call(t, "GET", "/v1/links/"+link, nil, merge(pageHeaders, cookie)).status, 200)
	eq(t, x.call(t, "GET", "/assets/page-ABC.js", nil, cookie).status, 200)
}

func TestHandleInAuthorizationRefused(t *testing.T) {
	x := newHarness(t, 0)
	for _, auth := range []string{
		"Bearer bnh_AbCdEfGhIjKlMnOpQrStUvWx", "Bearer " + link, "Bearer", "Bearer ",
		"Basic " + grant, grant, "", "Bearer bnsp_", "Bearer bnsp_a b", "Bearer " + grant + "!",
	} {
		h := headers{}
		if auth != "" {
			h["Authorization"] = auth
		}
		r := x.call(t, "GET", "/v1/sealing-key", nil, h)
		eq(t, r.status, 401)
		eq(t, r.body,
			`{"error":"put_grant_invalid","message":"Send a put grant as a bearer token."}`)
		eq(t, x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), h).status, 401)
	}
	eq(t, x.router.count(), 0)
}

func TestNameMismatch(t *testing.T) {
	x := newHarness(t, 0)
	r := x.call(t, "PUT", "/v1/secrets/OTHER_NAME", putBodyText(), bridgeHeaders)
	eq(t, r.status, 400)
	if !contains(r.body, `"error":"name_mismatch"`) {
		t.Fatal(r.body)
	}
	eq(t, x.router.count(), 0)
}

func TestClientIPInBodyRefused(t *testing.T) {
	x := newHarness(t, 0)
	put := `{"spec":` + specJSONText + `,"value":{"keyId":"k1","box":""},"clientIp":"1.2.3.4"}`
	r := x.call(t, "PUT", "/v1/secrets/HF_TOKEN", []byte(put), bridgeHeaders)
	eq(t, r.status, 400)
	if !contains(r.body, `"error":"client_ip_refused"`) {
		t.Fatal(r.body)
	}
	sub := `{"spec":` + specJSONText + `,"clientIp":"1.2.3.4"}`
	eq(t, x.call(t, "PUT", "/v1/links/"+link+"/secret", []byte(sub), pageHeaders).status, 400)
	eq(t, x.router.count(), 0)
}

func TestErrorStatusFromConnectCode(t *testing.T) {
	x := newHarness(t, 0)
	for _, c := range []struct {
		code   connect.Code
		reason string
		status int
	}{
		{connect.CodeInvalidArgument, "HOST_REFUSED", 400},
		{connect.CodePermissionDenied, "PUT_GRANT_INVALID", 401},
		{connect.CodeNotFound, "LINK_UNKNOWN", 404},
		{connect.CodeFailedPrecondition, "LINK_LOCKED", 409},
		{connect.CodeResourceExhausted, "RATE_LIMITED", 429},
		{connect.CodeUnavailable, "NOT_READY", 503},
		{connect.CodeOutOfRange, "OVER_CAP", 500},
		{connect.CodeInternal, "", 500},
		{connect.CodeUnauthenticated, "TOKEN_INVALID", 500},
	} {
		x.router.set(func(f *fakeRouter) { f.err = refusal(c.code, c.reason) })
		r := x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), bridgeHeaders)
		eq(t, [2]any{c.reason, r.status}, [2]any{c.reason, c.status})
		want := strings.ToLower(c.reason)
		if want == "" {
			want = "internal"
		}
		if !contains(r.body, `"error":"`+want+`"`) {
			t.Fatalf("%v: %s", c.code, r.body)
		}
		if contains(r.body, "router text") {
			t.Fatalf("the router's text reached the client: %s", r.body)
		}
		if c.status == 429 || c.status == 503 {
			if r.header.Get("Retry-After") == "" {
				t.Fatalf("%d has no Retry-After", c.status)
			}
		}
	}
}

func TestStaticPageHeaders(t *testing.T) {
	x := newHarness(t, 0)
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
		"connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
	for _, path := range []string{"/l/" + link, "/l/anything/at/all", "/assets/page-ABC.js",
		"/assets/page-DEF.css", "/v1/links/" + link} {
		hd := headers{}
		if strings.HasPrefix(path, "/v1/") {
			hd = pageHeaders
		}
		r := x.call(t, "GET", path, nil, hd)
		eq(t, [2]any{path, r.status}, [2]any{path, 200})
		eq(t, r.header.Get("Content-Security-Policy"), csp)
		eq(t, r.header.Get("Cache-Control"), "no-store")
		eq(t, r.header.Get("Referrer-Policy"), "no-referrer")
		eq(t, r.header.Get("X-Content-Type-Options"), "nosniff")
		eq(t, r.header.Get("Cross-Origin-Opener-Policy"), "same-origin")
		eq(t, r.header.Values("Set-Cookie"), []string(nil))
	}
	eq(t, x.call(t, "GET", "/l/"+link, nil, nil).header.Get("Content-Type"),
		"text/html; charset=utf-8")
	eq(t, x.call(t, "GET", "/assets/page-ABC.js", nil, nil).body, "console.log(1)")
	for _, path := range []string{"/", "/assets/notes.txt", "/assets/missing.js", "/assets/",
		"/assets/../index.html", "/robots.txt", "/v1/nothing"} {
		eq(t, [2]any{path, x.call(t, "GET", path, nil, nil).status}, [2]any{path, 404})
	}
	eq(t, x.call(t, "POST", "/l/"+link, nil, nil).status, 404)
	eq(t, x.call(t, "HEAD", "/l/"+link, nil, nil).status, 200)
}

func TestSixtyRequestsAMinutePerIP(t *testing.T) {
	x := newHarness(t, 60)
	for i := 0; i < 60; i++ {
		eq(t, x.call(t, "GET", "/v1/sealing-key", nil, bridgeHeaders).status, 200)
	}
	r := x.call(t, "GET", "/v1/sealing-key", nil, bridgeHeaders)
	eq(t, r.status, http.StatusTooManyRequests)
	eq(t, r.header.Get("Retry-After"), "60")
	if !contains(r.body, `"error":"rate_limited"`) {
		t.Fatal(r.body)
	}
	eq(t, x.router.count(), 60)
}

func TestLogsNeverTheToken(t *testing.T) {
	x := newHarness(t, 0)
	x.call(t, "GET", "/v1/links/"+link, nil, pageHeaders)
	x.call(t, "PUT", "/v1/links/"+link+"/secret", submitBodyText(), pageHeaders)
	x.call(t, "GET", "/v1/sealing-key", nil, bridgeHeaders)
	x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), bridgeHeaders)
	x.call(t, "GET", "/l/"+link, nil, nil)
	x.router.set(func(f *fakeRouter) { f.err = refusal(connect.CodeUnavailable, "NOT_READY") })
	x.call(t, "PUT", "/v1/secrets/HF_TOKEN", putBodyText(), bridgeHeaders)
	logs := x.logs.String()
	for _, secret := range []string{link, grant, "HF_TOKEN", b64("sealed"), "idem-1",
		"0b1d4a5e", token} {
		if contains(logs, secret) {
			t.Fatalf("the log holds %q:\n%s", secret, logs)
		}
	}
	for _, shape := range []string{"/v1/links/*", "/v1/links/*/secret", "/v1/sealing-key",
		"/v1/secrets/*", "/l/*"} {
		if !contains(logs, `"route":"`+shape+`"`) {
			t.Fatalf("no log line for %s:\n%s", shape, logs)
		}
	}
}

func TestNewRefusesAnIncompletePage(t *testing.T) {
	_, err := New(nil, Options{Host: host, PageDir: t.TempDir()})
	if err == nil {
		t.Fatal("a directory without index.html was accepted")
	}
}
