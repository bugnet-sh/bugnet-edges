package preview

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
)

/* Tokens and the query */

func TestTokenRemovalKeepsTheRestOfTheQuery(t *testing.T) { // review focus 5
	x := newHarness(t)
	tok := x.pv.token
	gateSees := func(path string) string {
		res, _ := x.get(t, at(path))
		eq(t, res.StatusCode, http.StatusOK)
		return x.gate.last().uri
	}
	got := gateSees("/app?page=2&bugnet_token=" + tok + "&q=a%20b&t=1&bugnet_token=x")
	eq(t, got, "/app?page=2&q=a%20b&t=1&bugnet_token=x")
	eq(t, gateSees("/?bugnet_token="+tok), "/")
	eq(t, gateSees("/v?t=1700000000&bugnet_token="+tok+"&;odd=%zz"), "/v?t=1700000000&;odd=%zz")

	res, body := x.get(t, at("/app?page=2&bugnet_token="+tok+"&q=a%20b"), "Accept", "text/html")
	eq(t, isInterstitial(t, res, body), true)
	next := formValue(t, body, "next")
	eq(t, next, "/app?page=2&q=a%20b")
	loc := x.postContinue(t, "https://"+host, next).Header.Get("Location")
	eq(t, loc, "/app?page=2&q=a%20b")
}

func TestStripToken(t *testing.T) {
	tok := newToken()
	for raw, want := range map[string]string{
		"":                                  "",
		"a=1":                               "a=1",
		"bugnet_token=" + tok:               "",
		"bugnet_token=" + tok + "&a=1":      "a=1",
		"a=1&bugnet_token=" + tok:           "a=1",
		"a=1&&bugnet_token=" + tok + "&b=2": "a=1&&b=2",
		"bugnet_token=other&t=1":            "bugnet_token=other&t=1",
		"Bugnet_token=" + tok:               "Bugnet_token=" + tok,
	} {
		rest, _ := stripToken(raw)
		eq(t, rest, want)
	}
	_, got := stripToken("t=1&bugnet_token=" + tok)
	eq(t, got, tok)
}

func TestTokenSources(t *testing.T) {
	x := newHarness(t)
	for name, kv := range map[string][]string{
		"header": {headerName, x.pv.token},
		"cookie": {"Cookie", "a=1; " + cookieName + "=" + x.pv.token},
	} {
		res, body := x.get(t, at("/x?t=1"), kv...)
		if res.StatusCode != http.StatusOK || body != "app on port 5173" {
			t.Fatalf("%s: %d %q", name, res.StatusCode, body)
		}
		eq(t, x.gate.last().uri, "/x?t=1")
	}
	res, _ := x.get(t, x.withToken("/x?t=1"))
	eq(t, res.StatusCode, http.StatusOK)
	// A bugnet_token without bnp_ belongs to the app, so the request has no token
	res, _ = x.get(t, at("/?bugnet_token=abc"))
	eq(t, res.StatusCode, http.StatusUnauthorized)
	res, body := x.get(t, at("/"))
	eq(t, res.StatusCode, http.StatusUnauthorized)
	if !strings.Contains(body, "This link is incomplete or no longer valid") {
		t.Fatalf("no 401 page: %s", body)
	}
	eq(t, x.router.count(&x.router.resolves), 1)
}

/* Review focus 4 */

func TestPreviewWorksOnceTheAppListens(t *testing.T) {
	x := newHarness(t)
	x.gate.portClosed(5173)
	res, body := x.browse(t, "/")
	eq(t, res.StatusCode, http.StatusBadGateway)
	if !strings.Contains(body, "Nothing is listening on port 5173") {
		t.Fatalf("no port page: %s", body)
	}
	eq(t, res.Header.Get("Cache-Control"), "no-store")
	x.gate.listen(5173)
	res, body = x.browse(t, "/")
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, body, "app on port 5173")
	time.Sleep(100 * time.Millisecond)
	eq(t, x.router.count(&x.router.repairs), 0)
}

/* The interstitial and Continue */

func TestInterstitialOnlyOnBrowserPageLoads(t *testing.T) {
	x := newHarness(t)
	link := x.link
	is := func(kv ...string) bool {
		res, body := x.get(t, link, kv...)
		return isInterstitial(t, res, body)
	}
	eq(t, is("Sec-Fetch-Dest", "document"), true)
	eq(t, is("Sec-Fetch-Dest", "iframe"), true)
	eq(t, is("Accept", "*/*"), false)
	eq(t, is("Sec-Fetch-Dest", "document", skipHeader, "1"), false)
	eq(t, is("Accept", "text/html"), true)
	eq(t, is("Accept", "text/html", "Sec-Fetch-Dest", "script"), false)
	eq(t, is("Sec-Fetch-Dest", "empty", "Sec-Fetch-Site", "same-origin"), false)
	// The header form and curl never see it
	res, body := x.get(t, at("/"), headerName, x.pv.token, "Sec-Fetch-Dest", "document")
	eq(t, isInterstitial(t, res, body), false)
	// Once the browser holds the cookie for this token, a new click goes straight through
	eq(t, is("Sec-Fetch-Dest", "document", "Cookie", cookieName+"="+x.pv.token), false)
	eq(t, is("Sec-Fetch-Dest", "document", "Cookie", cookieName+"=bnp_other"), true)

	res, body = x.get(t, link, "Sec-Fetch-Dest", "document")
	h := res.Header
	eq(t, h.Get("Cache-Control"), "no-store")
	eq(t, h.Get("Referrer-Policy"), "no-referrer")
	eq(t, h.Get("X-Content-Type-Options"), "nosniff")
	eq(t, h.Get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'; "+
		"form-action 'self'; frame-ancestors 'none'")
	eq(t, formValue(t, body, "token"), x.pv.token)
	if !strings.Contains(body, "mailto:support@bugnet.org") {
		t.Fatalf("no abuse contact in\n%s", body)
	}
}

func TestInterstitialOffSetsTheCookie(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.interstitial = false })
	res, body := x.get(t, x.link, "Sec-Fetch-Dest", "document")
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, body, "app on port 5173")
	eq(t, res.Header.Values("Set-Cookie"), []string{cookieFor(x.pv.token)})
	// A program never gets the cookie
	res, _ = x.get(t, x.link)
	eq(t, len(res.Header.Values("Set-Cookie")), 0)
}

func TestContinue(t *testing.T) {
	x := newHarness(t)
	res := x.postContinue(t, "https://"+host, "/app?page=2", "Sec-Fetch-Site", "same-origin")
	eq(t, res.StatusCode, http.StatusSeeOther)
	eq(t, res.Header.Get("Location"), "/app?page=2")
	eq(t, res.Header.Get("Cache-Control"), "no-store")
	ck := res.Header.Get("Set-Cookie")
	eq(t, ck, cookieName+"="+x.pv.token+"; Path=/; HttpOnly; Secure; SameSite=Lax")
	eq(t, strings.Contains(strings.ToLower(ck), "domain"), false)
	eq(t, x.postContinue(t, "https://"+host, "").Header.Get("Location"), "/")
	// The cookie then works for the page's own requests
	res2, body := x.browse(t, "/app?page=2")
	eq(t, res2.StatusCode, http.StatusOK)
	eq(t, body, "app on port 5173")
	// A token that does not resolve sets no cookie
	form := "token=" + newToken() + "&next=%2F"
	res = x.do(t, x.h2, http.MethodPost, at(continuePath), form,
		"Content-Type", "application/x-www-form-urlencoded", "Origin", "https://"+host)
	eq(t, res.StatusCode, http.StatusUnauthorized)
	eq(t, res.Header.Get("Set-Cookie"), "")
}

func TestContinueRefusesCrossOriginAndBadNext(t *testing.T) {
	x := newHarness(t)
	eq(t, x.postContinue(t, "https://evil.example", "/").StatusCode, 403)
	eq(t, x.postContinue(t, "https://"+secondID+"."+domain, "/").StatusCode, 403)
	eq(t, x.postContinue(t, "", "/").StatusCode, 403)
	eq(t, x.postContinue(t, "https://"+host, "/", "Sec-Fetch-Site", "same-site").StatusCode,
		403)
	for _, next := range []string{`/\evil.example`, "//evil.example", "/a\r\nb",
		"https://evil.example/", "evil", "/a\x00b", "/%0a\x7f"} {
		eq(t, x.postContinue(t, "https://"+host, next).StatusCode, 400)
	}
	eq(t, x.router.count(&x.router.resolves), 0)
}

func TestCleanNext(t *testing.T) {
	tok := newToken()
	for in, want := range map[string]string{
		"/":                             "/",
		"/a/b?c=d":                      "/a/b?c=d",
		"/a%20b?q=a%20b":                "/a%20b?q=a%20b",
		"/x?bugnet_token=" + tok + "&a": "/x?a",
		"/x?bugnet_token=" + tok:        "/x",
		"/%2F%2Fevil.example":           "/%2F%2Fevil.example",
	} {
		got, ok := cleanNext(in)
		eq(t, ok, true)
		eq(t, got, want)
	}
}

func TestInterstitialShowsTheStoredSource(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.source = "github.com/acme/app@1a2b3c4" })
	res, body := x.get(t, x.link, "Sec-Fetch-Dest", "document")
	eq(t, isInterstitial(t, res, body), true)
	if !strings.Contains(body, "Source: <code>github.com/acme/app@1a2b3c4</code>") {
		t.Fatalf("no source line in\n%s", body)
	}
	if !strings.Contains(body, "Do not enter passwords, keys or payment details unless you "+
		"started this sandbox yourself.") {
		t.Fatalf("no warning in\n%s", body)
	}
	// The label is data, never markup
	y := newHarness(t)
	y.router.set(func(f *fakeRouter) { f.source = `<img src=x onerror=alert(1)>` })
	_, body = y.get(t, y.link, "Sec-Fetch-Dest", "document")
	eq(t, strings.Contains(body, "<img"), false)
	eq(t, strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;"), true)
}

/* Strangers */

func TestPreviewTokenFailuresPerIP(t *testing.T) {
	x := newHarness(t)
	codes := map[int]int{}
	for range 21 {
		res, _ := x.get(t, at("/"), headerName, newToken())
		codes[res.StatusCode]++
	}
	eq(t, codes, map[int]int{401: 20, 429: 1})
	res, _ := x.get(t, at("/"), headerName, newToken())
	eq(t, res.StatusCode, http.StatusTooManyRequests)
	eq(t, res.Header.Get("Retry-After"), "600")
	// A good token from the marked address still works, a second after the address last asked
	time.Sleep(strangers.AskEvery)
	res, body := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, body, "app on port 5173")
}

func TestUnknownPreviewAndRepeatedTokens(t *testing.T) {
	x := newHarness(t)
	bad := newToken()
	for range 3 {
		res, _ := x.get(t, at("/"), headerName, bad)
		eq(t, res.StatusCode, http.StatusUnauthorized)
	}
	other := "https://" + secondID + "." + domain + "/"
	for range 3 {
		res, _ := x.get(t, other, headerName, newToken())
		eq(t, res.StatusCode, http.StatusNotFound)
	}
	// One router call each, the rest from the 10 s unknown cache
	eq(t, x.router.count(&x.router.resolves), 2)
	res, _ := x.get(t, at("/"), headerName, "bnp_short")
	eq(t, res.StatusCode, http.StatusUnauthorized)
	eq(t, x.router.count(&x.router.resolves), 2)
}

func TestMarkedAddressAsksOnceASecond(t *testing.T) {
	g := strangers.NewGuard(1, strangers.Mark, strangers.Unknown)
	x := newHarness(t, func(d *Deps) { d.Guard = g })
	for range 3 {
		x.get(t, at("/"), headerName, newToken())
	}
	// The address is marked and just asked, so the next unknown pair waits a second
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusTooManyRequests)
	eq(t, res.Header.Get("Retry-After"), "1")
	time.Sleep(strangers.AskEvery)
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	// A cached route never waits
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
}

/* The cross-preview rule */

func TestCrossPreviewRule(t *testing.T) {
	x := newHarness(t)
	cookie := cookieName + "=" + x.pv.token
	other := "https://" + secondID + "." + domain
	status := func(method string, kv ...string) int {
		res := x.do(t, x.h2, method, at("/api"), "", append([]string{"Cookie", cookie}, kv...)...)
		_ = res.Body.Close()
		return res.StatusCode
	}
	// Page A posting to B, fetching B with credentials
	eq(t, status("POST", "Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "cors",
		"Origin", other), 401)
	eq(t, status("GET", "Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "cors",
		"Sec-Fetch-Dest", "empty", "Origin", other), 401)
	eq(t, status("GET", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors",
		"Sec-Fetch-Dest", "image"), 401)
	// B's own navigation, module loads and fetches
	eq(t, status("GET", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "cors",
		"Sec-Fetch-Dest", "script"), 200)
	eq(t, status("POST", "Sec-Fetch-Site", "same-origin", "Origin", "https://"+host), 200)
	eq(t, status("GET", "Sec-Fetch-Site", "none", "Sec-Fetch-Mode", "navigate"), 200)
	eq(t, status("GET", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate",
		"Sec-Fetch-Dest", "document"), 200)
	eq(t, status("POST", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate",
		"Sec-Fetch-Dest", "document"), 401)
	// Without Sec-Fetch-*, a state change needs no Origin or this one
	eq(t, status("POST"), 200)
	eq(t, status("POST", "Origin", "https://"+host), 200)
	eq(t, status("POST", "Origin", other), 401)
	eq(t, status("GET", "Origin", other), 200)
	// The header and query forms are unaffected
	eq(t, status("POST", "Sec-Fetch-Site", "cross-site", headerName, x.pv.token), 200)

	// A WebSocket from page A to B, then B's own HMR socket
	code, _ := x.dialWS(t, host, "/ws", "Cookie", cookie, "Sec-Fetch-Site", "same-site",
		"Origin", other)
	eq(t, code, 401)
	code, _ = x.dialWS(t, host, "/ws", "Cookie", cookie, "Origin", other)
	eq(t, code, 401)
	code, _ = x.dialWS(t, host, "/ws", "Cookie", cookie, "Sec-Fetch-Site", "same-origin")
	eq(t, code, 401)
	code, _ = x.dialWS(t, host, "/ws", "Cookie", cookie, "Sec-Fetch-Site", "same-origin",
		"Origin", "https://"+host)
	eq(t, code, 101)
}

/* Request and response rewriting */

func TestIsolation(t *testing.T) {
	x := newHarness(t)
	x.gate.set(func(g *fakeGate) {
		g.app = func(_ int, w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Add("Set-Cookie", cookieName+"=stolen; Path=/; Secure; HttpOnly")
			h.Add("Set-Cookie", "__host-BNP=stolen2; Path=/")
			h.Add("Set-Cookie", "_port_auth=refreshed; Path=/")
			h.Add("Set-Cookie", "app=1; Domain=bugnet.sh; Path=/; Secure")
			h.Add("Set-Cookie", "plain=2; domain = .preview.bugnet.sh")
			h.Set("Server", "vite")
			_, _ = io.WriteString(w, "ok")
		}
	})
	res, _ := x.get(t, at("/?a=1"), "Cookie", "app=1; "+cookieName+"="+x.pv.token+
		"; _port_auth=forged", headerName, x.pv.token, gateKeyHeader, "forged",
		"Bugnet-Port", "22", "Bugnet-Anything", "x", "X-Forwarded-For", "6.6.6.6",
		"Authorization", "Bearer app-token", "Origin", "https://"+host)
	eq(t, res.StatusCode, http.StatusOK)
	got := x.gate.last().header
	eq(t, got.Values("Cookie"), []string{"app=1; _port_auth=route-cookie"})
	eq(t, got.Get(gateKeyHeader), gateKey)
	eq(t, got.Get(portHeader), "5173")
	eq(t, got.Get(hostHeader), host)
	eq(t, got.Get(clientIPHeader), "127.0.0.1")
	eq(t, got.Get("X-Provider-Token"), "provider-secret")
	eq(t, got.Get("Bugnet-Anything"), "")
	eq(t, got.Get(headerName), "")
	eq(t, got.Get("X-Forwarded-For"), "")
	eq(t, got.Get("Authorization"), "Bearer app-token")
	eq(t, got.Get("Origin"), "https://"+host)
	eq(t, x.gate.last().host, strings.TrimPrefix(x.gate.srv.URL, "https://"))
	eq(t, res.Header.Values("Set-Cookie"), []string{
		"app=1; Path=/; Secure", "plain=2",
	})
	eq(t, res.Header.Get("Server"), "vite")
	// A 600 KiB cookie jar still reaches the sandbox, ruling E1
	big := "jar=" + strings.Repeat("a", 600<<10)
	res, _ = x.get(t, at("/"), "Cookie", big, headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, len(x.gate.last().header.Get("Cookie")), len(big+"; _port_auth=route-cookie"))
}

func TestResponseRewriting(t *testing.T) {
	x := newHarness(t)
	var loc string
	x.gate.set(func(g *fakeGate) {
		g.app = func(_ int, w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			h.Set("Location", loc)
			h.Set("Cache-Control", "max-age=60")
			for _, name := range []string{"Alt-Svc", "NEL", "Report-To", "Reporting-Endpoints",
				"Strict-Transport-Security", "Via", "Cf-Ray", "X-Koyeb-Route", "Bugnet-Leak"} {
				h.Set(name, "x")
			}
			h.Set("X-App", "kept")
			w.WriteHeader(http.StatusFound)
		}
	})
	rewrittenLocation := func(t *testing.T, l string) string {
		t.Helper()
		loc = l
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		eq(t, res.StatusCode, http.StatusFound)
		return res.Header.Get("Location")
	}
	eq(t, rewrittenLocation(t, "http://localhost:3000/login?next=/x"),
		"https://"+host+"/login?next=/x")
	eq(t, rewrittenLocation(t, "https://example.com/x"), "https://example.com/x")
	eq(t, rewrittenLocation(t, "/relative"), "/relative")
	eq(t, rewrittenLocation(t, "http://127.0.0.1:5173/a?b=c#d"), "https://"+host+"/a?b=c#d")
	eq(t, rewrittenLocation(t, "http://[::1]:8000/"), "https://"+host+"/")
	eq(t, rewrittenLocation(t, "http://0.0.0.0/x"), "https://"+host+"/x")
	eq(t, rewrittenLocation(t, "HTTP://LOCALHOST:3000"), "https://"+host)
	eq(t, rewrittenLocation(t, "//localhost:3000/x"), "https://"+host+"/x")
	eq(t, rewrittenLocation(t, x.gate.srv.URL+"/p"), "https://"+host+"/p")
	eq(t, rewrittenLocation(t, "http://user@localhost/x"), "http://user@localhost/x")
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	h := res.Header
	eq(t, h.Get("Cache-Control"), "max-age=60")
	eq(t, h.Get("X-App"), "kept")
	for _, name := range []string{"Alt-Svc", "NEL", "Report-To", "Reporting-Endpoints",
		"Strict-Transport-Security", "Via", "Cf-Ray", "X-Koyeb-Route", "Bugnet-Leak",
		markHeader, cacheHeader, serverHeader} {
		eq(t, h.Get(name), "")
	}
	// The gate's - means the app sent none
	eq(t, h.Values("Server"), []string(nil))
	eq(t, h.Get("Access-Control-Allow-Origin"), "")
	eq(t, h.Get("X-Frame-Options"), "")
}

func TestKoyebExecutorPathsAreRefused(t *testing.T) { // controller ruling 15K
	x := newHarness(t)
	for _, p := range []string{"/koyeb-sandbox", "/koyeb-sandbox/", "/koyeb-sandbox/exec",
		"//koyeb-sandbox/x", "/./koyeb-sandbox", "/a/../koyeb-sandbox/x", "/KOYEB-SANDBOX",
		"/koyeb%2Dsandbox/x", "/koyeb-sandbox?x=1"} {
		res, body := x.get(t, at(p), headerName, x.pv.token)
		if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "No such preview") {
			t.Fatalf("%s: %d %s", p, res.StatusCode, body)
		}
	}
	eq(t, x.gate.received(), 0)
	res, _ := x.get(t, at("/koyeb-sandboxes"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	res, _ = x.get(t, at("/__bugnet/health"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusNotFound)
	eq(t, x.gate.received(), 1)
}

/* Provider answers and repairs */

func TestProviderAnswerShowsOurPageAndRepairs(t *testing.T) {
	x := newHarness(t)
	x.gate.set(func(g *fakeGate) { g.provider = true })
	res, body := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusBadGateway)
	if !strings.Contains(body, "preview service stopped") ||
		strings.Contains(body, "fake provider") {
		t.Fatalf("the provider's answer reached the visitor: %s", body)
	}
	within(t, "a repair", func() bool { return x.router.count(&x.router.repairs) == 1 })
	// The repair drops the route, so the next request resolves again
	within(t, "the route dropped", func() bool { return x.handler().cache.size() == 0 })
	before := x.router.count(&x.router.resolves)
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusBadGateway)
	eq(t, x.router.count(&x.router.resolves), before+1)
	// One repair a minute, however many requests fail
	for range 3 {
		x.get(t, at("/"), headerName, x.pv.token)
	}
	time.Sleep(100 * time.Millisecond)
	eq(t, x.router.count(&x.router.repairs), 1)
	x.gate.set(func(g *fakeGate) { g.provider = false })
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
}

func TestRefusedConnectionRepairs(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.upstream.BaseUrl = "https://127.0.0.1:1" })
	res, body := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusBadGateway)
	eq(t, strings.Contains(body, "preview service stopped"), true)
	within(t, "a repair", func() bool { return x.router.count(&x.router.repairs) == 1 })
}

func TestRouterAnswersMapToPages(t *testing.T) {
	x := newHarness(t)
	for _, tc := range []struct {
		err    error
		status int
		text   string
	}{
		{refusal(connect.CodeFailedPrecondition, "NOT_READY"), 410, "This sandbox has ended"},
		{refusal(connect.CodeFailedPrecondition, "PREVIEW_REVOKED"), 410, "turned off"},
		{refusal(connect.CodeResourceExhausted, "BUDGET_SPENT"), 429, "traffic limit"},
		{refusal(connect.CodeUnavailable, "GATE_UNAVAILABLE"), 502, "preview service stopped"},
		{connect.NewError(connect.CodeUnavailable, io.EOF), 503, "Try again shortly"},
	} {
		x.router.set(func(f *fakeRouter) { f.resolveErr = tc.err })
		res, body := x.get(t, at("/"), headerName, x.pv.token)
		if res.StatusCode != tc.status || !strings.Contains(body, tc.text) {
			t.Fatalf("%v: %d %s", tc.err, res.StatusCode, body)
		}
	}
	within(t, "a repair for GATE_UNAVAILABLE", func() bool {
		return x.router.count(&x.router.repairs) == 1
	})
}

func TestCachedRouteOutlivesARouterOutage(t *testing.T) {
	x := newHarness(t, func(d *Deps) { d.RouteTTL = 50 * time.Millisecond })
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	x.router.set(func(f *fakeRouter) {
		f.resolveErr = connect.NewError(connect.CodeUnavailable, io.EOF)
	})
	time.Sleep(100 * time.Millisecond)
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusOK)
	// A refusal is an answer, so the route goes
	x.router.set(func(f *fakeRouter) {
		f.resolveErr = refusal(connect.CodeFailedPrecondition, "PREVIEW_REVOKED")
	})
	time.Sleep(staleRetry + 50*time.Millisecond)
	res, _ = x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusGone)
}

/* WebSockets */

func TestWebSocketOverHTTP1WhilePageUsesH2(t *testing.T) {
	x := newHarness(t)
	res, body := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.ProtoMajor, 2)
	eq(t, body, "app on port 5173")
	w := x.openWS(t, x.pv, host)
	for i := range 5 {
		if err := w.echo("message " + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	// WebSocket bytes count toward the placement
	within(t, "the socket's bytes reported", func() bool {
		x.router.mu.Lock()
		defer x.router.mu.Unlock()
		return x.router.used >= 2*(5+5*9)
	})
}

func TestRevokedLeaseClosesWebSocketWithin1s(t *testing.T) {
	for name, ev := range map[string]func(x *harness) *routerv1.EdgeEvent{
		"revoked": func(*harness) *routerv1.EdgeEvent {
			return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PreviewRevoked{
				PreviewRevoked: &routerv1.PreviewRevoked{PlacementId: "p1", PreviewId: firstID},
			}}
		},
		"ended": func(*harness) *routerv1.EdgeEvent {
			return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
				PlacementEnded: &routerv1.PlacementEnded{
					PlacementId: "p1", Reason: routerv1.EndReason_END_REASON_STOPPED,
				},
			}}
		},
		"budget": func(*harness) *routerv1.EdgeEvent {
			return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
				BudgetSpent: &routerv1.BudgetSpent{
					PlacementId: "p1", Kind: routerv1.BudgetKind_BUDGET_KIND_EDGE,
				},
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := newHarness(t)
			w := x.openWS(t, x.pv, host)
			x.router.events <- ev(x)
			eq(t, w.closedWithin(time.Second), true)
		})
	}
	t.Run("deadline", func(t *testing.T) {
		x := newHarness(t)
		x.router.set(func(f *fakeRouter) { f.deadline = time.Now().Add(500 * time.Millisecond) })
		w := x.openWS(t, x.pv, host)
		eq(t, w.closedWithin(1500*time.Millisecond), true)
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		eq(t, res.StatusCode, http.StatusGone)
	})
}

func TestExtensionKeepsWebSocketPastOldDeadline(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.deadline = time.Now().Add(time.Second) })
	w := x.openWS(t, x.pv, host)
	later := time.Now().Add(time.Hour)
	x.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_DeadlineMoved{
		DeadlineMoved: &routerv1.DeadlineMoved{
			PlacementId: "p1", Deadline: timestamppb.New(later), EdgeBytesRemaining: gib,
		},
	}}
	x.router.set(func(f *fakeRouter) { f.deadline = later })
	eq(t, w.closedWithin(1500*time.Millisecond), false)
	if err := w.echo("still here"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeOnePreviewLeavesTheOther(t *testing.T) {
	x := newHarness(t)
	x.gate.listen(3000)
	other := x.router.add(secondID, 3000)
	otherHost := secondID + "." + domain
	a := x.openWS(t, x.pv, host)
	b := x.openWS(t, other, otherHost)
	x.router.set(func(*fakeRouter) { x.pv.revoked = true })
	x.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PreviewRevoked{
		PreviewRevoked: &routerv1.PreviewRevoked{PlacementId: "p1", PreviewId: firstID},
	}}
	eq(t, a.closedWithin(time.Second), true)
	if err := b.echo("other port"); err != nil {
		t.Fatal(err)
	}
	res, body := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusGone)
	eq(t, strings.Contains(body, "turned off"), true)
	res, body = x.get(t, "https://"+otherHost+"/", headerName, other.token)
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, body, "app on port 3000")
}

func TestLostRevocationStopsWithin60s(t *testing.T) {
	x := newHarness(t)
	w := x.openWS(t, x.pv, host)
	// The router revokes, but its PreviewRevoked never reaches the stream
	x.router.set(func(*fakeRouter) { x.pv.revoked = true })
	before := x.router.count(&x.router.checks)
	// The 60 s lease check, run now
	x.tr.Leases.CheckNow()
	within(t, "the lease check", func() bool { return x.router.count(&x.router.checks) > before })
	eq(t, w.closedWithin(time.Second), true)
	res, _ := x.get(t, at("/"), headerName, x.pv.token)
	eq(t, res.StatusCode, http.StatusGone)
}

/* Limits */

func TestLimits(t *testing.T) {
	t.Run("300 modules load", func(t *testing.T) {
		x := newHarness(t)
		start := time.Now()
		codes := parallel(300, func(i int) int {
			res, _ := x.get(t, at("/src/m"+strconv.Itoa(i)+".js"), "Cookie",
				cookieName+"="+x.pv.token, "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Dest",
				"script")
			return res.StatusCode
		})
		eq(t, countOf(codes, 200), 300)
		// 200 at once, the rest at 100 a second
		if took := time.Since(start); took < 900*time.Millisecond {
			t.Fatalf("300 requests took %s, past the request rate", took)
		}
	})
	t.Run("257th waiting", func(t *testing.T) {
		x := newHarness(t)
		x.router.set(func(f *fakeRouter) {
			f.budget.QueuedRequests, f.budget.RequestsPerSecond = 1, 0
		})
		hang := x.do(t, x.h1, http.MethodGet, at("/hang"), "", headerName, x.pv.token)
		defer func() { _ = hang.Body.Close() }()
		eq(t, hang.StatusCode, http.StatusOK)
		done := make(chan []int)
		go func() {
			done <- parallel(256, func(int) int {
				res := x.do(t, x.h1, http.MethodGet, at("/"), "", headerName, x.pv.token)
				_ = res.Body.Close()
				return res.StatusCode
			})
		}()
		within(t, "256 waiting requests", func() bool {
			g := x.handler().limits.gateFor(t)
			return g != nil && g.waiting.Load() == 256
		})
		start := time.Now()
		res, body := x.get(t, at("/"), headerName, x.pv.token)
		eq(t, res.StatusCode, http.StatusServiceUnavailable)
		eq(t, res.Header.Get("Retry-After"), "2")
		eq(t, strings.Contains(body, "busy"), true)
		if time.Since(start) > time.Second {
			t.Fatal("the 257th waiting request was not refused at once")
		}
		_ = hang.Body.Close()
		eq(t, countOf(<-done, 200), 256)
	})
	t.Run("queue wait", func(t *testing.T) {
		x := newHarness(t, func(d *Deps) { d.QueueWait = 200 * time.Millisecond })
		x.router.set(func(f *fakeRouter) { f.budget.QueuedRequests = 1 })
		hang := x.do(t, x.h1, http.MethodGet, at("/hang"), "", headerName, x.pv.token)
		defer func() { _ = hang.Body.Close() }()
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		eq(t, res.StatusCode, http.StatusServiceUnavailable)
		eq(t, res.Header.Get("Retry-After"), "2")
	})
	t.Run("100 a second", func(t *testing.T) {
		x := newHarness(t, func(d *Deps) { d.QueueWait = 200 * time.Millisecond })
		x.router.set(func(f *fakeRouter) { f.budget.RequestsBurst = 10 })
		codes := parallel(60, func(int) int {
			res, _ := x.get(t, at("/"), headerName, x.pv.token)
			return res.StatusCode
		})
		// 10 at once and about 20 more within the 200 ms wait
		if n := countOf(codes, 200); n < 10 || n > 35 {
			t.Fatalf("%d of 60 passed a rate of 100 a second with a burst of 10", n)
		}
		eq(t, countOf(codes, 200)+countOf(codes, 503), 60)
	})
	t.Run("33rd WebSocket", func(t *testing.T) {
		x := newHarness(t)
		for range 32 {
			x.openWS(t, x.pv, host)
		}
		code, _ := x.dialWS(t, host, "/ws", headerName, x.pv.token)
		eq(t, code, http.StatusTooManyRequests)
	})
	t.Run("pace", func(t *testing.T) {
		x := newHarness(t)
		x.router.set(func(f *fakeRouter) { f.budget.BytesPerSecond = 256 << 10 })
		start := time.Now()
		res, body := x.get(t, at("/big?n="+strconv.Itoa(512<<10)), headerName, x.pv.token)
		eq(t, res.StatusCode, http.StatusOK)
		eq(t, len(body), 512<<10)
		if took := time.Since(start); took < 1500*time.Millisecond {
			t.Fatalf("512 KiB at 256 KiB/s took %s", took)
		}
	})
}

// handler is the preview handler behind the harness's server
func (x *harness) handler() *handler {
	return x.edge.Config.Handler.(*handler)
}

// gateFor is the only placement gate, nil before the first request made it
func (l *limits) gateFor(t *testing.T) *gate {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.gates {
		return g
	}
	return nil
}

func TestBoatEdgeWideLimiter(t *testing.T) {
	lim := boatLimiter(5000)
	eq(t, float64(lim.Limit()), 5000.0/60)
	eq(t, lim.Burst(), 500)
	eq(t, newLimits(time.Second, 1, 0).boat == nil, true)

	boat := func(perMinute int) *harness {
		x := newHarness(t, func(d *Deps) {
			d.BoatPerMinute, d.QueueWait = perMinute, 200*time.Millisecond
			d.BoatSuffix = "127.0.0.1"
		})
		return x
	}
	x := boat(60)
	codes := parallel(10, func(int) int {
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		return res.StatusCode
	})
	eq(t, countOf(codes, 200), 6)
	eq(t, countOf(codes, 503), 4)
	// 0 turns it off
	x = boat(0)
	codes = parallel(10, func(int) int {
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		return res.StatusCode
	})
	eq(t, countOf(codes, 200), 10)
	// A route outside Boat never waits on it
	x = newHarness(t, func(d *Deps) {
		d.BoatPerMinute, d.QueueWait = 60, 200*time.Millisecond
	})
	codes = parallel(10, func(int) int {
		res, _ := x.get(t, at("/"), headerName, x.pv.token)
		return res.StatusCode
	})
	eq(t, countOf(codes, 200), 10)
}

/* Budget */

func TestBudgetSpentThenExtendSameLink(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.budget.BytesRemaining = 64 << 10 })
	res, _ := x.browse(t, "/big?n="+strconv.Itoa(128<<10))
	eq(t, res.StatusCode, http.StatusOK)
	within(t, "the traffic limit page", func() bool {
		res, body := x.browse(t, "/")
		return res.StatusCode == http.StatusTooManyRequests &&
			strings.Contains(body, "traffic limit")
	})
	// The extension adds budget, and the same link works again
	x.router.set(func(f *fakeRouter) { f.budget.BytesRemaining = gib })
	res, body := x.browse(t, "/")
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, body, "app on port 5173")
}

func TestUsageCountsBothWays(t *testing.T) {
	x := newHarness(t)
	payload := strings.Repeat("u", 10000)
	res := x.do(t, x.h2, http.MethodPost, at("/echo"), payload, headerName, x.pv.token)
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	eq(t, string(b), payload)
	within(t, "both ways reported", func() bool {
		x.router.mu.Lock()
		defer x.router.mu.Unlock()
		return x.router.used == 20000
	})
}
