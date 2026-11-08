package sessionsroute

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

// checkBundleHeaders fails unless h carries every line of headers.txt exactly
func checkBundleHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(testHeaders), "\n") {
		name, value, _ := strings.Cut(line, ": ")
		eq(t, h.Values(name), []string{value})
	}
	eq(t, h.Values("Set-Cookie"), []string(nil))
}

func gunzip(t *testing.T, s string) string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRecordBodyIsConcatenated(t *testing.T) {
	x := newHarness(t)
	r := x.post(t, "POST", id, key)
	eq(t, r.StatusCode, 200)
	eq(t, r.body, `{"state":"ended","record":`+string(fakeRecord)+`}`)
	eq(t, r.Header.Get("Content-Type"), "application/json")
	checkBundleHeaders(t, r.Header)

	running, expired := newID(), newID()
	x.router.set(func(f *fakeRouter) {
		f.records[running] = &record{key: key, res: &routerv1.GetSessionRecordResponse{
			State: "running", LiveJson: fakeLive}}
		f.records[expired] = &record{key: key, res: &routerv1.GetSessionRecordResponse{
			State: "expired", RecordJson: fakeRecord}}
	})
	eq(t, x.post(t, "POST", running, key).body, `{"state":"running","snapshot":`+
		string(fakeLive)+`}`)
	eq(t, x.post(t, "POST", expired, key).body, `{"state":"expired"}`)

	// The record goes gzipped to a client that accepts it
	h := x.page()
	h.Set("Accept-Encoding", "br, gzip;q=0.5")
	r = x.do(t, "POST", "/v1/s/"+id, `{"k":"`+key+`"}`, h)
	eq(t, r.Header.Get("Content-Encoding"), "gzip")
	eq(t, gunzip(t, r.body), `{"state":"ended","record":`+string(fakeRecord)+`}`)
	h.Set("Accept-Encoding", "gzip;q=0")
	eq(t, x.do(t, "POST", "/v1/s/"+id, `{"k":"`+key+`"}`, h).Header.Get("Content-Encoding"),
		"")
}

func TestRecordStatesThePageCannotShow(t *testing.T) {
	x := newHarness(t)
	for _, res := range []*routerv1.GetSessionRecordResponse{
		{State: "ended"}, {State: "running"}, {State: "held", RecordJson: fakeRecord},
	} {
		x.router.set(func(f *fakeRouter) { f.records[id].res = res })
		r := x.post(t, "POST", id, key)
		eq(t, r.StatusCode, 503)
		eq(t, r.body, "")
	}
}

func TestUnknownIDAndWrongKeyAlike(t *testing.T) {
	x := newHarness(t)
	unknown := x.post(t, "POST", newID(), key)
	wrong := x.post(t, "POST", id, newKey())
	for _, r := range []reply{unknown, wrong} {
		eq(t, r.StatusCode, 404)
		eq(t, r.body, "")
		eq(t, r.Header.Get("Content-Length"), "0")
		checkBundleHeaders(t, r.Header)
	}
	eq(t, unknown.Header.Get("Content-Type"), wrong.Header.Get("Content-Type"))

	// The same pair again within 10 s never reaches the router
	other := newKey()
	eq(t, x.post(t, "POST", id, other).StatusCode, 404)
	gets, _, _ := x.router.counts()
	for range 3 {
		eq(t, x.post(t, "POST", id, other).StatusCode, 404)
		eq(t, x.post(t, "DELETE", id, other).StatusCode, 404)
	}
	eq(t, fmt.Sprint(x.router.counts()), fmt.Sprint(gets, 0, 0))

	// A wrong key cached for the id never blocks its right key
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)

	// A key that cannot be one, or a body that is not the page's, never reaches the router
	gets, _, _ = x.router.counts()
	for _, body := range []string{`{"k":"bnk_short"}`, `{"k":"` + key[4:] + `"}`, `{}`, `[]`,
		`{"k":1}`, `not json`, ``} {
		eq(t, x.do(t, "POST", "/v1/s/"+id, body, x.page()).StatusCode, 404)
	}
	g, _, _ := x.router.counts()
	eq(t, g, gets)
}

func TestPageHeadersRequired(t *testing.T) {
	x := newHarness(t)
	body := `{"k":"` + key + `"}`
	for name, change := range map[string]func(http.Header){
		"no origin":          func(h http.Header) { h.Del("Origin") },
		"another origin":     func(h http.Header) { h.Set("Origin", "https://x.bugnet.sh") },
		"two origins":        func(h http.Header) { h.Add("Origin", x.origin) },
		"null origin":        func(h http.Header) { h.Set("Origin", "null") },
		"no fetch site":      func(h http.Header) { h.Del("Sec-Fetch-Site") },
		"same-site":          func(h http.Header) { h.Set("Sec-Fetch-Site", "same-site") },
		"cross-site":         func(h http.Header) { h.Set("Sec-Fetch-Site", "cross-site") },
		"fetch site none":    func(h http.Header) { h.Set("Sec-Fetch-Site", "none") },
		"no content type":    func(h http.Header) { h.Del("Content-Type") },
		"form content type":  func(h http.Header) { h.Set("Content-Type", "text/plain") },
		"json-like type":     func(h http.Header) { h.Set("Content-Type", "application/jsonx") },
		"bad content type":   func(h http.Header) { h.Set("Content-Type", "application/json;;") },
		"origin with a path": func(h http.Header) { h.Set("Origin", x.origin+"/") },
	} {
		for _, path := range []string{"/v1/s/" + id, "/v1/s/" + id + "/jobs/1/live", "/v1/x"} {
			h := x.page()
			change(h)
			r := x.do(t, "POST", path, body, h)
			if r.StatusCode != 403 || r.body != "" {
				t.Fatalf("%s %s: got %d %q", name, path, r.StatusCode, r.body)
			}
		}
	}
	gets, deletes, watches := x.router.counts()
	eq(t, gets+deletes+watches, 0)

	// A charset parameter is the same type, and the cookie jar is never read
	h := x.page()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cookie", "k="+newKey()+"; __Host-bnp=x")
	eq(t, x.do(t, "POST", "/v1/s/"+id, body, h).StatusCode, 200)
}

func TestBodyOver1KiB(t *testing.T) {
	x := newHarness(t)
	padded := `{"k":"` + key + `"}`
	padded += strings.Repeat(" ", maxBody-len(padded))
	eq(t, len(padded), 1024)
	eq(t, x.do(t, "POST", "/v1/s/"+id, padded, x.page()).StatusCode, 200)
	eq(t, x.do(t, "POST", "/v1/s/"+id, padded+" ", x.page()).StatusCode, 413)
	eq(t, x.do(t, "DELETE", "/v1/s/"+id, padded+" ", x.page()).StatusCode, 413)

	// A chunked body is cut at the cap too
	req, _ := http.NewRequest("POST", x.origin+"/v1/s/"+id,
		io.MultiReader(strings.NewReader(padded), strings.NewReader("  ")))
	req.Header = x.page()
	req.ContentLength = -1
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	eq(t, res.StatusCode, 413)
	gets, deletes, _ := x.router.counts()
	eq(t, fmt.Sprint(gets, deletes), "1 0")
}

func TestOtherPageCallsAndMethods(t *testing.T) {
	x := newHarness(t)
	body := `{"k":"` + key + `"}`
	for _, c := range []struct{ method, path string }{
		{"PUT", "/v1/s/" + id}, {"PATCH", "/v1/s/" + id},
		{"DELETE", "/v1/s/" + id + "/jobs/1/live"},
		{"POST", "/v1/s/" + id + "/"}, {"POST", "/v1/s/" + strings.ToUpper(id)},
		{"POST", "/v1/s/" + id[:15]}, {"POST", "/v1/s/" + id + "/jobs/0/live"},
		{"POST", "/v1/s/" + id + "/jobs/01/live"}, {"POST", "/v1/s/" + id + "/jobs/x/live"},
		{"POST", "/v1/s/" + id + "/jobs/4294967296/live"}, {"POST", "/v1/s/" + id + "/jobs/1"},
		{"POST", "/v1/links/" + id}, {"POST", "/v1/s/%6b" + id[1:]},
	} {
		r := x.do(t, c.method, c.path, body, x.page())
		if r.StatusCode != 404 || r.body != "" {
			t.Fatalf("%s %s: got %d", c.method, c.path, r.StatusCode)
		}
	}
	gets, deletes, watches := x.router.counts()
	eq(t, gets+deletes+watches, 0)
}

func TestRouterRefusals(t *testing.T) {
	x := newHarness(t)
	for _, c := range []struct {
		err    error
		status int
		retry  string
	}{
		{connect.NewError(connect.CodeUnavailable, nil), 503, "2"},
		{refusal(connect.CodeUnavailable, "FEATURE_UNAVAILABLE"), 503, "2"},
		{connect.NewError(connect.CodeInternal, nil), 503, "2"},
		{refusal(connect.CodeResourceExhausted, "RATE_LIMITED"), 429, "1"},
	} {
		x.router.set(func(f *fakeRouter) { f.err = c.err })
		r := x.post(t, "POST", id, key)
		eq(t, r.StatusCode, c.status)
		eq(t, r.Header.Get("Retry-After"), c.retry)
		eq(t, r.body, "")
	}
	// None of them counts as a wrong key, so the right key works at once
	x.router.set(func(f *fakeRouter) { f.err = nil })
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)
}

func TestDeleteAnswers204AndForgetsTheKey(t *testing.T) {
	x := newHarness(t)
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)
	r := x.post(t, "DELETE", id, key)
	eq(t, r.StatusCode, 204)
	eq(t, r.body, "")
	checkBundleHeaders(t, r.Header)
	eq(t, x.post(t, "POST", id, key).StatusCode, 404)
	eq(t, x.post(t, "DELETE", id, key).StatusCode, 404)
}

func TestGetNeverCallsTheRouter(t *testing.T) {
	x := newHarness(t)
	for _, rid := range []string{id, newID(), newID(), "aaaaaaaaaaaaaaaa"} {
		r := x.do(t, "GET", "/s/"+rid, "", nil)
		eq(t, r.StatusCode, 200)
		if !strings.HasPrefix(r.body, indexHTML) {
			t.Fatalf("got %q", r.body)
		}
		eq(t, r.Header.Get("Content-Type"), "text/html; charset=utf-8")
		eq(t, x.do(t, "GET", "/s/"+rid+"?utm=x", "", nil).StatusCode, 200)
		eq(t, x.do(t, "HEAD", "/s/"+rid, "", nil).StatusCode, 200)
	}
	for _, path := range []string{"/", "/s/", "/s/" + id + "/", "/s/" + id[:15],
		"/s/" + strings.ToUpper(id), "/s/" + id + "1", "/index.html", "/headers.txt",
		"/assets/", "/assets/notes.txt", "/assets/Bad_Name.js", "/assets/../headers.txt",
		"/assets/page-ABC.js/x", "/v1", "/favicon.ico"} {
		r := x.do(t, "GET", path, "", nil)
		if r.StatusCode != 404 || r.body != "" {
			t.Fatalf("%s: got %d %q", path, r.StatusCode, r.body)
		}
		checkBundleHeaders(t, r.Header)
	}
	eq(t, x.do(t, "POST", "/s/"+id, "", nil).StatusCode, 404)
	eq(t, x.do(t, "GET", "/v1/s/"+id, "", x.page()).StatusCode, 404)
	gets, deletes, watches := x.router.counts()
	eq(t, gets+deletes+watches, 0)
}

func TestBundleHeadersAndFonts(t *testing.T) {
	x := newHarness(t)
	for path, typ := range map[string]string{
		"/s/" + id:                      "text/html; charset=utf-8",
		"/assets/page-ABC.js":           "text/javascript; charset=utf-8",
		"/assets/page-DEF.css":          "text/css; charset=utf-8",
		"/assets/icon-QRS.svg":          "image/svg+xml",
		"/assets/manrope-400-XYZ.woff2": "font/woff2",
	} {
		r := x.do(t, "GET", path, "", nil)
		eq(t, r.StatusCode, 200)
		eq(t, r.Header.Get("Content-Type"), typ)
		checkBundleHeaders(t, r.Header)
	}
	r := x.do(t, "GET", "/assets/manrope-400-XYZ.woff2", "", nil)
	eq(t, r.body, "wOF2 font bytes")

	// Text goes gzipped to a client that accepts it, the fonts never
	h := http.Header{"Accept-Encoding": {"gzip, deflate"}}
	r = x.do(t, "GET", "/assets/page-ABC.js", "", h)
	eq(t, r.Header.Get("Content-Encoding"), "gzip")
	eq(t, r.Header.Get("Vary"), "Accept-Encoding")
	eq(t, gunzip(t, r.body), strings.Repeat("console.log(1);", 50))
	r = x.do(t, "GET", "/assets/manrope-400-XYZ.woff2", "", h)
	eq(t, r.Header.Get("Content-Encoding"), "")
	eq(t, r.body, "wOF2 font bytes")
	r = x.do(t, "GET", "/s/"+id, "", http.Header{"Accept-Encoding": {"identity"}})
	eq(t, r.Header.Get("Content-Encoding"), "")
}

func TestLoadBundleRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		headers string
		remove  string
		want    string
	}{
		"no csp":      {headers: "Cache-Control: no-store\n", want: "no Content-Security-Policy"},
		"cookie":      {headers: testHeaders + "Set-Cookie: a=b\n", want: "Set-Cookie"},
		"type":        {headers: testHeaders + "content-type: text/html\n", want: "content-type"},
		"not header":  {headers: testHeaders + "nonsense\n", want: "is not a header"},
		"bad name":    {headers: testHeaders + "Bad Name: x\n", want: "is not a header"},
		"no index":    {headers: testHeaders, remove: "index.html", want: "index.html"},
		"no headers":  {headers: testHeaders, remove: "headers.txt", want: "headers.txt"},
		"no assets":   {headers: testHeaders, remove: "assets", want: "assets"},
		"empty value": {headers: testHeaders + "X-Bad: \x01\n", want: "is not a header"},
	} {
		dir := writeBundle(t, c.headers)
		if c.remove != "" {
			if err := os.RemoveAll(filepath.Join(dir, c.remove)); err != nil {
				t.Fatal(err)
			}
		}
		_, err := LoadBundle(dir)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestRobots(t *testing.T) {
	x := newHarness(t)
	r := x.do(t, "GET", "/robots.txt", "", nil)
	eq(t, r.StatusCode, 200)
	eq(t, r.body, "User-agent: *\nDisallow: /\n")
	eq(t, r.Header.Get("Content-Type"), "text/plain; charset=utf-8")
	checkBundleHeaders(t, r.Header)
}

func TestRequestsPerIP(t *testing.T) {
	x := newHarness(t)
	for i := range 60 {
		r := x.direct("POST", "/v1/s/"+id, `{"k":"`+key+`"}`, "198.51.100.1:4000", x.page())
		eq(t, fmt.Sprint(i, r.StatusCode), fmt.Sprint(i, 200))
	}
	r := x.direct("POST", "/v1/s/"+id, `{"k":"`+key+`"}`, "198.51.100.1:4000", x.page())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "60")
	gets, _, _ := x.router.counts()
	eq(t, gets, 60)
	// The page itself is not counted, and another address is not limited
	eq(t, x.direct("GET", "/s/"+id, "", "198.51.100.1:4000", nil).StatusCode, 200)
	r = x.direct("POST", "/v1/s/"+id, `{"k":"`+key+`"}`, "198.51.100.2:4000", x.page())
	eq(t, r.StatusCode, 200)
}

func TestWrongKeysPerIP(t *testing.T) {
	x := newHarness(t)
	const ip = "198.51.100.1:4000"
	for i := range 20 {
		r := x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, ip, x.page())
		eq(t, fmt.Sprint(i, r.StatusCode), fmt.Sprint(i, 404))
	}
	r := x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, ip, x.page())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "600")

	// A marked address sends one call a second to the router, a right key among them
	gets, _, _ := x.router.counts()
	eq(t, x.direct("POST", "/v1/s/"+id, `{"k":"`+key+`"}`, ip, x.page()).StatusCode, 200)
	r = x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, ip, x.page())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "1")
	g, _, _ := x.router.counts()
	eq(t, g, gets+1)

	// A right key is never blocked once the router took it
	for range 5 {
		eq(t, x.direct("POST", "/v1/s/"+id, `{"k":"`+key+`"}`, ip, x.page()).StatusCode, 200)
	}
	// Another address is not marked
	r = x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, "198.51.100.2:4000", x.page())
	eq(t, r.StatusCode, 404)
}

func TestWrongKeysPerID(t *testing.T) {
	x := newHarness(t)
	ask := func(i int, k string) *http.Response {
		return x.direct("POST", "/v1/s/"+id, `{"k":"`+k+`"}`,
			fmt.Sprintf("198.51.100.%d:4000", i), x.page())
	}
	// Each wrong key from its own address, so only the id's count fills
	for i := range 21 {
		eq(t, fmt.Sprint(i, ask(i, newKey()).StatusCode), fmt.Sprint(i, 404))
	}
	gets, _, _ := x.router.counts()
	eq(t, gets, 21)

	// An address that sent the hot id a wrong key shares one call a second
	r := ask(5, newKey())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "1")
	eq(t, ask(6, key).StatusCode, 429)
	g, _, _ := x.router.counts()
	eq(t, g, gets)

	// An address with no wrong key for the id is never held by it (S2a)
	eq(t, ask(60, newKey()).StatusCode, 404)
	eq(t, ask(61, key).StatusCode, 200)

	// A second later one offender's call goes through, and the right key the router took is
	// never blocked even from an offender
	time.Sleep(1100 * time.Millisecond)
	eq(t, ask(8, newKey()).StatusCode, 404)
	eq(t, ask(9, newKey()).StatusCode, 429)
	for i := range 3 {
		eq(t, ask(i, key).StatusCode, 200)
	}
	// Another id is not limited
	r = x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, "198.51.100.1:4000", x.page())
	eq(t, r.StatusCode, 404)
}

func TestMalformedKeysMakeNoIDEntries(t *testing.T) {
	x := newHarness(t)
	for i, body := range []string{`{"k":"bnk_short"}`, `not json`, `{}`} {
		r := x.direct("POST", "/v1/s/"+newID(), body, fmt.Sprintf("198.51.100.%d:1", i),
			x.page())
		eq(t, r.StatusCode, 404)
	}
	ids, offenders := x.h.ids.size()
	eq(t, fmt.Sprint(ids, offenders), "0 0")
	eq(t, x.post(t, "POST", newID(), key).StatusCode, 404)
	ids, offenders = x.h.ids.size()
	eq(t, fmt.Sprint(ids, offenders), "1 1")
}

func TestIDTablesStayBounded(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	g := newIDGuard(20, clock.now)
	ip := netip.MustParseAddr("198.51.100.1")
	for i := range maxIDs + 10 {
		g.failed(fmt.Sprintf("id%d", i), ip)
	}
	ids, offenders := g.size()
	eq(t, ids <= maxIDs && offenders <= maxOffenders, true)
	// Past idHot the expired entries give way before any live one
	clock.advance(2 * idHot)
	g.failed("fresh", ip)
	ids, offenders = g.size()
	eq(t, fmt.Sprint(ids, offenders), "1 1")
}

func TestIPv6CountsBy64(t *testing.T) {
	x := newHarness(t)
	addrs := []string{"[2001:db8:1:2::1]:4000", "[2001:db8:1:2:ffff:ffff:ffff:ffff]:4000",
		"[2001:db8:1:2:abcd::9%eth0]:4000"}
	for i := range 20 {
		r := x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, addrs[i%3], x.page())
		eq(t, fmt.Sprint(i, r.StatusCode), fmt.Sprint(i, 404))
	}
	r := x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, "[2001:db8:1:2::77]:1", x.page())
	eq(t, r.StatusCode, 429)
	// The next /64 is another client, and so is an IPv4 address mapped or not
	r = x.direct("POST", "/v1/s/"+newID(), `{"k":"`+key+`"}`, "[2001:db8:1:3::1]:1", x.page())
	eq(t, r.StatusCode, 404)

	eq(t, clientKey(&http.Request{RemoteAddr: "[::ffff:198.51.100.7]:1"}).String(),
		"198.51.100.7")
	eq(t, clientKey(&http.Request{RemoteAddr: "198.51.100.7:1"}).String(), "198.51.100.7")
	eq(t, clientKey(&http.Request{RemoteAddr: "[2001:db8:a:b:c:d:e:f]:1"}).String(),
		"2001:db8:a:b::")
}

func TestFullCookieJarGets431Page(t *testing.T) {
	x := newHarness(t)
	full := http.Header{"Cookie": {"a=" + strings.Repeat("x", 1<<20)}}
	r := x.do(t, "GET", "/s/"+id, "", full)
	eq(t, r.StatusCode, 431)
	eq(t, r.body, cookieAdvice)
	eq(t, r.Header.Get("Content-Type"), "text/plain; charset=utf-8")
	checkBundleHeaders(t, r.Header)

	h := x.page()
	h.Set("Cookie", full.Get("Cookie"))
	eq(t, x.do(t, "POST", "/v1/s/"+id, `{"k":"`+key+`"}`, h).StatusCode, 431)

	// A large jar under the cap still gets the page and its record
	big := http.Header{"Cookie": {"a=" + strings.Repeat("x", 900<<10)}}
	eq(t, x.do(t, "GET", "/s/"+id, "", big).StatusCode, 200)
	h.Set("Cookie", big.Get("Cookie"))
	eq(t, x.do(t, "POST", "/v1/s/"+id, `{"k":"`+key+`"}`, h).StatusCode, 200)
}

func TestLogsNeverTheKey(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) {
		f.live[1] = script{frames: []*routerv1.WatchSessionJobResponse{text("1", "hi", false,
			false), end("exited")}}
	})
	wrong := newKey()
	x.post(t, "POST", id, key)
	x.post(t, "POST", id, wrong)
	x.do(t, "POST", "/v1/s/"+id+"/jobs/1/live", `{"k":"`+key+`","cursor":"c-secret"}`,
		x.page())
	x.do(t, "POST", "/v1/s/"+id, `{"k":"`+key+`","note":"body-secret"}`, x.page())
	x.post(t, "DELETE", id, key)
	logs := x.logs.String()
	for _, s := range []string{key, key[4:20], wrong, wrong[4:20], id, "#k=", "body-secret",
		"c-secret", "https://"} {
		if strings.Contains(logs, s) {
			t.Fatalf("%q reached the log\n%s", s, logs)
		}
	}
	for _, s := range []string{"route=record", "route=delete", "route=live", "status=404"} {
		if !strings.Contains(logs, s) {
			t.Fatalf("no %q in the log\n%s", s, logs)
		}
	}
	if bytes.Count([]byte(logs), []byte("session=")) < 5 {
		t.Fatalf("calls without their session hash\n%s", logs)
	}
}

// fakeClock is a clock a test moves by hand
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestHotIDNeverStarvesAFreshRightKey(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	x := newHarness(t, func(o *Options) {
		o.KeyFailuresPerMinute = 0
		o.now = clock.now
	})
	const stranger = "198.51.100.1:4000"
	ask := func(k, addr string) *http.Response {
		return x.direct("POST", "/v1/s/"+id, `{"k":"`+k+`"}`, addr, x.page())
	}
	// Twenty wrong keys from twenty addresses make the id hot at once
	for i := range 20 {
		eq(t, ask(newKey(), fmt.Sprintf("198.51.100.%d:4000", 100+i)).StatusCode, 404)
	}
	for sec := range 30 {
		clock.advance(time.Second)
		eq(t, fmt.Sprint(sec, ask(newKey(), stranger).StatusCode), fmt.Sprint(sec, 404))
		if sec == 0 {
			continue
		}
		// The stranger is held to its one call a second
		r := ask(newKey(), stranger)
		eq(t, r.StatusCode, 429)
		eq(t, r.Header.Get("Retry-After"), "1")
		if sec == 25 {
			// An address with no wrong key for the id gets through on its first try
			eq(t, ask(key, "203.0.113.9:4000").StatusCode, 200)
		}
	}
}

func TestSlowBodyTimesOut(t *testing.T) {
	x := newHarness(t, func(o *Options) { o.BodyTimeout = 200 * time.Millisecond })
	c, err := net.Dial("tcp", x.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprintf(c, "POST /v1/s/%s HTTP/1.1\r\nHost: x\r\nOrigin: %s\r\n"+
		"Sec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\n"+
		"Content-Length: 50\r\n\r\n{\"k\"", id, x.origin)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, res.StatusCode, 408)
	gets, _, _ := x.router.counts()
	eq(t, gets, 0)
}

func TestRouterCallsHaveADeadline(t *testing.T) {
	x := newHarness(t, func(o *Options) { o.CallTimeout = 100 * time.Millisecond })
	x.router.set(func(f *fakeRouter) { f.delay = 2 * time.Second })
	for _, method := range []string{"POST", "DELETE"} {
		start := time.Now()
		r := x.post(t, method, id, key)
		eq(t, r.StatusCode, 503)
		eq(t, r.Header.Get("Retry-After"), "2")
		if took := time.Since(start); took > time.Second {
			t.Fatalf("%s took %s", method, took)
		}
	}
	ids, offenders := x.h.ids.size()
	eq(t, fmt.Sprint(ids, offenders), "0 0")
}
