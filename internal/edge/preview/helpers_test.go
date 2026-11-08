package preview

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
	"github.com/bugnet-sh/bugnet-edges/internal/traffic"
)

const (
	domain     = "preview.bugnet.sh"
	firstID    = "k3fz2q7mak3fz2q7"
	secondID   = "abcdefghijklmnop"
	edgeToken  = "edge-token-0123456789abcdefghijklmnop"
	shortWait  = 5 * time.Second
	pollPeriod = 10 * time.Millisecond
)

var host = firstID + "." + domain

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// within polls cond until it holds or shortWait passes
func within(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(shortWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, shortWait)
		}
		time.Sleep(pollPeriod)
	}
}

// harness is the preview handler on a TLS test server, a fake router and a fake gate
type harness struct {
	router *fakeRouter
	gate   *fakeGate
	tr     *traffic.Traffic
	d      Deps
	edge   *httptest.Server
	h2     *http.Client
	h1     *http.Client
	pv     *fakePreview
	link   string
}

func newHarness(t *testing.T, change ...func(*Deps)) *harness {
	t.Helper()
	f := newFakeRouter()
	g := newFakeGate(t)
	g.listen(5173)
	f.upstream = &routerv1.GateUpstream{
		BaseUrl: g.srv.URL,
		Headers: []*routerv1.HeaderValue{
			{Name: "X-Provider-Token", Value: "provider-secret"},
			{Name: gateKeyHeader, Value: gateKey},
		},
		Cookies:             []*routerv1.HeaderValue{{Name: "_port_auth", Value: "route-cookie"}},
		BlockedPathPrefixes: []string{"/koyeb-sandbox/"},
	}
	base := f.serve(t)
	shared := routerv1connect.NewEdgeServiceClient(routerclient.New(base, edgeToken), base)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tr := traffic.Edge(shared, traffic.Settings{
		ReporterID: "edge-test", ReportInterval: 50 * time.Millisecond, ReportBytes: 8 << 20,
	}, log)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	up := newTransport()
	roots := x509.NewCertPool()
	roots.AddCert(g.srv.Certificate())
	up.TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(up.CloseIdleConnections)
	d := Deps{
		Traffic:      tr,
		Guard:        strangers.NewGuard(20, strangers.Mark, strangers.Unknown),
		CacheSize:    100,
		RouteTTL:     time.Minute,
		QueueWait:    30 * time.Second,
		QueueMax:     256,
		AbuseContact: "support@bugnet.org",
		BoatSuffix:   "on.boat.dev",
		Transport:    up,
		Log:          log,
	}
	for _, c := range change {
		c(&d)
	}
	edge := httptest.NewUnstartedServer(New(shared, d))
	edge.EnableHTTP2 = true
	edge.Config.MaxHeaderBytes = 1 << 20
	edge.StartTLS()
	t.Cleanup(edge.Close)
	x := &harness{router: f, gate: g, tr: tr, d: d, edge: edge}
	x.h2, x.h1 = x.client(true), x.client(false)
	x.pv = f.add(firstID, 5173)
	x.link = "https://" + host + "/?" + queryName + "=" + x.pv.token
	// Events sent before the edge watches would be lost
	within(t, "the event stream", func() bool { return f.count(&f.watching) > 0 })
	return x
}

// client reaches the edge for any preview name, over HTTP/2 or HTTP/1.1 only
func (x *harness) client(h2 bool) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(x.edge.Certificate())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, x.edge.Listener.Addr().String())
		},
		Protocols: new(http.Protocols),
	}
	tr.Protocols.SetHTTP1(true)
	if h2 {
		tr.Protocols.SetHTTP2(true)
		tr.ForceAttemptHTTP2 = true
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Minute,
	}
}

// do sends one request through the edge with headers given as name, value pairs
func (x *harness) do(t *testing.T, c *http.Client, method, rawURL, body string,
	kv ...string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		req.Header.Add(kv[i], kv[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// get is a GET over HTTP/2 whose body is read and closed
func (x *harness) get(t *testing.T, rawURL string, kv ...string) (*http.Response, string) {
	t.Helper()
	res := x.do(t, x.h2, http.MethodGet, rawURL, "", kv...)
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(b)
}

// at is a URL on the first preview's host
func at(path string) string {
	return "https://" + host + path
}

// withToken is a path on the first preview's host carrying the token in the query
func (x *harness) withToken(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return at(path + sep + queryName + "=" + x.pv.token)
}

// browse loads the link as a browser would after Continue, through the cookie
func (x *harness) browse(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	return x.get(t, at(path), "Cookie", cookieName+"="+x.pv.token,
		"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest",
		"document")
}

// ws is one WebSocket through the edge, over a raw HTTP/1.1 connection
type ws struct {
	conn net.Conn
	br   *bufio.Reader
}

// dialWS upgrades path on hostname and answers the status and, for 101, the open socket
func (x *harness) dialWS(t *testing.T, hostname, path string, kv ...string) (int, *ws) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(x.edge.Certificate())
	conn, err := tls.Dial("tcp", x.edge.Listener.Addr().String(), &tls.Config{
		RootCAs: roots, ServerName: "example.com", NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + hostname + "\r\n")
	b.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n")
	b.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(kv[i] + ": " + kv[i+1] + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(shortWait))
	br := bufio.NewReader(conn)
	code, _, err := readStatus(br)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return code, &ws{conn: conn, br: br}
}

// openWS dials a WebSocket on the first preview with the token header and checks it echoes
func (x *harness) openWS(t *testing.T, p *fakePreview, hostname string) *ws {
	t.Helper()
	code, w := x.dialWS(t, hostname, "/ws", headerName, p.token)
	eq(t, code, http.StatusSwitchingProtocols)
	if err := w.echo("hello"); err != nil {
		t.Fatal(err)
	}
	return w
}

// echo sends msg and reads it back
func (w *ws) echo(msg string) error {
	_ = w.conn.SetDeadline(time.Now().Add(shortWait))
	defer func() { _ = w.conn.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(w.conn, msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(w.br, got); err != nil {
		return err
	}
	if string(got) != msg {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// closedWithin reports whether the edge closes the socket within d
func (w *ws) closedWithin(d time.Duration) bool {
	_ = w.conn.SetReadDeadline(time.Now().Add(d))
	_, err := w.br.ReadByte()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

// isInterstitial reports whether an answer is the interstitial page
func isInterstitial(t *testing.T, res *http.Response, body string) bool {
	t.Helper()
	return res.StatusCode == http.StatusOK && strings.Contains(body, "Before you continue")
}

// formValue reads one hidden field off the interstitial
func formValue(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no %s field in\n%s", name, body)
	}
	rest := body[i+len(marker):]
	v := rest[:strings.IndexByte(rest, '"')]
	return strings.NewReplacer("&amp;", "&", "&#43;", "+", "&#34;", `"`).Replace(v)
}

// postContinue posts the Continue form with origin and next and the first preview's token
func (x *harness) postContinue(t *testing.T, origin, next string, kv ...string) *http.Response {
	t.Helper()
	form := url.Values{"token": {x.pv.token}, "next": {next}}.Encode()
	res := x.do(t, x.h2, http.MethodPost, at(continuePath), form, append([]string{
		"Content-Type", "application/x-www-form-urlencoded", "Origin", origin,
	}, kv...)...)
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res
}

// parallel runs n requests at once and answers their status codes
func parallel(n int, do func(i int) int) []int {
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { codes[i] = do(i) })
	}
	wg.Wait()
	return codes
}

func countOf(codes []int, code int) int {
	n := 0
	for _, c := range codes {
		if c == code {
			n++
		}
	}
	return n
}
