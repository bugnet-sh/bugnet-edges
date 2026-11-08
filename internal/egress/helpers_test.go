package egress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	pp "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/nacl/box"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	egressHost = "egress.bugnet.sh"
	shortWait  = 5 * time.Second
	pollPeriod = 5 * time.Millisecond
)

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

/* Keys and certificates */

func newBoxKey(t *testing.T, id string) BoxKey {
	t.Helper()
	dir := t.TempDir()
	if _, err := NewBoxKey(dir, id); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, boxKeyFile(id)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseBoxKey(id, raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t *testing.T, version uint32) *CA {
	t.Helper()
	dir := t.TempDir()
	if err := InitCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(filepath.Join(dir, CACertFile))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	ca, err := LoadCA(version, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func (c *CA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// outerPair writes a self-signed pair for the egress host and returns its directory and pool
func outerPair(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: egressHost},
		DNSNames:  []string{egressHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	write := func(name string, b *pem.Block) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("fullchain.pem", &pem.Block{Type: "CERTIFICATE", Bytes: der})
	write("key.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return dir, pool
}

/* The router */

func refusal(code connect.Code, reason string) *connect.Error {
	ce := connect.NewError(code, errors.New(reason))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: routerDomain})
	ce.AddDetail(d)
	return ce
}

// fakePlacement is one placement the fake router serves
type fakePlacement struct {
	id       uuid.UUID
	token    string
	resp     *routerv1.ResolveTunnelResponse
	spent    bool
	notReady bool
}

// fakeRouter is an EgressService that serves the placements a test adds
type fakeRouter struct {
	routerv1connect.UnimplementedEgressServiceHandler

	mu         sync.Mutex
	byToken    map[[32]byte]*fakePlacement
	byID       map[string]*fakePlacement
	resolves   int
	checks     int
	usageBytes uint64
	down       error
	events     chan *routerv1.EdgeEvent
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{
		byToken: map[[32]byte]*fakePlacement{}, byID: map[string]*fakePlacement{},
		events: make(chan *routerv1.EdgeEvent, 16),
	}
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "bnt_" + base64.RawURLEncoding.EncodeToString(b)
}

var b32lower = "abcdefghijklmnopqrstuvwxyz234567"

func newPlaceholder() string {
	b := make([]byte, 26)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = b32lower[int(b[i])%32]
	}
	return "bnsec_" + string(b)
}

// add registers a placement whose response is resp, filling in what the test leaves out
func (r *fakeRouter) add(p *fakePlacement) *fakePlacement {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.token == "" {
		p.token = newToken()
	}
	p.resp.PlacementId = p.id.String()
	if p.resp.Deadline == nil {
		p.resp.Deadline = timestamppb.New(time.Now().Add(time.Hour))
	}
	if p.resp.CaVersion == 0 {
		p.resp.CaVersion = 1
	}
	if p.resp.BytesRemaining == 0 && !p.spent {
		p.resp.BytesRemaining = 1 << 30
	}
	r.byToken[sha256.Sum256([]byte(p.token))] = p
	r.byID[p.id.String()] = p
	return p
}

func (r *fakeRouter) answer(
	p *fakePlacement, fetch bool,
) (*connect.Response[routerv1.ResolveTunnelResponse], error) {
	switch {
	case p == nil:
		return nil, refusal(connect.CodeNotFound, "TOKEN_UNKNOWN")
	case p.notReady:
		return nil, refusal(connect.CodeFailedPrecondition, "NOT_READY")
	case p.spent:
		return nil, refusal(connect.CodeResourceExhausted, "BUDGET_SPENT")
	}
	out := proto.Clone(p.resp).(*routerv1.ResolveTunnelResponse)
	// Sandbox callers never get fetch_only secrets
	if !fetch {
		out.Secrets = slices.DeleteFunc(out.Secrets, func(s *routerv1.EgressSecret) bool {
			return s.GetSpec().GetFetchOnly()
		})
	}
	return connect.NewResponse(out), nil
}

func (r *fakeRouter) ResolveTunnel(
	_ context.Context, req *connect.Request[routerv1.ResolveTunnelRequest],
) (*connect.Response[routerv1.ResolveTunnelResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolves++
	if r.down != nil {
		return nil, r.down
	}
	var p *fakePlacement
	fetch := false
	switch c := req.Msg.GetCaller().(type) {
	case *routerv1.ResolveTunnelRequest_TokenSha256:
		p = r.byToken[[32]byte(c.TokenSha256)]
	case *routerv1.ResolveTunnelRequest_FetchPlacementId:
		p, fetch = r.byID[c.FetchPlacementId], true
	}
	return r.answer(p, fetch)
}

func (r *fakeRouter) CheckEgressLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEgressLeasesRequest],
) (*connect.Response[routerv1.CheckEgressLeasesResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks++
	if r.down != nil {
		return nil, r.down
	}
	out := map[string]*routerv1.EgressLease{}
	for _, id := range req.Msg.GetPlacementIds() {
		if p := r.byID[id]; p != nil && !p.notReady {
			out[id] = &routerv1.EgressLease{
				Deadline: p.resp.Deadline, BytesRemaining: p.resp.BytesRemaining,
				SecretsVersion: p.resp.SecretsVersion,
			}
		}
	}
	return connect.NewResponse(&routerv1.CheckEgressLeasesResponse{Leases: out}), nil
}

func (r *fakeRouter) ReportEgressUsage(
	_ context.Context, req *connect.Request[routerv1.ReportEgressUsageRequest],
) (*connect.Response[routerv1.ReportEgressUsageResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	left := map[string]uint64{}
	for _, u := range req.Msg.GetUsage() {
		r.usageBytes += u.GetBytesIn() + u.GetBytesOut()
		if p := r.byID[u.GetPlacementId()]; p != nil {
			left[u.GetPlacementId()] = p.resp.BytesRemaining
		}
	}
	return connect.NewResponse(&routerv1.ReportEgressUsageResponse{BytesRemaining: left}), nil
}

func (r *fakeRouter) WatchEgressEvents(
	ctx context.Context, _ *connect.Request[routerv1.WatchEgressEventsRequest],
	stream *connect.ServerStream[routerv1.WatchEgressEventsResponse],
) error {
	for n := 1; ; n++ {
		select {
		case ev := <-r.events:
			if err := stream.Send(&routerv1.WatchEgressEventsResponse{
				Cursor: "1-" + string(rune('0'+n%10)), Event: ev,
			}); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (r *fakeRouter) resolveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolves
}

// secretOf seals a payload for the placement and returns the router's record and the placeholder
type secretSpec struct {
	name    string
	value   string
	hosts   []string
	headers []string
	fetch   bool
	custom  []string
	// binding overrides the placement's, for a box moved to another sandbox
	binding string
	// recordHosts overrides the hosts of the record the router serves
	recordHosts []string
}

func (h *harness) secret(
	t *testing.T, id uuid.UUID, s secretSpec,
) (*routerv1.EgressSecret, string) {
	t.Helper()
	ph := newPlaceholder()
	binding := s.binding
	if binding == "" {
		binding = Binding(id)
	}
	payload, _ := json.Marshal(Payload{
		V: 1, Binding: binding, Name: s.name, Hosts: s.hosts, Headers: s.headers,
		FetchOnly: s.fetch, Value: s.value,
	})
	pub := h.key.Public()
	sealed, err := box.SealAnonymous(nil, payload, &pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hosts := s.hosts
	if s.recordHosts != nil {
		hosts = s.recordHosts
	}
	sum := sha256.Sum256([]byte(ph))
	return &routerv1.EgressSecret{
		PlaceholderSha256: sum[:],
		Spec: &routerv1.SecretSpec{
			Name: s.name, Hosts: hosts, HeaderNames: s.headers, FetchOnly: s.fetch,
		},
		Value:       &routerv1.SealedValue{KeyId: h.key.ID, Box: sealed},
		CustomHosts: s.custom,
	}, ph
}

/* The harness */

// harness is a running proxy, a fake router and an upstream test server
type harness struct {
	t        *testing.T
	router   *fakeRouter
	server   *Server
	key      BoxKey
	ca       *CA
	outer    *x509.CertPool
	outerDir string
	addr     string
	metrics  string
	upstream *httptest.Server
	log      *logBuffer
	cancel   context.CancelFunc
	stopOnce sync.Once
	done     chan error

	mu   sync.Mutex
	seen []*http.Request

	// release unblocks the upstream's /block, which counts its waiting requests in inflight
	release  chan struct{}
	inflight atomic.Int32
}

// logBuffer collects the proxy's log lines, so a test can check that no secret reached them
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type option func(*Config, *Deps)

// start runs the proxy on loopback until the test ends
func start(t *testing.T, opts ...option) *harness {
	t.Helper()
	h := &harness{t: t, router: newFakeRouter(), key: newBoxKey(t, "k1"), ca: newCA(t, 1),
		log:     &logBuffer{},
		release: make(chan struct{})}
	dir, pool := outerPair(t)
	h.outer, h.outerDir = pool, dir
	rs := httptest.NewServer(routerHandler(h.router))
	t.Cleanup(rs.Close)
	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request,
	) {
		h.mu.Lock()
		h.seen = append(h.seen, r.Clone(context.Background()))
		h.mu.Unlock()
		h.upstreamHandler(w, r)
	}))
	t.Cleanup(h.upstream.Close)

	cfg := Defaults()
	cfg.RouterURL = rs.URL
	cfg.EgressHost = egressHost
	cfg.ListenAddr, cfg.MetricsListenAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.ACMEEnabled, cfg.StaticDir = false, dir
	cfg.Token = strings.Repeat("t", 40)
	cfg.UsageReportInterval = 50_000_000
	minter, err := NewMinter(time.Now, h.ca)
	if err != nil {
		t.Fatal(err)
	}
	client := routerv1connect.NewEgressServiceClient(http.DefaultClient, rs.URL)
	up := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certPool(h.upstream), ServerName: "example.com"},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, h.upstream.Listener.Addr().String())
		},
		ForceAttemptHTTP2: true,
	}
	deps := Deps{
		Router: client, Keys: NewKeys(h.key), Minter: minter, Transport: up,
		Log: slog.New(slog.NewTextHandler(h.log,
			&slog.HandlerOptions{Level: slog.LevelDebug})),
		CheckEvery: time.Minute,
	}
	for _, o := range opts {
		o(&cfg, &deps)
	}
	h.server = New(cfg, deps)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func() { h.done <- h.server.Run(ctx) }()
	select {
	case <-h.server.Started():
	case err := <-h.done:
		t.Fatalf("the proxy did not start: %v", err)
	case <-time.After(shortWait):
		t.Fatal("the proxy did not start")
	}
	h.addr, h.metrics = h.server.Addr("tunnel"), h.server.Addr("metrics")
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			h.t.Error("the proxy did not stop")
		}
	})
}

func certPool(s *httptest.Server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())
	return p
}

func routerHandler(r *fakeRouter) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEgressServiceHandler(r))
	return mux
}

// upstreamHandler echoes what the upstream saw, and honours the paths the tests use
func (h *harness) upstreamHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/redirect":
		http.Redirect(w, r, "https://other.example/next", http.StatusFound)
	case "/echo":
		// Echo the credential back in a header, as a server that mirrors requests would
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		w.Header().Set("X-Api-Echo", r.Header.Get("X-Api-Key"))
		_, _ = io.WriteString(w, "echo")
	case "/ws":
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		typ, msg, err := ws.Read(r.Context())
		if err == nil {
			_ = ws.Write(r.Context(), typ, msg)
		}
		_ = ws.Close(websocket.StatusNormalClosure, "")
	case "/mid":
		_, _ = w.Write(make([]byte, 3<<19))
	case "/block":
		h.inflight.Add(1)
		defer h.inflight.Add(-1)
		select {
		case <-h.release:
		case <-r.Context().Done():
		}
		_, _ = io.WriteString(w, "released")
	default:
		_, _ = io.WriteString(w, "ok")
	}
}

// lastSeen is the latest request the upstream received
func (h *harness) lastSeen() *http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) == 0 {
		return nil
	}
	return h.seen[len(h.seen)-1]
}

func (h *harness) seenCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.seen)
}

// placement adds a placement with the secrets, and returns it with their placeholders
func (h *harness) placement(t *testing.T, specs ...secretSpec) (*fakePlacement, []string) {
	t.Helper()
	id := uuid.New()
	resp := &routerv1.ResolveTunnelResponse{SecretsVersion: 1, MaxTunnels: 64}
	var phs []string
	for _, s := range specs {
		es, ph := h.secret(t, id, s)
		resp.Secrets = append(resp.Secrets, es)
		phs = append(phs, ph)
	}
	return h.router.add(&fakePlacement{id: id, resp: resp}), phs
}

/* Clients */

// tunnel opens a tunnel with token from source, returning the WebSocket as a byte stream
func (h *harness) tunnel(token, source string) (net.Conn, *http.Response, error) {
	return h.tunnelWith(token, source, nil)
}

func (h *harness) tunnelWith(
	token, source string, extra http.Header,
) (net.Conn, *http.Response, error) {
	src := net.ParseIP(source)
	hc := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, "tcp", h.addr)
			if err != nil {
				return nil, err
			}
			from := &net.TCPAddr{IP: src, Port: 40000}
			header := pp.HeaderProxyFromAddrs(2, from, raw.RemoteAddr())
			if _, err := header.WriteTo(raw); err != nil {
				_ = raw.Close()
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{
				ServerName: egressHost, RootCAs: h.outer, NextProtos: []string{"http/1.1"},
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}}
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range extra {
		header[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "https://"+egressHost+"/v1/tunnel", &websocket.DialOptions{
		HTTPClient: hc, HTTPHeader: header, Subprotocols: []string{tunnelProtocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, resp, err
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	c := wsNetConn(ctx2, ws)
	return &cancelConn{Conn: c, cancel: cancel2}, resp, nil
}

// inner does the sandbox's TLS for sni over a tunnel, trusting the Bugnet CA
func (h *harness) inner(token, sni string, protos ...string) (*tls.Conn, error) {
	c, _, err := h.tunnel(token, "203.0.113.9")
	if err != nil {
		return nil, err
	}
	if len(protos) == 0 {
		protos = []string{"http/1.1"}
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, RootCAs: h.ca.pool(), NextProtos: protos})
	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return tc, nil
}

// client is an HTTP client whose every connection is a new tunnel with token
func (h *harness) client(token string, protos ...string) *http.Client {
	tr := &http.Transport{
		DialTLSContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			return h.inner(token, host, protos...)
		},
		ForceAttemptHTTP2: len(protos) > 0 && protos[0] == "h2",
	}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 2 * shortWait,
	}
}

// get sends a GET for url on c with the headers and reads the body, so the connection is reusable
func get(t *testing.T, c *http.Client, url string, hdr map[string]string) *http.Response {
	t.Helper()
	resp := getStream(t, c, url, hdr)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}

// getStream is get without reading the body
func getStream(t *testing.T, c *http.Client, url string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func newUUID() uuid.UUID { return uuid.New() }

func readAll(resp *http.Response) ([]byte, error) { return io.ReadAll(resp.Body) }

// cancelConn ends the pumps of a tunnel's client side once it closes
type cancelConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *cancelConn) Close() error {
	err := c.Conn.Close()
	c.cancel()
	return err
}
