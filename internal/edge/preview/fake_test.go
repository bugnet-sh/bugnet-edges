package preview

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	gib     = 1 << 30
	gateKey = "gate-key-for-tests"
)

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func refusal(code connect.Code, reason string) *connect.Error {
	ce := connect.NewError(code, errors.New(reason))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: routerDomain})
	ce.AddDetail(d)
	return ce
}

/* The router */

// fakePreview is one preview the fake router knows
type fakePreview struct {
	id, token string
	port      uint32
	gen       uint32
	revoked   bool
}

// fakeRouter is an EdgeService for one placement that records what the edge asks
type fakeRouter struct {
	routerv1connect.UnimplementedEdgeServiceHandler

	mu           sync.Mutex
	previews     map[string]*fakePreview
	placement    string
	upstream     *routerv1.GateUpstream
	deadline     time.Time
	budget       *routerv1.EdgeBudget
	used         uint64
	spent, ended bool
	interstitial bool
	source       string
	resolves     int
	repairs      int
	// orderTP is the order_traceparent every ResolvePreview answers
	orderTP string
	// resolveErr, when set, answers every ResolvePreview
	resolveErr error
	events     chan *routerv1.EdgeEvent
	watching   int
	checks     int
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{
		previews:  map[string]*fakePreview{},
		placement: "p1",
		deadline:  time.Now().Add(time.Hour),
		budget: &routerv1.EdgeBudget{
			BytesRemaining: gib, QueuedRequests: 64, Websockets: 32, RequestsPerSecond: 100,
			RequestsBurst: 200,
		},
		interstitial: true,
		events:       make(chan *routerv1.EdgeEvent, 16),
	}
}

func (f *fakeRouter) serve(t interface{ Cleanup(func()) }) string {
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEdgeServiceHandler(f))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeRouter) add(id string, port uint32) *fakePreview {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &fakePreview{id: id, token: newToken(), port: port, gen: 1}
	f.previews[id] = p
	return p
}

// set changes the fake's state under its lock
func (f *fakeRouter) set(change func(f *fakeRouter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeRouter) count(n *int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *n
}

func (f *fakeRouter) remainingLocked() uint64 {
	if f.spent || f.used >= f.budget.GetBytesRemaining() {
		return 0
	}
	return f.budget.GetBytesRemaining() - f.used
}

func (f *fakeRouter) ResolvePreview(
	_ context.Context, req *connect.Request[routerv1.ResolvePreviewRequest],
) (*connect.Response[routerv1.ResolvePreviewResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves++
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	p, ok := f.previews[req.Msg.GetPreviewId()]
	switch {
	case !ok:
		return nil, refusal(connect.CodeNotFound, "PREVIEW_UNKNOWN")
	case req.Msg.GetToken() != p.token:
		return nil, refusal(connect.CodePermissionDenied, "TOKEN_INVALID")
	case p.revoked:
		return nil, refusal(connect.CodeFailedPrecondition, "PREVIEW_REVOKED")
	case f.ended || !time.Now().Before(f.deadline):
		return nil, refusal(connect.CodeFailedPrecondition, "NOT_READY")
	case f.remainingLocked() == 0:
		return nil, refusal(connect.CodeResourceExhausted, "BUDGET_SPENT")
	}
	b := proto.Clone(f.budget).(*routerv1.EdgeBudget)
	b.BytesRemaining = f.remainingLocked()
	return connect.NewResponse(&routerv1.ResolvePreviewResponse{
		PlacementId: f.placement, Port: p.port, Upstream: f.upstream,
		ExpiresAt: timestamppb.New(f.deadline), Generation: p.gen, Budget: b,
		Interstitial: f.interstitial, SourceLabel: f.source,
		StartedAt:        timestamppb.New(time.Now().Add(-time.Minute)),
		OrderTraceparent: f.orderTP,
	}), nil
}

func (f *fakeRouter) RepairPreview(
	_ context.Context, _ *connect.Request[routerv1.RepairPreviewRequest],
) (*connect.Response[routerv1.RepairPreviewResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repairs++
	return connect.NewResponse(&routerv1.RepairPreviewResponse{Repaired: true}), nil
}

func (f *fakeRouter) CheckEdgeLeases(
	_ context.Context, req *connect.Request[routerv1.CheckEdgeLeasesRequest],
) (*connect.Response[routerv1.CheckEdgeLeasesResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	out := &routerv1.CheckEdgeLeasesResponse{Leases: map[string]*routerv1.EdgeLease{}}
	for _, id := range req.Msg.GetPlacementIds() {
		if id == f.placement && !f.ended {
			out.Leases[id] = &routerv1.EdgeLease{
				Deadline: timestamppb.New(f.deadline), BytesRemaining: f.remainingLocked(),
			}
		}
	}
	for _, h := range req.Msg.GetPreviews() {
		p, ok := f.previews[h.GetPreviewId()]
		if !ok || p.revoked || p.gen != h.GetGeneration() {
			out.RevokedPreviewIds = append(out.RevokedPreviewIds, h.GetPreviewId())
		}
	}
	return connect.NewResponse(out), nil
}

func (f *fakeRouter) ReportEdgeUsage(
	_ context.Context, req *connect.Request[routerv1.ReportEdgeUsageRequest],
) (*connect.Response[routerv1.ReportEdgeUsageResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &routerv1.ReportEdgeUsageResponse{BytesRemaining: map[string]uint64{}}
	for _, u := range req.Msg.GetUsage() {
		f.used += u.GetBytesIn() + u.GetBytesOut()
		out.BytesRemaining[u.GetPlacementId()] = f.remainingLocked()
	}
	return connect.NewResponse(out), nil
}

func (f *fakeRouter) WatchEdgeEvents(
	ctx context.Context, _ *connect.Request[routerv1.WatchEdgeEventsRequest],
	out *connect.ServerStream[routerv1.WatchEdgeEventsResponse],
) error {
	f.mu.Lock()
	f.watching++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.watching--
		f.mu.Unlock()
	}()
	if err := out.Send(&routerv1.WatchEdgeEventsResponse{Cursor: "0"}); err != nil {
		return err
	}
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-f.events:
			err := out.Send(&routerv1.WatchEdgeEventsResponse{
				Cursor: strconv.Itoa(n), Event: ev,
			})
			if err != nil {
				return err
			}
		}
	}
}

/* The gate */

// seen is one request the fake gate received
type seen struct {
	uri    string
	host   string
	header http.Header
}

// fakeGate stands for a provider's route and the bugnet-run gate behind it
type fakeGate struct {
	srv *httptest.Server

	mu sync.Mutex
	// open holds the ports an app listens on
	open map[int]bool
	// provider makes the route answer itself, as a provider does with the gate down
	provider bool
	seen     []seen
	echoes   int
	app      func(port int, w http.ResponseWriter, r *http.Request)
}

func newFakeGate(t interface{ Cleanup(func()) }) *fakeGate {
	g := &fakeGate{open: map[int]bool{}}
	g.app = defaultApp
	g.srv = httptest.NewUnstartedServer(g)
	g.srv.EnableHTTP2 = true
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGate) set(change func(g *fakeGate)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	change(g)
}

func (g *fakeGate) listen(port int) {
	g.set(func(g *fakeGate) { g.open[port] = true })
}

func (g *fakeGate) portClosed(port int) {
	g.set(func(g *fakeGate) { delete(g.open, port) })
}

func (g *fakeGate) last() seen {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.seen) == 0 {
		return seen{}
	}
	return g.seen[len(g.seen)-1]
}

func (g *fakeGate) received() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

func (g *fakeGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	provider, app := g.provider, g.app
	g.mu.Unlock()
	if provider {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "fake provider: the port is not open")
		return
	}
	if r.Header.Get(gateKeyHeader) != gateKey {
		w.Header().Set(markHeader, "1")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	port, _ := strconv.Atoi(r.Header.Get(portHeader))
	g.mu.Lock()
	g.seen = append(g.seen, seen{uri: r.RequestURI, host: r.Host, header: r.Header.Clone()})
	open := g.open[port]
	g.mu.Unlock()
	if !open {
		w.Header().Set(markHeader, "1")
		w.Header().Set(errorHeader, portClosed)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if isUpgrade(r) {
		g.echo(w)
		return
	}
	app(port, &gateWriter{ResponseWriter: w}, r)
}

// echo answers 101 and sends back every byte it reads until either side closes
func (g *fakeGate) echo(w http.ResponseWriter) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+markHeader+": 1\r\n\r\n")
	g.set(func(g *fakeGate) { g.echoes++ })
	defer g.set(func(g *fakeGate) { g.echoes-- })
	_, _ = io.Copy(conn, brw)
}

// gateWriter moves the app's Cache-Control and Server aside and marks the answer, as the gate
type gateWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *gateWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		h := w.Header()
		for _, m := range [][2]string{{"Cache-Control", cacheHeader}, {"Server", serverHeader}} {
			v := strings.Join(h.Values(m[0]), ", ")
			if v == "" {
				v = "-"
			}
			h.Del(m[0])
			h.Set(m[1], v)
		}
		h.Set("Cache-Control", "private")
		h.Set(markHeader, "1")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gateWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gateWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// defaultApp answers /big?n=N with N bytes, /hang until the request ends, and its port elsewhere
func defaultApp(port int, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/big":
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = io.CopyN(w, zeros{}, int64(n))
	case "/hang":
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	case "/echo":
		_, _ = io.Copy(w, r.Body)
	default:
		_, _ = io.WriteString(w, "app on port "+strconv.Itoa(port))
	}
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

// readStatus reads an HTTP/1.1 answer's status code and headers off a raw connection
func readStatus(br *bufio.Reader) (int, http.Header, error) {
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, nil, err
	}
	return res.StatusCode, res.Header, nil
}
