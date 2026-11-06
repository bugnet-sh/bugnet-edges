package routerclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

const token = "edge-token-0123456789abcdef0123456789"

// fakeEdge answers three EdgeService calls, one of each streaming shape
type fakeEdge struct {
	routerv1connect.UnimplementedEdgeServiceHandler
}

func (fakeEdge) ReportEdgeUsage(
	context.Context, *connect.Request[routerv1.ReportEdgeUsageRequest],
) (*connect.Response[routerv1.ReportEdgeUsageResponse], error) {
	return connect.NewResponse(&routerv1.ReportEdgeUsageResponse{
		BytesRemaining: map[string]uint64{"p1": 7},
	}), nil
}

func (fakeEdge) WatchEdgeEvents(
	_ context.Context, _ *connect.Request[routerv1.WatchEdgeEventsRequest],
	s *connect.ServerStream[routerv1.WatchEdgeEventsResponse],
) error {
	for _, c := range []string{"1-0", "2-0"} {
		if err := s.Send(&routerv1.WatchEdgeEventsResponse{Cursor: c}); err != nil {
			return err
		}
	}
	return nil
}

func (fakeEdge) WriteTransfer(
	_ context.Context, s *connect.ClientStream[routerv1.WriteTransferRequest],
) (*connect.Response[routerv1.WriteTransferResponse], error) {
	var n uint64
	for s.Receive() {
		n += uint64(len(s.Msg().GetData()))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&routerv1.WriteTransferResponse{Size: n}), nil
}

// router is a fake router-api that counts connections and records each request
type router struct {
	url   string
	conns atomic.Int64

	mu     sync.Mutex
	protos []int
	auth   []string
}

func (r *router) seen() (protos []int, auth []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.protos...), append([]string(nil), r.auth...)
}

// startRouter serves the fake over HTTP/1.1 and h2c, as router-api does
func startRouter(t *testing.T) *router {
	t.Helper()
	r := &router{}
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewEdgeServiceHandler(fakeEdge{}))
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, req.URL.Query().Get("to"), http.StatusTemporaryRedirect)
	})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			r.mu.Lock()
			r.protos = append(r.protos, req.ProtoMajor)
			r.auth = append(r.auth, req.Header.Get("Authorization"))
			r.mu.Unlock()
			mux.ServeHTTP(w, req)
		}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			r.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

// callEach makes one call of each streaming shape and checks the answers
func callEach(t *testing.T, c routerv1connect.EdgeServiceClient) {
	t.Helper()
	ctx := t.Context()
	u, err := c.ReportEdgeUsage(ctx, connect.NewRequest(&routerv1.ReportEdgeUsageRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, u.Msg.GetBytesRemaining()["p1"], uint64(7))

	events, err := c.WatchEdgeEvents(ctx, connect.NewRequest(&routerv1.WatchEdgeEventsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var cursors []string
	for events.Receive() {
		cursors = append(cursors, events.Msg().GetCursor())
	}
	eq(t, events.Err(), nil)
	eq(t, cursors, []string{"1-0", "2-0"})

	w := c.WriteTransfer(ctx)
	for range 3 {
		if err := w.Send(&routerv1.WriteTransferRequest{Data: make([]byte, 256<<10)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.CloseAndReceive()
	if err != nil {
		t.Fatal(err)
	}
	eq(t, got.Msg.GetSize(), uint64(3*256<<10))
}

func TestPerCallClientOpensOneConnectionPerCall(t *testing.T) {
	r := startRouter(t)
	c := routerv1connect.NewEdgeServiceClient(PerCall(r.url, token), r.url)
	callEach(t, c)
	callEach(t, c)
	eq(t, r.conns.Load(), int64(6))

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			_, err := c.ReportEdgeUsage(t.Context(),
				connect.NewRequest(&routerv1.ReportEdgeUsageRequest{}))
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	eq(t, r.conns.Load(), int64(10))
	protos, auth := r.seen()
	for i := range protos {
		eq(t, protos[i], 1)
		eq(t, auth[i], "Bearer "+token)
	}
}

func TestSharedClientUsesOneConnection(t *testing.T) {
	r := startRouter(t)
	c := routerv1connect.NewEdgeServiceClient(New(r.url, token), r.url)
	callEach(t, c)
	callEach(t, c)
	eq(t, r.conns.Load(), int64(1))
	protos, auth := r.seen()
	eq(t, len(protos), 6)
	for i := range protos {
		eq(t, protos[i], 2)
		eq(t, auth[i], "Bearer "+token)
	}
}

func TestTokenGoesOnlyToTheRouter(t *testing.T) {
	r := startRouter(t)
	var leaked atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		leaked.Add(1)
	}))
	t.Cleanup(other.Close)

	for _, c := range []*http.Client{New(r.url, token), PerCall(r.url, token)} {
		_, err := c.Get(other.URL + "/x")
		eq(t, errors.Is(err, errOtherHost), true)

		resp, err := c.Get(r.url + "/elsewhere?to=" + other.URL + "/y")
		if err != nil {
			t.Fatal(err)
		}
		eq(t, resp.Body.Close(), nil)
		eq(t, resp.StatusCode, http.StatusTemporaryRedirect)
	}
	eq(t, leaked.Load(), int64(0))
}

func TestBadBaseURLFailsEveryCall(t *testing.T) {
	for _, base := range []string{"", "127.0.0.1:8080", "ftp://127.0.0.1", "http://"} {
		_, err := New(base, token).Get("http://127.0.0.1:1/x")
		eq(t, errors.Is(err, errBaseURL), true)
	}
}

func TestProtocolsByScheme(t *testing.T) {
	protocols := func(c *http.Client) (*http.Transport, string) {
		tr := c.Transport.(*bearer).next.(*http.Transport)
		return tr, tr.Protocols.String()
	}
	tr, p := protocols(New("http://127.0.0.1:8080", token))
	eq(t, p, "{UnencryptedHTTP2}")
	eq(t, tr.DisableKeepAlives, false)
	eq(t, tr.HTTP2.SendPingTimeout > 0 && tr.HTTP2.PingTimeout > 0, true)
	_, p = protocols(New("https://router.internal:8443", token))
	eq(t, p, "{HTTP1,HTTP2}")
	for _, base := range []string{"http://127.0.0.1:8080", "https://router.internal:8443"} {
		tr, p = protocols(PerCall(base, token))
		eq(t, p, "{HTTP1}")
		eq(t, tr.DisableKeepAlives, true)
	}
}
