package hooks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// fakeRouter records DeliverHook calls and answers with err, or 204 when nil
type fakeRouter struct {
	routerv1connect.UnimplementedEdgeServiceHandler

	mu    sync.Mutex
	got   []*routerv1.DeliverHookRequest
	err   error
	reply uint32
}

func (f *fakeRouter) DeliverHook(
	_ context.Context, req *connect.Request[routerv1.DeliverHookRequest],
) (*connect.Response[routerv1.DeliverHookResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, req.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&routerv1.DeliverHookResponse{Status: f.reply}), nil
}

func (f *fakeRouter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

type rig struct {
	router *fakeRouter
	srv    *httptest.Server
}

func newRig(t *testing.T, perMinute int) *rig {
	t.Helper()
	fr := &fakeRouter{reply: 204}
	path, h := routerv1connect.NewEdgeServiceHandler(fr)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	rs := httptest.NewServer(mux)
	t.Cleanup(rs.Close)
	client := routerv1connect.NewEdgeServiceClient(rs.Client(), rs.URL)
	hs := httptest.NewServer(New(client, Options{
		PathSecret: secret, MaxBody: 64 << 10, RequestsPerMinute: perMinute,
	}))
	t.Cleanup(hs.Close)
	return &rig{router: fr, srv: hs}
}

func (g *rig) do(t *testing.T, method, path string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, g.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("E2B-Signature", "sig")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (g *rig) post(t *testing.T, path string, n int) *http.Response {
	return g.do(t, http.MethodPost, path, bytes.Repeat([]byte("x"), n))
}

func TestHooksRoute(t *testing.T) {
	g := newRig(t, 0)
	eq(t, g.post(t, "/hooks/e2b/wrongsecret", 10).StatusCode, 404)
	eq(t, g.router.calls(), 0)
	eq(t, g.post(t, "/hooks/e2b/"+secret, 65<<10).StatusCode, 413)
	eq(t, g.router.calls(), 0)
	eq(t, g.do(t, http.MethodGet, "/hooks/e2b/"+secret, nil).StatusCode, 404)
	eq(t, g.post(t, "/hooks/E2B!/"+secret, 10).StatusCode, 404)
	eq(t, g.post(t, "/hooks/e2b/"+secret+"/x", 10).StatusCode, 404)
	eq(t, g.router.calls(), 0)

	resp := g.post(t, "/hooks/e2b/"+secret, 10)
	eq(t, resp.StatusCode, 204)
	eq(t, g.router.calls(), 1)
	got := g.router.got[0]
	eq(t, got.Provider, "e2b")
	eq(t, string(got.Body), strings.Repeat("x", 10))
	eq(t, got.ClientIp, "127.0.0.1")
	var sig string
	for _, h := range got.Headers {
		if h.Name == "e2b-signature" {
			sig = h.Value
		}
	}
	eq(t, sig, "sig")
}

func TestHooksRouterAnswers(t *testing.T) {
	g := newRig(t, 0)
	for _, c := range []struct {
		err  error
		want int
	}{
		{connect.NewError(connect.CodeNotFound, nil), 404},
		{connect.NewError(connect.CodePermissionDenied, nil), 401},
		{connect.NewError(connect.CodeUnavailable, nil), 503},
		{connect.NewError(connect.CodeInternal, nil), 503},
	} {
		g.router.err = c.err
		eq(t, g.post(t, "/hooks/e2b/"+secret, 5).StatusCode, c.want)
	}
}

func TestHooksSixtyAMinutePerIP(t *testing.T) {
	g := newRig(t, 60)
	for range 60 {
		eq(t, g.post(t, "/hooks/e2b/"+secret, 5).StatusCode, 204)
	}
	resp := g.post(t, "/hooks/e2b/"+secret, 5)
	eq(t, resp.StatusCode, 429)
	eq(t, resp.Header.Get("Retry-After"), "60")
	eq(t, g.router.calls(), 60)
	_, _ = io.Copy(io.Discard, resp.Body)
}
