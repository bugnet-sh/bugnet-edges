package secretsroute

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
)

const (
	host      = "secrets.example.test"
	origin    = "https://" + host
	token     = "secrets-token-0123456789abcdefghijk"
	link      = "bnsl_AbCdEfGhIjKlMnOpQrStUvWx"
	grant     = "bnsp_ZyXwVuTsRqPoNmLkJiHgFeDcBa"
	indexHTML = "<!doctype html><title>Bugnet secrets</title>"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

/* The fake router */

// fakeRouter is a SecretsRouteService that records what it was asked and answers from memory
type fakeRouter struct {
	routerv1connect.UnimplementedSecretsRouteServiceHandler

	mu      sync.Mutex
	calls   int
	last    any
	keys    []*routerv1.SealingKey
	secret  *routerv1.SecretInfo
	replace bool
	// err, when set, answers every call
	err error
}

func newFakeRouter() *fakeRouter {
	spec := &routerv1.SecretSpec{Name: "HF_TOKEN", Hosts: []string{"huggingface.co"}}
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	return &fakeRouter{
		keys: []*routerv1.SealingKey{{
			KeyId: "k1", PublicKey: pub,
			Binding: "IFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L5QA",
		}},
		secret: &routerv1.SecretInfo{
			Spec: spec, State: routerv1.SecretState_SECRET_STATE_ACTIVE,
			UpdatedAt: timestamppb.New(time.Date(2026, 11, 5, 13, 58, 2, 0, time.UTC)),
		},
	}
}

func refusal(code connect.Code, reason string) *connect.Error {
	ce := connect.NewError(code, errors.New("router text that must not reach a client"))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: "bugnet.router"})
	ce.AddDetail(d)
	return ce
}

func (f *fakeRouter) note(req any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = req
	return f.err
}

func (f *fakeRouter) GetSecretLink(
	_ context.Context, req *connect.Request[routerv1.GetSecretLinkRequest],
) (*connect.Response[routerv1.GetSecretLinkResponse], error) {
	if err := f.note(req.Msg); err != nil {
		return nil, err
	}
	return connect.NewResponse(&routerv1.GetSecretLinkResponse{
		PairingCode: "K3F9X2", SourceLabel: "github.com/acme/app@1a2b3c4",
		SandboxCreatedAt: timestamppb.New(time.Date(2026, 11, 5, 13, 55, 0, 0, time.UTC)),
		ExpiresAt:        timestamppb.New(time.Date(2026, 11, 5, 14, 5, 0, 0, time.UTC)),
		Suggested:        &routerv1.SecretSpec{Name: "HF_TOKEN", Hosts: []string{"huggingface.co"}},
		SealingKeys:      f.keys,
	}), nil
}

func (f *fakeRouter) SubmitSecretLink(
	_ context.Context, req *connect.Request[routerv1.SubmitSecretLinkRequest],
) (*connect.Response[routerv1.SubmitSecretLinkResponse], error) {
	if err := f.note(req.Msg); err != nil {
		return nil, err
	}
	return connect.NewResponse(&routerv1.SubmitSecretLinkResponse{Secret: f.secret}), nil
}

func (f *fakeRouter) GetBridgeSealingKey(
	_ context.Context, req *connect.Request[routerv1.GetBridgeSealingKeyRequest],
) (*connect.Response[routerv1.GetBridgeSealingKeyResponse], error) {
	if err := f.note(req.Msg); err != nil {
		return nil, err
	}
	return connect.NewResponse(&routerv1.GetBridgeSealingKeyResponse{SealingKeys: f.keys}), nil
}

func (f *fakeRouter) PutBridgeSecret(
	_ context.Context, req *connect.Request[routerv1.PutBridgeSecretRequest],
) (*connect.Response[routerv1.PutBridgeSecretResponse], error) {
	if err := f.note(req.Msg); err != nil {
		return nil, err
	}
	applying := &routerv1.SecretInfo{
		Spec: f.secret.Spec, State: routerv1.SecretState_SECRET_STATE_APPLYING,
		UpdatedAt: f.secret.UpdatedAt,
	}
	return connect.NewResponse(
		&routerv1.PutBridgeSecretResponse{Secret: applying, Replaced: f.replace}), nil
}

func (f *fakeRouter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeRouter) lastRequest() any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *fakeRouter) set(fn func(f *fakeRouter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

/* The harness */

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// harness is the route over a real server, with a fake router behind it
type harness struct {
	router *fakeRouter
	url    string
	logs   *syncBuffer
}

func writePage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"index.html":          indexHTML,
		"assets/page-ABC.js":  "console.log(1)",
		"assets/page-DEF.css": "body{margin:0}",
		"assets/notes.txt":    "never served",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newHarness(t *testing.T, perMinute int) *harness {
	t.Helper()
	router := newFakeRouter()
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewSecretsRouteServiceHandler(router))
	rsrv := httptest.NewUnstartedServer(mux)
	rsrv.Config.Protocols = new(http.Protocols)
	rsrv.Config.Protocols.SetHTTP1(true)
	rsrv.Config.Protocols.SetUnencryptedHTTP2(true)
	rsrv.Start()
	t.Cleanup(rsrv.Close)
	logs := &syncBuffer{}
	client := routerv1connect.NewSecretsRouteServiceClient(
		routerclient.New(rsrv.URL, token), rsrv.URL)
	h, err := New(client, Options{
		Host: host, PageDir: writePage(t), RequestsPerMinute: perMinute,
		Log: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.MaxHeaderBytes = 1 << 20
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{router: router, url: srv.URL, logs: logs}
}

type headers map[string]string

var (
	pageHeaders = headers{"Origin": origin, "Content-Type": "application/json",
		"Sec-Fetch-Site": "same-origin"}
	bridgeHeaders = headers{"Authorization": "Bearer " + grant}
)

// reply is one answer, its body read
type reply struct {
	status int
	header http.Header
	body   string
}

func (x *harness) call(t *testing.T, method, path string, body []byte, hd headers) reply {
	t.Helper()
	req, err := http.NewRequest(method, x.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hd {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reply{status: res.StatusCode, header: res.Header, body: string(raw)}
}

// merge copies base and sets more over it
func merge(base headers, more headers) headers {
	out := headers{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

const specJSONText = `{"name":"HF_TOKEN","hosts":["huggingface.co"],` +
	`"headerNames":[],"fetchOnly":false}`

func submitBodyText() []byte {
	return []byte(`{"spec":` + specJSONText + `,"value":{"keyId":"k1","box":"` + b64("sealed") +
		`"},"submissionId":"0b1d4a5e-1111-4222-8333-444455556666"}`)
}

func putBodyText() []byte {
	return []byte(`{"spec":` + specJSONText + `,"value":{"keyId":"k1","box":"` + b64("sealed") +
		`"},"idempotencyKey":"idem-1"}`)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
