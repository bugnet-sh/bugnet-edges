package sessionsroute

import (
	"bytes"
	"context"
	"crypto/rand"
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
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/oynozan/bugnet-edges/internal/routerclient"
)

const (
	sessionsToken = "sessions-token-0123456789abcdefghijk"
	// id is the one record most tests read, with key its right key
	id = "k3fz2q7mak3fz2q7"
	// testHeaders is the headers.txt of the session page's build
	testHeaders = "Cache-Control: no-store\n" +
		"Referrer-Policy: no-referrer\n" +
		"X-Content-Type-Options: nosniff\n" +
		"Cross-Origin-Opener-Policy: same-origin\n" +
		"X-Robots-Tag: noindex, nofollow, noarchive\n" +
		"Document-Policy: force-load-at-top\n" +
		"Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; " +
		"img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; " +
		"form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; " +
		"trusted-types 'none'\n"
	indexHTML = "<!doctype html><title>Bugnet session</title><script src=\"/assets/page-ABC.js\">"
)

var (
	key        = newKey()
	fakeRecord = []byte(`{"v":1,  "endedBecause":"deadline","events":[],"t":" <b>"}`)
	fakeLive   = []byte(`{"v":1,"jobs":[ ]}`)
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func newKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "bnk_" + base64.RawURLEncoding.EncodeToString(b)
}

// newID is a random id of the right shape
func newID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

/* The fake router */

type record struct {
	key     string
	res     *routerv1.GetSessionRecordResponse
	deleted bool
}

// script is one job's live stream, its frames and then an end of the call or a hold
type script struct {
	frames []*routerv1.WatchSessionJobResponse
	// hold keeps the call open after the frames until the edge ends it
	hold bool
}

// fakeRouter is a SessionPageService over memory that records every call
type fakeRouter struct {
	routerv1connect.UnimplementedSessionPageServiceHandler

	mu      sync.Mutex
	records map[string]*record
	live    map[uint32]script
	gets    int
	deletes int
	watches []*routerv1.WatchSessionJobRequest
	open    int
	// err, when set, answers every call
	err error
	// delay holds every call this long before it answers
	delay time.Duration
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{records: map[string]*record{
		id: {key: key, res: &routerv1.GetSessionRecordResponse{State: "ended",
			RecordJson: fakeRecord}},
	}, live: map[uint32]script{}}
}

func refusal(code connect.Code, reason string) *connect.Error {
	ce := connect.NewError(code, errors.New(reason))
	d, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: "bugnet.router"})
	ce.AddDetail(d)
	return ce
}

func (f *fakeRouter) find(id, key string) (*record, error) {
	if f.err != nil {
		return nil, f.err
	}
	r, ok := f.records[id]
	if !ok || r.deleted || r.key != key {
		return nil, refusal(connect.CodeNotFound, "SESSION_UNKNOWN")
	}
	return r, nil
}

func (f *fakeRouter) GetSessionRecord(
	ctx context.Context, req *connect.Request[routerv1.GetSessionRecordRequest],
) (*connect.Response[routerv1.GetSessionRecordResponse], error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	r, err := f.find(req.Msg.GetId(), req.Msg.GetKey())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(r.res), nil
}

func (f *fakeRouter) DeleteSessionRecord(
	ctx context.Context, req *connect.Request[routerv1.DeleteSessionRecordRequest],
) (*connect.Response[routerv1.DeleteSessionRecordResponse], error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	r, err := f.find(req.Msg.GetId(), req.Msg.GetKey())
	if err != nil {
		return nil, err
	}
	r.deleted = true
	return connect.NewResponse(&routerv1.DeleteSessionRecordResponse{}), nil
}

func (f *fakeRouter) WatchSessionJob(
	ctx context.Context, req *connect.Request[routerv1.WatchSessionJobRequest],
	stream *connect.ServerStream[routerv1.WatchSessionJobResponse],
) error {
	if err := f.wait(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	f.watches = append(f.watches, req.Msg)
	_, err := f.find(req.Msg.GetId(), req.Msg.GetKey())
	s, ok := f.live[req.Msg.GetSeq()]
	if err == nil && !ok {
		err = refusal(connect.CodeNotFound, "SESSION_UNKNOWN")
	}
	if err == nil {
		f.open++
	}
	f.mu.Unlock()
	if err != nil {
		return err
	}
	defer func() {
		f.mu.Lock()
		f.open--
		f.mu.Unlock()
	}()
	for _, m := range s.frames {
		if err := stream.Send(m); err != nil {
			return err
		}
	}
	if s.hold {
		<-ctx.Done()
	}
	return nil
}

// wait holds a call for the fake's delay, or until the edge ends it
func (f *fakeRouter) wait(ctx context.Context) error {
	f.mu.Lock()
	d := f.delay
	f.mu.Unlock()
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeRouter) counts() (gets, deletes, watches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.deletes, len(f.watches)
}

func (f *fakeRouter) openStreams() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func (f *fakeRouter) set(fn func(f *fakeRouter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// serve runs the fake over h2c and HTTP/1.1 until the test ends
func (f *fakeRouter) serve(t *testing.T) string {
	mux := http.NewServeMux()
	mux.Handle(routerv1connect.NewSessionPageServiceHandler(f))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

/* Frames */

func text(cursor, s string, stderr, cr bool) *routerv1.WatchSessionJobResponse {
	side := routerv1.OutputStream_OUTPUT_STREAM_STDOUT
	if stderr {
		side = routerv1.OutputStream_OUTPUT_STREAM_STDERR
	}
	return &routerv1.WatchSessionJobResponse{Cursor: cursor,
		Frame: &routerv1.WatchSessionJobResponse_Text{Text: &routerv1.SessionText{
			Stream: side, Text: s, Overwrite: cr}}}
}

func heartbeat() *routerv1.WatchSessionJobResponse {
	return &routerv1.WatchSessionJobResponse{
		Frame: &routerv1.WatchSessionJobResponse_Heartbeat{Heartbeat: true}}
}

func skip(cursor string, out, errs uint64) *routerv1.WatchSessionJobResponse {
	return &routerv1.WatchSessionJobResponse{Cursor: cursor,
		Frame: &routerv1.WatchSessionJobResponse_Skip{Skip: &routerv1.JobSkip{
			StdoutOffset: out, StderrOffset: errs}}}
}

func exit(code int32, oom bool, peak uint32) *routerv1.WatchSessionJobResponse {
	return &routerv1.WatchSessionJobResponse{
		Frame: &routerv1.WatchSessionJobResponse_Exit{Exit: &routerv1.JobExit{
			ExitCode: code, OomKilled: oom, PeakMemoryMib: peak}}}
}

func end(reason string) *routerv1.WatchSessionJobResponse {
	return &routerv1.WatchSessionJobResponse{
		Frame: &routerv1.WatchSessionJobResponse_End{End: &routerv1.SessionEnd{Reason: reason}}}
}

/* The bundle */

// writeBundle puts a small page bundle in a new directory, as the page's build lays it out
func writeBundle(t *testing.T, headers string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"headers.txt":                  headers,
		"index.html":                   indexHTML + strings.Repeat("<p>page</p>", 50),
		"assets/page-ABC.js":           strings.Repeat("console.log(1);", 50),
		"assets/page-DEF.css":          strings.Repeat("body{margin:0}", 50),
		"assets/manrope-400-XYZ.woff2": "wOF2 font bytes",
		"assets/icon-QRS.svg":          "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
		"assets/notes.txt":             "never served",
		"assets/Bad_Name.js":           "never served",
	}
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

/* The harness */

// syncBuffer is a log sink handlers write while the test reads it
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

// harness is the route on a test server, calling a fake router
type harness struct {
	router *fakeRouter
	h      *Handler
	srv    *httptest.Server
	origin string
	logs   *syncBuffer
}

// defaultOptions are SP 7.4's limits with short live timings
func defaultOptions() Options {
	return Options{
		RequestsPerMinute: 60, KeyFailuresPerMinute: 20, IDFailuresPerMinute: 20,
		LivePerRecord: 8, LivePerIP: 4, LiveMax: 256,
		Keepalive: time.Hour, FirstFrame: 100 * time.Millisecond,
	}
}

func newHarness(t *testing.T, change ...func(*Options)) *harness {
	t.Helper()
	f := newFakeRouter()
	base := f.serve(t)
	shared := routerv1connect.NewSessionPageServiceClient(
		routerclient.New(base, sessionsToken), base)
	newCall := func() routerv1connect.SessionPageServiceClient {
		return routerv1connect.NewSessionPageServiceClient(
			routerclient.PerCall(base, sessionsToken), base)
	}
	bundle, err := LoadBundle(writeBundle(t, testHeaders))
	if err != nil {
		t.Fatal(err)
	}
	x := &harness{router: f, logs: &syncBuffer{}}
	x.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		x.h.ServeHTTP(w, r)
	}))
	x.srv.Config.MaxHeaderBytes = 4 << 20
	x.srv.Start()
	x.origin = x.srv.URL
	o := defaultOptions()
	o.Origin, o.Bundle = x.origin, bundle
	o.Log = slog.New(slog.NewTextHandler(x.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	for _, c := range change {
		c(&o)
	}
	x.h = New(shared, newCall, o)
	t.Cleanup(func() {
		x.h.Close()
		x.srv.CloseClientConnections()
		x.srv.Close()
	})
	return x
}

// reply is one answer, its body read whole
type reply struct {
	*http.Response
	body string
}

// page is the headers the session page's fetch sends to its own origin
func (x *harness) page() http.Header {
	return http.Header{
		"Content-Type":   {"application/json"},
		"Origin":         {x.origin},
		"Sec-Fetch-Site": {"same-origin"},
	}
}

// do sends one request over the test server, with extra headers replacing the page's
func (x *harness) do(t *testing.T, method, path, body string, h http.Header) reply {
	t.Helper()
	req, err := http.NewRequest(method, x.origin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		req.Header = h
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reply{res, string(b)}
}

// post sends a page call with key k for record id
func (x *harness) post(t *testing.T, method, id, k string) reply {
	t.Helper()
	return x.do(t, method, "/v1/s/"+id, `{"k":"`+k+`"}`, x.page())
}

// direct runs the handler on one request from addr, without a server between
func (x *harness) direct(method, path, body, addr string, h http.Header) *http.Response {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = addr
	if h != nil {
		r.Header = h
	}
	w := httptest.NewRecorder()
	x.h.ServeHTTP(w, r)
	return w.Result()
}

// waitFor polls cond for up to 5 s
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
