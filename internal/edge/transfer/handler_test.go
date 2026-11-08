package transfer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/oynozan/bugnet-edges/internal/lease"
	"github.com/oynozan/bugnet-edges/internal/routerclient"
	"github.com/oynozan/bugnet-edges/internal/strangers"
	"github.com/oynozan/bugnet-edges/internal/traffic"
)

const (
	mib        = 1 << 20
	edgeToken  = "edge-token-0123456789abcdefghijklmnop"
	shortWait  = 5 * time.Second
	pollPeriod = 10 * time.Millisecond
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

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

// harness is the transfer handler on a test server, calling a fake router
type harness struct {
	router *fakeRouter
	h      http.Handler
	addr   string // the edge's test server, host and port
	tr     *traffic.Traffic
	logs   *syncBuffer
}

func newHarness(t *testing.T, change ...func(*Deps)) *harness {
	t.Helper()
	f := newFakeRouter()
	base := f.serve(t)
	shared := routerv1connect.NewEdgeServiceClient(routerclient.New(base, edgeToken), base)
	newCall := func() routerv1connect.EdgeServiceClient {
		return routerv1connect.NewEdgeServiceClient(routerclient.PerCall(base, edgeToken), base)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tr := traffic.Edge(shared, traffic.Settings{
		ReporterID: "edge-test", ReportInterval: 100 * time.Millisecond, ReportBytes: 8 * mib,
	}, log)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Run(ctx)
	}()
	d := Deps{
		EdgeID:      "edge-test",
		Traffic:     tr,
		Guard:       strangers.NewGuard(20, strangers.Mark, strangers.Unknown),
		Conns:       strangers.NewConns(16),
		Chunk:       256 << 10,
		IdleTimeout: time.Minute,
		Log:         log,
	}
	for _, c := range change {
		c(&d)
	}
	h := New(shared, newCall, d)
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		cancel()
		<-done
	})
	return &harness{router: f, h: h, addr: srv.Listener.Addr().String(), tr: tr, logs: logs}
}

func (h *harness) upTok(size uint64) string {
	return h.router.add(&file{dir: upload, size: size, name: "in.bin"})
}

func (h *harness) downTok(data []byte) string {
	return h.router.add(&file{dir: download, data: data})
}

// rawReq is one HTTP/1.1 request written byte for byte
type rawReq struct {
	headers [][2]string
	chunked bool
	length  int // -1 sends no Content-Length
}

type opt func(*rawReq)

func contentLength(n int) opt {
	return func(r *rawReq) { r.length = n }
}

func chunked() opt {
	return func(r *rawReq) { r.chunked = true }
}

func header(k, v string) opt {
	return func(r *rawReq) { r.headers = append(r.headers, [2]string{k, v}) }
}

// reply is a response with its body read, err set when the body ended short
type reply struct {
	*http.Response
	body []byte
	err  error
}

func (a reply) code() string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(a.body, &v)
	return v.Error
}

// do sends one request on its own connection and reads the whole reply, from any goroutine
func (h *harness) do(t *testing.T, method, path, body string, opts ...opt) reply {
	t.Helper()
	r := rawReq{length: -1}
	for _, o := range opts {
		o(&r)
	}
	failed := reply{Response: &http.Response{Header: http.Header{}}}
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Error(err)
		return failed
	}
	defer func() { _ = c.Close() }()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: transfer.example.test\r\n", method, path)
	for _, kv := range r.headers {
		fmt.Fprintf(&b, "%s: %s\r\n", kv[0], kv[1])
	}
	switch {
	case r.chunked:
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		if body != "" {
			fmt.Fprintf(&b, "%x\r\n%s\r\n", len(body), body)
		}
		b.WriteString("0\r\n\r\n")
	case r.length >= 0:
		fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", r.length, body)
	default:
		b.WriteString("\r\n")
	}
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Error(err)
		return failed
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Errorf("%s %s: %v", method, path, err)
		return failed
	}
	got, err := io.ReadAll(res.Body)
	return reply{Response: res, body: got, err: err}
}

func (h *harness) get(t *testing.T, tok string, kv ...string) reply {
	t.Helper()
	var opts []opt
	for i := 0; i+1 < len(kv); i += 2 {
		opts = append(opts, header(kv[i], kv[i+1]))
	}
	return h.do(t, "GET", "/"+tok, "", opts...)
}

// waitFor polls cond until it holds or a few seconds pass
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(shortWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never saw %s", what)
		}
		time.Sleep(pollPeriod)
	}
}

// counted counts the bytes a client body gave away
type counted struct {
	r io.Reader
	n atomic.Int64
}

func (c *counted) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func TestUploadRefusedBeforeBody(t *testing.T) {
	h := newHarness(t)
	tok := h.router.add(&file{dir: upload, size: 5 * mib, used: true})
	body := &counted{r: bytes.NewReader(make([]byte, 5*mib))}
	req, _ := http.NewRequest("PUT", "http://"+h.addr+"/"+tok, body)
	req.ContentLength = 5 * mib
	req.Header.Set("Expect", "100-continue")
	c := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 10 * time.Second}}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	discard(res.Body)
	eq(t, res.StatusCode, 410)
	eq(t, body.n.Load(), int64(0))
	eq(t, h.router.bytesReceived(), int64(0))
}

func TestUploadLengthRules(t *testing.T) {
	h := newHarness(t)
	put := func(size uint64, body string, opts ...opt) reply {
		t.Helper()
		return h.do(t, "PUT", "/"+h.upTok(size), body, opts...)
	}
	eq(t, put(5, "12345", contentLength(5)).StatusCode, 200)
	eq(t, put(0, "", contentLength(0)).StatusCode, 200)
	eq(t, put(0, "", chunked()).StatusCode, 200)
	eq(t, put(5, "12345", chunked()).StatusCode, 200)
	eq(t, put(5, "123456", contentLength(6)).StatusCode, 413)
	eq(t, put(5, "1234", contentLength(4)).StatusCode, 400)
	opens := h.router.openCount()
	r := put(5, "12345", contentLength(5), header("Content-Range", "bytes 0-4/5"))
	eq(t, r.StatusCode, 400)
	eq(t, r.code(), "content_range")
	eq(t, h.router.openCount(), opens)

	// A short or long chunked body commits nothing
	short := h.upTok(5)
	r = h.do(t, "PUT", "/"+short, "1234", chunked())
	eq(t, r.StatusCode, 400)
	eq(t, r.code(), "size_mismatch")
	long := h.upTok(5)
	r = h.do(t, "PUT", "/"+long, "123456", chunked())
	eq(t, r.StatusCode, 413)
	eq(t, r.code(), "over_cap")
	for _, tok := range []string{short, long} {
		used, written, _ := h.router.used(tok)
		eq(t, used, false)
		eq(t, len(written), 0)
	}
}

func TestUploadAnswersPathSizeAndDigest(t *testing.T) {
	h := newHarness(t)
	tok := h.upTok(5)
	r := h.do(t, "PUT", "/"+tok+"/name.txt", "hello", contentLength(5))
	eq(t, r.StatusCode, 200)
	eq(t, r.Header.Get("Content-Type"), "application/json")
	var got map[string]any
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello"))
	eq(t, got, map[string]any{
		"path": "/root/in.bin", "size": float64(5), "sha256": hex.EncodeToString(sum[:]),
	})
	used, written, _ := h.router.used(tok)
	eq(t, used, true)
	eq(t, string(written), "hello")
}

func TestUploadOfSeveralMessagesAndAWrongDigest(t *testing.T) {
	h := newHarness(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), 70000)
	tok := h.upTok(uint64(len(data)))
	eq(t, h.do(t, "PUT", "/"+tok, string(data), contentLength(len(data))).StatusCode, 200)
	_, written, _ := h.router.used(tok)
	eq(t, bytes.Equal(written, data), true)

	bad := h.router.add(&file{dir: upload, size: 3, sha: make([]byte, 32)})
	r := h.do(t, "PUT", "/"+bad, "abc", contentLength(3))
	eq(t, r.StatusCode, 422)
	eq(t, r.code(), "checksum_mismatch")
}

func TestUploadCutMidBodyCommitsNothing(t *testing.T) {
	h := newHarness(t)
	tok := h.upTok(10 * mib)
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	head := "PUT /" + tok + " HTTP/1.1\r\nHost: x\r\nContent-Length: " +
		strconv.Itoa(10*mib) + "\r\n\r\n"
	_, _ = io.WriteString(c, head)
	_, _ = c.Write(make([]byte, 3*mib))
	waitFor(t, "the router reading", func() bool { return h.router.bytesReceived() > 0 })
	_ = c.Close()
	waitFor(t, "the stream aborted", func() bool { return h.router.abortedCount() == 1 })
	used, _, _ := h.router.used(tok)
	eq(t, used, false)
}

func TestUploadIdleIsCut(t *testing.T) {
	h := newHarness(t, func(d *Deps) { d.IdleTimeout = 300 * time.Millisecond })
	tok := h.upTok(10)
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = io.WriteString(c, "PUT /"+tok+" HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n12345")
	waitFor(t, "the stream aborted", func() bool { return h.router.abortedCount() == 1 })
	_ = c.SetReadDeadline(time.Now().Add(shortWait))
	rest, _ := io.ReadAll(c)
	eq(t, string(rest), "")
}

func TestLeaseEndCutsAnUploadWithItsReason(t *testing.T) {
	h := newHarness(t)
	tok := h.upTok(10)
	got := make(chan reply, 1)
	go func() { got <- h.do(t, "PUT", "/"+tok, "12345", contentLength(10)) }()
	waitFor(t, "the lease", func() bool {
		_, ok := h.tr.Leases.Get("p1")
		return ok
	})
	waitFor(t, "the router reading", func() bool { return h.router.bytesReceived() > 0 })
	h.tr.Leases.End("p1", lease.ReasonBudget)
	r := <-got
	eq(t, r.StatusCode, 429)
	eq(t, r.code(), "budget_spent")
	waitFor(t, "the stream aborted", func() bool { return h.router.abortedCount() == 1 })
}

func TestDownloadRanges(t *testing.T) {
	h := newHarness(t)
	data := []byte("0123456789")
	r := h.get(t, h.downTok(data), "Range", "bytes=4-")
	eq(t, r.StatusCode, 206)
	eq(t, string(r.body), "456789")
	eq(t, r.Header.Get("Content-Range"), "bytes 4-9/10")
	eq(t, r.Header.Get("Content-Length"), "6")

	r = h.get(t, h.downTok(data), "Range", "bytes=2-3")
	eq(t, r.StatusCode, 206)
	eq(t, string(r.body), "23")
	eq(t, r.Header.Get("Content-Range"), "bytes 2-3/10")

	r = h.get(t, h.downTok(data), "Range", "bytes=-3")
	eq(t, r.StatusCode, 206)
	eq(t, string(r.body), "789")

	r = h.get(t, h.downTok(data), "Range", "bytes=0-1,4-5")
	eq(t, r.StatusCode, 200)
	eq(t, string(r.body), "0123456789")

	tok := h.downTok(data)
	r = h.get(t, tok, "Range", "bytes=20-")
	eq(t, r.StatusCode, 416)
	eq(t, r.code(), "range")
	eq(t, r.Header.Get("Content-Range"), "bytes */10")
	eq(t, h.get(t, h.downTok(data), "Range", "bytes=10-").StatusCode, 416)

	r = h.get(t, h.downTok(data), "Range", "bytes=4-", "If-Range", `"other"`)
	eq(t, r.StatusCode, 200)
	eq(t, string(r.body), "0123456789")
	r = h.get(t, h.downTok(data), "Range", "bytes=4-", "If-Range", `"a-1"`)
	eq(t, r.StatusCode, 206)
	eq(t, h.get(t, h.downTok(data), "Range", "lines=1-2").StatusCode, 200)
	eq(t, h.get(t, h.downTok(data), "Range", "bytes=5-2").StatusCode, 200)
}

func TestARefusedRangeLetsTheClaimGo(t *testing.T) {
	h := newHarness(t)
	h.get(t, h.downTok([]byte("0123456789")), "Range", "bytes=20-")
	waitFor(t, "the release", func() bool {
		h.router.mu.Lock()
		defer h.router.mu.Unlock()
		return len(h.router.reads) == 1 && h.router.reads[0].GetOffset() == 11
	})
}

func TestDownloadHeaders(t *testing.T) {
	h := newHarness(t)
	sum := sha256.Sum256([]byte("abc"))
	tok := h.router.add(&file{dir: download, data: []byte("abc"), name: "re\x01po\nrt\x7f.csv",
		sha: sum[:], etag: `"3-abc"`})
	r := h.get(t, tok)
	eq(t, r.StatusCode, 200)
	want := map[string]string{
		"Content-Length":          "3",
		"Etag":                    `"3-abc"`,
		"Accept-Ranges":           "bytes",
		"Content-Type":            "application/octet-stream",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "sandbox; default-src 'none'",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Bugnet-Sha256":         hex.EncodeToString(sum[:]),
	}
	for k, v := range want {
		eq(t, k+": "+r.Header.Get(k), k+": "+v)
	}
	kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, kind, "attachment")
	eq(t, params["filename"], "report.csv")

	r = h.get(t, h.router.add(&file{dir: download, data: []byte("x"), name: "résumé.pdf"}))
	_, params, _ = mime.ParseMediaType(r.Header.Get("Content-Disposition"))
	eq(t, params["filename"], "résumé.pdf")
	eq(t, r.Header.Get("X-Bugnet-Sha256"), "")
}

func TestZeroByteDownload(t *testing.T) {
	h := newHarness(t)
	tok := h.downTok(nil)
	r := h.get(t, tok)
	eq(t, r.StatusCode, 200)
	eq(t, r.Header.Get("Content-Length"), "0")
	eq(t, len(r.body), 0)
	eq(t, r.err, nil)
	used, _, _ := h.router.used(tok)
	eq(t, used, true)
}

func TestDownloadAbortsWithoutVerified(t *testing.T) {
	h := newHarness(t)
	data := bytes.Repeat([]byte("x"), mib)
	r := h.get(t, h.router.add(&file{dir: download, data: data, unverified: true}))
	eq(t, r.StatusCode, 200)
	if r.err == nil || len(r.body) >= len(data) {
		t.Fatalf("an unverified download ended cleanly with %d of %d bytes", len(r.body),
			len(data))
	}
	eq(t, len(r.body), 3*256<<10)

	// The router fails after two messages, so one went out and the connection is cut
	r = h.get(t, h.router.add(&file{dir: download, data: data, failAfter: 2}))
	eq(t, r.StatusCode, 200)
	eq(t, len(r.body), 256<<10)
	if r.err == nil {
		t.Fatal("a failed download ended cleanly")
	}

	// A failure before the second message leaves time to reply it
	r = h.get(t, h.router.add(&file{dir: download, data: data, failAfter: 1}))
	eq(t, r.StatusCode, 412)
	eq(t, r.code(), "file_changed")
}

func TestFourStalledUploadsNeverBlockAFifth(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stalled []string
	for range 4 {
		tok := h.router.add(&file{dir: upload, size: 4 * mib, stall: release})
		stalled = append(stalled, tok)
		go func() {
			req, _ := http.NewRequestWithContext(ctx, "PUT", "http://"+h.addr+"/"+tok,
				bytes.NewReader(make([]byte, 4*mib)))
			if res, err := http.DefaultClient.Do(req); err == nil {
				discard(res.Body)
			}
		}()
	}
	waitFor(t, "four stalled uploads", func() bool {
		for _, n := range h.router.gotBytes(stalled...) {
			if n == 0 {
				return false
			}
		}
		return true
	})
	time.Sleep(200 * time.Millisecond)

	tok := h.upTok(mib)
	done := make(chan int, 1)
	go func() {
		done <- h.do(t, "PUT", "/"+tok, string(make([]byte, mib)), contentLength(mib)).StatusCode
	}()
	select {
	case code := <-done:
		eq(t, code, 200)
	case <-time.After(shortWait):
		t.Fatal("the fifth upload waited on the four stalled ones")
	}
}

func TestUnknownTokensFromOneIP(t *testing.T) {
	h := newHarness(t)
	for i := range 20 {
		r := h.get(t, newToken())
		eq(t, fmt.Sprint(i, r.StatusCode), fmt.Sprint(i, 404))
		eq(t, r.code(), "token_unknown")
	}
	r := h.get(t, newToken())
	eq(t, r.StatusCode, 429)
	eq(t, r.code(), "rate_limited")
	eq(t, r.Header.Get("Retry-After"), "600")

	valid := h.get(t, h.downTok([]byte("ok")))
	eq(t, valid.StatusCode, 200)
	eq(t, string(valid.body), "ok")

	// A marked address sends at most one token a second to the router, the rest wait a second
	opens := h.router.openCount()
	r = h.get(t, h.downTok([]byte("ok")))
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "1")
	eq(t, h.get(t, newToken()).StatusCode, 429)
	eq(t, h.router.openCount(), opens)
}

func TestUnknownTokenCachedTenSeconds(t *testing.T) {
	h := newHarness(t)
	tok := newToken()
	eq(t, h.get(t, tok).StatusCode, 404)
	eq(t, h.router.openCount(), 1)
	eq(t, h.get(t, tok).StatusCode, 404)
	eq(t, h.router.openCount(), 1)

	// A token that cannot be one never reaches the router
	for _, bad := range []string{"bnx_short", "bnp_" + tok[4:], tok + "A", "x"} {
		eq(t, h.get(t, bad).StatusCode, 404)
	}
	eq(t, h.router.openCount(), 1)
}

func TestSixteenConnectionsPerIP(t *testing.T) {
	h := newHarness(t)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for range 16 {
		c, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_, _ = io.WriteString(c, "PUT /"+h.upTok(10)+" HTTP/1.1\r\nHost: x\r\n"+
			"Content-Length: 10\r\n\r\n")
	}
	waitFor(t, "sixteen open transfers", func() bool { return h.router.openCount() == 16 })
	r := h.get(t, newToken())
	eq(t, r.StatusCode, 429)
	eq(t, r.code(), "rate_limited")
	eq(t, h.router.openCount(), 16)

	// Another address still gets through
	req := httptest.NewRequest("GET", "/"+newToken(), nil)
	req.RemoteAddr = "198.51.100.7:4000"
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	eq(t, w.Code, 404)

	_ = conns[0].Close()
	waitFor(t, "a free slot", func() bool { return h.get(t, newToken()).StatusCode == 404 })
}

func TestTransferBytesReachUsage(t *testing.T) {
	h := newHarness(t)
	up := string(make([]byte, 3*mib))
	eq(t, h.do(t, "PUT", "/"+h.upTok(3*mib), up, contentLength(3*mib)).StatusCode, 200)
	eq(t, h.get(t, h.downTok(make([]byte, 2*mib))).StatusCode, 200)
	waitFor(t, "the bytes reported", func() bool {
		return h.router.usageOf("p1") == [2]uint64{3 * mib, 2 * mib}
	})
}

func TestTransferLogsOnlyHashPrefix(t *testing.T) {
	h := newHarness(t)
	up, down, unknown := h.upTok(2), h.downTok([]byte("ab")), newToken()
	used := h.router.add(&file{dir: download, data: []byte("x"), used: true})
	h.do(t, "PUT", "/"+up+"/secret-name.txt", "ab", contentLength(2))
	h.get(t, down)
	h.get(t, unknown)
	h.get(t, used)
	logs := h.logs.String()
	for _, tok := range []string{up, down, unknown, used} {
		if strings.Contains(logs, tok) || strings.Contains(logs, tok[4:20]) {
			t.Fatalf("a token reached the log\n%s", logs)
		}
		if !strings.Contains(logs, transferID(tok)[:8]) {
			t.Fatalf("no hash prefix %s in the log\n%s", transferID(tok)[:8], logs)
		}
		if strings.Contains(logs, transferID(tok)[:9]) {
			t.Fatalf("more than 8 hex characters of a hash in the log\n%s", logs)
		}
	}
	if strings.Contains(logs, "secret-name") {
		t.Fatalf("a path reached the log\n%s", logs)
	}
}

func TestHeadProbesWithoutClaim(t *testing.T) {
	h := newHarness(t)
	tok := h.downTok([]byte("0123456789"))
	r := h.do(t, "HEAD", "/"+tok, "")
	eq(t, r.StatusCode, 200)
	eq(t, r.Header.Get("Content-Length"), "10")
	eq(t, r.Header.Get("Accept-Ranges"), "bytes")
	eq(t, len(r.body), 0)
	eq(t, h.router.lastOpen().GetProbe(), true)
	eq(t, h.router.lastOpen().GetDirection(), download)
	_, _, claims := h.router.used(tok)
	eq(t, claims, 0)

	r = h.get(t, tok)
	eq(t, r.StatusCode, 200)
	eq(t, string(r.body), "0123456789")
	eq(t, h.router.lastOpen().GetProbe(), false)
	eq(t, h.router.lastOpen().GetEdgeId(), "edge-test")
	_, _, claims = h.router.used(tok)
	eq(t, claims, 1)
}

func TestMethodsOtherThanTheDirections(t *testing.T) {
	h := newHarness(t)
	r := h.do(t, "POST", "/"+newToken(), "")
	eq(t, r.StatusCode, 405)
	eq(t, r.code(), "method")
	eq(t, r.Header.Get("Allow"), "GET, HEAD, PUT")
	eq(t, h.router.openCount(), 0)

	r = h.do(t, "PUT", "/"+h.downTok([]byte("x")), "x", contentLength(1))
	eq(t, r.StatusCode, 405)
	r = h.get(t, h.upTok(1))
	eq(t, r.StatusCode, 405)
}

func TestRouterRefusalsAsDP86(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{refusal(connect.CodeFailedPrecondition, "TOKEN_USED"), 410, "token_used"},
		{refusal(connect.CodeFailedPrecondition, "TOKEN_EXPIRED"), 410, "token_expired"},
		{refusal(connect.CodeFailedPrecondition, "IN_USE"), 409, "in_use"},
		{refusal(connect.CodeFailedPrecondition, "FILE_CHANGED"), 412, "file_changed"},
		{refusal(connect.CodeNotFound, "FILE_NOT_FOUND"), 412, "file_changed"},
		{refusal(connect.CodeInvalidArgument, "NOT_REGULAR"), 412, "file_changed"},
		{refusal(connect.CodeFailedPrecondition, "NOT_READY"), 410, "sandbox_ended"},
		{refusal(connect.CodeResourceExhausted, "BUDGET_SPENT"), 429, "budget_spent"},
		{refusal(connect.CodeResourceExhausted, "TOO_MANY_TRANSFERS"), 429,
			"too_many_transfers"},
		{refusal(connect.CodeResourceExhausted, "RATE_LIMITED"), 503, "unavailable"},
		{refusal(connect.CodeOutOfRange, "OVER_CAP"), 413, "over_cap"},
		{refusal(connect.CodeResourceExhausted, "NO_SPACE"), 507, "no_space"},
		{connect.NewError(connect.CodeUnavailable, fmt.Errorf("down")), 503, "unavailable"},
		{connect.NewError(connect.CodeInternal, fmt.Errorf("boom")), 503, "unavailable"},
	} {
		h := newHarness(t)
		h.router.openErr = tc.err
		r := h.get(t, newToken())
		eq(t, fmt.Sprint(tc.err, r.StatusCode, r.code()), fmt.Sprint(tc.err, tc.status, tc.code))
	}
}
