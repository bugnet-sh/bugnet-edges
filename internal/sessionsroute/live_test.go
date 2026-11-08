package sessionsroute

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

func livePath(id string, seq int) string {
	return fmt.Sprintf("/v1/s/%s/jobs/%d/live", id, seq)
}

func liveBody(k, cursor string) string {
	return `{"k":"` + k + `","cursor":"` + cursor + `"}`
}

// held is a live stream that sends one frame and then stays open until the edge ends it
func held() script {
	return script{frames: []*routerv1.WatchSessionJobResponse{text("1", "x", false, false)},
		hold: true}
}

// openStream starts a live call over the test server and reads it up to its first event
func (x *harness) openStream(t *testing.T, id string) (*http.Response, *bufio.Reader) {
	t.Helper()
	req, _ := http.NewRequest("POST", x.origin+livePath(id, 1),
		strings.NewReader(liveBody(key, "")))
	req.Header = x.page()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	eq(t, res.StatusCode, 200)
	br := bufio.NewReader(res.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\n" {
			return res, br
		}
	}
}

// openDirect runs a live call from addr straight on the handler, until the returned stop
func (x *harness) openDirect(id, addr string) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(ctx, "POST", livePath(id, 1),
		strings.NewReader(liveBody(key, "")))
	r.RemoteAddr = addr
	r.Header = x.page()
	done := make(chan struct{})
	go func() {
		defer close(done)
		x.h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	return func() {
		cancel()
		<-done
	}
}

func TestLiveFrames(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) {
		f.live[3] = script{frames: []*routerv1.WatchSessionJobResponse{
			heartbeat(),
			text("c1", "ok 1\n<b>", false, false),
			text("", "held", true, true),
			skip("c2", 10, 20),
			text("bad\ncursor", "x", false, false),
			heartbeat(),
			exit(1, true, 512),
			end("exited"),
		}}
	})
	h := x.page()
	h.Set("Accept", "text/event-stream")
	r := x.do(t, "POST", livePath(id, 3), liveBody(key, "c0"), h)
	eq(t, r.StatusCode, 200)
	eq(t, r.Header.Get("Content-Type"), "text/event-stream")
	checkBundleHeaders(t, r.Header)
	eq(t, r.body, "event: out\nid: c1\ndata: {\"s\":\"o\",\"t\":\"ok 1\\n\\u003cb\\u003e\","+
		"\"cr\":false}\n\n"+
		"event: out\ndata: {\"s\":\"e\",\"t\":\"held\",\"cr\":true}\n\n"+
		"event: skip\nid: c2\ndata: {\"outBytes\":10,\"errBytes\":20}\n\n"+
		"event: out\ndata: {\"s\":\"o\",\"t\":\"x\",\"cr\":false}\n\n"+
		"event: exit\ndata: {\"exitCode\":1,\"oom\":true,\"peakMib\":512}\n\n"+
		"event: end\ndata: {\"reason\":\"exited\"}\n\n")

	x.router.mu.Lock()
	w := x.router.watches[0]
	x.router.mu.Unlock()
	eq(t, fmt.Sprint(w.GetId(), w.GetKey() == key, w.GetSeq(), w.GetCursor()),
		fmt.Sprint(id, true, 3, "c0"))
}

func TestLiveKeepalive(t *testing.T) {
	x := newHarness(t, func(o *Options) { o.Keepalive = 50 * time.Millisecond })
	x.router.set(func(f *fakeRouter) { f.live[1] = held() })
	_, br := x.openStream(t, id)
	for range 2 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		eq(t, line, ": keepalive\n")
		line, _ = br.ReadString('\n')
		eq(t, line, "\n")
	}
}

func TestLiveWaitsForTheFirstFrameOnlySoLong(t *testing.T) {
	x := newHarness(t, func(o *Options) { o.Keepalive = 50 * time.Millisecond })
	x.router.set(func(f *fakeRouter) { f.live[1] = script{hold: true} })
	req, _ := http.NewRequest("POST", x.origin+livePath(id, 1),
		strings.NewReader(liveBody(key, "")))
	req.Header = x.page()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	eq(t, res.StatusCode, 200)
	line, _ := bufio.NewReader(res.Body).ReadString('\n')
	eq(t, line, ": keepalive\n")
}

func TestLiveRefusals(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.live[1] = held() })
	// A wrong key, and a job the router does not know, are 404 and never cached as unknown
	wrong := newKey()
	for range 2 {
		r := x.do(t, "POST", livePath(id, 1), liveBody(wrong, ""), x.page())
		eq(t, r.StatusCode, 404)
		eq(t, r.body, "")
		eq(t, x.do(t, "POST", livePath(id, 9), liveBody(key, ""), x.page()).StatusCode, 404)
	}
	_, _, watches := x.router.counts()
	eq(t, watches, 4)
	// A router that is out of reach is 503, and the page retries
	x.router.set(func(f *fakeRouter) { f.err = context.DeadlineExceeded })
	r := x.do(t, "POST", livePath(id, 1), liveBody(key, ""), x.page())
	eq(t, r.StatusCode, 503)
	eq(t, r.Header.Get("Retry-After"), "2")
}

func TestLiveCaps(t *testing.T) {
	x := newHarness(t)
	other := newID()
	x.router.set(func(f *fakeRouter) {
		f.live[1] = held()
		f.records[other] = &record{key: key, res: f.records[id].res}
	})
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	// 4 per address
	for range 4 {
		stops = append(stops, x.openDirect(id, "198.51.100.1:4000"))
	}
	waitFor(t, "four streams", func() bool { return x.router.openStreams() == 4 })
	r := x.direct("POST", livePath(other, 1), liveBody(key, ""), "198.51.100.1:4000", x.page())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "5")

	// 8 per record, from any addresses
	for i := range 4 {
		stops = append(stops, x.openDirect(id, fmt.Sprintf("198.51.100.%d:4000", 10+i)))
	}
	waitFor(t, "eight streams", func() bool { return x.router.openStreams() == 8 })
	r = x.direct("POST", livePath(id, 1), liveBody(key, ""), "198.51.100.50:4000", x.page())
	eq(t, r.StatusCode, 429)
	stops = append(stops, x.openDirect(other, "198.51.100.50:4000"))
	waitFor(t, "a stream of another record", func() bool { return x.router.openStreams() == 9 })
	_, _, watches := x.router.counts()
	eq(t, watches, 9)

	for _, stop := range stops {
		stop()
	}
	stops = nil
	eq(t, x.h.live.count(), 0)
	waitFor(t, "the router's streams to end", func() bool { return x.router.openStreams() == 0 })
}

func TestLiveCapPerProcess(t *testing.T) {
	s := newStreams(8, 4, 256)
	var open []*liveStream
	for i := range 256 {
		ls, refusal := s.add(netip.AddrFrom4([4]byte{10, 0, byte(i), 1}))
		eq(t, refusal, 0)
		eq(t, s.join(ls, fmt.Sprintf("id%d", i)), true)
		open = append(open, ls)
	}
	_, refusal := s.add(netip.MustParseAddr("10.1.0.1"))
	eq(t, refusal, http.StatusTooManyRequests)
	s.remove(open[0])
	s.remove(open[0])
	eq(t, s.count(), 255)
	pending, refusal := s.add(netip.MustParseAddr("10.1.0.1"))
	eq(t, refusal, 0)

	// A stream not yet joined to its record still ends on shutdown
	s.closeAll()
	eq(t, <-open[1].stop, "")
	eq(t, <-pending.stop, "")
	_, refusal = s.add(netip.MustParseAddr("10.1.0.2"))
	eq(t, refusal, http.StatusServiceUnavailable)
}

func TestRecordCapCountsOnlyJoinedStreams(t *testing.T) {
	s := newStreams(2, 0, 0)
	var joined []*liveStream
	for i := range 2 {
		ls, _ := s.add(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
		eq(t, s.join(ls, "r"), true)
		joined = append(joined, ls)
	}
	pending, refusal := s.add(netip.MustParseAddr("10.0.1.1"))
	eq(t, refusal, 0)
	eq(t, s.join(pending, "r"), false)
	eq(t, s.join(pending, "other"), true)
	eq(t, s.join(pending, "other"), true)
	s.remove(joined[0])
	late, _ := s.add(netip.MustParseAddr("10.0.1.2"))
	eq(t, s.join(late, "r"), true)
	s.endRecord("r")
	eq(t, <-late.stop, reasonClosed)
	eq(t, len(pending.stop), 0)
}

func TestDeleteEndsLiveStreams(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.live[1] = held() })
	res, br := x.openStream(t, id)
	_, br2 := x.openStream(t, id)
	start := time.Now()
	eq(t, x.post(t, "DELETE", id, key).StatusCode, 204)
	for _, b := range []*bufio.Reader{br, br2} {
		rest, err := io.ReadAll(b)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, string(rest), "event: end\ndata: {\"reason\":\"closed\"}\n\n")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the streams ended after %s", took)
	}
	_ = res.Body.Close()
	waitFor(t, "the router's streams to end", func() bool { return x.router.openStreams() == 0 })
	eq(t, x.h.live.count(), 0)
}

func TestCloseEndsStreamsWithoutAnEnd(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.live[1] = held() })
	_, br := x.openStream(t, id)
	x.h.Close()
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, string(rest), "")
	r := x.do(t, "POST", livePath(id, 1), liveBody(key, ""), x.page())
	eq(t, r.StatusCode, 503)
	// Records still answer while the server drains
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)
}

func TestStalledReaderFreesItsSlot(t *testing.T) {
	x := newHarness(t, func(o *Options) { o.WriteTimeout = 200 * time.Millisecond })
	chunk := strings.Repeat("y", 32<<10)
	frames := make([]*routerv1.WatchSessionJobResponse, 1000)
	for i := range frames {
		frames[i] = text("", chunk, false, false)
	}
	x.router.set(func(f *fakeRouter) { f.live[1] = script{frames: frames, hold: true} })
	c, err := net.Dial("tcp", x.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	body := liveBody(key, "")
	_, _ = fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: x\r\nOrigin: %s\r\n"+
		"Sec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n%s", livePath(id, 1), x.origin, len(body), body)
	waitFor(t, "the stream to open", func() bool { return x.h.live.count() == 1 })
	// The client reads nothing, so a write meets its deadline and the slot is freed
	waitFor(t, "the slot to free", func() bool { return x.h.live.count() == 0 })
	waitFor(t, "the router's stream to end", func() bool { return x.router.openStreams() == 0 })
}

func TestWrongKeyOnAFullRecordIs404(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) { f.live[1] = held() })
	var stops []func()
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	for i := range 8 {
		stops = append(stops, x.openDirect(id, fmt.Sprintf("198.51.100.%d:4000", 10+i)))
	}
	waitFor(t, "eight streams", func() bool { return x.router.openStreams() == 8 })
	// A wrong key learns nothing of the record, full or not
	r := x.direct("POST", livePath(id, 1), liveBody(newKey(), ""), "203.0.113.5:4000", x.page())
	eq(t, r.StatusCode, 404)
	// The right key still meets the cap
	r = x.direct("POST", livePath(id, 1), liveBody(key, ""), "203.0.113.6:4000", x.page())
	eq(t, r.StatusCode, 429)
	eq(t, r.Header.Get("Retry-After"), "5")
}

func TestLiveNotFoundAfterTheWaitCountsAsAWrongKey(t *testing.T) {
	x := newHarness(t)
	x.router.set(func(f *fakeRouter) {
		f.live[1] = held()
		f.delay = 300 * time.Millisecond
	})
	r := x.do(t, "POST", livePath(id, 1), liveBody(newKey(), ""), x.page())
	eq(t, r.StatusCode, 200)
	eq(t, r.body, "")
	ids, offenders := x.h.ids.size()
	eq(t, fmt.Sprint(ids, offenders), "1 1")
}

func TestLiveNotFoundForARightKeyKeepsItRight(t *testing.T) {
	x := newHarness(t)
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)
	// A job the router will not stream, as for a placement not ready or past its deadline
	for range 3 {
		eq(t, x.do(t, "POST", livePath(id, 7), liveBody(key, ""), x.page()).StatusCode, 404)
	}
	ids, offenders := x.h.ids.size()
	eq(t, fmt.Sprint(ids, offenders), "0 0")
	eq(t, x.h.good.has(sha256.Sum256([]byte(id+"\x00"+key))), true)
	eq(t, x.post(t, "POST", id, key).StatusCode, 200)
}
