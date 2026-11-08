package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
	"weak"

	"github.com/oynozan/bugnet-edges/internal/metrics"
)

var (
	errBroken       = errors.New("connection reset")
	errStillBlocked = errors.New("still blocked after a second")
)

// pattern is n bytes that differ from place to place, so a reordered byte shows
func pattern(n int64) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(b)
	return b
}

// far is a deadline no test reaches
func far() time.Time {
	return time.Now().Add(5 * time.Second)
}

// split cuts b into n chunks of nearly equal size
func split(b []byte, n int) [][]byte {
	var chunks [][]byte
	size := (len(b) + n - 1) / n
	for len(b) > size {
		chunks = append(chunks, b[:size])
		b = b[size:]
	}
	return append(chunks, b)
}

// arriving is a body whose chunks arrive gap apart, then ends
func arriving(t *testing.T, chunks [][]byte, gap time.Duration) io.Reader {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		for i, c := range chunks {
			if i > 0 {
				time.Sleep(gap)
			}
			if _, err := pw.Write(c); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()
	return pr
}

// gated is a body that sends first, then waits for release before it sends rest and ends with end
func gated(t *testing.T, first, rest []byte, end error) (io.Reader, chan<- struct{}) {
	t.Helper()
	pr, pw := io.Pipe()
	release, stop := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = pr.Close()
	})
	go func() {
		if _, err := pw.Write(first); err != nil {
			return
		}
		select {
		case <-release:
		case <-stop:
			return
		}
		if _, err := pw.Write(rest); err != nil {
			return
		}
		_ = pw.CloseWithError(end)
	}()
	return pr, release
}

// wait is Wait with a bound, failing the test on an error
func wait(t *testing.T, r *Replay) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

// same fails the test when two byte slices differ, without printing them
func same(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d bytes, and they differ", len(got), len(want))
	}
}

// drain reads r to its end, failing the test on another error
func drain(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

func TestReplayKeepsAndHashes(t *testing.T) {
	body := pattern(mib)
	r := ReadReplay(bytes.NewReader(body), mib, far())
	wait(t, r)
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
	eq(t, r.Sum, sha256.Sum256(body))
	same(t, drain(t, r.Upstream), body)

	const emptySum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, limit := range []int64{mib, 0} {
		r = ReadReplay(http.NoBody, limit, far())
		wait(t, r)
		eq(t, r.Mark, Code(""))
		eq(t, len(r.Kept), 0)
		eq(t, hex.EncodeToString(r.Sum[:]), emptySum)
		same(t, drain(t, r.Upstream), nil)
	}
}

func TestReplayReadsWithoutTheUpstream(t *testing.T) {
	body := pattern(512 * kib)
	start := time.Now()
	r := ReadReplay(arriving(t, split(body, 4), 100*time.Millisecond), mib, far())
	wait(t, r)
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("Wait returned after %v, before the last chunk", took)
	}
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
	eq(t, r.Sum, sha256.Sum256(body))
}

func TestReplayBodySlow(t *testing.T) {
	body := pattern(10 + 100*kib)
	in, release := gated(t, body[:10], body[10:], nil)
	r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	wait(t, r)
	eq(t, r.Mark, CodeBodySlow)
	eq(t, len(r.Kept), 0)
	eq(t, r.Sum, [32]byte{})

	close(release)
	same(t, drain(t, r.Upstream), body)
}

func TestReplayGrowsPastMax(t *testing.T) {
	body := pattern(mib + 10)
	for name, in := range map[string]func(*testing.T) io.Reader{
		"whole": func(*testing.T) io.Reader { return bytes.NewReader(body) },
		"chunked": func(t *testing.T) io.Reader {
			return arriving(t, split(body, 9), time.Millisecond)
		},
		"halves": func(*testing.T) io.Reader { return iotest.HalfReader(bytes.NewReader(body)) },
	} {
		t.Run(name, func(t *testing.T) {
			r := ReadReplay(in(t), mib, far())
			wait(t, r)
			eq(t, r.Mark, CodeBodyTooLarge)
			eq(t, len(r.Kept), 0)
			eq(t, r.Sum, [32]byte{})
			same(t, drain(t, iotest.HalfReader(r.Upstream)), body)
		})
	}
}

func TestReplayExactlyMaxIsWhole(t *testing.T) {
	body := pattern(mib)
	r := ReadReplay(arriving(t, split(body, 4), time.Millisecond), mib, far())
	wait(t, r)
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
	same(t, drain(t, r.Upstream), body)
}

func TestReplayUpstreamStreamsAsItArrives(t *testing.T) {
	body := pattern(10 + 100*kib)
	in, release := gated(t, body[:10], body[10:], nil)
	r := ReadReplay(in, mib, far())

	head := make([]byte, 10)
	if _, err := io.ReadFull(r.Upstream, head); err != nil {
		t.Fatal(err)
	}
	same(t, head, body[:10])

	close(release)
	same(t, drain(t, r.Upstream), body[10:])
	wait(t, r)
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
}

func TestReplayUpstreamWhileKeeping(t *testing.T) {
	body := pattern(700 * kib)
	r := ReadReplay(arriving(t, split(body, 7), 5*time.Millisecond), mib, far())
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(iotest.HalfReader(r.Upstream))
		got <- b
	}()
	wait(t, r)
	same(t, r.Kept, body)
	same(t, <-got, body)
}

func TestReplayDataWithTheEnd(t *testing.T) {
	body := pattern(200 * kib)
	r := ReadReplay(iotest.DataErrReader(bytes.NewReader(body)), mib, far())
	wait(t, r)
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
	same(t, drain(t, r.Upstream), body)
}

func TestReplayReadError(t *testing.T) {
	body := pattern(64 * kib)
	in := io.MultiReader(bytes.NewReader(body), iotest.ErrReader(errBroken))
	r := ReadReplay(in, mib, far())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.Wait(ctx); !errors.Is(err, errBroken) {
		t.Fatalf("Wait gave %v, want %v", err, errBroken)
	}
	eq(t, r.Mark, Code(""))
	eq(t, len(r.Kept), 0)
	eq(t, r.Sum, [32]byte{})
	got, err := io.ReadAll(r.Upstream)
	same(t, got, body)
	eq(t, errors.Is(err, errBroken), true)
}

func TestReplayShortBodyKeepsNothing(t *testing.T) {
	body := pattern(10)
	in, release := gated(t, body, nil, io.ErrUnexpectedEOF)
	r := ReadReplay(in, mib, far())
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.Wait(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Wait gave %v, want %v", err, io.ErrUnexpectedEOF)
	}
	eq(t, r.Kept == nil, true)
	eq(t, r.Sum, [32]byte{})
}

func TestReplayErrorAfterTheMark(t *testing.T) {
	body := pattern(20)
	in, release := gated(t, body[:10], body[10:], errBroken)
	r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	wait(t, r)
	eq(t, r.Mark, CodeBodySlow)

	close(release)
	got, err := io.ReadAll(r.Upstream)
	same(t, got, body)
	eq(t, errors.Is(err, errBroken), true)
}

func TestReplayWaitHonoursTheContext(t *testing.T) {
	in, _ := gated(t, nil, nil, nil)
	r := ReadReplay(in, mib, far())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	eq(t, errors.Is(r.Wait(ctx), context.DeadlineExceeded), true)
}

func TestReplayMarkFreesItsUnusedRoom(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)

	in, release := gated(t, pattern(10), pattern(10), nil)
	r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	r.FreeOnMark(take(t, b, "pl_slow", mib))
	wait(t, r)
	eq(t, r.Mark, CodeBodySlow)
	eq(t, b.Held("pl_slow"), int64(10))
	close(release)

	r = ReadReplay(bytes.NewReader(pattern(mib+1)), mib, far())
	r.FreeOnMark(take(t, b, "pl_large", mib))
	wait(t, r)
	eq(t, r.Mark, CodeBodyTooLarge)
	eq(t, b.Held("pl_large"), mib)

	r = ReadReplay(bytes.NewReader(pattern(mib)), mib, far())
	r.FreeOnMark(take(t, b, "pl_whole", mib))
	wait(t, r)
	eq(t, r.Mark, Code(""))
	eq(t, b.Held("pl_whole"), mib)
	drain(t, r.Upstream)
	r.Close()
	eq(t, b.Held("pl_whole"), mib)

	in, _ = gated(t, pattern(10), nil, nil)
	r = ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	wait(t, r)
	r.FreeOnMark(take(t, b, "pl_late", mib))
	eq(t, b.Held("pl_late"), int64(10))
	r.Close()
	eq(t, b.Held("pl_late"), int64(0))
	eq(t, b.Total(), int64(10)+mib+mib)
}

// gauge is what egress_x402_buffer_bytes reads at a scrape of reg
func gauge(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	var out strings.Builder
	if _, err := reg.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(out.String()) {
		if v, ok := strings.CutPrefix(line, "egress_x402_buffer_bytes "); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatal("no egress_x402_buffer_bytes in the scrape")
	return ""
}

func TestMarkedKeepsKeptRoomUntilSent(t *testing.T) {
	t.Run("body_slow", func(t *testing.T) {
		b := NewBuffers(256*mib, 4*mib)
		reg := metrics.New()
		b.Export(reg)
		body := pattern(10)
		in, _ := gated(t, body, nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		r.FreeOnMark(take(t, b, "pl_a", mib))
		wait(t, r)
		eq(t, r.Mark, CodeBodySlow)
		eq(t, r.Kept == nil, true)
		eq(t, b.Held("pl_a"), int64(10))
		eq(t, gauge(t, reg), "10")

		head := make([]byte, 9)
		if _, err := io.ReadFull(r.Upstream, head); err != nil {
			t.Fatal(err)
		}
		eq(t, b.Held("pl_a"), int64(10))
		last := make([]byte, 1)
		if _, err := io.ReadFull(r.Upstream, last); err != nil {
			t.Fatal(err)
		}
		same(t, append(head, last...), body)
		eq(t, b.Held("pl_a"), int64(0))
		eq(t, gauge(t, reg), "0")
	})
	t.Run("body_too_large", func(t *testing.T) {
		b := NewBuffers(256*mib, 4*mib)
		body := pattern(mib + 10)
		r := ReadReplay(bytes.NewReader(body), mib, far())
		r.FreeOnMark(take(t, b, "pl_a", mib))
		wait(t, r)
		eq(t, r.Mark, CodeBodyTooLarge)
		eq(t, b.Held("pl_a"), mib)
		eq(t, b.Total(), mib)

		head := make([]byte, mib)
		if _, err := io.ReadFull(r.Upstream, head); err != nil {
			t.Fatal(err)
		}
		eq(t, b.Held("pl_a"), int64(0))
		eq(t, b.Total(), int64(0))
		same(t, append(head, drain(t, r.Upstream)...), body)
	})
}

func TestMarkedRoomFreedAtEnd(t *testing.T) {
	t.Run("closed after the mark", func(t *testing.T) {
		b := NewBuffers(256*mib, 4*mib)
		in, _ := gated(t, pattern(10), nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		r.FreeOnMark(take(t, b, "pl_a", mib))
		wait(t, r)
		eq(t, b.Held("pl_a"), int64(10))
		r.Close()
		eq(t, b.Held("pl_a"), int64(0))
		eq(t, b.Total(), int64(0))
	})
	t.Run("closed before the mark", func(t *testing.T) {
		b := NewBuffers(256*mib, 4*mib)
		in, _ := gated(t, pattern(10), nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		r.FreeOnMark(take(t, b, "pl_a", mib))
		r.Close()
		wait(t, r)
		eq(t, r.Mark, CodeBodySlow)
		eq(t, b.Held("pl_a"), int64(0))
		eq(t, b.Total(), int64(0))
	})
}

func TestReplayWaitPrefersTheEnd(t *testing.T) {
	r := ReadReplay(bytes.NewReader(pattern(10)), mib, far())
	wait(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 100 {
		if err := r.Wait(ctx); err != nil {
			t.Fatalf("call %d: Wait gave %v on a finished read", i, err)
		}
	}
}

func TestReplayEmptyReadWhileKeeping(t *testing.T) {
	body := pattern(10)
	in, _ := gated(t, body, nil, nil)
	r := ReadReplay(in, mib, far())
	head := make([]byte, len(body))
	if _, err := io.ReadFull(r.Upstream, head); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		n, err := r.Upstream.Read(nil)
		if err == nil && n != 0 {
			err = fmt.Errorf("read %d bytes into none", n)
		}
		read <- err
	}()
	if err := within(read); err != nil {
		t.Fatalf("an empty read gave %v, want 0 and nil at once", err)
	}
	r.Close()
}

func TestReplayKeptHasNoSpareRoom(t *testing.T) {
	body := pattern(300 * kib)
	r := ReadReplay(bytes.NewReader(body), mib, far())
	wait(t, r)
	same(t, r.Kept, body)
	eq(t, cap(r.Kept), len(r.Kept))
}

// sizes is a body that records the largest read asked of it
type sizes struct {
	io.Reader
	largest int
}

func (s *sizes) Read(p []byte) (int, error) {
	s.largest = max(s.largest, len(p))
	return s.Reader.Read(p)
}

func TestReplayReadsAChunkAtATime(t *testing.T) {
	for _, c := range []struct {
		name        string
		size, limit int64
	}{
		{"whole", 300 * kib, mib},
		{"past the limit", mib + 10, mib},
		{"empty at a limit of 0", 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := &sizes{Reader: bytes.NewReader(pattern(c.size))}
			r := ReadReplay(in, c.limit, far())
			wait(t, r)
			if in.largest > chunkSize {
				t.Fatalf("a read asked for %d bytes, over %d", in.largest, chunkSize)
			}
		})
	}
}

// weakRoom is a weak pointer to the room r keeps the body in
func weakRoom(r *Replay) weak.Pointer[byte] {
	r.mu.Lock()
	defer r.mu.Unlock()
	return weak.Make(&r.buf[:1][0])
}

// collected reports whether what w points to is gone after a few collections
func collected(w weak.Pointer[byte]) bool {
	for range 5 {
		runtime.GC()
		if w.Value() == nil {
			return true
		}
	}
	return false
}

func TestReplayLetsGoOfAMarkedBody(t *testing.T) {
	t.Run("whole body kept", func(t *testing.T) {
		r := ReadReplay(bytes.NewReader(pattern(300*kib)), mib, far())
		room := weakRoom(r)
		wait(t, r)
		drain(t, r.Upstream)
		eq(t, collected(room), false)
		runtime.KeepAlive(r)
	})
	t.Run("too large after the drain", func(t *testing.T) {
		r := ReadReplay(bytes.NewReader(pattern(mib+10)), mib, far())
		room := weakRoom(r)
		wait(t, r)
		drain(t, r.Upstream)
		eq(t, collected(room), true)
		runtime.KeepAlive(r)
	})
	t.Run("slow with the client stalled", func(t *testing.T) {
		body := pattern(10)
		in, _ := gated(t, body, nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		room := weakRoom(r)
		wait(t, r)
		head := make([]byte, len(body))
		if _, err := io.ReadFull(r.Upstream, head); err != nil {
			t.Fatal(err)
		}
		same(t, head, body)
		eq(t, collected(room), true)
		runtime.KeepAlive(r)
	})
	t.Run("slow and closed unsent", func(t *testing.T) {
		in, _ := gated(t, pattern(10), nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		room := weakRoom(r)
		wait(t, r)
		r.Close()
		eq(t, collected(room), true)
		runtime.KeepAlive(r)
	})
	t.Run("closed before the slow stop", func(t *testing.T) {
		in, _ := gated(t, pattern(10), nil, nil)
		r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
		room := weakRoom(r)
		r.Close()
		wait(t, r)
		eq(t, collected(room), true)
		runtime.KeepAlive(r)
	})
}

// within is what ch gives within a second, else errStillBlocked
func within(ch <-chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		return errStillBlocked
	}
}

// closesWithin reports whether ch closes within a second
func closesWithin(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(time.Second):
		return false
	}
}

func TestReplayCloseEndsUpstream(t *testing.T) {
	body := pattern(10)
	in, _ := gated(t, body, nil, nil)
	r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	wait(t, r)
	eq(t, r.Mark, CodeBodySlow)
	head := make([]byte, len(body))
	if _, err := io.ReadFull(r.Upstream, head); err != nil {
		t.Fatal(err)
	}
	same(t, head, body)

	ended := make(chan error, 1)
	go func() {
		_, err := r.Upstream.Read(make([]byte, 1))
		ended <- err
	}()
	select {
	case err := <-ended:
		t.Fatalf("Upstream ended with %v while the client stalls", err)
	case <-time.After(50 * time.Millisecond):
	}
	r.Close()
	r.Close()
	eq(t, errors.Is(within(ended), io.ErrClosedPipe), true)
	_, err := r.Upstream.Read(make([]byte, 1))
	eq(t, errors.Is(err, io.ErrClosedPipe), true)
}

func TestReplayCloseLeavesKept(t *testing.T) {
	body := pattern(10)
	in, release := gated(t, body[:5], body[5:], nil)
	r := ReadReplay(in, mib, far())
	r.Close()
	_, err := r.Upstream.Read(make([]byte, len(body)))
	eq(t, errors.Is(err, io.ErrClosedPipe), true)

	close(release)
	wait(t, r)
	eq(t, r.Mark, Code(""))
	same(t, r.Kept, body)
}

// stalledOutcome is what a handler saw of a client that stalls past the body deadline
type stalledOutcome struct {
	mark Code
	// upstream is what a reader of Upstream got once Close was called
	upstream error
	// exited is set when the body's read in flight ended after the read deadline
	exited bool
}

// stallingHandler keeps a body that stalls, ends it as the request ends and reports what it saw
func stallingHandler(got chan<- stalledOutcome) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r := ReadReplay(req.Body, mib, time.Now().Add(100*time.Millisecond))
		sent := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, r.Upstream)
			sent <- err
		}()
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		var o stalledOutcome
		if r.Wait(ctx) == nil {
			o.mark = r.Mark
		}
		r.Close()
		o.upstream = within(sent)
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		o.exited = closesWithin(r.exited)
		got <- o
		w.WriteHeader(http.StatusPaymentRequired)
	}
}

func TestReplayStalledClientEndsWithTheRequest(t *testing.T) {
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		t.Run(proto, func(t *testing.T) {
			got := make(chan stalledOutcome, 1)
			srv := httptest.NewUnstartedServer(stallingHandler(got))
			closed := make(chan struct{})
			var once sync.Once
			srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateClosed {
					once.Do(func() { close(closed) })
				}
			}
			if proto == "HTTP/2.0" {
				srv.EnableHTTP2 = true
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()

			pr, pw := io.Pipe()
			defer func() { _ = pw.Close() }()
			go func() { _, _ = pw.Write(pattern(10)) }()
			req, err := http.NewRequest(http.MethodPost, srv.URL, pr)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			eq(t, res.Proto, proto)
			eq(t, res.StatusCode, http.StatusPaymentRequired)

			o := <-got
			eq(t, o.mark, CodeBodySlow)
			eq(t, errors.Is(o.upstream, io.ErrClosedPipe), true)
			eq(t, o.exited, true)
			if proto == "HTTP/1.1" && !closesWithin(closed) {
				t.Fatal("the server still holds the connection")
			}
		})
	}
}
