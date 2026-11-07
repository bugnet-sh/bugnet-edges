package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"runtime"
	"testing"
	"testing/iotest"
	"time"
	"weak"
)

var errBroken = errors.New("connection reset")

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
	got, err := io.ReadAll(r.Upstream)
	same(t, got, body)
	eq(t, errors.Is(err, errBroken), true)
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

func TestReplayMarkFreesItsSlot(t *testing.T) {
	b := NewBuffers(256*mib, 4*mib)

	in, release := gated(t, pattern(10), pattern(10), nil)
	r := ReadReplay(in, mib, time.Now().Add(100*time.Millisecond))
	r.FreeOnMark(take(t, b, "pl_slow", mib))
	wait(t, r)
	eq(t, r.Mark, CodeBodySlow)
	eq(t, b.Held("pl_slow"), int64(0))
	close(release)

	r = ReadReplay(bytes.NewReader(pattern(mib+1)), mib, far())
	r.FreeOnMark(take(t, b, "pl_large", mib))
	wait(t, r)
	eq(t, r.Mark, CodeBodyTooLarge)
	eq(t, b.Held("pl_large"), int64(0))

	r = ReadReplay(bytes.NewReader(pattern(mib)), mib, far())
	r.FreeOnMark(take(t, b, "pl_whole", mib))
	wait(t, r)
	eq(t, r.Mark, Code(""))
	eq(t, b.Held("pl_whole"), mib)

	r = ReadReplay(bytes.NewReader(pattern(mib+1)), mib, far())
	wait(t, r)
	r.FreeOnMark(take(t, b, "pl_late", mib))
	eq(t, b.Held("pl_late"), int64(0))
	eq(t, b.Total(), mib)
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
}
