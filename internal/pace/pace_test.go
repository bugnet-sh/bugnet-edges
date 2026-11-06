package pace

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// zeros is an endless reader of zero bytes
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// until reads zeros until the bubble's clock reaches end
type until struct{ end time.Time }

func (u until) Read(p []byte) (int, error) {
	if !time.Now().Before(u.end) {
		return 0, io.EOF
	}
	return zeros{}.Read(p)
}

// sizes records the size of every write it is given
type sizes struct {
	mu sync.Mutex
	n  []int
}

func (s *sizes) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n = append(s.n, len(p))
	return len(p), nil
}

// timeCopy sets the lane's rate and reports how long n bytes take through its reader
func timeCopy(t *testing.T, l *Lane, n, bytesPerSecond int64) time.Duration {
	t.Helper()
	l.SetRate(bytesPerSecond)
	var counted atomic.Int64
	start := time.Now()
	r := l.Reader(io.LimitReader(zeros{}, n), true, func(c int) { counted.Add(int64(c)) })
	got, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, got, n)
	eq(t, counted.Load(), n)
	return time.Since(start)
}

// pump copies through r for d and returns the bytes it counted
func pump(r func(io.Reader, func(int)) io.Reader, d time.Duration) *atomic.Int64 {
	var n atomic.Int64
	src := r(until{end: time.Now().Add(d)}, func(c int) { n.Add(int64(c)) })
	_, _ = io.Copy(io.Discard, src)
	return &n
}

func TestLaneHoldsItsRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		took := timeCopy(t, New(0).Lane("p"), 512<<10, 128<<10)
		// The first 64 KiB is the burst, each of the other seven waits half a second
		eq(t, took >= 3500*time.Millisecond && took < 4500*time.Millisecond, true)
	})
}

func TestLaneWriterHoldsItsRateInPieces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(0).Lane("p")
		l.SetRate(128 << 10)
		var w sizes
		var counted atomic.Int64
		start := time.Now()
		n, err := l.Writer(&w, false, func(c int) { counted.Add(int64(c)) }).
			Write(make([]byte, 512<<10))
		eq(t, err, nil)
		eq(t, n, 512<<10)
		took := time.Since(start)
		eq(t, took >= 3500*time.Millisecond && took < 4500*time.Millisecond, true)
		eq(t, counted.Load(), int64(512<<10))
		eq(t, w.n, []int{64 << 10, 64 << 10, 64 << 10, 64 << 10, 64 << 10, 64 << 10, 64 << 10,
			64 << 10})
	})
}

func TestLaneReaderReadsAtMostOnePiece(t *testing.T) {
	l := New(0).Lane("p")
	r := l.Reader(zeros{}, true, nil)
	n, err := r.Read(make([]byte, 1<<20))
	eq(t, err, nil)
	eq(t, n, 64<<10)
}

func TestFreshLaneIsUnpaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(0).Lane("p")
		start := time.Now()
		got, err := io.Copy(io.Discard, l.Reader(io.LimitReader(zeros{}, 64<<20), false, nil))
		eq(t, err, nil)
		eq(t, got, int64(64<<20))
		eq(t, time.Since(start), time.Duration(0))

		l.SetRate(128 << 10)
		l.SetRate(0)
		start = time.Now()
		_, _ = io.Copy(io.Discard, l.Reader(io.LimitReader(zeros{}, 64<<20), false, nil))
		eq(t, time.Since(start), time.Duration(0))
	})
}

func TestSetRateMovesThePace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(0).Lane("p")
		eq(t, timeCopy(t, l, 512<<10, 128<<10) >= 3500*time.Millisecond, true)
		took := timeCopy(t, l, 1<<20, 256<<10)
		eq(t, took >= 3750*time.Millisecond && took < 4500*time.Millisecond, true)
	})
}

func TestLaneDirectionsArePacedApart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(0).Lane("p")
		l.SetRate(128 << 10)
		var in, out *atomic.Int64
		var wg sync.WaitGroup
		wg.Go(func() {
			in = pump(func(r io.Reader, c func(int)) io.Reader { return l.Reader(r, true, c) },
				8*time.Second)
		})
		wg.Go(func() {
			out = pump(func(r io.Reader, c func(int)) io.Reader { return l.Reader(r, false, c) },
				8*time.Second)
		})
		wg.Wait()
		for _, n := range []int64{in.Load(), out.Load()} {
			eq(t, n >= 8*128<<10 && n <= 9*128<<10, true)
		}
	})
}

func TestTotalCapSharedFairly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(256 << 10)
		a, b := p.Lane("a"), p.Lane("b")
		var na, nb *atomic.Int64
		var wg sync.WaitGroup
		wg.Go(func() {
			na = pump(func(r io.Reader, c func(int)) io.Reader { return a.Reader(r, false, c) },
				20*time.Second)
		})
		wg.Go(func() {
			nb = pump(func(r io.Reader, c func(int)) io.Reader { return b.Reader(r, false, c) },
				20*time.Second)
		})
		wg.Wait()
		total := na.Load() + nb.Load()
		eq(t, total <= 20*256<<10+3*64<<10, true)
		eq(t, total >= 19*256<<10, true)
		for _, n := range []int64{na.Load(), nb.Load()} {
			share := float64(n) / float64(total)
			if share < 0.45 || share > 0.55 {
				t.Fatalf("share %.3f of %d bytes", share, total)
			}
		}
	})
}

func TestTotalCapCountsBothWays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(256 << 10)
		l := p.Lane("a")
		var in, out *atomic.Int64
		var wg sync.WaitGroup
		wg.Go(func() {
			in = pump(func(r io.Reader, c func(int)) io.Reader { return l.Reader(r, true, c) },
				10*time.Second)
		})
		wg.Go(func() {
			var w sizes
			var n atomic.Int64
			out = &n
			end := time.Now().Add(10 * time.Second)
			lw := l.Writer(&w, false, func(c int) { n.Add(int64(c)) })
			for time.Now().Before(end) {
				if _, err := lw.Write(make([]byte, 64<<10)); err != nil {
					t.Error(err)
					return
				}
			}
		})
		wg.Wait()
		total := in.Load() + out.Load()
		eq(t, total <= 10*256<<10+3*64<<10, true)
		eq(t, total >= 9*256<<10, true)
	})
}

func TestLaneIsPerPlacement(t *testing.T) {
	p := New(0)
	a := p.Lane("a")
	eq(t, p.Lane("a") == a, true)
	eq(t, p.Lane("b") == a, false)
	p.Drop("a")
	eq(t, p.Lane("a") == a, false)
}

func TestDropEndsAWaitingCopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := New(0)
		l := p.Lane("a")
		l.SetRate(1 << 10)
		var err error
		var counted atomic.Int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, err = io.Copy(io.Discard, l.Reader(zeros{}, true, func(c int) {
				counted.Add(int64(c))
			}))
		}()
		time.Sleep(time.Second)
		p.Drop("a")
		<-done
		eq(t, errors.Is(err, ErrDropped), true)
		eq(t, counted.Load(), int64(64<<10))

		_, err = l.Writer(io.Discard, false, nil).Write([]byte("x"))
		eq(t, errors.Is(err, ErrDropped), true)
	})
}

func TestWriterStopsAtTheFirstError(t *testing.T) {
	l := New(0).Lane("a")
	boom := errors.New("closed")
	var counted int
	n, err := l.Writer(&failAfter{left: 70 << 10, err: boom}, true, func(c int) { counted += c }).
		Write(make([]byte, 256<<10))
	eq(t, err, boom)
	eq(t, n, 70<<10)
	eq(t, counted, 70<<10)
}

// failAfter accepts left bytes, then fails every write with err
type failAfter struct {
	left int
	err  error
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.left >= len(p) {
		f.left -= len(p)
		return len(p), nil
	}
	n := f.left
	f.left = 0
	return n, f.err
}

// short takes at most n bytes of each write and reports no error
type short struct{ n int }

func (s short) Write(p []byte) (int, error) {
	return min(len(p), s.n), nil
}

func TestWriterShortWriteIsAnError(t *testing.T) {
	l := New(0).Lane("a")
	var counted int
	n, err := l.Writer(short{n: 10}, true, func(c int) { counted += c }).Write(make([]byte, 100))
	eq(t, err, io.ErrShortWrite)
	eq(t, n, 10)
	eq(t, counted, 10)
}
