package events

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

// msg is one answer a fake stream gives
type msg struct {
	cursor string
	ev     *routerv1.EdgeEvent
	err    error
}

// stream is a fake event stream fed by the test
type stream struct {
	ctx  context.Context
	msgs chan msg
}

func (s *stream) Recv() (string, *routerv1.EdgeEvent, error) {
	select {
	case m := <-s.msgs:
		return m.cursor, m.ev, m.err
	case <-s.ctx.Done():
		return "", nil, s.ctx.Err()
	}
}

func (s *stream) Close() error { return nil }

// router is a fake WatchEdgeEvents that records each open's cursor and when it came
type router struct {
	mu      sync.Mutex
	start   time.Time
	cursors []string
	at      []time.Duration
	fail    int // opens left to refuse
	current *stream
}

func newRouter() *router { return &router{start: time.Now()} }

func (r *router) open(ctx context.Context, cursor string) (Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cursors = append(r.cursors, cursor)
	r.at = append(r.at, time.Since(r.start))
	if r.fail > 0 {
		r.fail--
		return nil, errors.New("router unreachable")
	}
	r.current = &stream{ctx: ctx, msgs: make(chan msg, 16)}
	return r.current, nil
}

// send gives the open stream one answer, then lets the watcher act on it
func (r *router) send(m msg) {
	r.mu.Lock()
	s := r.current
	r.mu.Unlock()
	s.msgs <- m
	synctest.Wait()
}

func (r *router) set(f func(r *router)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

func (r *router) opens() ([]string, []time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cursors...), append([]time.Duration(nil), r.at...)
}

// seen records what the watcher hands to its callbacks
type seen struct {
	mu      sync.Mutex
	events  []string
	resyncs int
	downs   []bool
}

func (s *seen) on(ev *routerv1.EdgeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e := ev.GetEvent().(type) {
	case *routerv1.EdgeEvent_PlacementEnded:
		s.events = append(s.events, "ended "+e.PlacementEnded.GetPlacementId())
	case *routerv1.EdgeEvent_PreviewRevoked:
		s.events = append(s.events, "revoked "+e.PreviewRevoked.GetPreviewId())
	default:
		s.events = append(s.events, "other")
	}
}

func (s *seen) resync() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resyncs++
}

func (s *seen) down(d bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downs = append(s.downs, d)
}

func (s *seen) get() ([]string, int, []bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...), s.resyncs, append([]bool(nil), s.downs...)
}

func ended(id string) *routerv1.EdgeEvent {
	return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
		PlacementEnded: &routerv1.PlacementEnded{PlacementId: id},
	}}
}

func revoked(id string) *routerv1.EdgeEvent {
	return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PreviewRevoked{
		PreviewRevoked: &routerv1.PreviewRevoked{PreviewId: id},
	}}
}

func resync() *routerv1.EdgeEvent {
	return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_Resync{Resync: &routerv1.Resync{}}}
}

// watch runs a watcher on r until the returned stop is called or the test ends
func watch(t *testing.T, r *router) (*seen, func()) {
	t.Helper()
	s := &seen{}
	w := NewWatcher(r.open, s.on, s.resync, s.down)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stop)
	synctest.Wait()
	return s, stop
}

func TestWatcherResumesFromCursor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		s, _ := watch(t, r)
		r.send(msg{cursor: "1-0", ev: ended("p1")})
		r.send(msg{cursor: "2-0", ev: revoked("v1")})
		r.send(msg{err: errors.New("connection reset")})
		time.Sleep(time.Second)
		synctest.Wait()
		r.send(msg{cursor: "3-0", ev: ended("p2")})
		r.send(msg{err: io.EOF})
		time.Sleep(time.Second)
		synctest.Wait()

		cursors, _ := r.opens()
		eq(t, cursors, []string{"", "2-0", "3-0"})
		events, resyncs, _ := s.get()
		eq(t, events, []string{"ended p1", "revoked v1", "ended p2"})
		eq(t, resyncs, 0)
	})
}

func TestWatcherResyncEventCallsResyncOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		s, _ := watch(t, r)
		r.send(msg{cursor: "5-0", ev: resync()})
		events, resyncs, _ := s.get()
		eq(t, events, []string(nil))
		eq(t, resyncs, 1)
	})
}

func TestWatcherCursorWithoutEventMovesOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		s, _ := watch(t, r)
		r.send(msg{cursor: "7-0"})
		r.send(msg{err: io.EOF})
		time.Sleep(time.Second)
		synctest.Wait()
		cursors, _ := r.opens()
		eq(t, cursors, []string{"", "7-0"})
		events, resyncs, _ := s.get()
		eq(t, events, []string(nil))
		eq(t, resyncs, 0)
	})
}

func TestWatcherResyncsAfterAGapWithoutCursor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		s, _ := watch(t, r)
		r.send(msg{err: errors.New("connection reset")})
		time.Sleep(time.Second)
		synctest.Wait()
		cursors, _ := r.opens()
		eq(t, cursors, []string{"", ""})
		_, resyncs, _ := s.get()
		eq(t, resyncs, 1)
	})
}

func TestWatcherReportsDownAndBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.fail = 2
		s, _ := watch(t, r)
		_, _, downs := s.get()
		eq(t, downs, []bool{true})
		for cursors, _ := r.opens(); len(cursors) < 3; cursors, _ = r.opens() {
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
		}
		_, at := r.opens()
		time.Sleep(at[2] + upAfter - time.Since(r.start) - time.Millisecond)
		synctest.Wait()
		_, _, downs = s.get()
		eq(t, downs, []bool{true})

		// The stream counts as back once it has stayed open a second
		time.Sleep(time.Millisecond)
		synctest.Wait()
		_, _, downs = s.get()
		eq(t, downs, []bool{true, false})

		r.send(msg{err: errors.New("connection reset")})
		_, _, downs = s.get()
		eq(t, downs, []bool{true, false, true})

		// A message brings it back at once
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		r.send(msg{cursor: "1-0", ev: ended("p1")})
		_, _, downs = s.get()
		eq(t, downs, []bool{true, false, true, false})
	})
}

func TestWatcherBacksOffWhileRouterDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.fail = 1000
		watch(t, r)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		_, at := r.opens()
		var gaps []time.Duration
		for i := 1; i < len(at); i++ {
			gaps = append(gaps, at[i]-at[i-1])
		}
		want := minBackoff
		for i, g := range gaps {
			if g < want*3/4 || g > want*5/4 {
				t.Fatalf("gap %d is %v, want about %v", i, g, want)
			}
			want = min(want*2, maxBackoff)
		}
		eq(t, len(gaps) > 10, true)
		eq(t, want, maxBackoff)
	})
}

func TestWatcherBackoffResetsOnceTheStreamWasUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.fail = 6
		watch(t, r)
		time.Sleep(time.Minute)
		synctest.Wait()
		r.send(msg{err: errors.New("connection reset")})
		time.Sleep(time.Second)
		synctest.Wait()
		_, at := r.opens()
		eq(t, len(at), 8)
		gap := at[7] - time.Minute
		eq(t, gap > 0 && gap <= minBackoff*5/4, true)
	})
}

func TestWatcherStopsWithItsContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		_, stop := watch(t, r)
		stop()

		r = newRouter()
		r.fail = 1000
		_, stop = watch(t, r)
		time.Sleep(3 * time.Second)
		stop()
	})
}

func TestWatcherDownMayCallBackIntoTheWatcher(t *testing.T) {
	r := newRouter()
	r.fail = 1
	called := make(chan string, 4)
	var w *Watcher
	w = NewWatcher(r.open, func(*routerv1.EdgeEvent) {}, func() {}, func(bool) {
		called <- w.Cursor()
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx)
	}()
	select {
	case got := <-called:
		eq(t, got, "")
	case <-time.After(5 * time.Second):
		t.Fatal("down never returned from reading the cursor")
	}
	cancel()
	<-done
}
