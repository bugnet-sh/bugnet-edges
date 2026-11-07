package traffic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"

	"github.com/oynozan/bugnet-edges/internal/events"
	"github.com/oynozan/bugnet-edges/internal/lease"
	"github.com/oynozan/bugnet-edges/internal/pace"
)

const mib = 1 << 20

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// fake is a router whose usage answers and events the test sets
type fake struct {
	mu        sync.Mutex
	remaining map[string]uint64
	pace      map[string]uint64
	reports   int
	events    chan *routerv1.EdgeEvent
}

func newFake() *fake {
	return &fake{remaining: map[string]uint64{}, pace: map[string]uint64{},
		events: make(chan *routerv1.EdgeEvent)}
}

func (f *fake) parts() Parts {
	return Parts{
		Check: func(context.Context, lease.CheckIn) (lease.CheckOut, error) {
			return lease.CheckOut{}, errors.New("no checks in these tests")
		},
		Open: func(ctx context.Context, _ string) (events.Stream, error) {
			return &stream{ctx: ctx, events: f.events}, nil
		},
		Send: func(context.Context, []*routerv1.PlacementUsage) (
			map[string]uint64, map[string]uint64, error,
		) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.reports++
			return clone(f.remaining), clone(f.pace), nil
		},
		Kind: routerv1.BudgetKind_BUDGET_KIND_EDGE,
	}
}

func clone(m map[string]uint64) map[string]uint64 {
	c := map[string]uint64{}
	for k, v := range m {
		c[k] = v
	}
	return c
}

type stream struct {
	ctx    context.Context
	events chan *routerv1.EdgeEvent
}

func (s *stream) Recv() (string, *routerv1.EdgeEvent, error) {
	select {
	case ev := <-s.events:
		return "1-0", ev, nil
	case <-s.ctx.Done():
		return "", nil, s.ctx.Err()
	}
}

func (s *stream) Close() error {
	return nil
}

// start runs a Traffic on f with 5 s reports and an 8 MiB threshold until the test ends
func start(t *testing.T, f *fake) *Traffic {
	t.Helper()
	tr := New(f.parts(), Settings{
		ReporterID: "edge-1", ReportInterval: 5 * time.Second, ReportBytes: 8 * mib,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return tr
}

func live(remaining uint64) lease.State {
	return lease.State{Deadline: time.Now().Add(time.Hour), Remaining: remaining}
}

func TestHoldGivesTheBytesLeftToUsageWhichCutsAtZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := start(t, newFake())
		l := tr.Hold("p1", live(10*mib), 0)
		tr.Usage.Add("p1", 4*mib, 0)
		eq(t, l.Reason(), "")
		tr.Usage.Add("p1", 0, 6*mib)
		eq(t, l.Reason(), lease.ReasonBudget)
	})
}

func TestAUsageAnswerOfZeroEndsTheLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFake()
		f.remaining["p1"] = 0
		tr := start(t, f)
		l := tr.Hold("p1", live(gib), 0)
		tr.Usage.Add("p1", 1, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		eq(t, l.Reason(), lease.ReasonBudget)
	})
}

const gib = 1 << 30

func TestBudgetSpentEndsOnlyTheEdgeKind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFake()
		tr := start(t, f)
		l := tr.Hold("p1", live(gib), 0)
		spent := func(kind routerv1.BudgetKind) *routerv1.EdgeEvent {
			return &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
				BudgetSpent: &routerv1.BudgetSpent{PlacementId: "p1", Kind: kind}}}
		}
		f.events <- spent(routerv1.BudgetKind_BUDGET_KIND_EGRESS)
		synctest.Wait()
		eq(t, l.Reason(), "")
		f.events <- spent(routerv1.BudgetKind_BUDGET_KIND_EDGE)
		synctest.Wait()
		eq(t, l.Reason(), lease.ReasonBudget)
	})
}

// timed is how long writing n bytes through the placement's lane takes
func timed(tr *Traffic, placement string, n int) (time.Duration, error) {
	start := time.Now()
	w := tr.Pacer.Lane(placement).Writer(io.Discard, false, nil)
	_, err := w.Write(make([]byte, n))
	return time.Since(start), err
}

func TestHoldPacesANewLeaseAndUsageAnswersRepace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFake()
		f.remaining["p1"], f.pace["p1"] = gib, 4*mib
		tr := start(t, f)
		tr.Hold("p1", live(gib), 1*mib)
		took, err := timed(tr, "p1", 2*mib)
		eq(t, err, nil)
		eq(t, took > 1900*time.Millisecond && took < 2100*time.Millisecond, true)

		// A second hold of the live lease keeps its pace
		tr.Hold("p1", live(gib), 64*mib)
		tr.Usage.Add("p1", 1, 0)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		took, err = timed(tr, "p1", 4*mib)
		eq(t, err, nil)
		eq(t, took > 900*time.Millisecond && took < 1100*time.Millisecond, true)
	})
}

func TestAnEndedLeaseDropsItsLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := start(t, newFake())
		tr.Hold("p1", live(gib), 64<<10)
		done := make(chan error, 1)
		go func() {
			_, err := timed(tr, "p1", 64*mib)
			done <- err
		}()
		time.Sleep(time.Second)
		tr.Leases.End("p1", lease.ReasonEnded)
		eq(t, <-done, pace.ErrDropped)

		// A lease made again is paced afresh
		tr.Hold("p1", live(gib), 1*mib)
		took, err := timed(tr, "p1", 1*mib)
		eq(t, err, nil)
		eq(t, took > 900*time.Millisecond && took < 1100*time.Millisecond, true)
	})
}
