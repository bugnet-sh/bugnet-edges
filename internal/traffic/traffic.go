// Package traffic wires one process's leases, event stream, usage reports and pace together
package traffic

import (
	"context"
	"log/slog"
	"sync"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/events"
	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/pace"
	"github.com/bugnet-sh/bugnet-edges/internal/usage"
)

const (
	// checkEvery and checkWhileDown are DP 4.2's lease checks, with and without the event stream
	checkEvery     = time.Minute
	checkWhileDown = 30 * time.Second
)

// Settings are the process's report interval and threshold, its total cap and its reporter id
type Settings struct {
	ReporterID          string
	ReportInterval      time.Duration
	ReportBytes         int64
	TotalBytesPerSecond int64
	// CheckEvery spaces the lease checks, zero keeps DP 4.2's minute
	CheckEvery time.Duration
}

// Parts are the router calls of one service and the budget kind the process enforces
type Parts struct {
	Check lease.Check
	Open  events.Open
	Send  usage.Send
	Kind  routerv1.BudgetKind
	// Tap sees each event before the lease table does, nil for none
	Tap func(*routerv1.EdgeEvent)
}

// Traffic is one process's leases, usage reporter, pacer and event watcher, made once and shared
type Traffic struct {
	Leases *lease.Table
	Usage  *usage.Reporter
	Pacer  *pace.Pacer

	watcher *events.Watcher
}

// Edge wires the pieces to EdgeService, enforcing the edge budget
func Edge(c routerv1connect.EdgeServiceClient, s Settings, log *slog.Logger) *Traffic {
	return New(Parts{
		Check: lease.EdgeCheck(c),
		Open:  events.EdgeEvents(c),
		Send:  usage.EdgeSend(c, s.ReporterID),
		Kind:  routerv1.BudgetKind_BUDGET_KIND_EDGE,
	}, s, log)
}

// Egress wires the pieces to EgressService, enforcing the egress budget
func Egress(
	c routerv1connect.EgressServiceClient, s Settings, tap func(*routerv1.EdgeEvent),
	log *slog.Logger,
) *Traffic {
	return New(Parts{
		Check: lease.EgressCheck(c),
		Open:  events.EgressEvents(c),
		Send:  usage.EgressSend(c, s.ReporterID),
		Kind:  routerv1.BudgetKind_BUDGET_KIND_EGRESS,
		Tap:   tap,
	}, s, log)
}

// New wires leases to events, usage answers to leases and pace, and lease states to usage
func New(p Parts, s Settings, log *slog.Logger) *Traffic {
	if log == nil {
		log = slog.Default()
	}
	every := checkEvery
	if s.CheckEvery > 0 {
		every = s.CheckEvery
	}
	t := &Traffic{
		Leases: lease.NewTable(loggedCheck(p.Check, log), every, min(checkWhileDown, every)),
		Usage:  usage.NewReporter(loggedSend(p.Send, log), s.ReportInterval, s.ReportBytes),
		Pacer:  pace.New(s.TotalBytesPerSecond),
	}
	t.watcher = events.NewWatcher(loggedOpen(p.Open, log),
		func(ev *routerv1.EdgeEvent) {
			if p.Tap != nil {
				p.Tap(ev)
			}
			t.Leases.Apply(ev, p.Kind)
		},
		t.Leases.CheckNow,
		func(down bool) {
			if down {
				log.Warn("traffic: the router's event stream is down")
			} else {
				log.Info("traffic: the router's event stream is up")
			}
			t.Leases.EventsDown(down)
		})
	// The reporter takes only its own lock, so calling it under the table's lock is safe
	t.Leases.OnState(func(placement string, st lease.State) {
		t.Usage.SetRemaining(placement, st.Remaining)
	})
	t.Usage.OnAnswer(func(placement string, remaining, perSecond uint64) {
		if remaining == 0 {
			t.Leases.End(placement, lease.ReasonBudget)
			return
		}
		if _, ok := t.Leases.Get(placement); ok && perSecond > 0 {
			t.Pacer.Lane(placement).SetRate(int64(perSecond))
		}
	})
	return t
}

// Run checks leases, follows events and reports usage until ctx ends, then sends a last report
func (t *Traffic) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { t.Leases.Run(ctx) })
	wg.Go(func() { t.watcher.Run(ctx) })
	wg.Go(func() { t.Usage.Run(ctx) })
	wg.Wait()
}

// Hold moves the placement's live lease to s, or makes one paced at bytesPerSecond each way
func (t *Traffic) Hold(placement string, s lease.State, bytesPerSecond uint64) *lease.Lease {
	prev, had := t.Leases.Get(placement)
	l := t.Leases.Put(placement, s)
	if had && prev == l {
		return l
	}
	if bytesPerSecond > 0 {
		t.Pacer.Lane(placement).SetRate(int64(bytesPerSecond))
	}
	context.AfterFunc(l.Context(), func() {
		// A lease made again since keeps its lane and its figure
		if cur, ok := t.Leases.Get(placement); ok && cur != l {
			return
		}
		t.Pacer.Drop(placement)
		t.Usage.Drop(placement)
	})
	return l
}

func loggedCheck(check lease.Check, log *slog.Logger) lease.Check {
	return func(ctx context.Context, in lease.CheckIn) (lease.CheckOut, error) {
		out, err := check(ctx, in)
		if err != nil {
			log.Warn("traffic: a lease check failed", "placements", len(in.Placements),
				"err", err)
		}
		return out, err
	}
}

func loggedSend(send usage.Send, log *slog.Logger) usage.Send {
	return func(ctx context.Context, u []*routerv1.PlacementUsage) (
		map[string]uint64, map[string]uint64, error,
	) {
		remaining, perSecond, err := send(ctx, u)
		if err != nil {
			log.Warn("traffic: a usage report failed", "placements", len(u), "err", err)
		}
		return remaining, perSecond, err
	}
}

func loggedOpen(open events.Open, log *slog.Logger) events.Open {
	return func(ctx context.Context, cursor string) (events.Stream, error) {
		s, err := open(ctx, cursor)
		if err != nil && ctx.Err() == nil {
			log.Warn("traffic: the event stream did not open", "err", err)
		}
		return s, err
	}
}
