package x402

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// The event sender's log lines, which carry only the fields of XS 6.14's log rule
const (
	msgEventSent    = "x402 event sent"
	msgEventDropped = "x402 event dropped"
)

const (
	// maxBatch is the most events one AppendX402Events call carries
	maxBatch = 50
	// sendWorkers is how many placements one flush sends to at once
	sendWorkers = 8
	// rowRetries is how often a row that cannot involve money is sent again after a failure
	rowRetries = 3
	// moneyRetry is how long a money row is sent again after its first failure
	moneyRetry = 5 * time.Minute
)

// Append sends one batch
type Append func(ctx context.Context, r *routerv1.AppendX402EventsRequest,
) (*routerv1.AppendX402EventsResponse, error)

// EventsSend sends batches through the router's AppendX402Events
func EventsSend(c routerv1connect.EgressServiceClient) Append {
	return func(ctx context.Context, r *routerv1.AppendX402EventsRequest,
	) (*routerv1.AppendX402EventsResponse, error) {
		res, err := c.AppendX402Events(ctx, connect.NewRequest(r))
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
}

// round says which queues a flush sends
type round int

const (
	// roundTick closes the windows whose minute ended and sends every queue
	roundTick round = iota
	// roundFull sends only the queues holding a whole batch never sent
	roundFull
	// roundLast closes every window and sends every queue once
	roundLast
)

// Run flushes every interval, at 50 events and at each minute's close, and once when ctx ends
func (e *Events) Run(ctx context.Context) {
	tick := e.tick
	if tick == nil {
		t := time.NewTicker(e.flush)
		defer t.Stop()
		tick = t.C
	}
	minute := time.NewTimer(untilMinute(e.now()))
	defer minute.Stop()
	for {
		select {
		case <-ctx.Done():
			e.flushRound(context.WithoutCancel(ctx), roundLast)
			return
		case <-tick:
			e.flushAll(ctx)
		case <-minute.C:
			e.flushAll(ctx)
			minute.Reset(untilMinute(e.now()))
		case <-e.full:
			e.flushRound(ctx, roundFull)
		}
	}
}

// untilMinute is the wait from now to the next UTC minute
func untilMinute(now time.Time) time.Duration {
	return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

// flushAll closes the windows whose minute ended and sends every queue
func (e *Events) flushAll(ctx context.Context) {
	e.flushRound(ctx, roundTick)
}

// outgoing is one placement's rows taken for a flush
type outgoing struct {
	placement string
	rows      []*eventRow
}

// take closes the round's windows and takes the queues it sends
func (e *Events) take(r round) []outgoing {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r != roundFull {
		e.closeWindows(e.now(), r == roundLast)
	}
	var out []outgoing
	for id, p := range e.places {
		if len(p.queue) > 0 && (r != roundFull || p.fresh >= maxBatch) {
			out = append(out, outgoing{placement: id, rows: p.queue})
			p.queue, p.fresh = nil, 0
		}
		e.tidy(id)
	}
	return out
}

// flushRound sends the round's queues, a few placements at once, all within one flush interval
func (e *Events) flushRound(ctx context.Context, r round) {
	out := e.take(r)
	if len(out) == 0 {
		return
	}
	budget, cancel := context.WithTimeout(ctx, e.flush)
	defer cancel()
	work := make(chan outgoing)
	var wg sync.WaitGroup
	for range min(len(out), sendWorkers) {
		wg.Go(func() {
			for o := range work {
				e.sendRows(ctx, budget, o, r == roundLast)
			}
		})
	}
	for _, o := range out {
		work <- o
	}
	close(work)
	wg.Wait()
}

// sendRows sends one placement's rows within the round's budget, money rows first
func (e *Events) sendRows(ctx, budget context.Context, o outgoing, last bool) {
	slices.SortStableFunc(o.rows, func(a, b *eventRow) int {
		switch {
		case a.money == b.money:
			return 0
		case a.money:
			return -1
		}
		return 1
	})
	var keep []*eventRow
	for rows := o.rows; len(rows) > 0; {
		if budget.Err() != nil && !last {
			// Rows the round had no time left to start wait for the next round with no try counted
			e.requeue(o.placement, append(keep, rows...))
			return
		}
		batch := rows[:min(len(rows), maxBatch)]
		rows = rows[len(batch):]
		err := e.sendBatch(budget, o.placement, batch)
		switch {
		case err == nil:
		case ctx.Err() != nil && !last:
			// Rows cut by the end of Run go out with its last flush, with no try counted
			e.requeue(o.placement, append(append(keep, batch...), rows...))
			return
		default:
			keep = append(keep, e.failed(o.placement, batch, err, last)...)
		}
	}
	e.requeue(o.placement, keep)
}

// sendBatch sends one batch and logs each row the router answered for
func (e *Events) sendBatch(ctx context.Context, placement string, batch []*eventRow) error {
	req := &routerv1.AppendX402EventsRequest{
		PlacementId: placement, Events: make([]*routerv1.X402Event, len(batch)),
	}
	for i, r := range batch {
		req.Events[i] = r.ev
	}
	res, err := e.send(ctx, req)
	if err != nil {
		return err
	}
	rejected := map[int]bool{}
	for _, i := range res.GetRejected() {
		rejected[int(i)] = true
	}
	for i, r := range batch {
		if rejected[i] {
			e.logRow(r.dropLevel(), msgEventDropped, placement, r.ev, "why", "rejected")
			continue
		}
		e.logRow(slog.LevelInfo, msgEventSent, placement, r.ev)
	}
	return nil
}

// failed applies the retry rules to a batch the router did not take and returns the rows kept
func (e *Events) failed(placement string, batch []*eventRow, err error, last bool) []*eventRow {
	now := e.now()
	code := connect.CodeOf(err)
	var keep []*eventRow
	for _, r := range batch {
		var why string
		switch {
		case code == connect.CodeInvalidArgument:
			why = "invalid_argument"
		case last:
			why = "shutdown"
		case r.money:
			if r.failedAt.IsZero() {
				r.failedAt = now
			}
			if now.Sub(r.failedAt) >= moneyRetry {
				why = "retry_window"
			}
		default:
			r.tries++
			if r.tries > rowRetries {
				why = "tries"
			}
		}
		if why == "" {
			keep = append(keep, r)
			continue
		}
		e.logRow(r.dropLevel(), msgEventDropped, placement, r.ev, "why", why,
			"code", code.String())
	}
	return keep
}

// requeue puts rows back ahead of the placement's queue
func (e *Events) requeue(placement string, rows []*eventRow) {
	if len(rows) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.place(placement)
	p.queue = append(rows, p.queue...)
}

// dropLevel is an error for a row that can involve money, else a warning
func (r *eventRow) dropLevel() slog.Level {
	if r.money {
		return slog.LevelError
	}
	return slog.LevelWarn
}

// logRow writes XS 6.14's line for a row, never its path, refs, pay_to or service
func (e *Events) logRow(
	level slog.Level, msg, placement string, ev *routerv1.X402Event, more ...any,
) {
	e.log.Log(context.Background(), level, msg, append([]any{
		"placement", PlacementHash(placement), "host", ev.GetHost(), "method", ev.GetMethod(),
		"status", ev.GetStatus(), "reason", ev.GetReason(),
		"amount_micros", ev.GetAmountMicros(), "bytes_out", ev.GetBytesOut(),
		"bytes_in", ev.GetBytesIn(), "count", ev.GetCount(),
	}, more...)...)
}
