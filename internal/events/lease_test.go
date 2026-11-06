package events

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oynozan/bugnet-edges/internal/lease"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

// leaseChecks counts lease checks and answers every placement as still live
type leaseChecks struct {
	mu sync.Mutex
	n  int
}

func (c *leaseChecks) check(_ context.Context, in lease.CheckIn) (lease.CheckOut, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	out := lease.CheckOut{States: map[string]lease.State{}}
	for _, id := range in.Placements {
		out.States[id] = lease.State{Deadline: time.Now().Add(time.Hour), Remaining: 1}
	}
	return out, nil
}

func (c *leaseChecks) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// wire runs a lease table and a watcher feeding it, as the edge does
func wire(t *testing.T, r *router) (*lease.Table, *leaseChecks) {
	t.Helper()
	c := &leaseChecks{}
	table := lease.NewTable(c.check, 60*time.Second, 30*time.Second)
	w := NewWatcher(r.open, func(ev *routerv1.EdgeEvent) {
		table.Apply(ev, routerv1.BudgetKind_BUDGET_KIND_EDGE)
	}, table.CheckNow, table.EventsDown)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { table.Run(ctx) })
	wg.Go(func() { w.Run(ctx) })
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	synctest.Wait()
	return table, c
}

func TestWatcherResyncChecksLeases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		table, c := wire(t, r)
		l := table.Put("p1", lease.State{Deadline: time.Now().Add(time.Hour), Remaining: 1})
		r.send(msg{cursor: "4-0", ev: resync()})
		eq(t, c.count(), 1)
		r.send(msg{cursor: "5-0", ev: ended("p1")})
		eq(t, l.Reason(), lease.ReasonEnded)
	})
}

func TestWatcherDownMakesLeaseChecksEvery30s(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newRouter()
		r.fail = 1000
		table, c := wire(t, r)
		table.Put("p1", lease.State{Deadline: time.Now().Add(time.Hour), Remaining: 1})
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		eq(t, c.count(), 4)

		// The stream is back within one backoff, and its gap without a cursor costs one check
		r.set(func(r *router) { r.fail = 0 })
		time.Sleep(15 * time.Second)
		synctest.Wait()
		before := c.count()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		eq(t, c.count()-before, 2)
	})
}
