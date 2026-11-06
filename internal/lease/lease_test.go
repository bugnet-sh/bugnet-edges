package lease

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

const gib = 1 << 30

// checker is a fake lease check that records each CheckIn and answers its out
type checker struct {
	mu    sync.Mutex
	start time.Time
	ins   []CheckIn
	at    []time.Duration
	// returned holds when each check returned
	returned []time.Duration
	out      CheckOut
	err      error
	// hold, when set, keeps each check waiting until it is closed or the check times out
	hold chan struct{}
}

func newChecker() *checker {
	return &checker{start: time.Now()}
}

func (c *checker) check(ctx context.Context, in CheckIn) (CheckOut, error) {
	c.mu.Lock()
	c.ins = append(c.ins, in)
	c.at = append(c.at, time.Since(c.start))
	hold := c.hold
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.returned = append(c.returned, time.Since(c.start))
	}()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return CheckOut{}, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return CheckOut{}, c.err
	}
	out := CheckOut{States: map[string]State{}, Revoked: c.out.Revoked}
	for k, v := range c.out.States {
		out.States[k] = v
	}
	return out, nil
}

func (c *checker) set(f func(c *checker)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func (c *checker) calls() ([]CheckIn, []time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CheckIn(nil), c.ins...), append([]time.Duration(nil), c.at...)
}

func (c *checker) ends() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.returned...)
}

func (c *checker) last(t *testing.T) CheckIn {
	t.Helper()
	ins, _ := c.calls()
	if len(ins) == 0 {
		t.Fatal("no lease check was made")
	}
	return ins[len(ins)-1]
}

// run starts a table with a 60 s check and 30 s while events are down until the test ends
func run(t *testing.T, c *checker) *Table {
	t.Helper()
	return runEvery(t, c, 60*time.Second)
}

func runEvery(t *testing.T, c *checker, every time.Duration) *Table {
	t.Helper()
	table := NewTable(c.check, every, 30*time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		table.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return table
}

// answer makes the next check answer out, runs one and waits for the table to act on it
func answer(t *testing.T, c *checker, table *Table, out CheckOut) {
	t.Helper()
	c.set(func(c *checker) { c.out = out })
	table.CheckNow()
	synctest.Wait()
}

func live(deadline time.Time, ids ...string) map[string]State {
	m := map[string]State{}
	for _, id := range ids {
		m[id] = State{Deadline: deadline, Remaining: gib}
	}
	return m
}

func ended(ctx context.Context) bool {
	return ctx.Err() != nil
}

func TestLeaseCheckSendsHeldPreviews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		c.out = CheckOut{States: live(deadline, "p1", "p2")}
		l := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		table.Put("p2", State{Deadline: deadline, Remaining: gib})
		_, stop := l.Preview(HeldPreview{ID: "abc", Generation: 2})
		_, stopAgain := l.Preview(HeldPreview{ID: "abc", Generation: 2})
		l.Preview(HeldPreview{ID: "abb", Generation: 1})
		time.Sleep(60 * time.Second)
		synctest.Wait()
		eq(t, c.last(t), CheckIn{
			Placements: []string{"p1", "p2"},
			Held:       []HeldPreview{{ID: "abb", Generation: 1}, {ID: "abc", Generation: 2}},
		})

		stop()
		time.Sleep(60 * time.Second)
		synctest.Wait()
		eq(t, len(c.last(t).Held), 2)
		stopAgain()
		time.Sleep(60 * time.Second)
		synctest.Wait()
		eq(t, c.last(t).Held, []HeldPreview{{ID: "abb", Generation: 1}})
	})
}

func TestLeaseCheckRevokedCancelsOnlyThatChild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		l := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		a, _ := l.Preview(HeldPreview{ID: "a"})
		b, _ := l.Preview(HeldPreview{ID: "b"})
		x, _ := l.Child("transfer")
		answer(t, c, table, CheckOut{States: live(deadline, "p1"), Revoked: []string{"a"}})
		eq(t, a.Err() != nil && b.Err() == nil && l.Context().Err() == nil, true)
		eq(t, x.Err(), nil)
		eq(t, Reason(a), ReasonRevoked)
		eq(t, Reason(b), "")
		eq(t, l.Reason(), "")

		answer(t, c, table, CheckOut{States: live(deadline, "p1")})
		eq(t, c.last(t).Held, []HeldPreview{{ID: "b"}})
	})
}

func TestLeaseCheckVersionMoveCallsBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		var mu sync.Mutex
		var calls []uint64
		table.OnVersion(func(placement string, version uint64) {
			mu.Lock()
			defer mu.Unlock()
			eq(t, placement, "p1")
			calls = append(calls, version)
		})
		deadline := time.Now().Add(time.Hour)
		table.Put("p1", State{Deadline: deadline, Remaining: gib, SecretsVersion: 3})
		moved := CheckOut{States: map[string]State{
			"p1": {Deadline: deadline, Remaining: gib, SecretsVersion: 4},
		}}
		answer(t, c, table, moved)
		answer(t, c, table, moved)
		mu.Lock()
		defer mu.Unlock()
		eq(t, calls, []uint64{4})
	})
}

func TestLeaseDeadlineChecksOnceThenCancels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := runEvery(t, c, time.Hour)
		deadline := time.Now().Add(10 * time.Second)
		c.out = CheckOut{States: live(deadline, "p1")}
		l := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		time.Sleep(10*time.Second - time.Millisecond)
		synctest.Wait()
		ins, _ := c.calls()
		eq(t, len(ins), 0)
		time.Sleep(time.Millisecond)
		synctest.Wait()
		ins, at := c.calls()
		eq(t, ins, []CheckIn{{Placements: []string{"p1"}}})
		eq(t, at, []time.Duration{10 * time.Second})
		eq(t, ended(l.Context()), true)
		eq(t, l.Reason(), ReasonExpired)
		_, ok := table.Get("p1")
		eq(t, ok, false)
	})
}

func TestLeaseDeadlineCheckWithALaterDeadlineRearms(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := runEvery(t, c, time.Hour)
		later := time.Now().Add(70 * time.Second)
		c.out = CheckOut{States: map[string]State{"p1": {Deadline: later, Remaining: 5}}}
		l := table.Put("p1", State{Deadline: time.Now().Add(10 * time.Second), Remaining: gib})
		time.Sleep(10 * time.Second)
		synctest.Wait()
		eq(t, ended(l.Context()), false)
		eq(t, l.State(), State{Deadline: later, Remaining: 5})
		time.Sleep(60 * time.Second)
		synctest.Wait()
		_, at := c.calls()
		eq(t, at, []time.Duration{10 * time.Second, 70 * time.Second})
		eq(t, l.Reason(), ReasonExpired)
	})
}

func TestLeaseDeadlineCheckGetsTwoSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		c.hold = make(chan struct{})
		table := runEvery(t, c, time.Hour)
		l := table.Put("p1", State{Deadline: time.Now().Add(10 * time.Second), Remaining: gib})
		time.Sleep(12*time.Second - time.Millisecond)
		synctest.Wait()
		eq(t, ended(l.Context()), false)
		time.Sleep(time.Millisecond)
		synctest.Wait()
		eq(t, l.Reason(), ReasonExpired)
	})
}

func TestLeaseMoveRearmsTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := runEvery(t, c, time.Hour)
		l := table.Put("p1", State{Deadline: time.Now().Add(10 * time.Second), Remaining: gib})
		table.Move("p1", State{Deadline: time.Now().Add(20 * time.Second), Remaining: gib})
		time.Sleep(15 * time.Second)
		synctest.Wait()
		ins, _ := c.calls()
		eq(t, len(ins), 0)
		eq(t, ended(l.Context()), false)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		_, at := c.calls()
		eq(t, at, []time.Duration{20 * time.Second})
		eq(t, l.Reason(), ReasonExpired)
	})
}

func TestLeaseChildCancelLeavesSiblings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		table := run(t, newChecker())
		l := table.Put("p1", State{Deadline: time.Now().Add(time.Hour), Remaining: gib})
		a, cancelA := l.Child("ws")
		b, _ := l.Child("ws")
		x, _ := l.Child("transfer")
		cancelA()
		eq(t, ended(a), true)
		eq(t, Reason(a), "")
		eq(t, ended(b) || ended(x) || ended(l.Context()), false)

		l.CancelChildren("ws", "closed")
		eq(t, ended(b), true)
		eq(t, Reason(b), "closed")
		eq(t, ended(x) || ended(l.Context()), false)

		table.End("p1", ReasonBudget)
		eq(t, ended(x), true)
		eq(t, Reason(x), ReasonBudget)
		eq(t, Reason(l.Context()), ReasonBudget)

		late, _ := l.Child("ws")
		eq(t, ended(late), true)
		eq(t, Reason(late), ReasonBudget)
		p, _ := l.Preview(HeldPreview{ID: "a"})
		eq(t, Reason(p), ReasonBudget)
	})
}

func TestLeaseChecksEvery30sWhileEventsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		deadline := time.Now().Add(time.Hour)
		c.out = CheckOut{States: live(deadline, "p1")}
		table := run(t, c)
		table.Put("p1", State{Deadline: deadline, Remaining: gib})
		table.EventsDown(true)
		time.Sleep(90 * time.Second)
		synctest.Wait()
		table.EventsDown(false)
		time.Sleep(90 * time.Second)
		synctest.Wait()
		_, at := c.calls()
		eq(t, at, []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second,
			150 * time.Second})
	})
}

func TestLeaseCheckWithNoLeasesCallsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		time.Sleep(5 * time.Minute)
		table.CheckNow()
		synctest.Wait()
		ins, _ := c.calls()
		eq(t, len(ins), 0)
	})
}

func TestLeaseEndedPlacementAbsentFromAnswerEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		p1 := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		p2 := table.Put("p2", State{Deadline: deadline, Remaining: gib})
		answer(t, c, table, CheckOut{States: live(deadline, "p2")})
		eq(t, p1.Reason(), ReasonEnded)
		eq(t, ended(p2.Context()), false)
		_, ok := table.Get("p1")
		eq(t, ok, false)
		got, ok := table.Get("p2")
		eq(t, ok && got == p2, true)
	})
}

func TestLeaseCheckFailureChangesNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		c.err = errors.New("router unreachable")
		table := run(t, c)
		l := table.Put("p1", State{Deadline: time.Now().Add(time.Hour), Remaining: gib})
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		ins, _ := c.calls()
		eq(t, len(ins), 5)
		eq(t, ended(l.Context()), false)
	})
}

func TestLeaseZeroRemainingEndsWithBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		a := table.Put("a", State{Deadline: deadline, Remaining: gib})
		b := table.Put("b", State{Deadline: deadline, Remaining: gib})
		answer(t, c, table, CheckOut{States: map[string]State{
			"a": {Deadline: deadline}, "b": {Deadline: deadline, Remaining: 1},
		}})
		eq(t, a.Reason(), ReasonBudget)
		eq(t, ended(b.Context()), false)

		table.Move("b", State{Deadline: deadline})
		eq(t, b.Reason(), ReasonBudget)

		spent := table.Put("c", State{Deadline: deadline})
		eq(t, spent.Reason(), ReasonBudget)
		_, ok := table.Get("c")
		eq(t, ok, false)
	})
}

func TestLeasePutSharesTheLiveLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		table := run(t, newChecker())
		deadline := time.Now().Add(time.Hour)
		a := table.Put("p1", State{Deadline: deadline, Remaining: gib, SecretsVersion: 2})
		b := table.Put("p1", State{Deadline: deadline.Add(time.Minute), Remaining: 5})
		eq(t, a == b, true)
		eq(t, a.State(), State{Deadline: deadline.Add(time.Minute), Remaining: 5,
			SecretsVersion: 2})
		table.End("p1", ReasonEnded)
		c := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		eq(t, c == a, false)
		eq(t, ended(c.Context()), false)
	})
}

func TestLeaseStaleCheckAnswerIsSkipped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		hold := make(chan struct{})
		c.hold = hold
		table := run(t, c)
		old := time.Now().Add(time.Minute)
		l := table.Put("p1", State{Deadline: old, Remaining: gib})
		c.out = CheckOut{States: map[string]State{"p1": {Deadline: old}}}
		table.CheckNow()
		synctest.Wait()

		later := time.Now().Add(time.Hour)
		table.Move("p1", State{Deadline: later, Remaining: gib})
		c.set(func(c *checker) { c.hold = nil })
		close(hold)
		synctest.Wait()
		eq(t, ended(l.Context()), false)
		eq(t, l.State(), State{Deadline: later, Remaining: gib})
	})
}

func TestLeaseStaleCheckAnswerStillEndsAndRevokes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		hold := make(chan struct{})
		c.hold = hold
		table := run(t, c)
		deadline := time.Now().Add(time.Hour)
		p1 := table.Put("p1", State{Deadline: deadline, Remaining: gib})
		p2 := table.Put("p2", State{Deadline: deadline, Remaining: gib})
		preview, _ := p1.Preview(HeldPreview{ID: "a", Generation: 1})
		c.out = CheckOut{States: live(deadline, "p1"), Revoked: []string{"a"}}
		table.CheckNow()
		synctest.Wait()

		later := deadline.Add(time.Hour)
		table.Move("p1", State{Deadline: later, Remaining: 5})
		table.Put("p2", State{Deadline: later, Remaining: 5})
		c.set(func(c *checker) { c.hold = nil })
		close(hold)
		synctest.Wait()
		eq(t, Reason(preview), ReasonRevoked)
		eq(t, p2.Reason(), ReasonEnded)
		eq(t, ended(p1.Context()), false)
		eq(t, p1.State(), State{Deadline: later, Remaining: 5})
	})
}

func TestLeasePeriodicCheckGetsTenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		c.hold = make(chan struct{})
		table := run(t, c)
		l := table.Put("p1", State{Deadline: time.Now().Add(time.Hour), Remaining: gib})
		time.Sleep(70*time.Second - time.Millisecond)
		synctest.Wait()
		eq(t, c.ends(), []time.Duration(nil))
		time.Sleep(time.Millisecond)
		synctest.Wait()
		eq(t, c.ends(), []time.Duration{70 * time.Second})
		eq(t, ended(l.Context()), false)

		// A hung check leaves the next one on time
		time.Sleep(50 * time.Second)
		synctest.Wait()
		_, at := c.calls()
		eq(t, at, []time.Duration{60 * time.Second, 120 * time.Second})
	})
}

func TestLeaseOnStateSeesEveryStoredState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		table := run(t, c)
		var mu sync.Mutex
		var got []uint64
		table.OnState(func(placement string, s State) {
			mu.Lock()
			defer mu.Unlock()
			eq(t, placement, "p1")
			got = append(got, s.Remaining)
		})
		deadline := time.Now().Add(time.Hour)
		l := table.Put("p1", State{Deadline: deadline, Remaining: 10})
		table.Put("p1", State{Deadline: deadline, Remaining: 9})
		table.Move("p1", State{Deadline: deadline, Remaining: 8})
		table.Move("absent", State{Deadline: deadline, Remaining: 1})
		answer(t, c, table, CheckOut{States: map[string]State{
			"p1": {Deadline: deadline, Remaining: 7},
		}})

		// A stale answer is not handed on
		hold := make(chan struct{})
		c.set(func(c *checker) {
			c.hold = hold
			c.out = CheckOut{States: map[string]State{"p1": {Deadline: deadline, Remaining: 5}}}
		})
		table.CheckNow()
		synctest.Wait()
		table.Move("p1", State{Deadline: deadline, Remaining: 6})
		c.set(func(c *checker) { c.hold = nil })
		close(hold)
		synctest.Wait()

		table.Move("p1", State{Deadline: deadline})
		eq(t, l.Reason(), ReasonBudget)
		mu.Lock()
		defer mu.Unlock()
		eq(t, got, []uint64{10, 9, 8, 7, 6, 0})
	})
}

func TestLeaseMoveKeepsTheVersionWhenZero(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		table := run(t, newChecker())
		deadline := time.Now().Add(time.Hour)
		l := table.Put("p1", State{Deadline: deadline, Remaining: gib, SecretsVersion: 7})
		table.Move("p1", State{Deadline: deadline, Remaining: 9})
		eq(t, l.State(), State{Deadline: deadline, Remaining: 9, SecretsVersion: 7})
		table.Move("p1", State{Deadline: deadline, Remaining: 9, SecretsVersion: 8})
		eq(t, l.State().SecretsVersion, uint64(8))
		table.Move("absent", State{Deadline: deadline, Remaining: 9})
		_, ok := table.Get("absent")
		eq(t, ok, false)
	})
}

func TestReasonOfAnUnrelatedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	eq(t, Reason(ctx), "")
	cancel()
	eq(t, Reason(ctx), "")
}

func TestLeaseExtensionDuringTheDeadlineCheckKeepsTheLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newChecker()
		c.hold = make(chan struct{})
		table := runEvery(t, c, time.Hour)
		l := table.Put("p1", State{Deadline: time.Now().Add(10 * time.Second), Remaining: gib})
		time.Sleep(11 * time.Second)
		later := time.Now().Add(time.Hour)
		table.Move("p1", State{Deadline: later, Remaining: gib})
		time.Sleep(2 * time.Second)
		synctest.Wait()
		eq(t, ended(l.Context()), false)
		eq(t, l.State().Deadline, later)
	})
}
