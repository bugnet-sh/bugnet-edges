// Package lease ends each placement's traffic at its deadline, its end, its spent bytes or an event
package lease

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

// Reasons a lease or one of its children ends with, which the pages show
const (
	ReasonEnded   = "ended"
	ReasonExpired = "expired"
	ReasonBudget  = "budget"
	ReasonRevoked = "revoked"
)

const (
	// deadlineCheck bounds the one check made when a deadline timer fires
	deadlineCheck = 2 * time.Second
	checkTimeout  = 10 * time.Second
)

// Ended is the cause every lease and child context ends with
type Ended struct {
	Reason string
}

func (e *Ended) Error() string {
	return "lease ended: " + e.Reason
}

// Reason is the reason the lease or child behind ctx ended with, empty for any other end
func Reason(ctx context.Context) string {
	var e *Ended
	if errors.As(context.Cause(ctx), &e) {
		return e.Reason
	}
	return ""
}

// HeldPreview is a preview route the edge holds, by id and generation
type HeldPreview struct {
	ID         string
	Generation uint32
}

// CheckIn is what one lease check asks about
type CheckIn struct {
	Placements []string
	Held       []HeldPreview // every preview route held, empty from the proxy
}

// State is what the router says about a placement, Remaining 0 means its bytes are spent
type State struct {
	Deadline       time.Time
	Remaining      uint64
	SecretsVersion uint64 // the proxy's, zero from the edge
}

// CheckOut is the router's answer to a lease check
type CheckOut struct {
	States  map[string]State // placements still ready, ended ones absent
	Revoked []string         // held preview ids revoked or whose generation moved
}

// Check asks the router about the leases in CheckIn
type Check func(ctx context.Context, in CheckIn) (CheckOut, error)

// Table holds one lease per placement
type Table struct {
	check            Check
	every, whileDown time.Duration
	// wake recomputes the next check after the event stream went down or came back
	wake chan struct{}
	now  chan struct{}

	mu        sync.Mutex
	leases    map[string]*Lease
	onVersion func(placement string, version uint64)
	down      bool
}

// Lease is one placement's context and the children that run under it
type Lease struct {
	t         *Table
	placement string
	ctx       context.Context
	cancel    context.CancelCauseFunc

	// The fields below are guarded by the table's mutex
	state State
	// seq counts state changes, so an answer to a check sent before the last one is not applied
	seq      uint64
	timer    *time.Timer
	reason   string
	children map[*child]struct{}
}

type child struct {
	key     string
	preview *HeldPreview
	cancel  context.CancelCauseFunc
}

// NewTable checks every lease each every, and each everyWhileDown while events are down
func NewTable(check Check, every, everyWhileDown time.Duration) *Table {
	return &Table{
		check:     check,
		every:     every,
		whileDown: everyWhileDown,
		wake:      make(chan struct{}, 1),
		now:       make(chan struct{}, 1),
		leases:    map[string]*Lease{},
	}
}

// OnVersion runs when a check answers a secrets version other than the lease's
func (t *Table) OnVersion(f func(placement string, version uint64)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onVersion = f
}

// Get returns the placement's live lease
func (t *Table) Get(placement string) (*Lease, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.leases[placement]
	return l, ok
}

// Put returns the placement's live lease moved to s, or a new one, ended at once when s is spent
func (t *Table) Put(placement string, s State) *Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.leases[placement]; ok {
		t.moveLocked(l, s)
		return l
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &Lease{
		t: t, placement: placement, ctx: ctx, cancel: cancel, children: map[*child]struct{}{},
	}
	t.leases[placement] = l
	t.moveLocked(l, s)
	return l
}

// Move gives the placement's lease a new state, a zero SecretsVersion keeps the lease's
func (t *Table) Move(placement string, s State) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.leases[placement]; ok {
		t.moveLocked(l, s)
	}
}

// End cancels the placement's lease and every child with reason and forgets it
func (t *Table) End(placement string, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.leases[placement]; ok {
		t.endLocked(l, reason)
	}
}

// Revoke cancels the placement's children holding that preview, with ReasonRevoked
func (t *Table) Revoke(placement, previewID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.leases[placement]; ok {
		l.revokeLocked(map[string]bool{previewID: true})
	}
}

// EventsDown switches checks to everyWhileDown while the event stream is down
func (t *Table) EventsDown(down bool) {
	t.mu.Lock()
	changed := t.down != down
	t.down = down
	t.mu.Unlock()
	if changed {
		signal(t.wake)
	}
}

// CheckNow asks Run for a check of every lease at once
func (t *Table) CheckNow() {
	signal(t.now)
}

// Apply acts on one event, kind picks the budget this binary enforces
func (t *Table) Apply(ev *routerv1.EdgeEvent, kind routerv1.BudgetKind) {
	switch e := ev.GetEvent().(type) {
	case *routerv1.EdgeEvent_PlacementEnded:
		reason := ReasonEnded
		if e.PlacementEnded.GetReason() == routerv1.EndReason_END_REASON_EXPIRED {
			reason = ReasonExpired
		}
		t.End(e.PlacementEnded.GetPlacementId(), reason)
	case *routerv1.EdgeEvent_DeadlineMoved:
		m := e.DeadlineMoved
		if m.GetDeadline() == nil {
			return
		}
		left := m.GetEdgeBytesRemaining()
		if kind == routerv1.BudgetKind_BUDGET_KIND_EGRESS {
			left = m.GetEgressBytesRemaining()
		}
		t.Move(m.GetPlacementId(), State{Deadline: m.GetDeadline().AsTime(), Remaining: left})
	case *routerv1.EdgeEvent_PreviewRevoked:
		t.Revoke(e.PreviewRevoked.GetPlacementId(), e.PreviewRevoked.GetPreviewId())
	case *routerv1.EdgeEvent_BudgetSpent:
		if e.BudgetSpent.GetKind() == kind {
			t.End(e.BudgetSpent.GetPlacementId(), ReasonBudget)
		}
	case *routerv1.EdgeEvent_Resync:
		t.CheckNow()
	}
}

// Run checks every lease on its interval until ctx ends
func (t *Table) Run(ctx context.Context) {
	last := time.Now()
	for {
		t.mu.Lock()
		period := t.every
		if t.down {
			period = t.whileDown
		}
		t.mu.Unlock()
		timer := time.NewTimer(time.Until(last.Add(period)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-t.wake:
			timer.Stop()
			continue
		case <-t.now:
			timer.Stop()
		case <-timer.C:
		}
		last = time.Now()
		t.checkAll(ctx)
	}
}

// taken is a lease as it stood when a check was sent
type taken struct {
	l   *Lease
	seq uint64
}

func (t *Table) checkAll(ctx context.Context) {
	t.mu.Lock()
	snap := make(map[string]taken, len(t.leases))
	ls := make([]*Lease, 0, len(t.leases))
	for id, l := range t.leases {
		snap[id] = taken{l, l.seq}
		ls = append(ls, l)
	}
	in := checkIn(ls)
	t.mu.Unlock()
	if len(snap) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	out, err := t.check(ctx, in)
	cancel()
	if err != nil {
		return
	}
	t.answer(snap, out, ReasonEnded)
}

// expire runs when l's deadline timer fires, checking once before it cancels
func (t *Table) expire(l *Lease, armed time.Time) {
	t.mu.Lock()
	if t.leases[l.placement] != l || !l.state.Deadline.Equal(armed) {
		t.mu.Unlock()
		return
	}
	snap := map[string]taken{l.placement: {l, l.seq}}
	in := checkIn([]*Lease{l})
	t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), deadlineCheck)
	out, err := t.check(ctx, in)
	cancel()
	if err == nil {
		if s, ok := out.States[l.placement]; ok && s.Deadline.After(time.Now()) {
			t.answer(snap, out, ReasonExpired)
			return
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.leases[l.placement] == l && !l.state.Deadline.After(time.Now()) {
		t.endLocked(l, ReasonExpired)
	}
}

// answer applies a check's answer to the leases it asked about, absent ones end with absent
func (t *Table) answer(snap map[string]taken, out CheckOut, absent string) {
	revoked := map[string]bool{}
	for _, id := range out.Revoked {
		revoked[id] = true
	}
	type moved struct {
		placement string
		version   uint64
	}
	var versions []moved

	t.mu.Lock()
	for id, k := range snap {
		l := k.l
		if t.leases[id] != l {
			continue
		}
		if len(revoked) > 0 {
			l.revokeLocked(revoked)
		}
		s, ok := out.States[id]
		if !ok {
			t.endLocked(l, absent)
			continue
		}
		if l.seq != k.seq {
			continue
		}
		if s.SecretsVersion != l.state.SecretsVersion {
			versions = append(versions, moved{id, s.SecretsVersion})
		}
		t.setLocked(l, s)
	}
	f := t.onVersion
	t.mu.Unlock()

	if f == nil {
		return
	}
	slices.SortFunc(versions, func(a, b moved) int { return cmp.Compare(a.placement, b.placement) })
	for _, v := range versions {
		f(v.placement, v.version)
	}
}

func (t *Table) moveLocked(l *Lease, s State) {
	if s.SecretsVersion == 0 {
		s.SecretsVersion = l.state.SecretsVersion
	}
	t.setLocked(l, s)
}

// setLocked stores s, re-arms the deadline timer and ends the lease when its bytes are spent
func (t *Table) setLocked(l *Lease, s State) {
	l.seq++
	moved := !s.Deadline.Equal(l.state.Deadline) || l.timer == nil
	l.state = s
	if s.Remaining == 0 {
		t.endLocked(l, ReasonBudget)
		return
	}
	if moved {
		if l.timer != nil {
			l.timer.Stop()
		}
		armed := s.Deadline
		l.timer = time.AfterFunc(time.Until(armed), func() { t.expire(l, armed) })
	}
}

func (t *Table) endLocked(l *Lease, reason string) {
	if t.leases[l.placement] == l {
		delete(t.leases, l.placement)
	}
	if l.timer != nil {
		l.timer.Stop()
	}
	if l.reason == "" {
		l.reason = reason
	}
	clear(l.children)
	l.cancel(&Ended{Reason: reason})
}

// Child is a context under the lease, cancelled alone, by CancelChildren with key, or with it
func (l *Lease) Child(key string) (context.Context, context.CancelFunc) {
	return l.add(key, nil)
}

// Preview is a child lease that every check reports as held, cancelled when revoked
func (l *Lease) Preview(p HeldPreview) (context.Context, context.CancelFunc) {
	return l.add("", &p)
}

func (l *Lease) add(key string, p *HeldPreview) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(l.ctx)
	c := &child{key: key, preview: p, cancel: cancel}
	l.t.mu.Lock()
	if l.ctx.Err() == nil {
		l.children[c] = struct{}{}
	}
	l.t.mu.Unlock()
	return ctx, func() {
		l.t.mu.Lock()
		delete(l.children, c)
		l.t.mu.Unlock()
		cancel(context.Canceled)
	}
}

// CancelChildren cancels every child made with key, with reason
func (l *Lease) CancelChildren(key, reason string) {
	l.t.mu.Lock()
	defer l.t.mu.Unlock()
	for c := range l.children {
		if c.preview == nil && c.key == key {
			delete(l.children, c)
			c.cancel(&Ended{Reason: reason})
		}
	}
}

func (l *Lease) revokeLocked(ids map[string]bool) {
	for c := range l.children {
		if c.preview != nil && ids[c.preview.ID] {
			delete(l.children, c)
			c.cancel(&Ended{Reason: ReasonRevoked})
		}
	}
}

// Context ends with the lease, its cause an *Ended
func (l *Lease) Context() context.Context {
	return l.ctx
}

// Reason is why the lease ended, empty while it is live
func (l *Lease) Reason() string {
	l.t.mu.Lock()
	defer l.t.mu.Unlock()
	return l.reason
}

// State is the lease's last known state
func (l *Lease) State() State {
	l.t.mu.Lock()
	defer l.t.mu.Unlock()
	return l.state
}

// checkIn lists the leases' placements and their held previews, sorted and without repeats
func checkIn(ls []*Lease) CheckIn {
	var in CheckIn
	for _, l := range ls {
		in.Placements = append(in.Placements, l.placement)
		for c := range l.children {
			if c.preview != nil {
				in.Held = append(in.Held, *c.preview)
			}
		}
	}
	slices.Sort(in.Placements)
	slices.SortFunc(in.Held, func(a, b HeldPreview) int {
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.Generation, b.Generation))
	})
	in.Held = slices.Compact(in.Held)
	return in
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}
