package sshgw

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

const (
	// firedTries and firedGap bound the router calls a fired deadline timer makes
	firedTries = 3
	firedGap   = time.Second
)

// setDeadline arms the connection's timer and its PTY sessions' warnings for t
func (c *conn) setDeadline(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return
	}
	c.dl = t
	if c.dlTimer != nil {
		c.dlTimer.Stop()
	}
	c.dlTimer = time.AfterFunc(time.Until(t), c.deadlineFired)
	for s := range c.sessions {
		s.arm(t)
	}
}

// deadline is the time the connection's grant last said it ends
func (c *conn) deadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dl
}

func (c *conn) stopTimers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dlTimer != nil {
		c.dlTimer.Stop()
	}
	for s := range c.sessions {
		s.disarm()
	}
}

// deadlineFired asks the router once whether the grant lives on, then re-arms or closes (DP 9.6)
func (c *conn) deadlineFired() {
	for try := range firedTries {
		deadlines, err := c.g.checkGrants(c.ctx, []string{c.grantID})
		if c.ctx.Err() != nil {
			return
		}
		if err == nil {
			if d, ok := deadlines[c.grantID]; ok && d.After(time.Now()) {
				c.setDeadline(d)
				return
			}
			c.close("deadline")
			return
		}
		if try < firedTries-1 {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(firedGap):
			}
		}
	}
	c.close("deadline")
}

// checkGrants is CheckSshGrants, answering the deadline of each grant that still stands
func (g *Gateway) checkGrants(ctx context.Context, ids []string) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, g.routerTimeout)
	defer cancel()
	res, err := g.router.CheckSshGrants(ctx,
		connect.NewRequest(&routerv1.CheckSshGrantsRequest{GrantIds: ids}))
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(res.Msg.GetDeadlines()))
	for id, t := range res.Msg.GetDeadlines() {
		out[id] = t.AsTime()
	}
	return out, nil
}

// checkNow asks checkLoop for a check of every live grant at once
func (g *Gateway) checkNow() {
	select {
	case g.check <- struct{}{}:
	default:
	}
}

// checkLoop checks every live grant in one call each checkEvery, which bounds a lost event
func (g *Gateway) checkLoop(ctx context.Context) {
	t := time.NewTicker(g.checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-g.check:
		}
		g.checkAll(ctx)
	}
}

func (g *Gateway) checkAll(ctx context.Context) {
	g.mu.Lock()
	byGrant := map[string][]*conn{}
	var ids []string
	for c := range g.conns {
		if _, ok := byGrant[c.grantID]; !ok {
			ids = append(ids, c.grantID)
		}
		byGrant[c.grantID] = append(byGrant[c.grantID], c)
	}
	g.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	deadlines, err := g.checkGrants(ctx, ids)
	if err != nil {
		if ctx.Err() == nil {
			g.log.Warn("ssh: the grant check failed", "grants", len(ids), "err", err)
		}
		return
	}
	for id, conns := range byGrant {
		d, ok := deadlines[id]
		for _, c := range conns {
			switch {
			case !ok || !d.After(time.Now()):
				c.close("revoked")
			case !d.Equal(c.deadline()):
				c.setDeadline(d)
			}
		}
	}
}

// onEvent acts on one event of the router's stream (DP 9.6)
func (g *Gateway) onEvent(ev *routerv1.EdgeEvent) {
	switch e := ev.GetEvent().(type) {
	case *routerv1.EdgeEvent_PlacementEnded:
		g.closePlacement(e.PlacementEnded.GetPlacementId(), "ended")
	case *routerv1.EdgeEvent_SshKeyRemoved:
		k := e.SshKeyRemoved
		g.closeWhere("key_removed", func(c *conn) bool {
			return c.placement == k.GetPlacementId() && c.fingerprint == k.GetFingerprint()
		})
	case *routerv1.EdgeEvent_BudgetSpent:
		if e.BudgetSpent.GetKind() == routerv1.BudgetKind_BUDGET_KIND_EDGE {
			g.closePlacement(e.BudgetSpent.GetPlacementId(), "budget")
		}
	case *routerv1.EdgeEvent_DeadlineMoved:
		m := e.DeadlineMoved
		if m.GetDeadline() == nil {
			return
		}
		g.rep.SetRemaining(m.GetPlacementId(), m.GetEdgeBytesRemaining())
		for _, c := range g.connsOf(m.GetPlacementId()) {
			c.setDeadline(m.GetDeadline().AsTime())
		}
	case *routerv1.EdgeEvent_Resync:
		g.checkNow()
	}
}

func (g *Gateway) closePlacement(placement, reason string) {
	for _, c := range g.connsOf(placement) {
		c.close(reason)
	}
}

// answered is the usage reporter's word on a placement, the pace it now gets or no bytes left
func (g *Gateway) answered(placement string, remaining, perSecond uint64) {
	if remaining == 0 {
		g.closePlacement(placement, "budget")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.places[placement] > 0 && perSecond > 0 {
		g.pacer.Lane(placement).SetRate(int64(perSecond))
	}
}

// eventsDown logs the event stream dropping or returning, the 60 s check bounds what is lost
func (g *Gateway) eventsDown(down bool) {
	if down {
		g.log.Warn("ssh: the router's event stream is down")
		return
	}
	g.log.Info("ssh: the router's event stream is up")
}

/* PTY warnings */

// warnLine is the one line a PTY session gets before its sandbox ends (DP 9.6)
func warnLine(end time.Time) string {
	return fmt.Sprintf("bugnet: this sandbox ends at %s, bugnet_extend extends it\r\n",
		end.UTC().Format("15:04:05 MST"))
}

// arm schedules the session's warning for warnBefore ahead of end, once for each end
func (s *session) arm(end time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pty || s.closed || s.warned.Equal(end) {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(time.Until(end.Add(-s.c.g.warnBefore)), func() { s.warn(end) })
}

func (s *session) disarm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
}

func (s *session) warn(end time.Time) {
	s.mu.Lock()
	if s.closed || s.warned.Equal(end) {
		s.mu.Unlock()
		return
	}
	s.warned = end
	s.mu.Unlock()
	_, _ = s.ch.Stderr().Write([]byte(warnLine(end)))
}
