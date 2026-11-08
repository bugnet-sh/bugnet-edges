package x402

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
)

// Unpaid is one host's unpaid use
type Unpaid struct {
	Requests uint32
	Bytes    uint64
}

// plus adds v to u, each count stopping at its largest value
func (u Unpaid) plus(v Unpaid) Unpaid {
	return Unpaid{Requests: sat(u.Requests, v.Requests), Bytes: sat(u.Bytes, v.Bytes)}
}

// minus takes v from u, each count stopping at zero
func (u Unpaid) minus(v Unpaid) Unpaid {
	return Unpaid{Requests: u.Requests - min(u.Requests, v.Requests),
		Bytes: u.Bytes - min(u.Bytes, v.Bytes)}
}

func sat[T uint32 | uint64](a, b T) T {
	if s := a + b; s >= a {
		return s
	}
	return ^T(0)
}

// Caps are the per-placement caps X402Config carries
type Caps struct {
	Requests uint32
	Bytes    uint64
}

// Counters hold each placement's unpaid use per host and the deltas not yet reported
type Counters struct {
	mu     sync.Mutex
	places map[string]*placeUse
}

// placeUse is one placement's hosts
type placeUse struct {
	hosts map[string]*hostUse
	// dropped forgets the placement once none of its deltas is left to report
	dropped bool
}

// hostUse is a host's count, its deltas not yet taken and those a report is carrying
type hostUse struct {
	own, unreported, out Unpaid
}

// NewCounters makes counters that know no placement yet
func NewCounters() *Counters {
	return &Counters{places: map[string]*placeUse{}}
}

// host is a host's entry, made when missing, with c.mu held
func (c *Counters) host(placement, host string) *hostUse {
	pl := c.places[placement]
	if pl == nil {
		pl = &placeUse{hosts: map[string]*hostUse{}}
		c.places[placement] = pl
	}
	hu := pl.hosts[host]
	if hu == nil {
		hu = &hostUse{}
		pl.hosts[host] = hu
	}
	return hu
}

// Merge sets each host's count to max(own, used plus unreported), on every resolve
func (c *Counters) Merge(placement string, used map[string]Unpaid) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pl := c.places[placement]
	if pl == nil {
		pl = &placeUse{hosts: map[string]*hostUse{}}
		c.places[placement] = pl
	}
	pl.dropped = false
	for h, u := range used {
		hu := c.host(placement, h)
		// A report still out is not yet known to be in used, so it counts as unreported
		least := u.plus(hu.unreported).plus(hu.out)
		hu.own = Unpaid{Requests: max(hu.own.Requests, least.Requests),
			Bytes: max(hu.own.Bytes, least.Bytes)}
	}
}

// Over says whether either cap is reached for this host, so a zero cap always is
func (c *Counters) Over(placement, host string, caps Caps) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var u Unpaid
	if pl := c.places[placement]; pl != nil {
		if hu := pl.hosts[host]; hu != nil {
			u = hu.own
		}
	}
	return u.Requests >= caps.Requests || u.Bytes >= caps.Bytes
}

// AddRequest counts one unpaid request to the host
func (c *Counters) AddRequest(placement, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hu := c.host(placement, host)
	one := Unpaid{Requests: 1}
	hu.own = hu.own.plus(one)
	hu.unreported = hu.unreported.plus(one)
}

// AddBytes counts bytes and says whether the byte cap is now reached
func (c *Counters) AddBytes(placement, host string, n int64, caps Caps) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	hu := c.host(placement, host)
	if n > 0 {
		b := Unpaid{Bytes: uint64(n)}
		hu.own = hu.own.plus(b)
		hu.unreported = hu.unreported.plus(b)
	}
	return hu.own.Bytes >= caps.Bytes
}

// Take hands out the unreported deltas, nil when there are none
func (c *Counters) Take() map[string]*routerv1.X402UnpaidByHost {
	c.mu.Lock()
	defer c.mu.Unlock()
	var d map[string]*routerv1.X402UnpaidByHost
	for p, pl := range c.places {
		for h, hu := range pl.hosts {
			u := hu.unreported
			if u == (Unpaid{}) {
				continue
			}
			if d == nil {
				d = map[string]*routerv1.X402UnpaidByHost{}
			}
			if d[p] == nil {
				d[p] = &routerv1.X402UnpaidByHost{Hosts: map[string]*routerv1.X402Unpaid{}}
			}
			d[p].Hosts[h] = &routerv1.X402Unpaid{Requests: u.Requests, Bytes: u.Bytes}
			hu.out = hu.out.plus(u)
			hu.unreported = Unpaid{}
		}
	}
	return d
}

// Restore puts back the deltas of a failed report
func (c *Counters) Restore(d map[string]*routerv1.X402UnpaidByHost) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, byHost := range d {
		if c.places[p] == nil {
			// A placement these counters no longer hold is reported once more, then forgotten
			c.places[p] = &placeUse{hosts: map[string]*hostUse{}, dropped: true}
		}
		for h, u := range byHost.GetHosts() {
			hu := c.host(p, h)
			back := Unpaid{Requests: u.GetRequests(), Bytes: u.GetBytes()}
			hu.out = hu.out.minus(back)
			hu.unreported = hu.unreported.plus(back)
		}
	}
}

// settle forgets the deltas of a report the router took
func (c *Counters) settle(d map[string]*routerv1.X402UnpaidByHost) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, byHost := range d {
		pl := c.places[p]
		if pl == nil {
			continue
		}
		for h, u := range byHost.GetHosts() {
			if hu := pl.hosts[h]; hu != nil {
				hu.out = hu.out.minus(Unpaid{Requests: u.GetRequests(), Bytes: u.GetBytes()})
			}
		}
		c.tidy(p)
	}
}

// Drop forgets a placement once its last deltas went out
func (c *Counters) Drop(placement string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pl := c.places[placement]; pl != nil {
		pl.dropped = true
		c.tidy(placement)
	}
}

// tidy forgets a dropped placement with no delta left to report, with c.mu held
func (c *Counters) tidy(placement string) {
	pl := c.places[placement]
	if pl == nil || !pl.dropped {
		return
	}
	for _, hu := range pl.hosts {
		if hu.unreported != (Unpaid{}) || hu.out != (Unpaid{}) {
			return
		}
	}
	delete(c.places, placement)
}

// SendUnpaid reports deltas through ReportEgressUsage under the egress reporter id
type SendUnpaid func(ctx context.Context, d map[string]*routerv1.X402UnpaidByHost) error

// UnpaidSend reports through ReportEgressUsage under reporterID, with usage empty
func UnpaidSend(c routerv1connect.EgressServiceClient, reporterID string) SendUnpaid {
	return func(ctx context.Context, d map[string]*routerv1.X402UnpaidByHost) error {
		_, err := c.ReportEgressUsage(ctx, connect.NewRequest(&routerv1.ReportEgressUsageRequest{
			ReporterId: reporterID, X402Unpaid: d,
		}))
		return err
	}
}

// RunReports sends deltas every interval and once more when ctx ends
func (c *Counters) RunReports(ctx context.Context, send SendUnpaid, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			last, cancel := context.WithTimeout(context.WithoutCancel(ctx), every)
			c.report(last, send)
			cancel()
			return
		case <-tick.C:
			// A report the router has not answered by the next tick goes out again with it
			one, cancel := context.WithTimeout(ctx, every)
			c.report(one, send)
			cancel()
		}
	}
}

// report sends the unreported deltas once, restoring them when the send fails
func (c *Counters) report(ctx context.Context, send SendUnpaid) {
	d := c.Take()
	if d == nil {
		return
	}
	if err := send(ctx, d); err != nil {
		c.Restore(d)
		return
	}
	c.settle(d)
}

// UnpaidEnd says whether an end with this event status was not paid by Bugnet
func UnpaidEnd(status string) bool {
	return status != EventPaid && status != EventUncertain
}

// CountsRequest says whether an ended request counts toward the unpaid request cap
func CountsRequest(reached bool, status string, reason Code) bool {
	if !reached || !UnpaidEnd(status) {
		return false
	}
	r, ok := Lookup(reason)
	return !ok || !r.OwnLimit
}
