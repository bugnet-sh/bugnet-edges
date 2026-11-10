package sshgw

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/pace"
)

// releaseTimeout bounds the lease release a closing connection sends
const releaseTimeout = 5 * time.Second

// conn is one user connection, from accept to close
type conn struct {
	g      *Gateway
	nc     net.Conn
	ip     netip.Addr
	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once

	mu     sync.Mutex
	grants map[string]*routerv1.AuthorizeSshKeyResponse // by fingerprint, from checkKey

	// Set once by attach, before the connection is shared
	placement   string
	grantID     string
	fingerprint string
	lease       string
	lane        *pace.Lane
	maxSessions int
	maxForwards int

	sc *ssh.ServerConn
	up ssh.Conn

	// deadline state, see deadline.go
	dl       time.Time
	dlTimer  *time.Timer
	sessions map[*session]struct{}

	// trace is the connection's ssh.connection span, once acquire has succeeded
	trace connTrace

	noMoreSessions atomic.Bool
	sessionCount   atomic.Int32
	forwardCount   atomic.Int32
	relays         sync.WaitGroup
}

func newConn(bg context.Context, g *Gateway, nc net.Conn, ip netip.Addr) *conn {
	ctx, cancel := context.WithCancel(bg)
	return &conn{
		g: g, nc: nc, ip: ip, ctx: ctx, cancel: cancel, trace: connTrace{accepted: time.Now()},
		grants:   map[string]*routerv1.AuthorizeSshKeyResponse{},
		sessions: map[*session]struct{}{},
	}
}

// setUp keeps the upstream connection, or closes it when the connection already ended
func (c *conn) setUp(up ssh.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		_ = up.Close()
		return false
	}
	c.up = up
	return true
}

func (c *conn) rememberGrant(fp string, r *routerv1.AuthorizeSshKeyResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grants[fp] = r
}

func (c *conn) grantFor(fp string) *routerv1.AuthorizeSshKeyResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.grants[fp]
}

// attach records the lease and registers the connection for events, deadlines and budget
func (c *conn) attach(
	grant *routerv1.AuthorizeSshKeyResponse, fp string, res *routerv1.AcquireSshConnectionResponse,
) {
	c.placement, c.grantID, c.fingerprint = grant.GetPlacementId(), grant.GetGrantId(), fp
	c.lease = res.GetLeaseId()
	c.trace.begin(c.g.cfg.Tracing, grant.GetOrderTraceparent(), c.placement)
	c.maxSessions = limit(int(grant.GetMaxSessions()), c.g.cfg.MaxSessionsPerConnection)
	c.maxForwards = limit(int(grant.GetMaxForwards()), c.g.cfg.MaxForwardsPerConnection)
	c.g.attach(c, res.GetBudget())
	c.lane = c.g.pacer.Lane(c.placement)
	if grant.GetDeadline() != nil {
		c.setDeadline(grant.GetDeadline().AsTime())
	}
	go c.renewLoop()
}

// limit is the router's figure when it gave one and it is the smaller, else the setting
func limit(router, setting int) int {
	if router > 0 && router < setting {
		return router
	}
	return setting
}

// run takes the connection through the handshake, the relay and the close
func (c *conn) run() {
	defer c.close("done")
	_ = c.nc.SetDeadline(time.Now().Add(time.Duration(c.g.cfg.HandshakeTimeout)))
	sc, chans, reqs, err := ssh.NewServerConn(c.nc, c.g.serverConfig(c))
	if err != nil {
		return
	}
	_ = c.nc.SetDeadline(time.Time{})
	c.sc = sc
	defer c.g.detach(c)
	if text, ok := sc.Permissions.Extensions[extRefuse]; ok {
		go c.globalRequests(reqs)
		c.refuseSessions(chans, text)
		return
	}
	c.serve(chans, reqs)
	c.relays.Wait()
}

// close ends both legs and gives the lease back, once
func (c *conn) close(reason string) {
	c.closeOnce.Do(func() {
		c.g.m.closes.Inc(reason)
		defer c.trace.end(reason)
		c.cancel()
		c.stopTimers()
		_ = c.nc.Close()
		c.mu.Lock()
		up := c.up
		c.mu.Unlock()
		if up != nil {
			_ = up.Close()
		}
		if c.lease != "" {
			c.release()
		}
	})
}

// release gives the lease back without waiting for the router
func (c *conn) release() {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.traced()), releaseTimeout)
		defer cancel()
		_, err := c.g.router.ReleaseSshConnection(ctx,
			connect.NewRequest(&routerv1.ReleaseSshConnectionRequest{
				GrantId: c.grantID, LeaseId: c.lease,
			}))
		if err != nil {
			c.g.log.Debug("ssh: lease release failed", "err", err)
		}
	}()
}

// renewLoop renews the lease every renewEvery, and closes the connection when the grant is gone
func (c *conn) renewLoop() {
	t := time.NewTicker(c.g.renewEvery)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(c.ctx, c.g.routerTimeout)
		_, err := c.g.router.RenewSshConnection(ctx,
			connect.NewRequest(&routerv1.RenewSshConnectionRequest{
				GrantId: c.grantID, LeaseId: c.lease,
			}))
		cancel()
		if err != nil && c.ctx.Err() == nil {
			if classify(err) == denied {
				c.close("revoked")
				return
			}
			c.g.log.Warn("ssh: lease renewal failed", "err", err)
		}
	}
}

// counted wraps r so each piece read counts toward the placement, in is toward the sandbox
func (c *conn) counted(r io.Reader, in bool) io.Reader {
	return c.lane.Reader(r, in, func(n int) {
		if in {
			c.g.rep.Add(c.placement, int64(n), 0)
			c.trace.bytesIn.Add(int64(n))
		} else {
			c.g.rep.Add(c.placement, 0, int64(n))
			c.trace.bytesOut.Add(int64(n))
		}
	})
}
