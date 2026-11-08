// Package sshgw is the SSH gateway, DP 9, which relays an authenticated user to one sandbox's sshd
package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/events"
	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/pace"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
	"github.com/bugnet-sh/bugnet-edges/internal/usage"
)

const (
	// reportBytes is the unsent byte count that makes the usage reporter send at once
	reportBytes = 8 << 20
	// serverVersion is the version string the gateway announces
	serverVersion = "SSH-2.0-Bugnet"
)

// Gateway accepts SSH connections and relays each one to its placement's sshd
type Gateway struct {
	cfg    Config
	router routerv1connect.SshGatewayServiceClient
	log    *slog.Logger
	seed   [32]byte

	accepts *strangers.PerIP
	guard   *strangers.Guard
	aliases *aliasFailures
	keys    *keyCache
	pacer   *pace.Pacer
	rep     *usage.Reporter
	watcher *events.Watcher
	m       gatewayMetrics

	// Timings that tests shorten
	renewEvery    time.Duration
	checkEvery    time.Duration
	warnBefore    time.Duration
	upstreamWait  time.Duration
	routerTimeout time.Duration

	live sync.WaitGroup
	// check asks checkLoop for a check of every live grant at once
	check chan struct{}

	mu     sync.Mutex
	conns  map[*conn]struct{}
	places map[string]int // live connections by placement
}

type gatewayMetrics struct {
	accepts  *metrics.Counter
	auths    *metrics.Counter
	closes   *metrics.Counter
	live     *metrics.Gauge
	sessions *metrics.Counter
}

// New makes a gateway for cfg that calls router, with a fresh seed for its upstream keys
func New(cfg Config, router routerv1connect.SshGatewayServiceClient) *Gateway {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New()
	}
	g := &Gateway{
		cfg: cfg, router: router, log: cfg.Log.With("role", "ssh"),
		accepts: strangers.NewPerIP(cfg.AcceptsPerMinutePerIP),
		guard: strangers.NewGuard(cfg.AuthFailuresPerMinutePerIP, strangers.Mark,
			strangers.Unknown),
		aliases:       newAliasFailures(cfg.AuthFailuresPerMinutePerIP),
		keys:          newKeyCache(),
		pacer:         pace.New(int64(cfg.TotalBytesPerSecond)),
		renewEvery:    20 * time.Second,
		checkEvery:    time.Minute,
		warnBefore:    time.Minute,
		upstreamWait:  time.Minute,
		routerTimeout: 15 * time.Second,
		check:         make(chan struct{}, 1),
		conns:         map[*conn]struct{}{},
		places:        map[string]int{},
	}
	if _, err := rand.Read(g.seed[:]); err != nil {
		panic(err)
	}
	r := cfg.Metrics
	g.m = gatewayMetrics{
		accepts:  r.Counter("bugnet_ssh_accepts_total", "Accepted connections by result", "result"),
		auths:    r.Counter("bugnet_ssh_auths_total", "Authentications by result", "result"),
		closes:   r.Counter("bugnet_ssh_closes_total", "Closed connections by reason", "reason"),
		live:     r.Gauge("bugnet_ssh_connections", "Open authenticated connections"),
		sessions: r.Counter("bugnet_ssh_sessions_total", "Sessions relayed"),
	}
	g.rep = usage.NewReporter(usage.SSHSend(router, cfg.GatewayID),
		time.Duration(cfg.UsageReportInterval), reportBytes)
	g.rep.OnAnswer(g.answered)
	g.watcher = events.NewWatcher(events.SSHEvents(router), g.onEvent,
		func() { g.checkNow() }, g.eventsDown)
	return g
}

// upstreamKey is the key placement's sandbox accepts from this process and no other
func (g *Gateway) upstreamKey(placement string) ed25519.PrivateKey {
	mac := hmac.New(sha256.New, g.seed[:])
	mac.Write([]byte(placement))
	return ed25519.NewKeyFromSeed(mac.Sum(nil))
}

// Serve accepts connections on ln until ctx ends, then drains the open ones to their deadlines
func (g *Gateway) Serve(ctx context.Context, ln net.Listener) error {
	// The background work outlives ctx, since the drained sessions still need it
	bg, stopBg := context.WithCancel(context.WithoutCancel(ctx))
	var work sync.WaitGroup
	work.Go(func() { g.rep.Run(bg) })
	work.Go(func() { g.watcher.Run(bg) })
	work.Go(func() { g.checkLoop(bg) })
	defer func() {
		stopBg()
		work.Wait()
	}()

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			g.log.Warn("ssh: accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		g.live.Add(1)
		go g.handle(bg, nc)
	}
	g.drain()
	return nil
}

// drain waits for the open connections, which close at their deadlines, up to drain_max
func (g *Gateway) drain() {
	done := make(chan struct{})
	go func() {
		g.live.Wait()
		close(done)
	}()
	t := time.NewTimer(time.Duration(g.cfg.DrainMax))
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		g.closeWhere("drain", func(*conn) bool { return true })
		<-done
	}
}

// handle runs one accepted connection to its end
func (g *Gateway) handle(bg context.Context, nc net.Conn) {
	defer g.live.Done()
	defer func() { _ = nc.Close() }()
	ip := addrOf(nc.RemoteAddr())
	switch {
	case !g.accepts.Allow(ip):
		g.m.accepts.Inc("limited")
		return
	case g.guard.Marked(ip):
		g.m.accepts.Inc("marked")
		return
	}
	g.m.accepts.Inc("ok")
	newConn(bg, g, nc, ip).run()
}

// addrOf is the peer's address, or the zero address when it has none
func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// serverConfig is DP 9.3's, with the callbacks of one connection
func (g *Gateway) serverConfig(c *conn) *ssh.ServerConfig {
	sc := &ssh.ServerConfig{
		ServerVersion:             serverVersion,
		MaxAuthTries:              3,
		PublicKeyAuthAlgorithms:   acceptedAlgorithms,
		PublicKeyCallback:         c.checkKey,
		VerifiedPublicKeyCallback: c.acquire,
		AuthLogCallback:           c.authLog,
	}
	for _, k := range g.cfg.HostKeys {
		sc.AddHostKey(k)
	}
	return sc
}

// closeWhere closes every connection that match selects
func (g *Gateway) closeWhere(reason string, match func(*conn) bool) {
	g.mu.Lock()
	var hit []*conn
	for c := range g.conns {
		if match(c) {
			hit = append(hit, c)
		}
	}
	g.mu.Unlock()
	for _, c := range hit {
		c.close(reason)
	}
}

// connsOf lists the open connections of a placement
func (g *Gateway) connsOf(placement string) []*conn {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*conn
	for c := range g.conns {
		if c.placement == placement {
			out = append(out, c)
		}
	}
	return out
}

// attach registers a connection whose key the router proved and whose lease it took
func (g *Gateway) attach(c *conn, budget *routerv1.EdgeBudget) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.conns[c] = struct{}{}
	g.places[c.placement]++
	g.m.live.Add(1)
	if budget != nil {
		g.rep.SetRemaining(c.placement, budget.GetBytesRemaining())
		if pace := budget.GetBytesPerSecond(); pace > 0 {
			g.pacer.Lane(c.placement).SetRate(int64(pace))
		}
	}
}

// detach forgets a connection, and the placement's pace and figures with its last one
func (g *Gateway) detach(c *conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.conns[c]; !ok {
		return
	}
	delete(g.conns, c)
	g.m.live.Add(-1)
	if g.places[c.placement]--; g.places[c.placement] <= 0 {
		delete(g.places, c.placement)
		g.pacer.Drop(c.placement)
		g.rep.Drop(c.placement)
	}
}
