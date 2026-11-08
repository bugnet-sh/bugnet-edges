package egress

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"golang.org/x/sync/singleflight"

	"github.com/bugnet-sh/bugnet-edges/internal/certmetric"
	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/proxyproto"
	"github.com/bugnet-sh/bugnet-edges/internal/reuseport"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
	"github.com/bugnet-sh/bugnet-edges/internal/tlsconf"
	"github.com/bugnet-sh/bugnet-edges/internal/traffic"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

const (
	// ReporterID names this process in usage reports
	ReporterID = "egress"
	// reportBytes sends a usage report at once when a placement's unsent bytes reach it
	reportBytes = 8 << 20
	// outerHeaderBytes bounds the upgrade request, which carries one token
	outerHeaderBytes = 16 << 10
	idleTimeout      = 2 * time.Minute
	drainTimeout     = 5 * time.Second
)

// Deps are what the proxy needs besides its settings
type Deps struct {
	Router routerv1connect.EgressServiceClient
	Keys   *Keys
	Minter *Minter
	Log    *slog.Logger
	// Metrics is a new registry when nil
	Metrics *metrics.Registry
	// Now is time.Now when nil
	Now func() time.Time
	// RefusedSNI sees each inner handshake refused for its name, with the placement it came from
	RefusedSNI func(placement, sni string)
	// CheckEvery spaces the lease checks, zero keeps DP 4.2's minute
	CheckEvery time.Duration
	// RefreshEvery spaces the resolves a missing placeholder may cause, zero keeps 2 s
	RefreshEvery time.Duration
	// Transport reaches upstream hosts, a transport over the refusing dialer when nil
	Transport http.RoundTripper
	// SellerTransport reaches x402 sellers, the x402 transport over the refusing dialer when nil
	SellerTransport http.RoundTripper
	// Events queues the x402 events, nothing is queued when nil
	Events *x402.Events
	// Counters holds the unpaid use, new counters when nil
	Counters *x402.Counters
	// HostRate holds the host buckets, new buckets from the settings when nil
	HostRate *x402.HostRate
	// Signer asks Payments to sign, a payable 402 is refused as payments_unavailable when nil
	Signer *x402.Signer
}

// Server is the egress proxy, the outer listener and the tunnels it carries
type Server struct {
	cfg       Config
	router    routerv1connect.EgressServiceClient
	keys      *Keys
	minter    *Minter
	log       *slog.Logger
	reg       *metrics.Registry
	now       func() time.Time
	cacheLife time.Duration
	// refreshEvery is the least time between resolves of one placement that its traffic causes
	refreshEvery time.Duration
	tr           *traffic.Traffic
	dialer       *Dialer
	guard        *strangers.Guard
	m            *proxyMetrics
	custom       *customRates
	events       *x402.Events
	counters     *x402.Counters
	hostRate     *x402.HostRate
	seller       http.RoundTripper
	signer       *x402.Signer
	buffers      *x402.Buffers
	open         *openCount
	netRefused   *metrics.Counter

	group   singleflight.Group
	cacheMu sync.Mutex
	callers map[string]cached
	swept   time.Time

	placesMu sync.Mutex
	places   map[string]*placement

	endedListeners   []func(placement string)
	versionListeners []func(placement string, version uint64)
	refusedSNI       func(placement, sni string)

	proxy   http.Handler
	inner   *http.Server
	innerLn *connQueue
	conns   sync.Map // *tls.Conn to *tunnelConn, for the inner server's ConnContext
	tunnels sync.WaitGroup
	// closing is set once Run stops, under tunnelMu, so no tunnel starts after the wait begins
	tunnelMu sync.Mutex
	closing  bool
	// runCtx ends every tunnel, it is set by Run before the listener opens
	runCtx context.Context

	ready   atomic.Bool
	started chan struct{}
	bound   map[string]string
}

// New builds the proxy from cfg and d
func New(cfg Config, d Deps) *Server {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Metrics == nil {
		d.Metrics = metrics.New()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{
		cfg: cfg, router: d.Router, keys: d.Keys, minter: d.Minter,
		log: d.Log.With("role", "egress"), reg: d.Metrics, now: d.Now,
		cacheLife: time.Duration(cfg.ResolveCache),
		dialer:    NewDialer(cfg.Resolvers),
		guard: strangers.NewGuard(cfg.TokenFailuresPerMinute, strangers.Mark,
			strangers.Unknown),
		callers: map[string]cached{}, places: map[string]*placement{},
		refusedSNI: d.RefusedSNI, started: make(chan struct{}), bound: map[string]string{},
		innerLn: newConnQueue(),
	}
	s.refreshEvery = cmp.Or(d.RefreshEvery, defaultRefreshEvery)
	s.m = newProxyMetrics(d.Metrics)
	s.custom = newCustomRates(cfg.CustomHostRequestsPerMinute, d.Now)
	s.custom.export(d.Metrics)
	s.tr = traffic.Egress(d.Router, traffic.Settings{
		ReporterID:          ReporterID,
		ReportInterval:      time.Duration(cfg.UsageReportInterval),
		ReportBytes:         reportBytes,
		TotalBytesPerSecond: int64(cfg.TotalBytesPerSecond),
		CheckEvery:          d.CheckEvery,
	}, s.tap, s.log)
	s.tr.Leases.OnVersion(s.versionMoved)
	s.events, s.counters, s.hostRate = d.Events, d.Counters, d.HostRate
	if s.counters == nil {
		s.counters = x402.NewCounters()
	}
	if s.hostRate == nil {
		s.hostRate = x402.NewHostRate(cfg.CustomHostRequestsPerMinute,
			cfg.X402.HostRateFloorPerPlacement, d.Now)
	}
	s.signer, s.open = d.Signer, newOpenCount()
	s.buffers = x402.NewBuffers(int64(cfg.X402.BufferBudget), int64(cfg.X402.BufferPerPlacement))
	s.buffers.Export(d.Metrics)
	s.netRefused = d.Metrics.Counter("egress_x402_network_unsupported_total",
		"x402 402s with no exact USDC on Solana, by namespace offered", "namespace")
	s.seller = d.SellerTransport
	if s.seller == nil {
		s.seller = s.newSellerTransport()
	}
	s.proxy = s.newProxy(d.Transport)
	s.inner = s.innerServer()
	return s
}

// Dialer is the refusing dialer, which a second transport may use and no setting can loosen
func (s *Server) Dialer() *Dialer {
	return s.dialer
}

// enterTunnel counts a tunnel that is about to start, false once the proxy is stopping
func (s *Server) enterTunnel() bool {
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()
	if s.closing {
		return false
	}
	s.tunnels.Add(1)
	return true
}

// OnEnded runs f with the placement id when a placement's lease ends, before Run
func (s *Server) OnEnded(f func(placement string)) {
	s.endedListeners = append(s.endedListeners, f)
}

// OnVersion runs f when a lease check finds the secrets version moved, before Run
func (s *Server) OnVersion(f func(placement string, version uint64)) {
	s.versionListeners = append(s.versionListeners, f)
}

// tap sees each event first, and re-resolves a placement whose secrets changed
func (s *Server) tap(ev *routerv1.EdgeEvent) {
	if e, ok := ev.GetEvent().(*routerv1.EdgeEvent_SecretsChanged); ok {
		s.secretsChanged(e.SecretsChanged.GetPlacementId())
	}
}

// Addr is the address a listener is bound to, empty before Run bound it
func (s *Server) Addr(name string) string {
	select {
	case <-s.started:
		return s.bound[name]
	default:
		return ""
	}
}

// Started is closed once every listener is bound
func (s *Server) Started() <-chan struct{} {
	return s.started
}

func (s *Server) tlsOptions() tlsconf.Options {
	return tlsconf.Options{
		Names: []tlsconf.Name{{Host: s.cfg.EgressHost, ALPN: []string{"http/1.1"}}},
		ACME: tlsconf.ACME{
			Enabled: s.cfg.ACMEEnabled, Directory: s.cfg.ACMEDirectory, Email: s.cfg.ACMEEmail,
			StateDir: s.cfg.ACMEDir,
		},
		Static: s.cfg.StaticDir,
	}
}

// Run binds the listeners, serves until ctx ends, then closes every tunnel and returns
func (s *Server) Run(ctx context.Context) error {
	tlsCfg, err := tlsconf.New(s.tlsOptions())
	if err != nil {
		return fmt.Errorf("egress: %w", err)
	}
	ln, err := proxyproto.Listen(s.cfg.ListenAddr, s.cfg.ProxyProtocolFrom)
	if err != nil {
		return fmt.Errorf("egress: listener: %w", err)
	}
	mln, err := reuseport.Listen(s.cfg.MetricsListenAddr)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("egress: metrics listener: %w", err)
	}
	s.bound["tunnel"], s.bound["metrics"] = ln.Addr().String(), mln.Addr().String()
	certmetric.Export(s.reg, tlsCfg, s.log)

	runCtx, stopTunnels := context.WithCancel(context.WithoutCancel(ctx))
	defer stopTunnels()
	s.runCtx = runCtx
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		s.tr.Run(runCtx)
	}()

	outer, metricsSrv := s.outerServer(), s.metricsServer()
	failed := make(chan error, 3)
	serve := func(srv *http.Server, l net.Listener) {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}
	go serve(outer, tls.NewListener(ln, tlsCfg))
	go serve(metricsSrv, mln)
	go serve(s.inner, s.innerLn)
	s.ready.Store(true)
	close(s.started)
	s.log.Info("serving", "tunnel", s.bound["tunnel"], "metrics", s.bound["metrics"])

	select {
	case <-ctx.Done():
		err = nil
	case err = <-failed:
		s.log.Error("a listener failed", "err", err)
	}
	s.ready.Store(false)
	dctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	_ = outer.Shutdown(dctx)
	s.tunnelMu.Lock()
	s.closing = true
	s.tunnelMu.Unlock()
	stopTunnels()
	_ = s.inner.Close()
	_ = s.innerLn.Close()
	_ = metricsSrv.Close()
	s.tunnels.Wait()
	<-trafficDone
	s.zeroAll()
	s.log.Info("stopped")
	return err
}

// zeroAll zeroes every value still held
func (s *Server) zeroAll() {
	s.placesMu.Lock()
	defer s.placesMu.Unlock()
	for _, p := range s.places {
		p.view().set.zero()
	}
}

func (s *Server) outerServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tunnel", s.handleTunnel)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	return &http.Server{
		Handler:           mux,
		Protocols:         &protocols,
		ReadHeaderTimeout: time.Duration(s.cfg.HandshakeTimeout),
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    outerHeaderBytes,
		ErrorLog:          s.errorLog(),
	}
}

func (s *Server) metricsServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.Handle("GET /metrics", s.reg)
	return &http.Server{
		Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: idleTimeout,
		ErrorLog: s.errorLog(),
	}
}
