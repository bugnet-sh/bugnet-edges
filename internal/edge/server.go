package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oynozan/bugnet-edges/internal/certmetric"
	"github.com/oynozan/bugnet-edges/internal/hostname"
	"github.com/oynozan/bugnet-edges/internal/metrics"
	"github.com/oynozan/bugnet-edges/internal/pages"
	"github.com/oynozan/bugnet-edges/internal/proxyproto"
	"github.com/oynozan/bugnet-edges/internal/reuseport"
	"github.com/oynozan/bugnet-edges/internal/tlsconf"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	edgeHeaderBytes   = 64 << 10
	secretsDrain      = time.Minute
	secretsStreams    = 128
	hstsValue         = "max-age=31536000"
)

var (
	both  = []string{"h2", "http/1.1"}
	plain = []string{"http/1.1"}
)

// Deps are the edge's route handlers, each nil one serving the 404 page
type Deps struct {
	Preview  http.Handler      // <id>.<preview_domain>, every path
	Transfer http.Handler      // <transfer_host>/<token> and /<token>/<name>
	Hooks    http.Handler      // POST <hooks_host>/hooks/<provider>/<path secret>
	Landing  http.Handler      // <preview_domain>/ only
	Log      *slog.Logger      // slog.Default when nil
	Metrics  *metrics.Registry // a new registry when nil
}

// SecretsDeps is the secrets route's handler, nil serving the 404 page
type SecretsDeps struct {
	Route   http.Handler
	Log     *slog.Logger
	Metrics *metrics.Registry
}

// Server is one bugnet-edge process, in the edge role or the secrets role
type Server struct {
	role           string
	tlsAddr        string
	redirectAddr   string
	metricsAddr    string
	trusted        []netip.Prefix
	tlsOptions     tlsconf.Options
	handler        http.Handler
	drain          time.Duration
	maxHeaderBytes int
	maxStreams     int
	log            *slog.Logger
	metrics        *metrics.Registry
	hijacks        *hijacks

	ready   atomic.Bool
	started chan struct{}
	bound   map[string]string // the addresses bound, written before started closes
}

func newServer(role string, log *slog.Logger, reg *metrics.Registry) *Server {
	if log == nil {
		log = slog.Default()
	}
	if reg == nil {
		reg = metrics.New()
	}
	return &Server{
		role: role, log: log.With("role", role), metrics: reg, hijacks: newHijacks(),
		started: make(chan struct{}), bound: map[string]string{},
	}
}

// New is the edge role, serving previews, the landing page, transfers and hooks
func New(cfg Config, d Deps) *Server {
	s := newServer("edge", d.Log, d.Metrics)
	s.tlsAddr, s.redirectAddr, s.metricsAddr =
		cfg.TLSListenAddr, cfg.RedirectListenAddr, cfg.MetricsListenAddr
	s.trusted = cfg.ProxyProtocolFrom
	s.drain = time.Duration(cfg.Drain)
	s.maxHeaderBytes, s.maxStreams = edgeHeaderBytes, cfg.MaxConcurrentStreams
	n := cfg.Names
	s.tlsOptions = tlsconf.Options{
		Names: []tlsconf.Name{
			{Host: n.PreviewDomain, ALPN: both},
			{Host: n.TransferHost, ALPN: plain},
			{Host: n.HooksHost, ALPN: both},
		},
		Wildcard: &tlsconf.Wildcard{Suffix: n.PreviewDomain, Dir: cfg.ACME.WildcardDir, ALPN: both},
		ACME: tlsconf.ACME{
			Enabled: cfg.ACME.Enabled, Directory: cfg.ACME.Directory, Email: cfg.ACME.Email,
			StateDir: cfg.ACME.StateDir,
		},
		Static: cfg.ACME.StaticDir,
	}
	s.handler = withHSTS(&hosts{
		suffix: "." + n.PreviewDomain, landing: n.PreviewDomain, transfer: n.TransferHost,
		hooks: n.HooksHost, previewH: orNotFound(d.Preview), landingH: orNotFound(d.Landing),
		transferH: orNotFound(d.Transfer), hooksH: orNotFound(d.Hooks),
	})
	return s
}

// NewSecrets is the secrets role, serving only its own host with no redirect listener
func NewSecrets(cfg SecretsConfig, d SecretsDeps) *Server {
	s := newServer("secrets", d.Log, d.Metrics)
	s.tlsAddr, s.metricsAddr = cfg.TLSListenAddr, cfg.MetricsListenAddr
	s.trusted = cfg.ProxyProtocolFrom
	s.drain = secretsDrain
	s.maxHeaderBytes, s.maxStreams = int(cfg.MaxHeaderBytes), secretsStreams
	s.tlsOptions = tlsconf.Options{
		Names: []tlsconf.Name{{Host: cfg.Host, ALPN: both}},
		ACME: tlsconf.ACME{
			Enabled: cfg.ACMEEnabled, Directory: cfg.ACMEDirectory, Email: cfg.ACMEEmail,
			StateDir: cfg.ACMEDir,
		},
		Static: cfg.StaticDir,
	}
	host, route := cfg.Host, orNotFound(d.Route)
	s.handler = withHSTS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostOf(r.Host) != host {
			pages.Write(w, pages.NotFound)
			return
		}
		route.ServeHTTP(w, r)
	}))
	return s
}

func orNotFound(h http.Handler) http.Handler {
	if h != nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pages.Write(w, pages.NotFound)
	})
}

// addr is a listener's bound address, empty for one not serving
func (s *Server) addr(name string) string {
	return s.bound[name]
}

/* Serving */

// Run binds every listener, serves until ctx ends, then drains and returns
func (s *Server) Run(ctx context.Context) error {
	tlsCfg, err := tlsconf.New(s.tlsOptions)
	if err != nil {
		return fmt.Errorf("%s: %w", s.role, err)
	}
	var opened []net.Listener
	closeAll := func() {
		for _, ln := range opened {
			_ = ln.Close()
		}
	}
	type opener func(string) (net.Listener, error)
	listen := func(name, addr string, open opener) (net.Listener, error) {
		ln, err := open(addr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("%s: %s listener: %w", s.role, name, err)
		}
		opened = append(opened, ln)
		s.bound[name] = ln.Addr().String()
		return ln, nil
	}
	tlsLn, err := listen("tls", s.tlsAddr, func(a string) (net.Listener, error) {
		return proxyproto.Listen(a, s.trusted)
	})
	if err != nil {
		return err
	}
	var redirectLn net.Listener
	if s.redirectAddr != "" {
		if redirectLn, err = listen("redirect", s.redirectAddr, reuseport.Listen); err != nil {
			return err
		}
	}
	metricsLn, err := listen("metrics", s.metricsAddr, reuseport.Listen)
	if err != nil {
		return err
	}
	certmetric.Export(s.metrics, tlsCfg, s.log)

	hs, ms := s.tlsServer(), s.metricsServer()
	var rs *http.Server
	failed := make(chan error, 3)
	serve := func(srv *http.Server, ln net.Listener) {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			failed <- err
		}
	}
	go serve(hs, tls.NewListener(s.hijacks.listener(tlsLn), tlsCfg))
	if redirectLn != nil {
		rs = s.redirectServer()
		go serve(rs, redirectLn)
	}
	go serve(ms, metricsLn)
	s.ready.Store(true)
	close(s.started)
	s.log.Info("serving", "tls", s.bound["tls"], "redirect", s.bound["redirect"],
		"metrics", s.bound["metrics"])

	select {
	case <-ctx.Done():
	case err = <-failed:
		s.log.Error("a listener failed", "err", err)
	}
	s.ready.Store(false)
	s.shutdown(hs, rs)
	_ = ms.Close()
	return err
}

// shutdown stops accepting, waits up to drain for open work, then closes what is left
func (s *Server) shutdown(servers ...*http.Server) {
	s.log.Info("draining", "for", s.drain.String())
	ctx, cancel := context.WithTimeout(context.Background(), s.drain)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		wg.Go(func() {
			if srv.Shutdown(ctx) != nil {
				_ = srv.Close()
			}
		})
	}
	wg.Wait()
	s.hijacks.wait(ctx)
	if n := s.hijacks.count(); n > 0 {
		s.log.Info("closing hijacked connections after the drain", "open", n)
	}
	s.hijacks.closeAll()
	s.log.Info("stopped")
}

func (s *Server) tlsServer() *http.Server {
	return &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    s.maxHeaderBytes,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: s.maxStreams},
		ConnState:         s.hijacks.connState,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
}

func (s *Server) redirectServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(redirect),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    edgeHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
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
	mux.Handle("GET /metrics", s.metrics)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
}

/* Routing */

type route int

const (
	routeNone route = iota
	routePreview
	routeLanding
	routeTransfer
	routeHooks
)

var (
	previewID = regexp.MustCompile(`^[a-z2-7]{16}$`)
	provider  = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// hosts routes a request by its host, DP 8.1's table
type hosts struct {
	suffix                   string
	landing, transfer, hooks string
	previewH, landingH       http.Handler
	transferH, hooksH        http.Handler
}

func (h *hosts) route(host string) (route, string) {
	switch host {
	case h.landing:
		return routeLanding, ""
	case h.transfer:
		return routeTransfer, ""
	case h.hooks:
		return routeHooks, ""
	}
	if label, ok := strings.CutSuffix(host, h.suffix); ok && label != "" &&
		!strings.Contains(label, ".") {
		return routePreview, label
	}
	return routeNone, ""
}

func (h *hosts) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, label := h.route(hostOf(r.Host))
	if rt == routeNone {
		pages.Write(w, pages.NotFound)
		return
	}
	// A preview connection reused for another name, or a transfer over h2, must reconnect
	if r.TLS != nil {
		if sni, _ := h.route(normal(r.TLS.ServerName)); sni != rt {
			pages.Write(w, pages.Misdirected)
			return
		}
	}
	path := r.URL.EscapedPath()
	switch {
	case rt == routePreview && previewID.MatchString(label):
		h.previewH.ServeHTTP(w, r)
	case rt == routeLanding && path == "/":
		h.landingH.ServeHTTP(w, r)
	case rt == routeTransfer && transferPath(path):
		h.transferH.ServeHTTP(w, r)
	case rt == routeHooks && r.Method == http.MethodPost && hooksPath(path):
		h.hooksH.ServeHTTP(w, r)
	default:
		pages.Write(w, pages.NotFound)
	}
}

// transferPath is /<token> or /<token>/<name>
func transferPath(p string) bool {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	return strings.HasPrefix(p, "/") && len(parts) <= 2 && !strings.Contains(p[1:], "//") &&
		parts[0] != "" && parts[len(parts)-1] != ""
}

// hooksPath is /hooks/<provider>/<path secret>
func hooksPath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/hooks/")
	parts := strings.Split(rest, "/")
	return ok && len(parts) == 2 && provider.MatchString(parts[0]) && parts[1] != ""
}

func hostOf(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return normal(h)
}

func normal(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

/* Responses */

// withHSTS sets the edge's HSTS on every answer, replacing any a handler or upstream set
func withHSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		next.ServeHTTP(&hstsWriter{ResponseWriter: w}, r)
	})
}

type hstsWriter struct {
	http.ResponseWriter
	sent bool
}

func (w *hstsWriter) WriteHeader(code int) {
	if !w.sent {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		w.sent = code >= 200
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hstsWriter) Write(b []byte) (int, error) {
	if !w.sent {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		w.sent = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush and Hijack on the server's writer
func (w *hstsWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// redirect answers port 80 with a 301 to the same URL on https, for host names only
func redirect(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r.Host)
	if !hostname.Valid(host) || !strings.Contains(host, ".") {
		pages.Write(w, pages.NotFound)
		return
	}
	uri := r.RequestURI
	if !strings.HasPrefix(uri, "/") {
		uri = "/"
		if strings.HasPrefix(r.URL.Path, "/") {
			uri = r.URL.RequestURI()
		}
	}
	w.Header().Set("Location", "https://"+host+uri)
	w.WriteHeader(http.StatusMovedPermanently)
}
