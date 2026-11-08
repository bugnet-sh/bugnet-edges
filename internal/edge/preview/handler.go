// Package preview serves <id>.<preview_domain>, proxying each request to its sandbox's gate
package preview

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/pace"
	"github.com/bugnet-sh/bugnet-edges/internal/pages"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
	"github.com/bugnet-sh/bugnet-edges/internal/traffic"
)

const (
	reservedPrefix = "/__bugnet/"
	continuePath   = "/__bugnet/continue"
	// repairEvery is how often the edge asks for one preview's repair, the router's own minute
	repairEvery   = time.Minute
	repairTimeout = 30 * time.Second
	maxRepairs    = 10000
	routerDomain  = "bugnet.router"

	dialTimeout = 10 * time.Second
	// headerTimeout bounds the wait for an answer's headers, a long poll included
	headerTimeout = 5 * time.Minute
)

// Deps are the process's traffic pieces and this route's settings
type Deps struct {
	Traffic       *traffic.Traffic // the process's, shared with transfers
	Guard         *strangers.Guard // this route's own token failure rule
	CacheSize     int              // previews.resolve_cache
	RouteTTL      time.Duration    // previews.route_ttl
	QueueWait     time.Duration    // previews.queue_wait
	QueueMax      int              // previews.queue_max
	AbuseContact  string           // previews.abuse_contact
	BoatPerMinute int              // previews.boat_requests_per_minute, 0 is off
	BoatSuffix    string           // previews.boat_host_suffix, the host Boat routes end in
	// Transport reaches the providers' routes, DP 8.2.7's when nil
	Transport http.RoundTripper
	Log       *slog.Logger
}

type handler struct {
	router routerv1connect.EdgeServiceClient
	d      Deps
	cache  *cache
	limits *limits
	proxy  *httputil.ReverseProxy

	mu       sync.Mutex
	repaired map[string]time.Time // by preview id
}

// New serves the preview names through ResolvePreview and the gate route it answers
func New(router routerv1connect.EdgeServiceClient, d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Guard == nil {
		d.Guard = strangers.NewGuard(0, strangers.Mark, strangers.Unknown)
	}
	if d.CacheSize <= 0 {
		d.CacheSize = 10000
	}
	if d.RouteTTL <= 0 {
		d.RouteTTL = time.Minute
	}
	if d.QueueWait <= 0 {
		d.QueueWait = 30 * time.Second
	}
	if d.QueueMax <= 0 {
		d.QueueMax = 256
	}
	if d.Transport == nil {
		d.Transport = newTransport()
	}
	h := &handler{
		router:   router,
		d:        d,
		cache:    newCache(router, d.Traffic, d.CacheSize, d.RouteTTL, d.BoatSuffix),
		limits:   newLimits(d.QueueWait, d.QueueMax, d.BoatPerMinute),
		repaired: map[string]time.Time{},
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite:        h.rewrite,
		Transport:      d.Transport,
		ModifyResponse: h.modify,
		ErrorHandler:   h.proxyError,
		ErrorLog:       slog.NewLogLogger(d.Log.Handler(), slog.LevelDebug),
	}
	return h
}

// newTransport is DP 8.2.7's upstream, HTTP/2 where offered and HTTP/1.1 for upgrades
func newTransport() *http.Transport {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  headerTimeout,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxIdleConnsPerHost:    64,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
}

// call is what the proxy's hooks need about the request they handle
type call struct {
	rt      *route
	token   string
	host    string
	ip      netip.Addr
	lane    *pace.Lane
	countIn func(int)
}

type callKey struct{}

func callOf(r *http.Request) *call {
	c, _ := r.Context().Value(callKey{}).(*call)
	return c
}

/* Requests */

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r.Host)
	id, _, _ := strings.Cut(host, ".")
	path := r.URL.EscapedPath()
	if strings.HasPrefix(path, reservedPrefix) {
		if path == continuePath && r.Method == http.MethodPost {
			h.cont(w, r, id, host)
			return
		}
		pages.Write(w, pages.NotFound)
		return
	}
	tok, src := findToken(r)
	if src == fromCookie && !cookieAllowed(r, host) {
		tok = ""
	}
	if tok == "" {
		pages.Write(w, pages.Unauthorized)
		return
	}
	rt, page, ok := h.lookup(r.Context(), id, tok, clientIP(r))
	if !ok {
		pages.Write(w, page)
		return
	}
	if src == fromQuery && browserLoad(r) && r.Header.Get(skipHeader) == "" {
		if rt.interstitial && cookieToken(r) != tok {
			h.warn(w, r, rt, tok)
			return
		}
		// The page's own later requests carry no token, so they need the cookie
		w.Header().Add("Set-Cookie", cookieFor(tok))
	}
	if blocked(r, rt.blocked) {
		pages.Write(w, pages.NotFound)
		return
	}
	h.serve(w, r, rt, tok, host)
}

// lookup is the route behind id and tok, or the page that refuses them, DP 4.5's rule applied
func (h *handler) lookup(
	ctx context.Context, id, tok string, ip netip.Addr,
) (*route, pages.Page, bool) {
	g := h.d.Guard
	pair := sha256.Sum256([]byte(id + "\x00" + tok))
	idKey := sha256.Sum256([]byte("preview\x00" + id))
	switch {
	case !tokenShape.MatchString(tok):
		return nil, h.failed(ip, pages.Unauthorized), false
	case g.KnownUnknown(idKey):
		return nil, h.failed(ip, pages.NotFound), false
	case g.KnownUnknown(pair):
		return nil, h.failed(ip, pages.Unauthorized), false
	}
	if rt := h.cache.fresh(pair); rt != nil {
		return rt, pages.Page{}, true
	}
	if g.Marked(ip) && !g.MayAsk(ip) {
		return nil, pages.SlowDown.RetryAfter(strangers.AskEvery), false
	}
	rt, err := h.cache.resolve(ctx, pair, id, tok)
	if err == nil {
		return rt, pages.Page{}, true
	}
	switch reasonOf(err) {
	case "PREVIEW_UNKNOWN":
		g.RememberUnknown(idKey)
		return nil, h.failed(ip, pages.NotFound), false
	case "TOKEN_INVALID":
		g.RememberUnknown(pair)
		return nil, h.failed(ip, pages.Unauthorized), false
	case "NOT_READY":
		return nil, pages.Ended, false
	case "PREVIEW_REVOKED":
		return nil, pages.Revoked, false
	case "BUDGET_SPENT":
		return nil, pages.BudgetSpent, false
	case "GATE_UNAVAILABLE":
		h.repair(id, tok)
		return nil, pages.GateDown, false
	}
	if errors.Is(err, errSpent) {
		return nil, pages.BudgetSpent, false
	}
	h.d.Log.Warn("preview: the router refused", "preview", id,
		"code", connect.CodeOf(err).String())
	return nil, pages.RouterDown, false
}

// failed counts a token that did not resolve against ip, which a marked ip answers with 429
func (h *handler) failed(ip netip.Addr, page pages.Page) pages.Page {
	h.d.Guard.Failed(ip)
	if h.d.Guard.Marked(ip) {
		return pages.SlowDown.RetryAfter(strangers.Mark)
	}
	return page
}

// serve proxies the request under its own preview child of the placement's lease
func (h *handler) serve(w http.ResponseWriter, r *http.Request, rt *route, tok, host string) {
	child, done := rt.lease.Preview(lease.HeldPreview{ID: rt.id, Generation: rt.gen})
	defer done()
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	defer context.AfterFunc(child, func() { cancel(context.Cause(child)) })()
	if child.Err() != nil {
		pages.Write(w, byLease(lease.Reason(child)))
		return
	}
	release, page, ok := h.limits.admit(ctx, rt, isUpgrade(r))
	if !ok {
		pages.Write(w, page)
		return
	}
	defer release()
	usage := h.d.Traffic.Usage
	lane := h.d.Traffic.Pacer.Lane(rt.placement)
	c := &call{
		rt: rt, token: tok, host: host, ip: clientIP(r), lane: lane,
		countIn: func(n int) { usage.Add(rt.placement, int64(n), 0) },
	}
	out := func(n int) { usage.Add(rt.placement, 0, int64(n)) }
	h.proxy.ServeHTTP(newMeter(w, lane, c.countIn, out),
		r.WithContext(context.WithValue(ctx, callKey{}, c)))
}

// proxyError answers a failed proxy call with the edge's page, asking for a repair when due
func (h *handler) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	c := callOf(r)
	var ge *gateError
	switch {
	case errors.As(err, &ge):
		switch ge.value {
		case portClosed:
			pages.Write(w, pages.NothingOnPort(c.rt.port))
		case gateBusy:
			pages.Write(w, pages.Busy)
		default:
			pages.Write(w, pages.GateDown)
		}
	case errors.Is(err, errProvider):
		h.repair(c.rt.id, c.token)
		pages.Write(w, pages.GateDown)
	case lease.Reason(r.Context()) != "":
		pages.Write(w, byLease(lease.Reason(r.Context())))
	case r.Context().Err() != nil:
		// The visitor left, so nobody reads an answer
	case errors.Is(err, syscall.ECONNREFUSED):
		h.repair(c.rt.id, c.token)
		pages.Write(w, pages.GateDown)
	default:
		h.d.Log.Debug("preview: the gate route failed", "preview", c.rt.id,
			"placement", c.rt.placement, "err", withoutURL(err))
		pages.Write(w, pages.GateDown)
	}
}

// withoutURL drops the request URL a transport error names, since its query is the app's
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// repair asks the router to repair a preview's gate, at most once a minute per preview
func (h *handler) repair(id, tok string) {
	now := time.Now()
	h.mu.Lock()
	if last, ok := h.repaired[id]; ok && now.Sub(last) < repairEvery {
		h.mu.Unlock()
		return
	}
	if len(h.repaired) >= maxRepairs {
		for k, at := range h.repaired {
			if now.Sub(at) >= repairEvery {
				delete(h.repaired, k)
			}
		}
	}
	h.repaired[id] = now
	h.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), repairTimeout)
		defer cancel()
		_, err := h.router.RepairPreview(ctx, connect.NewRequest(&routerv1.RepairPreviewRequest{
			PreviewId: id, Token: tok,
		}))
		if err != nil {
			h.d.Log.Warn("preview: a repair failed", "preview", id,
				"code", connect.CodeOf(err).String())
		}
		// The repaired gate may answer through a new route, so the next request resolves again
		h.cache.dropPreview(id)
	}()
}

// blocked reports a path under one of the route's blocked prefixes, or the bare prefix itself
func blocked(r *http.Request, prefixes []string) bool {
	if len(prefixes) == 0 {
		return false
	}
	paths := []string{strings.ToLower(r.URL.EscapedPath()), strings.ToLower(r.URL.Path)}
	for _, p := range paths[:2] {
		paths = append(paths, collapse(p))
	}
	for _, prefix := range prefixes {
		prefix = strings.ToLower(prefix)
		bare := strings.TrimSuffix(prefix, "/")
		for _, p := range paths {
			if strings.HasPrefix(p, prefix) || p == bare {
				return true
			}
		}
	}
	return false
}

// collapse joins repeated slashes and drops dot segments, as an upstream server might
func collapse(p string) string {
	var out []string
	for seg := range strings.SplitSeq(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	c := "/" + strings.Join(out, "/")
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

/* Helpers */

// reasonOf is the ErrorInfo reason the router put on err, empty when there is none
func reasonOf(err error) string {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return ""
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if info, ok := v.(*errdetails.ErrorInfo); derr == nil && ok &&
			info.GetDomain() == routerDomain {
			return info.GetReason()
		}
	}
	return ""
}

// clientIP is the address PROXY v2 gave the connection, IPv4-mapped addresses as IPv4
func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func hostOf(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}
