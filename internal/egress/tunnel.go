package egress

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/bugnet-sh/bugnet-edges/internal/hostname"
	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
)

const (
	// tunnelProtocol is the WebSocket subprotocol of DP 10.5
	tunnelProtocol = "bugnet-tunnel.v1"
	routerDomain   = "bugnet.router"
	// maxFrame is the largest WebSocket message a tunnel may carry
	maxFrame = 1 << 20
)

// tunnelToken is bnt_ and the base64url form of 32 bytes
var tunnelToken = regexp.MustCompile(`^bnt_[A-Za-z0-9_-]{43}$`)

// isUpgrade says whether r asks for the tunnel's WebSocket, the one thing the outer listener serves
func isUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerHas(r.Header, "Connection", "upgrade") {
		return false
	}
	return headerHas(r.Header, "Sec-WebSocket-Protocol", tunnelProtocol)
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func sourceOf(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// bearer is the token of a Bearer authorization header, empty for any other
func bearer(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

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

// handleTunnel authenticates the upgrade, then carries the tunnel until it or its lease ends
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !isUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	src := sourceOf(r)
	p, deny := s.authenticate(r, src)
	if p == nil {
		s.refuse(w, deny)
		return
	}
	if !s.minter.Has(p.view().ca) {
		s.refuse(w, denial{status: http.StatusServiceUnavailable})
		return
	}
	if !s.takeTunnel(p) {
		s.refuse(w, denial{status: http.StatusTooManyRequests})
		return
	}
	defer s.freeTunnel(p)
	if !s.enterTunnel() {
		s.refuse(w, denial{status: http.StatusServiceUnavailable})
		return
	}
	defer s.tunnels.Done()
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{tunnelProtocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(maxFrame)
	s.m.tunnels.Add(1)
	defer s.m.tunnels.Add(-1)
	s.carry(p, ws)
}

// takeTunnel counts one more tunnel of p, false at the limit
func (s *Server) takeTunnel(p *placement) bool {
	limit := s.cfg.MaxTunnelsPerPlacement
	if m := int(p.view().resp.GetMaxTunnels()); m > 0 && m < limit {
		limit = m
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tunnels >= limit {
		return false
	}
	p.tunnels++
	return true
}

func (s *Server) freeTunnel(p *placement) {
	p.mu.Lock()
	p.tunnels--
	p.mu.Unlock()
}

// denial is the status of a refused upgrade and the Retry-After it asks for
type denial struct {
	status     int
	retryAfter string
}

func (s *Server) refuse(w http.ResponseWriter, d denial) {
	if d.retryAfter != "" {
		w.Header().Set("Retry-After", d.retryAfter)
	}
	s.m.tunnelRefused.Inc(strconv.Itoa(d.status))
	http.Error(w, http.StatusText(d.status), d.status)
}

// authenticate finds the placement a tunnel token or the fetcher's token reaches, else a status
func (s *Server) authenticate(r *http.Request, src netip.Addr) (*placement, denial) {
	token := bearer(r)
	sum := sha256.Sum256([]byte(token))
	if strings.HasPrefix(token, "bnf_") && s.fetchAllowed(src, token) {
		id := r.Header.Get("Bugnet-Placement")
		if _, err := uuid.Parse(id); err != nil {
			return nil, denial{status: http.StatusUnauthorized}
		}
		req := &routerv1.ResolveTunnelRequest{
			Caller: &routerv1.ResolveTunnelRequest_FetchPlacementId{FetchPlacementId: id}}
		return s.resolved(r.Context(), req, src, sum, false)
	}
	if !tunnelToken.MatchString(token) || s.guard.KnownUnknown(sum) {
		return nil, s.unknown(src, sum, false)
	}
	req := &routerv1.ResolveTunnelRequest{
		Caller: &routerv1.ResolveTunnelRequest_TokenSha256{TokenSha256: sum[:]}}
	return s.resolved(r.Context(), req, src, sum, true)
}

// fetchAllowed is true for the fetcher's token from a source in fetch_sources
func (s *Server) fetchAllowed(src netip.Addr, token string) bool {
	if s.cfg.FetchToken == "" {
		return false
	}
	ok := false
	for _, p := range s.cfg.FetchSources {
		ok = ok || p.Contains(src)
	}
	want := s.cfg.FetchToken
	if !strings.HasPrefix(want, "bnf_") {
		want = "bnf_" + want
	}
	eq := subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
	return ok && eq
}

// resolved asks the router for the caller, counting an unknown token against its source
func (s *Server) resolved(
	ctx context.Context, req *routerv1.ResolveTunnelRequest, src netip.Addr, sum [32]byte,
	stranger bool,
) (*placement, denial) {
	if p := s.cachedCaller(callerKey(req)); p != nil {
		return p, denial{}
	}
	if stranger && s.guard.Marked(src) && !s.guard.MayAsk(src) {
		return nil, denial{http.StatusTooManyRequests, "1"}
	}
	p, err := s.resolveCaller(ctx, req)
	switch {
	case err == nil:
		return p, denial{}
	case errors.Is(err, errSpent), connect.CodeOf(err) == connect.CodeResourceExhausted:
		return nil, denial{status: http.StatusTooManyRequests}
	case connect.CodeOf(err) == connect.CodeNotFound ||
		connect.CodeOf(err) == connect.CodeFailedPrecondition:
		if !stranger {
			return nil, denial{status: http.StatusUnauthorized}
		}
		return nil, s.unknown(src, sum, true)
	}
	s.log.Warn("egress: the router could not resolve a tunnel", "reason", reasonOf(err),
		"code", connect.CodeOf(err).String())
	return nil, denial{status: http.StatusServiceUnavailable}
}

// unknown counts a token that resolves to nothing, 429 once the source is marked
func (s *Server) unknown(src netip.Addr, sum [32]byte, remember bool) denial {
	if remember {
		s.guard.RememberUnknown(sum)
	}
	s.guard.Failed(src)
	if s.guard.Marked(src) {
		return denial{http.StatusTooManyRequests, strconv.Itoa(int(strangers.Mark.Seconds()))}
	}
	return denial{status: http.StatusUnauthorized}
}

// carry runs the inner TLS over the WebSocket and gives it to the shared server until it ends
func (s *Server) carry(p *placement, ws *websocket.Conn) {
	ctx, cancel := p.lease.Child("tunnel")
	defer cancel()
	stop := context.AfterFunc(s.runCtx, cancel)
	defer stop()
	defer func() {
		s.log.Debug("egress: tunnel closed", "placement", p.short, "lease", lease.Reason(ctx))
	}()
	raw := wsNetConn(ctx, ws)
	tc := newTunnelConn(raw, p.lane, time.Duration(s.cfg.TunnelIdleTimeout),
		func(n int) { s.tr.Usage.Add(p.id, int64(n), 0); s.m.bytes.Add(uint64(n), "in") },
		func(n int) { s.tr.Usage.Add(p.id, 0, int64(n)); s.m.bytes.Add(uint64(n), "out") })
	defer func() { _ = tc.Close() }()
	stopClose := context.AfterFunc(ctx, func() { _ = tc.Close() })
	defer stopClose()

	inner := tls.Server(tc, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: s.innerCert(p),
	})
	hctx, hcancel := context.WithTimeout(ctx, time.Duration(s.cfg.HandshakeTimeout))
	err := inner.HandshakeContext(hctx)
	hcancel()
	if err != nil {
		return
	}
	s.conns.Store(inner, &connInfo{p: p, sni: inner.ConnectionState().ServerName})
	defer s.conns.Delete(inner)
	if !s.innerLn.push(inner) {
		return
	}
	select {
	case <-tc.done:
	case <-ctx.Done():
	}
	_ = inner.Close()
}

// connInfo is what the inner server learns about a tunnel's connection
type connInfo struct {
	p   *placement
	sni string
}

// innerCert picks the certificate for the SNI the sandbox asked for, or fails the handshake
func (s *Server) innerCert(p *placement) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := normalHost(h.ServerName)
		if err := s.checkSNI(p, name); err != nil {
			s.m.refusedSNI.Inc()
			if s.refusedSNI != nil {
				s.refusedSNI(p.id, name)
			}
			return nil, err
		}
		return s.minter.Leaf(p.view().ca, name)
	}
}

var errSNI = errors.New("egress: the server name is not one of this sandbox's secret hosts")

// checkSNI refuses an empty name, an IP literal, Bugnet's own names and a host outside the set
func (s *Server) checkSNI(p *placement, name string) error {
	if name == "" || !hostname.Valid(name) || s.isOwnName(name) {
		return errSNI
	}
	if s.kindOf(p, name) == kindNone {
		return errSNI
	}
	return nil
}

// isOwnName is true for the proxy's host and every refused name and the names under them
func (s *Server) isOwnName(name string) bool {
	if name == s.cfg.EgressHost {
		return true
	}
	for _, r := range s.cfg.RefusedHosts {
		if name == r || strings.HasSuffix(name, "."+r) {
			return true
		}
	}
	return false
}

// kindOf says how the placement's current view treats host, kindNone when it holds no secret there
func (s *Server) kindOf(p *placement, host string) hostKind {
	return p.current(context.Background()).hosts[host]
}

func normalHost(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
