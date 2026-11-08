package egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/google/uuid"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/pace"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

const (
	// defaultRefreshEvery spaces the resolves a missing placeholder or an old view may cause
	defaultRefreshEvery = 2 * time.Second
	// resolveTimeout bounds each ResolveTunnel, which runs apart from the request that asked
	resolveTimeout   = 3 * time.Second
	defaultInFlight  = 32
	cacheSweepEvery  = time.Minute
	maxCachedCallers = 200_000
)

// hostKind says how the proxy treats a host of a placement (DP 10.5 step 6)
type hostKind int

const (
	kindNone hostKind = iota
	// kindPreset is a host in some preset, forwarded with or without a swap
	kindPreset
	// kindCustom is a host outside every preset, forwarded only after a swap
	kindCustom
	// kindX402 is a host with x402 services, which no secret is ever swapped on (XS 6.6)
	kindX402
)

// hostSet lists the hosts a placement's secrets and x402 services reach, each with its kind
func hostSet(resp *routerv1.ResolveTunnelResponse, cfg x402.Config) map[string]hostKind {
	out := map[string]hostKind{}
	for _, es := range resp.GetSecrets() {
		custom := canonical(es.GetCustomHosts())
		for _, h := range canonical(es.GetSpec().GetHosts()) {
			if slices.Contains(custom, h) {
				out[h] = kindCustom
			} else if out[h] == kindNone {
				out[h] = kindPreset
			}
		}
	}
	for _, h := range cfg.Hosts() {
		out[h] = kindX402
	}
	return out
}

// view is one answer of ResolveTunnel with the secrets it opened
type view struct {
	resp  *routerv1.ResolveTunnelResponse
	at    time.Time
	hosts map[string]hostKind
	set   *secretSet
	ca    uint32
	x402  x402.Config
}

// placement is one placement's proxy state for one kind of caller, a sandbox or the fetcher
type placement struct {
	s      *Server
	id     string
	uid    uuid.UUID
	short  string // the first 8 hex characters of the SHA-256 of the id, all the logs show
	fetch  bool
	caller *routerv1.ResolveTunnelRequest
	lease  *lease.Lease
	lane   *pace.Lane
	flight chan struct{}

	mu         sync.Mutex
	cur        *view
	attemptAt  time.Time
	refreshing chan struct{}
	tunnels    int
}

func (p *placement) alive() bool {
	return p.lease.Context().Err() == nil
}

func (p *placement) view() *view {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur
}

// setView makes v current, zeroing the secrets of the old view that v did not carry over
func (p *placement) setView(v *view) {
	p.mu.Lock()
	old := p.cur
	p.cur = v
	p.attemptAt = v.at
	p.mu.Unlock()
	if old == nil {
		return
	}
	for h, x := range old.set.byHash {
		if v.set.byHash[h] != x {
			x.zero()
		}
	}
}

// dropSecrets forgets every secret at once, a refresh then brings back the ones that remain
func (p *placement) dropSecrets() {
	p.mu.Lock()
	cur := p.cur
	next := *cur
	next.x402 = x402.Config{}
	next.hosts = maps.Collect(func(yield func(string, hostKind) bool) {
		for h, k := range cur.hosts {
			if k != kindX402 && !yield(h, k) {
				return
			}
		}
	})
	next.set = &secretSet{byHash: map[[32]byte]*secret{}, headers: map[string][]string{}}
	p.cur = &next
	p.mu.Unlock()
	cur.set.zero()
}

// current is the view to serve from, resolved again when it is older than the cache life
func (p *placement) current(ctx context.Context) *view {
	v := p.view()
	if p.s.now().Sub(v.at) >= p.s.cacheLife {
		p.refresh(ctx, true)
		v = p.view()
	}
	return v
}

// refresh resolves the placement again, at most once every refreshEvery when limited
func (p *placement) refresh(ctx context.Context, limited bool) {
	p.mu.Lock()
	if p.refreshing != nil {
		wait := p.refreshing
		p.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
		}
		return
	}
	now := p.s.now()
	if limited && now.Sub(p.attemptAt) < p.s.refreshEvery {
		p.mu.Unlock()
		return
	}
	done := make(chan struct{})
	p.refreshing, p.attemptAt = done, now
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.refreshing = nil
		p.mu.Unlock()
		close(done)
	}()

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveTimeout)
	defer cancel()
	res, err := p.s.router.ResolveTunnel(rctx, connect.NewRequest(p.caller))
	if err != nil {
		p.s.log.Debug("egress: a placement could not be resolved again", "placement", p.short,
			"code", connect.CodeOf(err).String())
		return
	}
	if res.Msg.GetPlacementId() != p.id {
		return
	}
	p.s.install(p, res.Msg)
}

/* The server's table of placements and the callers it resolved */

type cached struct {
	p     *placement
	until time.Time
}

// callerKey names a resolve cache entry, by token digest or by the fetcher's placement
func callerKey(req *routerv1.ResolveTunnelRequest) string {
	if id := req.GetFetchPlacementId(); id != "" {
		return "f" + id
	}
	return "t" + string(req.GetTokenSha256())
}

// resolveCaller finds the placement a caller reaches, from the cache while it is fresh
func (s *Server) resolveCaller(
	ctx context.Context, req *routerv1.ResolveTunnelRequest,
) (*placement, error) {
	key := callerKey(req)
	if p := s.cachedCaller(key); p != nil {
		return p, nil
	}
	v, err, _ := s.group.Do(key, func() (any, error) {
		if p := s.cachedCaller(key); p != nil {
			return p, nil
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveTimeout)
		defer cancel()
		res, err := s.router.ResolveTunnel(rctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		p, err := s.place(req, res.Msg)
		if err != nil {
			return nil, err
		}
		s.cacheMu.Lock()
		s.sweepLocked()
		s.callers[key] = cached{p, s.now().Add(s.cacheLife)}
		s.cacheMu.Unlock()
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*placement), nil
}

func (s *Server) cachedCaller(key string) *placement {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	c, ok := s.callers[key]
	if !ok {
		return nil
	}
	if !c.p.alive() || !s.now().Before(c.until) {
		delete(s.callers, key)
		return nil
	}
	return c.p
}

// sweepLocked drops the callers that expired or whose placement ended, at most once a minute
func (s *Server) sweepLocked() {
	now := s.now()
	if now.Sub(s.swept) < cacheSweepEvery && len(s.callers) < maxCachedCallers {
		return
	}
	s.swept = now
	for k, c := range s.callers {
		if !c.p.alive() || !now.Before(c.until) {
			delete(s.callers, k)
		}
	}
}

var errSpent = errors.New("egress: the placement's budget is spent")

// place makes the placement's state for resp, or moves the one held to it
func (s *Server) place(
	req *routerv1.ResolveTunnelRequest, resp *routerv1.ResolveTunnelResponse,
) (*placement, error) {
	uid, err := uuid.Parse(resp.GetPlacementId())
	if err != nil || resp.GetDeadline() == nil {
		return nil, errors.New("egress: the router answered a tunnel without a placement")
	}
	fetch := req.GetFetchPlacementId() != ""
	key := resp.GetPlacementId() + kindSuffix(fetch)
	s.placesMu.Lock()
	defer s.placesMu.Unlock()
	p := s.places[key]
	if p == nil || !p.alive() {
		sum := sha256.Sum256([]byte(resp.GetPlacementId()))
		flight := int(resp.GetRequestsInFlight())
		if flight <= 0 {
			flight = defaultInFlight
		}
		p = &placement{
			s: s, id: resp.GetPlacementId(), uid: uid, fetch: fetch, caller: req,
			short:  hex.EncodeToString(sum[:4]),
			flight: make(chan struct{}, flight),
		}
		p.cur = s.buildView(p, resp)
		s.mergeUsed(p, p.cur)
		p.attemptAt = p.cur.at
		p.lease = s.hold(p.id, resp)
		p.lane = s.tr.Pacer.Lane(p.id)
		s.places[key] = p
		context.AfterFunc(p.lease.Context(), func() { s.ended(p, key) })
	} else {
		s.install(p, resp)
	}
	if !p.alive() {
		return nil, errSpent
	}
	return p, nil
}

func kindSuffix(fetch bool) string {
	if fetch {
		return "/fetch"
	}
	return "/tunnel"
}

// hold keeps a placement's lease at the answer's deadline, bytes left and secrets version
func (s *Server) hold(id string, resp *routerv1.ResolveTunnelResponse) *lease.Lease {
	return s.tr.Hold(id, lease.State{
		Deadline: resp.GetDeadline().AsTime(), Remaining: resp.GetBytesRemaining(),
		SecretsVersion: resp.GetSecretsVersion(),
	}, resp.GetBytesPerSecond())
}

// ended forgets a placement and zeroes its values once its lease ends
func (s *Server) ended(p *placement, key string) {
	s.placesMu.Lock()
	if s.places[key] == p {
		delete(s.places, key)
	}
	s.placesMu.Unlock()
	p.view().set.zero()
	s.counters.Drop(p.id)
	s.cache.DropPlacement(p.id)
	for _, f := range s.endedListeners {
		f(p.id)
	}
}

// mergeUsed folds the unpaid use the router counted into egress's own counts
func (s *Server) mergeUsed(p *placement, v *view) {
	if len(v.x402.Services) > 0 {
		s.counters.Merge(p.id, v.x402.Used)
	}
}

// install opens resp's secrets into a view and makes it the placement's current one
func (s *Server) install(p *placement, resp *routerv1.ResolveTunnelResponse) {
	if !p.alive() {
		return
	}
	v := s.buildView(p, resp)
	p.setView(v)
	s.mergeUsed(p, v)
	s.hold(p.id, resp)
}

// versionMoved drops the secrets of every kind of caller of a placement whose version moved
func (s *Server) versionMoved(placement string, version uint64) {
	for _, fetch := range []bool{false, true} {
		s.placesMu.Lock()
		p := s.places[placement+kindSuffix(fetch)]
		s.placesMu.Unlock()
		if p == nil || p.view() == nil || p.view().resp.GetSecretsVersion() == version {
			continue
		}
		p.dropSecrets()
		go p.refresh(context.Background(), false)
	}
	for _, f := range s.versionListeners {
		f(placement, version)
	}
}

// secretsChanged re-resolves every kind of caller of the placement
func (s *Server) secretsChanged(placement string) {
	for _, fetch := range []bool{false, true} {
		s.placesMu.Lock()
		p := s.places[placement+kindSuffix(fetch)]
		s.placesMu.Unlock()
		if p != nil {
			go p.refresh(context.Background(), false)
		}
	}
}

/* Views */

// buildView opens the secrets of resp, keeping the ones prev already holds unchanged
func (s *Server) buildView(p *placement, resp *routerv1.ResolveTunnelResponse) *view {
	cfg := x402.ConfigFrom(resp.GetX402())
	v := &view{
		resp: resp, at: s.now(), hosts: hostSet(resp, cfg), ca: resp.GetCaVersion(), x402: cfg,
		set: &secretSet{byHash: map[[32]byte]*secret{}, headers: map[string][]string{}},
	}
	prev := p.view()
	binding := Binding(p.uid)
	for _, es := range resp.GetSecrets() {
		spec := es.GetSpec()
		hash, ok := toHash(es.GetPlaceholderSha256())
		if !ok || es.GetValue() == nil {
			continue
		}
		sum := fingerprint(es)
		var x *secret
		if prev != nil {
			if old := prev.set.byHash[hash]; old != nil && old.print == sum {
				x = old
			}
		}
		if x == nil {
			pl, err := s.keys.openPayload(es.GetValue().GetKeyId(), es.GetValue().GetBox())
			if err != nil || !pl.matches(binding, spec.GetName(), spec.GetHosts(),
				spec.GetHeaderNames(), spec.GetFetchOnly()) {
				s.log.Warn("egress: a secret could not be opened and will not be swapped",
					"placement", p.short, "secret", spec.GetName())
				continue
			}
			x = &secret{
				name: spec.GetName(), hosts: map[string]bool{}, value: []byte(pl.Value), print: sum,
			}
			for _, h := range canonical(spec.GetHosts()) {
				x.hosts[h] = true
			}
		}
		v.set.byHash[hash] = x
		for _, h := range canonical(spec.GetHosts()) {
			for _, name := range canonical(spec.GetHeaderNames()) {
				if !slices.Contains(v.set.headers[h], name) {
					v.set.headers[h] = append(v.set.headers[h], name)
				}
			}
		}
	}
	return v
}

func toHash(b []byte) ([32]byte, bool) {
	var h [32]byte
	if len(b) != len(h) {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

// fingerprint covers everything that decides whether a secret may be swapped, box included
func fingerprint(es *routerv1.EgressSecret) [32]byte {
	spec := es.GetSpec()
	h := sha256.New()
	for _, part := range [][]string{
		{es.GetValue().GetKeyId(), string(es.GetValue().GetBox()), spec.GetName()},
		canonical(spec.GetHosts()), {"|"}, canonical(spec.GetHeaderNames()),
		{strings.Join([]string{"fetch", boolText(spec.GetFetchOnly())}, "=")},
	} {
		for _, s := range part {
			_, _ = h.Write([]byte(s))
			_, _ = h.Write([]byte{0})
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
