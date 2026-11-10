package preview

import (
	"container/list"
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"golang.org/x/sync/singleflight"

	"github.com/bugnet-sh/bugnet-edges/internal/lease"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
	"github.com/bugnet-sh/bugnet-edges/internal/traffic"
)

const (
	// resolveTimeout bounds each ResolvePreview, which runs apart from the request that asked
	resolveTimeout = 2 * time.Second
	// staleRetry spaces the resolves of a route kept while the router cannot answer
	staleRetry = 5 * time.Second
)

var (
	errSpent    = errors.New("preview: the placement's budget is spent")
	errBadRoute = errors.New("preview: the router answered a route that is not an https origin")
)

// route is one resolved preview, held under the placement's lease until revoked or evicted
type route struct {
	id           string
	placement    string
	port         int
	gen          uint32
	base         *url.URL
	headers      []*routerv1.HeaderValue
	cookies      []*routerv1.HeaderValue
	cookieNames  map[string]bool
	blocked      []string
	budget       *routerv1.EdgeBudget
	interstitial bool
	source       string
	started      time.Time
	expires      time.Time
	boat         bool

	trace routeTrace
	lease *lease.Lease
	// alive is the route's own preview child, which a revocation or the lease's end cancels
	alive context.Context
	stop  context.CancelFunc
}

// cache keeps resolved routes by preview id and token hash, DP 8.2.2
type cache struct {
	router     routerv1connect.EdgeServiceClient
	tr         *traffic.Traffic
	max        int
	ttl        time.Duration
	boatSuffix string
	tel        *telemetry.Telemetry
	group      singleflight.Group

	mu  sync.Mutex
	m   map[[32]byte]*list.Element
	lru *list.List
}

type entry struct {
	key [32]byte
	rt  *route
	// until is when the route is resolved again, the route kept meanwhile if the router is down
	until time.Time
}

func newCache(
	router routerv1connect.EdgeServiceClient, tr *traffic.Traffic, limit int, ttl time.Duration,
	boatSuffix string, tel *telemetry.Telemetry,
) *cache {
	return &cache{
		router: router, tr: tr, max: limit, ttl: ttl, boatSuffix: strings.ToLower(boatSuffix),
		tel: tel,
		m:   map[[32]byte]*list.Element{}, lru: list.New(),
	}
}

// fresh is the cached route for key while its ttl runs and it lives, else nil
func (c *cache) fresh(key [32]byte) *route {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil
	}
	e := el.Value.(*entry)
	if e.rt.alive.Err() != nil {
		c.removeLocked(el, "done")
		return nil
	}
	if !time.Now().Before(e.until) {
		return nil
	}
	c.lru.MoveToFront(el)
	return e.rt
}

// resolve asks the router once for all requests that wait on key, apart from their contexts
func (c *cache) resolve(ctx context.Context, key [32]byte, id, tok string) (*route, error) {
	v, err, _ := c.group.Do(string(key[:]), func() (any, error) {
		if rt := c.fresh(key); rt != nil {
			return rt, nil
		}
		arrived := time.Now()
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveTimeout)
		defer cancel()
		res, err := c.router.ResolvePreview(rctx, connect.NewRequest(
			&routerv1.ResolvePreviewRequest{PreviewId: id, Token: tok}))
		if err != nil {
			if transient(err) {
				if rt := c.stale(key); rt != nil {
					return rt, nil
				}
			}
			c.drop(key)
			return nil, err
		}
		rt, err := c.build(id, res.Msg, arrived)
		if err != nil {
			c.drop(key)
			return nil, err
		}
		c.put(key, rt)
		return rt, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*route), nil
}

// transient is a failure that says nothing about the preview, so a cached route may stand
func transient(err error) bool {
	if reasonOf(err) != "" {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled,
		connect.CodeUnknown, connect.CodeInternal, connect.CodeAborted:
		return true
	}
	return false
}

// stale keeps a live route while the router cannot answer, asking again after staleRetry
func (c *cache) stale(key [32]byte) *route {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil
	}
	e := el.Value.(*entry)
	if e.rt.alive.Err() != nil {
		c.removeLocked(el, "done")
		return nil
	}
	e.until = time.Now().Add(staleRetry)
	return e.rt
}

// build holds the placement's lease at the answer's deadline and budget, and the route's child
func (c *cache) build(
	id string, m *routerv1.ResolvePreviewResponse, arrived time.Time,
) (*route, error) {
	up := m.GetUpstream()
	base, err := url.Parse(up.GetBaseUrl())
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || strings.Trim(base.Path, "/") != "" {
		return nil, errBadRoute
	}
	base.Path, base.RawPath = "", ""
	rt := &route{
		id: id, placement: m.GetPlacementId(), port: int(m.GetPort()),
		gen: m.GetGeneration(), base: base, headers: up.GetHeaders(), cookies: up.GetCookies(),
		cookieNames: map[string]bool{}, blocked: up.GetBlockedPathPrefixes(),
		budget: m.GetBudget(), interstitial: m.GetInterstitial(), source: m.GetSourceLabel(),
		started: m.GetStartedAt().AsTime(), expires: m.GetExpiresAt().AsTime(),
	}
	if m.GetStartedAt() == nil {
		rt.started = time.Time{}
	}
	for _, ck := range rt.cookies {
		rt.cookieNames[ck.GetName()] = true
	}
	host := strings.ToLower(base.Hostname())
	rt.boat = c.boatSuffix != "" && (host == c.boatSuffix ||
		strings.HasSuffix(host, "."+c.boatSuffix))
	b := m.GetBudget()
	rt.lease = c.tr.Hold(rt.placement, lease.State{
		Deadline: rt.expires, Remaining: b.GetBytesRemaining(),
	}, b.GetBytesPerSecond())
	rt.alive, rt.stop = rt.lease.Preview(lease.HeldPreview{ID: id, Generation: rt.gen})
	if rt.alive.Err() != nil {
		rt.stop()
		if lease.Reason(rt.alive) == lease.ReasonBudget {
			return nil, errSpent
		}
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("lease ended"))
	}
	rt.trace.begin(rt.alive, c.tel, m.GetOrderTraceparent(), arrived,
		attr.PlacementID(rt.placement), attr.PreviewID(id), attr.Port(rt.port))
	return rt, nil
}

func (c *cache) put(key [32]byte, rt *route) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.removeLocked(el, "deadline")
	}
	c.m[key] = c.lru.PushFront(&entry{key: key, rt: rt, until: time.Now().Add(c.ttl)})
	for c.lru.Len() > c.max {
		c.removeLocked(c.lru.Back(), "done")
	}
}

func (c *cache) drop(key [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.removeLocked(el, "done")
	}
}

// dropPreview forgets every route of one preview, whatever token found it
func (c *cache) dropPreview(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, el := range c.m {
		if el.Value.(*entry).rt.id == id {
			c.removeLocked(el, "done")
		}
	}
}

func (c *cache) removeLocked(el *list.Element, cause string) {
	e := el.Value.(*entry)
	delete(c.m, e.key)
	c.lru.Remove(el)
	e.rt.trace.setCause(cause)
	e.rt.stop()
}

func (c *cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
