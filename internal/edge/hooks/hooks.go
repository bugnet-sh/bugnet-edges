// Package hooks serves the hooks host, handing provider webhooks to the router to verify
package hooks

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
)

const (
	// callTimeout stays under the 5 s Boat allows an acknowledgement
	callTimeout = 4 * time.Second
	// retryAfter is what a rate limited address is told to wait
	retryAfter = time.Minute
)

var provider = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// Options are the route's path secret, body cap and per address rate
type Options struct {
	PathSecret        string // BUGNET_HOOK_PATH_SECRET
	MaxBody           int64  // bytes, larger bodies get 413
	RequestsPerMinute int    // per client address, 0 or less is no limit
	Log               *slog.Logger
}

type handler struct {
	router routerv1connect.EdgeServiceClient
	o      Options
	perIP  *strangers.PerIP
}

// New serves POST /hooks/<provider>/<path secret>, passing the exact body to DeliverHook
func New(router routerv1connect.EdgeServiceClient, o Options) http.Handler {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 64 << 10
	}
	return &handler{router: router, o: o, perIP: strangers.NewPerIP(o.RequestsPerMinute)}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name, secret, ok := split(r)
	if !ok {
		status(w, http.StatusNotFound)
		return
	}
	ip := clientIP(r)
	if !h.perIP.Allow(limitKey(ip)) {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		status(w, http.StatusTooManyRequests)
		return
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(h.o.PathSecret)) != 1 {
		status(w, http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.o.MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			w.Header().Set("Connection", "close")
			status(w, http.StatusRequestEntityTooLarge)
			return
		}
		status(w, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	resp, err := h.router.DeliverHook(ctx, connect.NewRequest(&routerv1.DeliverHookRequest{
		Provider: name, Headers: headers(r.Header), Body: body, ClientIp: ip.String(),
	}))
	if err != nil {
		code := answerFor(err)
		h.o.Log.Info("hook refused", "provider", name, "status", code,
			"connect_code", connect.CodeOf(err).String())
		status(w, code)
		return
	}
	code := int(resp.Msg.GetStatus())
	if code < 200 || code > 299 {
		code = http.StatusNoContent
	}
	status(w, code)
}

// split returns the provider and path secret of /hooks/<provider>/<path secret> on a POST
func split(r *http.Request) (name, secret string, ok bool) {
	rest, found := strings.CutPrefix(r.URL.EscapedPath(), "/hooks/")
	if !found || r.Method != http.MethodPost {
		return "", "", false
	}
	name, secret, found = strings.Cut(rest, "/")
	if !found || !provider.MatchString(name) || secret == "" || strings.Contains(secret, "/") {
		return "", "", false
	}
	return name, secret, true
}

// answerFor maps a router refusal to the status the provider sees
func answerFor(err error) int {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		return http.StatusNotFound
	case connect.CodePermissionDenied, connect.CodeUnauthenticated:
		return http.StatusUnauthorized
	default:
		return http.StatusServiceUnavailable
	}
}

// headers lists every request header with its name lower-cased
func headers(h http.Header) []*routerv1.HeaderValue {
	out := make([]*routerv1.HeaderValue, 0, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, &routerv1.HeaderValue{Name: strings.ToLower(k), Value: v})
		}
	}
	return out
}

func status(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(code)
}

func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}

// limitKey groups an IPv6 client by its /64
func limitKey(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}
