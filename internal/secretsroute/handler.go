// Package secretsroute serves the secrets host, the entry page and the bridge's sealed PUTs, DP 8.4
package secretsroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
)

const (
	// maxBody is the largest call body, DP 8.4
	maxBody = 128 << 10
	// maxBundle bounds what the page directory may hold in memory
	maxBundle    = 16 << 20
	routerDomain = "bugnet.router"
	slowDown     = time.Minute
	busyRetry    = 2 * time.Second
	// csp is DP 8.4's Content-Security-Policy, exactly
	csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
		"connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)

var (
	linkShape  = regexp.MustCompile(`^bnsl_[A-Za-z0-9_-]{1,128}$`)
	grantShape = regexp.MustCompile(`^bnsp_[A-Za-z0-9_-]{1,256}$`)
	nameShape  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	assetShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// assetTypes are the only files /assets/ serves
	assetTypes = map[string]string{
		".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
		".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2",
		".ico": "image/x-icon",
	}
)

// Options are the route's host, page and limits
type Options struct {
	Host              string // the route's own host name, the page's origin is https and this
	PageDir           string // index.html and assets/, read once by New
	RequestsPerMinute int    // calls per client address, 0 or less is no limit
	Log               *slog.Logger
}

// Handler serves the page and the five calls
type Handler struct {
	router routerv1connect.SecretsRouteServiceClient
	origin string
	index  []byte
	assets map[string]asset
	perIP  *strangers.PerIP
	log    *slog.Logger
}

type asset struct {
	body []byte
	typ  string
}

// New reads the page from o.PageDir and serves calls through router
func New(router routerv1connect.SecretsRouteServiceClient, o Options) (*Handler, error) {
	h := &Handler{
		router: router, origin: "https://" + o.Host, assets: map[string]asset{},
		perIP: strangers.NewPerIP(o.RequestsPerMinute), log: o.Log,
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if err := h.load(o.PageDir); err != nil {
		return nil, fmt.Errorf("secrets route: the page: %w", err)
	}
	return h, nil
}

// load reads index.html and the files of assets/ whose names and types the route serves
func (h *Handler) load(dir string) error {
	total := 0
	read := func(path string) ([]byte, error) {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if total += len(body); total > maxBundle {
			return nil, errors.New("the page is over 16 MiB")
		}
		return body, nil
	}
	var err error
	if h.index, err = read(filepath.Join(dir, "index.html")); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "assets"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		typ, ok := assetTypes[strings.ToLower(filepath.Ext(e.Name()))]
		if !ok || !assetShape.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		body, err := read(filepath.Join(dir, "assets", e.Name()))
		if err != nil {
			return err
		}
		h.assets[e.Name()] = asset{body: body, typ: typ}
	}
	return nil
}

// call is one request and what the route learned about it
type call struct {
	w      http.ResponseWriter
	r      *http.Request
	shape  string
	ip     netip.Addr
	status int
	start  time.Time
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := &call{w: w, r: r, shape: "other", ip: addrOf(r), start: time.Now()}
	defer h.done(q)
	path := r.URL.EscapedPath()
	switch {
	case strings.HasPrefix(path, "/v1/"):
		h.v1(q, path)
	default:
		h.static(q, path)
	}
}

// addrOf is the client address, with an IPv6 address counted by its /64 for the limit
func addrOf(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap().WithZone("")
}

func limitKey(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// setHeaders is what every answer carries, the page's and the JSON's alike
func setHeaders(hd http.Header) {
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")
	hd.Set("Content-Security-Policy", csp)
}

// send answers status with body of type typ, or with no body when typ is empty
func (q *call) send(status int, typ string, body []byte) {
	q.status = status
	hd := q.w.Header()
	setHeaders(hd)
	if typ != "" {
		hd.Set("Content-Type", typ)
	}
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	q.w.WriteHeader(status)
	if q.r.Method != http.MethodHead {
		_, _ = q.w.Write(body)
	}
}

// static serves the page for any /l/ path and the assets, and the 404 page for the rest
func (h *Handler) static(q *call, path string) {
	if q.r.Method != http.MethodGet && q.r.Method != http.MethodHead {
		q.send(http.StatusNotFound, "", nil)
		return
	}
	if strings.HasPrefix(path, "/l/") {
		q.shape = "/l/*"
		q.send(http.StatusOK, "text/html; charset=utf-8", h.index)
		return
	}
	if name, ok := strings.CutPrefix(path, "/assets/"); ok {
		q.shape = "/assets/*"
		if a, ok := h.assets[name]; ok {
			q.send(http.StatusOK, a.typ, a.body)
			return
		}
	}
	q.send(http.StatusNotFound, "", nil)
}

// fail answers {"error": reason, "message": ...}, with Retry-After when retry is set
func (q *call) fail(status int, reason, message string, retry time.Duration) {
	if retry > 0 {
		q.w.Header().Set("Retry-After", strconv.Itoa(int((retry+time.Second-1)/time.Second)))
	}
	body, _ := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{reason, message})
	q.send(status, "application/json", body)
}

// reply answers 200 with v as JSON
func (q *call) reply(v any) {
	body, err := json.Marshal(v)
	if err != nil {
		q.fail(http.StatusInternalServerError, "internal", "The route could not answer.", 0)
		return
	}
	q.send(http.StatusOK, "application/json", body)
}

// route is a /v1 path matched, the token or name that its path carries and which call it is
type route struct {
	kind string // get_link, submit, key or put
	arg  string
}

func (h *Handler) v1(q *call, path string) {
	rt, ok := match(q.r.Method, path)
	if !ok {
		q.send(http.StatusNotFound, "", nil)
		return
	}
	q.shape = rt.shape()
	bridge := rt.kind == "key" || rt.kind == "put"
	if bridge {
		if !h.bridgeCall(q) {
			return
		}
	} else if !h.pageCall(q) {
		return
	}
	if !h.perIP.Allow(limitKey(q.ip)) {
		q.fail(http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again later.",
			slowDown)
		return
	}
	body, ok := h.readBody(q)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), 20*time.Second)
	defer cancel()
	ip := q.ip.String()
	switch rt.kind {
	case "get_link":
		res, err := h.router.GetSecretLink(ctx, connect.NewRequest(
			&routerv1.GetSecretLinkRequest{LinkToken: rt.arg}))
		if err != nil {
			h.refused(q, err)
			return
		}
		q.reply(linkOf(res.Msg))
	case "submit":
		h.submit(ctx, q, rt.arg, body, ip)
	case "key":
		res, err := h.router.GetBridgeSealingKey(ctx, connect.NewRequest(
			&routerv1.GetBridgeSealingKeyRequest{PutGrant: grantOf(q.r), ClientIp: ip}))
		if err != nil {
			h.refused(q, err)
			return
		}
		q.reply(keysJSON{SealingKeys: keysOf(res.Msg.GetSealingKeys())})
	case "put":
		h.put(ctx, q, rt.arg, body, ip)
	}
}

func (h *Handler) submit(ctx context.Context, q *call, token string, body []byte, ip string) {
	var b submitBody
	if decode(body, &b) != nil || b.ClientIP != nil {
		badBody(q, b.ClientIP != nil)
		return
	}
	value, err := b.Value.proto()
	if err != nil {
		badBody(q, false)
		return
	}
	res, err := h.router.SubmitSecretLink(ctx, connect.NewRequest(&routerv1.SubmitSecretLinkRequest{
		LinkToken: token, Spec: b.Spec.proto(), Value: value,
		SubmissionId: b.SubmissionID, ClientIp: ip,
	}))
	if err != nil {
		h.refused(q, err)
		return
	}
	q.reply(submitJSON{Secret: secretOf(res.Msg.GetSecret())})
}

func (h *Handler) put(ctx context.Context, q *call, name string, body []byte, ip string) {
	var b putBody
	if decode(body, &b) != nil || b.ClientIP != nil {
		badBody(q, b.ClientIP != nil)
		return
	}
	if b.Spec.Name != name {
		q.fail(http.StatusBadRequest, "name_mismatch",
			"The name in the path is not the name in the spec.", 0)
		return
	}
	value, err := b.Value.proto()
	if err != nil {
		badBody(q, false)
		return
	}
	res, err := h.router.PutBridgeSecret(ctx, connect.NewRequest(&routerv1.PutBridgeSecretRequest{
		PutGrant: grantOf(q.r), Spec: b.Spec.proto(), Value: value,
		IdempotencyKey: b.IdempotencyKey, ClientIp: ip,
	}))
	if err != nil {
		h.refused(q, err)
		return
	}
	q.reply(putJSON{Secret: secretOf(res.Msg.GetSecret()), Replaced: res.Msg.GetReplaced()})
}

func badBody(q *call, clientIP bool) {
	if clientIP {
		q.fail(http.StatusBadRequest, "client_ip_refused",
			"The body may not carry a client address.", 0)
		return
	}
	q.fail(http.StatusBadRequest, "invalid_body", "The body is not the JSON of this call.", 0)
}

// match finds the call a method and path name
func match(method, path string) (route, bool) {
	switch {
	case path == "/v1/sealing-key" && method == http.MethodGet:
		return route{kind: "key"}, true
	case strings.HasPrefix(path, "/v1/secrets/") && method == http.MethodPut:
		name := strings.TrimPrefix(path, "/v1/secrets/")
		return route{kind: "put", arg: name}, nameShape.MatchString(name)
	case strings.HasPrefix(path, "/v1/links/"):
		token, rest, sub := strings.Cut(strings.TrimPrefix(path, "/v1/links/"), "/")
		if !linkShape.MatchString(token) {
			return route{}, false
		}
		switch {
		case !sub && method == http.MethodGet:
			return route{kind: "get_link", arg: token}, true
		case sub && rest == "secret" && method == http.MethodPut:
			return route{kind: "submit", arg: token}, true
		}
	}
	return route{}, false
}

// shape is the path with its token or name left out, the only form a log line carries
func (r route) shape() string {
	switch r.kind {
	case "get_link":
		return "/v1/links/*"
	case "submit":
		return "/v1/links/*/secret"
	case "key":
		return "/v1/sealing-key"
	}
	return "/v1/secrets/*"
}

// pageCall is DP 8.4's rule for the page, its own origin and JSON, never a same-site preview
func (h *Handler) pageCall(q *call) bool {
	r := q.r
	origin := r.Header.Values("Origin")
	if len(origin) != 1 || origin[0] != h.origin {
		q.fail(http.StatusForbidden, "origin_refused", "This call is for the secrets page.", 0)
		return false
	}
	if site := r.Header.Values("Sec-Fetch-Site"); len(site) > 1 ||
		len(site) == 1 && site[0] != "same-origin" {
		q.fail(http.StatusForbidden, "origin_refused", "This call is for the secrets page.", 0)
		return false
	}
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		q.fail(http.StatusBadRequest, "invalid_body", "Send application/json.", 0)
		return false
	}
	return true
}

// bridgeCall refuses a browser's request, then a header that does not carry a put grant
func (h *Handler) bridgeCall(q *call) bool {
	hd := q.r.Header
	if len(hd.Values("Origin")) > 0 || len(hd.Values("Sec-Fetch-Site")) > 0 {
		q.fail(http.StatusForbidden, "browser_refused", "This call is not for browsers.", 0)
		return false
	}
	if !grantShape.MatchString(grantOf(q.r)) {
		q.fail(http.StatusUnauthorized, "put_grant_invalid",
			"Send a put grant as a bearer token.", 0)
		return false
	}
	return true
}

// grantOf is the bearer token of Authorization, empty when there is not exactly one
func grantOf(r *http.Request) string {
	v := r.Header.Values("Authorization")
	if len(v) != 1 {
		return ""
	}
	scheme, token, ok := strings.Cut(v[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return token
}

// readBody reads at most 128 KiB, answering 413 or 400 when it cannot
func (h *Handler) readBody(q *call) ([]byte, bool) {
	if q.r.ContentLength > maxBody {
		q.w.Header().Set("Connection", "close")
		q.fail(http.StatusRequestEntityTooLarge, "body_too_large", "The body is over 128 KiB.", 0)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(q.w, q.r.Body, maxBody))
	if err != nil {
		q.w.Header().Set("Connection", "close")
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			q.fail(http.StatusRequestEntityTooLarge, "body_too_large",
				"The body is over 128 KiB.", 0)
			return nil, false
		}
		q.fail(http.StatusBadRequest, "invalid_body", "The body could not be read.", 0)
		return nil, false
	}
	return body, true
}

// refused answers the router's error with the status of its Connect code
func (h *Handler) refused(q *call, err error) {
	if q.r.Context().Err() != nil {
		q.status = 499
		return
	}
	code := connect.CodeOf(err)
	status, retry := http.StatusInternalServerError, time.Duration(0)
	switch code {
	case connect.CodeInvalidArgument:
		status = http.StatusBadRequest
	case connect.CodePermissionDenied:
		status = http.StatusUnauthorized
	case connect.CodeNotFound:
		status = http.StatusNotFound
	case connect.CodeFailedPrecondition:
		status = http.StatusConflict
	case connect.CodeResourceExhausted:
		status, retry = http.StatusTooManyRequests, max(retryDelay(err), time.Second)
	case connect.CodeUnavailable:
		status, retry = http.StatusServiceUnavailable, busyRetry
	}
	reason := strings.ToLower(reasonOf(err))
	if reason == "" {
		reason = strings.ReplaceAll(code.String(), " ", "_")
	}
	if status >= 500 {
		h.log.Warn("secrets route: the router refused a call", "route", q.shape,
			"code", code.String(), "reason", reason)
	}
	q.fail(status, reason, messages[status], retry)
}

var messages = map[int]string{
	http.StatusBadRequest:          "The router refused the request.",
	http.StatusUnauthorized:        "The router refused the credential.",
	http.StatusNotFound:            "The router does not know it.",
	http.StatusConflict:            "The router cannot do it in the state it is in.",
	http.StatusTooManyRequests:     "Too many requests. Try again later.",
	http.StatusServiceUnavailable:  "The router is busy. Try again.",
	http.StatusInternalServerError: "The router could not answer.",
}

// done logs the path shape, the status and the time, never the token, grant, name or body
func (h *Handler) done(q *call) {
	level := slog.LevelDebug
	switch {
	case q.status >= 500 && q.status != 499:
		level = slog.LevelWarn
	case q.status >= 200 && q.status < 300:
		level = slog.LevelInfo
	}
	h.log.Log(context.Background(), level, "secrets route: call ended", "route", q.shape,
		"method", q.r.Method, "status", q.status,
		"took", time.Since(q.start).Round(time.Millisecond).String())
}

// reasonOf is the router's ErrorInfo reason on err, empty when there is none
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

// retryDelay is the RetryInfo delay the router put on err, 0 when there is none
func retryDelay(err error) time.Duration {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return 0
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if info, ok := v.(*errdetails.RetryInfo); derr == nil && ok {
			return info.GetRetryDelay().AsDuration()
		}
	}
	return 0
}
