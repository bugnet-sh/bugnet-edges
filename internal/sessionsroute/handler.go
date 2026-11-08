// Package sessionsroute serves the session page at sessions.bugnet.sh and its calls, SP 7.2
package sessionsroute

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/oynozan/bugnet-edges/internal/strangers"
)

const (
	// maxBody is the largest page call body, SP 7.4
	maxBody = 1 << 10
	// slowDown is the Retry-After past the per-address request limit
	slowDown = time.Minute
	// busyRetry is the Retry-After when the router is out of reach or asks for no reason
	busyRetry    = 2 * time.Second
	routerDomain = "bugnet.router"
	robots       = "User-agent: *\nDisallow: /\n"
	cookieAdvice = "This browser sent more bugnet.sh cookies than Bugnet reads. Clear the " +
		"cookies for bugnet.sh in your browser's site settings, then reload the page.\n"
)

var (
	// idShape is 16 base32 characters, keyShape bnk_ and 43 base64url (SP 3)
	idShape  = regexp.MustCompile(`^[a-z2-7]{16}$`)
	keyShape = regexp.MustCompile(`^bnk_[A-Za-z0-9_-]{43}$`)
	seqShape = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

// Options are the route's page, origin and limits. A limit of 0 or less is no limit
type Options struct {
	Origin         string  // the page's own origin, https and the host
	Bundle         *Bundle // the page, from LoadBundle
	MaxHeaderBytes int     // headers past this get the 431 page, 1 MiB when 0

	RequestsPerMinute    int // page calls per client address
	KeyFailuresPerMinute int // wrong keys per client address before DP 4.5's mark
	IDFailuresPerMinute  int // wrong keys per id before one router call a second
	LivePerRecord        int // live streams of one record
	LivePerIP            int // live streams of one client address
	LiveMax              int // live streams of the process

	BodyTimeout  time.Duration // to read a page call's body, 10 s when 0
	CallTimeout  time.Duration // for a record or delete call to the router, 10 s when 0
	Keepalive    time.Duration // between keepalive lines, 15 s when 0
	WriteTimeout time.Duration // each live write's deadline, 30 s when 0
	// FirstFrame is how long a live call waits for the router's first frame before its 200
	FirstFrame time.Duration

	Log *slog.Logger

	// now is the per-id limit's clock, time.Now when nil
	now func() time.Time
}

func (o *Options) defaults() {
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = 1 << 20
	}
	setD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	setD(&o.BodyTimeout, 10*time.Second)
	setD(&o.CallTimeout, 10*time.Second)
	setD(&o.Keepalive, 15*time.Second)
	setD(&o.WriteTimeout, 30*time.Second)
	setD(&o.FirstFrame, 2*time.Second)
	if o.Log == nil {
		o.Log = slog.Default()
	}
}

// Handler serves the page and its calls. Close ends every live stream
type Handler struct {
	router  routerv1connect.SessionPageServiceClient
	newCall func() routerv1connect.SessionPageServiceClient
	o       Options
	perIP   *strangers.PerIP
	ips     *strangers.Guard
	ids     *idGuard
	good    *goodPairs
	live    *streams
}

// New serves the page from o.Bundle, router for records and deletes, newCall for each live stream
func New(
	router routerv1connect.SessionPageServiceClient,
	newCall func() routerv1connect.SessionPageServiceClient, o Options,
) *Handler {
	o.defaults()
	return &Handler{
		router: router, newCall: newCall, o: o,
		perIP: strangers.NewPerIP(o.RequestsPerMinute),
		ips:   strangers.NewGuard(o.KeyFailuresPerMinute, strangers.Mark, strangers.Unknown),
		ids:   newIDGuard(o.IDFailuresPerMinute, o.now),
		good:  newGoodPairs(),
		live:  newStreams(o.LivePerRecord, o.LivePerIP, o.LiveMax),
	}
}

// Close ends every live stream without an end frame, so each page resumes elsewhere
func (h *Handler) Close() {
	h.live.closeAll()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if headerBytes(r) > h.o.MaxHeaderBytes {
		h.tooLarge(w, r)
		return
	}
	path := r.URL.EscapedPath()
	if strings.HasPrefix(path, "/v1/") {
		h.v1(w, r, path)
		return
	}
	h.static(w, r, path)
}

// headerBytes is about what the request's line and headers took on the wire
func headerBytes(r *http.Request) int {
	n := len(r.Method) + len(r.RequestURI) + len(r.Proto) + len(r.Host) + 12
	for k, vs := range r.Header {
		for _, v := range vs {
			n += len(k) + len(v) + 4
		}
	}
	return n
}

// tooLarge is data-plane 17's 431 page, for a bugnet.sh cookie jar a preview filled
func (h *Handler) tooLarge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	h.send(w, r, http.StatusRequestHeaderFieldsTooLarge,
		&file{body: []byte(cookieAdvice), typ: "text/plain; charset=utf-8"})
}

/* The page */

// static serves the bundle, never looking an id up, so a GET tells nothing (SP 7.2)
func (h *Handler) static(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.send(w, r, http.StatusNotFound, nil)
		return
	}
	b := h.o.Bundle
	if id, ok := strings.CutPrefix(path, "/s/"); ok && idShape.MatchString(id) {
		h.send(w, r, http.StatusOK, &b.index)
		return
	}
	if name, ok := strings.CutPrefix(path, "/assets/"); ok {
		if f, ok := b.assets[name]; ok {
			h.send(w, r, http.StatusOK, &f)
			return
		}
	}
	if path == "/robots.txt" {
		h.send(w, r, http.StatusOK, &file{body: []byte(robots), typ: "text/plain; charset=utf-8"})
		return
	}
	h.send(w, r, http.StatusNotFound, nil)
}

// send answers with the bundle's headers and f, gzipped when r accepts it, or no body when nil
func (h *Handler) send(w http.ResponseWriter, r *http.Request, status int, f *file) {
	hd := w.Header()
	h.o.Bundle.setHeaders(hd)
	if f == nil {
		if status != http.StatusNoContent {
			hd.Set("Content-Length", "0")
		}
		w.WriteHeader(status)
		return
	}
	body := f.body
	hd.Set("Content-Type", f.typ)
	if f.gz != nil {
		hd.Add("Vary", "Accept-Encoding")
		if r != nil && acceptsGzip(r) {
			body = f.gz
			hd.Set("Content-Encoding", "gzip")
		}
	}
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// acceptsGzip reports whether Accept-Encoding names gzip, or *, without q=0
func acceptsGzip(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept-Encoding") {
		for part := range strings.SplitSeq(v, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "gzip" && name != "x-gzip" && name != "*" {
				continue
			}
			q := 1.0
			for p := range strings.SplitSeq(params, ";") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(p), "q="); ok {
					if f, err := strconv.ParseFloat(v, 64); err == nil {
						q = f
					}
				}
			}
			return q > 0
		}
	}
	return false
}

/* Page calls */

// call is one /v1 request and what the route learned about it
type call struct {
	w      http.ResponseWriter
	r      *http.Request
	route  string
	ip     netip.Addr
	id     string
	sum    [32]byte // SHA-256 of the id and key, the unknown cache's and good pairs' key
	status int
	start  time.Time
}

func (h *Handler) v1(w http.ResponseWriter, r *http.Request, path string) {
	q := &call{w: w, r: r, route: "other", ip: clientKey(r), start: time.Now()}
	defer h.done(q)
	if !h.pageCall(r) {
		h.answer(q, http.StatusForbidden, 0)
		return
	}
	if !h.perIP.Allow(q.ip) {
		h.answer(q, http.StatusTooManyRequests, slowDown)
		return
	}
	if r.ContentLength > maxBody {
		h.answer(q, http.StatusRequestEntityTooLarge, 0)
		return
	}
	// A slow body holds nothing past its deadline, and a live stream's reads then have none
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(h.o.BodyTimeout))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		// The deadline stays, so the server never waits on the rest of the body
		w.Header().Set("Connection", "close")
		mbe := (*http.MaxBytesError)(nil)
		switch {
		case errors.As(err, &mbe):
			h.answer(q, http.StatusRequestEntityTooLarge, 0)
		case errors.Is(err, os.ErrDeadlineExceeded):
			h.answer(q, http.StatusRequestTimeout, 0)
		default:
			h.answer(q, http.StatusBadRequest, 0)
		}
		return
	}
	_ = rc.SetReadDeadline(time.Time{})
	id, seq, ok := v1Path(path)
	if !ok {
		h.answer(q, http.StatusNotFound, 0)
		return
	}
	q.id = id
	switch {
	case seq == 0 && r.Method == http.MethodPost:
		q.route = "record"
		h.record(q, body)
	case seq == 0 && r.Method == http.MethodDelete:
		q.route = "delete"
		h.delete(q, body)
	case seq > 0 && r.Method == http.MethodPost:
		q.route = "live"
		h.watch(q, body, uint32(seq))
	default:
		h.answer(q, http.StatusNotFound, 0)
	}
}

// pageCall is SP 4's rule, the page's own origin with same-origin, and Cookie is never read
func (h *Handler) pageCall(r *http.Request) bool {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	origin := r.Header.Values("Origin")
	return err == nil && t == "application/json" && len(origin) == 1 &&
		origin[0] == h.o.Origin && r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// v1Path is /v1/s/<id> with seq 0, or /v1/s/<id>/jobs/<seq>/live
func v1Path(path string) (id string, seq uint64, ok bool) {
	rest, ok := strings.CutPrefix(path, "/v1/s/")
	if !ok {
		return "", 0, false
	}
	parts := strings.Split(rest, "/")
	if !idShape.MatchString(parts[0]) {
		return "", 0, false
	}
	switch {
	case len(parts) == 1:
		return parts[0], 0, true
	case len(parts) == 4 && parts[1] == "jobs" && parts[3] == "live" &&
		seqShape.MatchString(parts[2]):
		n, err := strconv.ParseUint(parts[2], 10, 32)
		return parts[0], n, err == nil
	}
	return "", 0, false
}

// pageBody is what the page sends, its key and on a live call the cursor
type pageBody struct {
	K      string `json:"k"`
	Cursor string `json:"cursor"`
}

// admit reads the key and decides whether the call may reach the router, answering when not
func (h *Handler) admit(q *call, body []byte) (pageBody, bool) {
	var b pageBody
	if json.Unmarshal(body, &b) != nil || !keyShape.MatchString(b.K) {
		// No router call, so the id's count is left alone
		h.ips.Failed(q.ip)
		h.answerUnknown(q)
		return b, false
	}
	q.sum = sha256.Sum256([]byte(q.id + "\x00" + b.K))
	if h.good.has(q.sum) {
		return b, true
	}
	if h.ips.KnownUnknown(q.sum) {
		h.unknown(q, false)
		return b, false
	}
	if h.ips.Marked(q.ip) && !h.ips.MayAsk(q.ip) || !h.ids.mayAsk(q.id, q.ip) {
		h.answer(q, http.StatusTooManyRequests, strangers.AskEvery)
		return b, false
	}
	return b, true
}

// unknown answers an unknown id or a wrong key alike and counts it against the address and id
func (h *Handler) unknown(q *call, remember bool) {
	h.count(q, remember)
	h.answerUnknown(q)
}

// count counts a wrong key against the address and the id, remember caching the pair for 10 s
func (h *Handler) count(q *call, remember bool) {
	if remember {
		h.ips.RememberUnknown(q.sum)
	}
	h.good.remove(q.sum)
	h.ips.Failed(q.ip)
	h.ids.failed(q.id, q.ip)
}

// answerUnknown is 404, or 429 for 10 minutes once the address is marked
func (h *Handler) answerUnknown(q *call) {
	if h.ips.Marked(q.ip) {
		h.answer(q, http.StatusTooManyRequests, strangers.Mark)
		return
	}
	h.answer(q, http.StatusNotFound, 0)
}

// refused answers a router error, remember caching an unknown pair for 10 s
func (h *Handler) refused(q *call, err error, remember bool) {
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		h.unknown(q, remember)
	case q.r.Context().Err() != nil:
		// The client left, and nothing reaches it
		q.status = 499
	case connect.CodeOf(err) == connect.CodeResourceExhausted:
		h.answer(q, http.StatusTooManyRequests, max(retryDelay(err), strangers.AskEvery))
	default:
		h.o.Log.Warn("sessions: the router refused a page call", "route", q.route,
			"code", connect.CodeOf(err).String(), "reason", reasonOf(err))
		h.answer(q, http.StatusServiceUnavailable, busyRetry)
	}
}

// record is POST /v1/s/<id>, its 200 body built around the router's bytes and never parsed
func (h *Handler) record(q *call, body []byte) {
	b, ok := h.admit(q, body)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), h.o.CallTimeout)
	defer cancel()
	res, err := h.router.GetSessionRecord(ctx, connect.NewRequest(
		&routerv1.GetSessionRecordRequest{Id: q.id, Key: b.K}))
	if err != nil {
		h.refused(q, err, true)
		return
	}
	h.good.add(q.sum)
	out, ok := recordBody(res.Msg)
	if !ok {
		h.o.Log.Error("sessions: the router sent a record the page cannot show",
			"state", res.Msg.GetState())
		h.answer(q, http.StatusServiceUnavailable, busyRetry)
		return
	}
	q.status = http.StatusOK
	f := &file{body: out, typ: "application/json"}
	if acceptsGzip(q.r) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(out)
		_ = zw.Close()
		f.gz = buf.Bytes()
	}
	h.send(q.w, q.r, http.StatusOK, f)
}

// recordBody is SP 7.2's 200 body by concatenation, false for a state the page cannot show
func recordBody(m *routerv1.GetSessionRecordResponse) ([]byte, bool) {
	wrap := func(head string, inner []byte) ([]byte, bool) {
		if len(inner) == 0 {
			return nil, false
		}
		out := make([]byte, 0, len(head)+len(inner)+1)
		out = append(append(append(out, head...), inner...), '}')
		return out, true
	}
	switch m.GetState() {
	case "ended":
		return wrap(`{"state":"ended","record":`, m.GetRecordJson())
	case "running":
		return wrap(`{"state":"running","snapshot":`, m.GetLiveJson())
	case "expired":
		return []byte(`{"state":"expired"}`), true
	}
	return nil, false
}

// delete is DELETE /v1/s/<id>, which also ends the record's live streams
func (h *Handler) delete(q *call, body []byte) {
	b, ok := h.admit(q, body)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), h.o.CallTimeout)
	defer cancel()
	_, err := h.router.DeleteSessionRecord(ctx, connect.NewRequest(
		&routerv1.DeleteSessionRecordRequest{Id: q.id, Key: b.K}))
	if err != nil {
		h.refused(q, err, true)
		return
	}
	h.good.remove(q.sum)
	h.live.endRecord(q.id)
	h.answer(q, http.StatusNoContent, 0)
}

// answer sends status with no body, and Retry-After when retry is set
func (h *Handler) answer(q *call, status int, retry time.Duration) {
	q.status = status
	if retry > 0 {
		q.w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retry.Seconds()))))
	}
	h.send(q.w, q.r, status, nil)
}

// done logs route, status and 8 hex of the id's SHA-256, never the body, key or link
func (h *Handler) done(q *call) {
	level := slog.LevelDebug
	switch {
	case q.status >= 500 && q.status != 499:
		level = slog.LevelWarn
	case q.status >= 200 && q.status < 300:
		level = slog.LevelInfo
	}
	session := ""
	if q.id != "" {
		sum := sha256.Sum256([]byte(q.id))
		session = hex.EncodeToString(sum[:4])
	}
	h.o.Log.Log(context.Background(), level, "sessions: call ended", "route", q.route,
		"session", session, "method", q.r.Method, "status", q.status,
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
