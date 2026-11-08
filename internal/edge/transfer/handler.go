// Package transfer serves the transfer host, relaying each upload and download through router-api
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"
	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/oynozan/bugnet-edges/internal/lease"
	"github.com/oynozan/bugnet-edges/internal/pace"
	"github.com/oynozan/bugnet-edges/internal/pages"
	"github.com/oynozan/bugnet-edges/internal/strangers"
	"github.com/oynozan/bugnet-edges/internal/traffic"
)

const (
	allow = "GET, HEAD, PUT"
	// childKey names the lease children transfers run under
	childKey = "transfer"
	// slotRetry is the Retry-After for an address whose connection slots are all taken
	slotRetry = 5 * time.Second
	// letGoTimeout bounds the call that frees a claim a refused range took
	letGoTimeout = 5 * time.Second
	// cutSlack is how near a hard stop a router cut counts as it, the router checking each second
	cutSlack     = 2 * time.Second
	routerDomain = "bugnet.router"
)

var (
	// tokenShape is bnx_ and 256 bits in base64url without padding, DP 8.3.1
	tokenShape = regexp.MustCompile(`^bnx_[A-Za-z0-9_-]{43}$`)
	errCut     = errors.New("transfer: the download was cut")
)

// Deps are the process's traffic pieces and this route's own limits on strangers
type Deps struct {
	EdgeID      string
	Traffic     *traffic.Traffic // the process's, shared with previews
	Guard       *strangers.Guard // this route's own token failure rule
	Conns       *strangers.Conns // this route's own open connections per address
	Chunk       int              // bytes in one message to the router
	IdleTimeout time.Duration    // a transfer whose client moves nothing this long is cut
	Log         *slog.Logger
}

type handler struct {
	router  routerv1connect.EdgeServiceClient
	newCall func() routerv1connect.EdgeServiceClient
	d       Deps
}

// New serves /<token> and /<token>/<name>, router for OpenTransfer and newCall for each stream
func New(
	router routerv1connect.EdgeServiceClient, newCall func() routerv1connect.EdgeServiceClient,
	d Deps,
) http.Handler {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Chunk <= 0 {
		d.Chunk = 256 << 10
	}
	if d.IdleTimeout <= 0 {
		d.IdleTimeout = time.Minute
	}
	if d.Guard == nil {
		d.Guard = strangers.NewGuard(0, strangers.Mark, strangers.Unknown)
	}
	if d.Conns == nil {
		d.Conns = strangers.NewConns(0)
	}
	return &handler{router: router, newCall: newCall, d: d}
}

// request is one transfer request and what the handler learned about it
type request struct {
	w         http.ResponseWriter
	r         *http.Request
	rc        *http.ResponseController
	ip        netip.Addr
	sum       [32]byte
	short     string // the first 8 hex characters of the token's SHA-256, the only form logged
	placement string
	lease     *lease.Lease // the placement's, nil before the transfer opens
	stop      time.Time    // the max_duration hard stop, zero when the placement deadline is first
	status    int
	bytes     int64
	start     time.Time
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := &request{w: w, r: r, rc: http.NewResponseController(w), ip: clientIP(r),
		start: time.Now()}
	release, ok := h.d.Conns.Acquire(q.ip)
	if !ok {
		answer(q, pages.RateLimited.RetryAfter(slotRetry))
		return
	}
	defer release()

	dir := routerv1.TransferDirection_TRANSFER_DIRECTION_DOWNLOAD
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPut:
		dir = routerv1.TransferDirection_TRANSFER_DIRECTION_UPLOAD
		if r.Header.Get("Content-Range") != "" {
			answer(q, pages.ContentRange)
			return
		}
	default:
		w.Header().Set("Allow", allow)
		answer(q, pages.MethodNotAllowed)
		return
	}
	token := tokenOf(r)
	q.sum = sha256.Sum256([]byte(token))
	q.short = hex.EncodeToString(q.sum[:4])
	if !tokenShape.MatchString(token) || h.d.Guard.KnownUnknown(q.sum) {
		h.unknown(q, false)
		return
	}
	if h.d.Guard.Marked(q.ip) && !h.d.Guard.MayAsk(q.ip) {
		answer(q, pages.RateLimited.RetryAfter(strangers.AskEvery))
		return
	}
	res, err := h.router.OpenTransfer(r.Context(), connect.NewRequest(
		&routerv1.OpenTransferRequest{Token: token, Direction: dir,
			Probe: r.Method == http.MethodHead, EdgeId: h.d.EdgeID}))
	if err != nil {
		if reasonOf(err) == "TOKEN_UNKNOWN" {
			h.unknown(q, true)
			return
		}
		answer(q, h.refusal(r.Context(), q, err))
		h.done(q)
		return
	}
	m := res.Msg
	q.placement = m.GetPlacementId()
	defer h.done(q)
	if r.Method == http.MethodHead {
		h.head(q, m)
		return
	}

	b := m.GetBudget()
	expires := m.GetExpiresAt().AsTime()
	q.lease = h.d.Traffic.Hold(q.placement, lease.State{
		Deadline: expires, Remaining: b.GetBytesRemaining(),
	}, b.GetBytesPerSecond())
	ctx, stop := q.lease.Child(childKey)
	defer stop()
	defer context.AfterFunc(r.Context(), stop)()
	cancel := stop
	// The lease follows the placement deadline and each extension, so only max_duration has a timer
	if hs := m.GetHardStop(); hs != nil && hs.AsTime().Before(expires) {
		q.stop = hs.AsTime()
		var end context.CancelFunc
		ctx, end = context.WithDeadline(ctx, q.stop)
		defer end()
		cancel = end
	}
	if c, ok := passed(q, 0); ok {
		answer(q, c)
		return
	}
	if ctx.Err() != nil {
		answer(q, h.refusal(ctx, q, ctx.Err()))
		return
	}
	if dir == routerv1.TransferDirection_TRANSFER_DIRECTION_UPLOAD {
		h.upload(ctx, cancel, q, m)
		return
	}
	h.download(ctx, q, m)
}

// unknown answers a token that resolves to nothing and counts it against the address
func (h *handler) unknown(q *request, remember bool) {
	if remember {
		h.d.Guard.RememberUnknown(q.sum)
	}
	h.d.Guard.Failed(q.ip)
	if h.d.Guard.Marked(q.ip) {
		answer(q, pages.RateLimited.RetryAfter(strangers.Mark))
	} else {
		answer(q, pages.TokenUnknown)
	}
	h.d.Log.Debug("transfer: unknown token", "transfer", q.short, "status", q.status)
}

// done logs the request's end by the token's hash prefix, never the token or the path
func (h *handler) done(q *request) {
	h.d.Log.Info("transfer: request ended", "transfer", q.short, "placement", q.placement,
		"method", q.r.Method, "status", q.status, "bytes", q.bytes,
		"took", time.Since(q.start).Round(time.Millisecond).String())
}

func answer(q *request, c pages.Code) {
	q.status = c.Status()
	pages.WriteJSON(q.w, c)
}

// abort cuts the client's connection, so a short body never looks complete
func abort(q *request) {
	q.status = 0
	panic(http.ErrAbortHandler)
}

/* Downloads */

// head answers a download's headers from a probe that claims nothing
func (h *handler) head(q *request, m *routerv1.OpenTransferResponse) {
	s := pick(q.r, m.GetSize(), m.GetEtag())
	if s.status == http.StatusRequestedRangeNotSatisfiable {
		q.w.Header().Set("Content-Range", "bytes */"+strconv.FormatUint(m.GetSize(), 10))
		answer(q, pages.Range)
		return
	}
	fileHeaders(q.w.Header(), m, s)
	q.status = s.status
	q.w.WriteHeader(s.status)
}

func (h *handler) download(ctx context.Context, q *request, m *routerv1.OpenTransferResponse) {
	s := pick(q.r, m.GetSize(), m.GetEtag())
	if s.status == http.StatusRequestedRangeNotSatisfiable {
		q.w.Header().Set("Content-Range", "bytes */"+strconv.FormatUint(m.GetSize(), 10))
		answer(q, pages.Range)
		_ = q.rc.Flush()
		h.letGo(m)
		return
	}
	req := &routerv1.ReadTransferRequest{TransferId: m.GetTransferId(), Lease: m.GetLease()}
	if s.status == http.StatusPartialContent {
		req.Offset, req.Length = s.offset, s.n
	}
	stream, err := h.newCall().ReadTransfer(ctx, connect.NewRequest(req))
	if err != nil {
		answer(q, h.refusal(ctx, q, err))
		return
	}
	defer func() { _ = stream.Close() }()

	dl := &deadlines{set: q.rc.SetWriteDeadline, idle: h.d.IdleTimeout}
	defer context.AfterFunc(ctx, dl.end)()
	// The last flush gets the idle timeout too, and the deadline never meets a next request
	defer dl.extend()
	q.w.Header().Set("Connection", "close")
	usage := h.d.Traffic.Usage
	out := h.d.Traffic.Pacer.Lane(q.placement).Writer(&idleWriter{w: q.w, dl: dl}, false,
		func(n int) {
			q.bytes += int64(n)
			usage.Add(q.placement, 0, int64(n))
		})
	started, sent := false, uint64(0)
	write := func(b []byte) error {
		if !started {
			fileHeaders(q.w.Header(), m, s)
			q.status, started = s.status, true
			dl.begin()
			q.w.WriteHeader(s.status)
		}
		if uint64(len(b)) > s.n-sent {
			return errCut
		}
		sent += uint64(len(b))
		_, err := out.Write(b)
		return err
	}

	// The last message waits for the router's verified mark, so a changed file is never whole
	var held []byte
	holding, verified := false, false
	for !verified && stream.Receive() {
		msg := stream.Msg()
		if holding {
			if write(held) != nil {
				abort(q)
			}
		}
		held, holding, verified = msg.GetData(), true, msg.GetVerified()
	}
	if !verified {
		if !started {
			answer(q, h.refusal(ctx, q, cmpErr(stream.Err(), errCut)))
			return
		}
		abort(q)
	}
	if write(held) != nil || sent != s.n {
		abort(q)
	}
}

// letGo frees the claim a refused range took, with a read the router refuses as out of range
func (h *handler) letGo(m *routerv1.OpenTransferResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), letGoTimeout)
	defer cancel()
	stream, err := h.newCall().ReadTransfer(ctx, connect.NewRequest(&routerv1.ReadTransferRequest{
		TransferId: m.GetTransferId(), Lease: m.GetLease(), Offset: m.GetSize() + 1,
	}))
	if err != nil {
		return
	}
	for stream.Receive() {
	}
	_ = stream.Close()
}

// span is the part of a file one download answers
type span struct {
	status    int
	offset, n uint64
}

// pick reads Range and If-Range against the file's size and ETag, as DP 8.3.4 step 2
func pick(r *http.Request, size uint64, etag string) span {
	whole := span{status: http.StatusOK, n: size}
	header := r.Header.Get("Range")
	if header == "" {
		return whole
	}
	if v := r.Header.Get("If-Range"); v != "" && v != etag {
		return whole
	}
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return whole
	}
	first, last, ok := strings.Cut(spec, "-")
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)
	if !ok || first == "" && last == "" {
		return whole
	}
	refused := span{status: http.StatusRequestedRangeNotSatisfiable}
	if first == "" {
		k, err := strconv.ParseUint(last, 10, 64)
		switch {
		case err != nil:
			return whole
		case k == 0 || size == 0:
			return refused
		}
		k = min(k, size)
		return span{status: http.StatusPartialContent, offset: size - k, n: k}
	}
	a, err := strconv.ParseUint(first, 10, 64)
	if err != nil {
		return whole
	}
	b := size - 1
	if last != "" {
		if b, err = strconv.ParseUint(last, 10, 64); err != nil || b < a {
			return whole
		}
	}
	if a >= size {
		return refused
	}
	b = min(b, size-1)
	return span{status: http.StatusPartialContent, offset: a, n: b - a + 1}
}

// fileHeaders sets DP 8.3.4 step 3's headers for the part s of the file m describes
func fileHeaders(h http.Header, m *routerv1.OpenTransferResponse, s span) {
	h.Set("Content-Length", strconv.FormatUint(s.n, 10))
	if m.GetEtag() != "" {
		h.Set("ETag", m.GetEtag())
	}
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Disposition", disposition(m.GetFileName()))
	if sum := m.GetSha256(); len(sum) == sha256.Size {
		h.Set("X-Bugnet-Sha256", hex.EncodeToString(sum))
	}
	if s.status == http.StatusPartialContent {
		h.Set("Content-Range", "bytes "+strconv.FormatUint(s.offset, 10)+"-"+
			strconv.FormatUint(s.offset+s.n-1, 10)+"/"+strconv.FormatUint(m.GetSize(), 10))
	}
}

// disposition is attachment with the file name, its control characters and bad bytes dropped
func disposition(name string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, name)
	if clean != "" {
		if v := mime.FormatMediaType("attachment", map[string]string{"filename": clean}); v != "" {
			return v
		}
	}
	return "attachment"
}

/* Uploads */

func (h *handler) upload(
	ctx context.Context, cancel context.CancelFunc, q *request, m *routerv1.OpenTransferResponse,
) {
	size := m.GetSize()
	if n := q.r.ContentLength; n >= 0 && uint64(n) != size {
		h.letGoUpload(m)
		if uint64(n) > size {
			answer(q, pages.OverCap)
		} else {
			answer(q, pages.SizeMismatch)
		}
		return
	}
	// The first message opens the router's writer before the body is read, empty or not
	call := h.newCall().WriteTransfer(ctx)
	if err := call.Send(&routerv1.WriteTransferRequest{
		TransferId: m.GetTransferId(), Lease: m.GetLease(),
	}); err != nil {
		h.routerEnded(ctx, q, call)
		return
	}
	body := q.r.Body
	if q.r.ContentLength < 0 {
		body = http.MaxBytesReader(q.w, body, int64(size)+1)
	}
	dl := &deadlines{set: q.rc.SetReadDeadline, idle: h.d.IdleTimeout}
	dl.begin()
	defer context.AfterFunc(ctx, dl.end)()
	// An answer before the body's end closes the connection, so the server never waits for the rest
	q.w.Header().Set("Connection", "close")
	usage := h.d.Traffic.Usage
	in := h.d.Traffic.Pacer.Lane(q.placement).Reader(body, true, func(n int) {
		q.bytes += int64(n)
		usage.Add(q.placement, int64(n), 0)
	})

	buf := make([]byte, h.d.Chunk)
	var total uint64
	for {
		dl.extend()
		n, err := fill(in, buf)
		if total += uint64(n); total > size {
			// Cancelling before any clean close means the router never commits
			cancel()
			answer(q, pages.OverCap)
			return
		}
		if n > 0 {
			if serr := call.Send(&routerv1.WriteTransferRequest{Data: buf[:n]}); serr != nil {
				h.routerEnded(ctx, q, call)
				return
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cancel()
			if c, ok := ended(ctx); ok {
				answer(q, c)
				return
			}
			// The client left or stalled past the idle timeout
			abort(q)
		}
	}
	if total < size {
		cancel()
		answer(q, pages.SizeMismatch)
		return
	}
	res, err := call.CloseAndReceive()
	if err != nil {
		answer(q, h.refusal(ctx, q, err))
		return
	}
	body2, _ := json.Marshal(struct {
		Path   string `json:"path"`
		Size   uint64 `json:"size"`
		SHA256 string `json:"sha256"`
	}{res.Msg.GetPath(), res.Msg.GetSize(), hex.EncodeToString(res.Msg.GetSha256())})
	body2 = append(body2, '\n')
	hd := q.w.Header()
	hd.Set("Content-Type", "application/json")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Length", strconv.Itoa(len(body2)))
	hd.Del("Connection")
	q.status = http.StatusOK
	q.w.WriteHeader(http.StatusOK)
	_, _ = q.w.Write(body2)
}

// letGoUpload frees the claim of an upload refused before its body, with a write of another size
func (h *handler) letGoUpload(m *routerv1.OpenTransferResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), letGoTimeout)
	defer cancel()
	first := &routerv1.WriteTransferRequest{TransferId: m.GetTransferId(), Lease: m.GetLease()}
	// The router commits only the size, so a close after no bytes, or one byte for 0, is refused
	if m.GetSize() == 0 {
		first.Data = []byte{0}
	}
	call := h.newCall().WriteTransfer(ctx)
	_ = call.Send(first)
	_, _ = call.CloseAndReceive()
}

// routerEnded answers an upload whose stream the router closed first, with the router's reason
func (h *handler) routerEnded(
	ctx context.Context, q *request,
	call *connect.ClientStreamForClient[routerv1.WriteTransferRequest,
		routerv1.WriteTransferResponse],
) {
	// The router answered already, so closing the send side cannot commit anything
	_, err := call.CloseAndReceive()
	answer(q, h.refusal(ctx, q, cmpErr(err, errCut)))
}

// fill reads into buf until it is full, the body ends, or a read comes back short
func fill(r io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		want := min(len(buf)-n, pace.Piece)
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
		if m < want {
			break
		}
	}
	return n, nil
}

/* Deadlines */

// deadlines moves a connection deadline forward while a transfer moves, and to now once it is cut
type deadlines struct {
	set  func(time.Time) error
	idle time.Duration

	mu   sync.Mutex
	live bool // the transfer reads or writes the client now
	cut  bool
}

func (d *deadlines) begin() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live = true
	if d.cut {
		_ = d.set(time.Now())
	}
}

func (d *deadlines) extend() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.cut {
		_ = d.set(time.Now().Add(d.idle))
	}
}

// end cuts a live transfer at once, so a read or write blocked on the client returns
func (d *deadlines) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cut = true
	if d.live {
		_ = d.set(time.Now())
	}
}

// idleWriter gives each write to the client the idle timeout
type idleWriter struct {
	w  io.Writer
	dl *deadlines
}

func (x *idleWriter) Write(p []byte) (int, error) {
	x.dl.extend()
	return x.w.Write(p)
}

/* Router refusals */

// refusal is DP 8.6's answer to a router error, or to the reason the lease ended
func (h *handler) refusal(ctx context.Context, q *request, err error) pages.Code {
	if c, ok := ended(ctx); ok {
		return c
	}
	switch reasonOf(err) {
	case "TOKEN_USED":
		return pages.TokenUsed
	case "TOKEN_EXPIRED":
		return pages.TokenExpired
	case "IN_USE":
		return pages.InUse
	case "FILE_CHANGED", "FILE_NOT_FOUND", "IS_DIRECTORY", "NOT_REGULAR":
		return pages.FileChanged
	case "NOT_READY":
		return pages.SandboxEnded
	case "BUDGET_SPENT":
		return pages.TrafficLimit
	case "TOO_MANY_TRANSFERS":
		return pages.TooManyTransfers
	case "RATE_LIMITED":
		return pages.Unavailable.RetryAfter(max(retryDelay(err), time.Second))
	case "OVER_CAP":
		return pages.OverCap
	case "RANGE":
		return pages.Range
	case "SIZE_MISMATCH":
		return pages.SizeMismatch
	case "CHECKSUM_MISMATCH":
		return pages.ChecksumMismatch
	case "NO_SPACE":
		return pages.NoSpace
	}
	code := connect.CodeOf(err)
	switch code {
	case connect.CodeInvalidArgument:
		// The router names no reason for a token of the other direction
		return pages.MethodNotAllowed
	case connect.CodeCanceled:
		return pages.Unavailable
	case connect.CodeDeadlineExceeded:
		if q.lease == nil {
			break
		}
		// The router cuts an open transfer this way for idleness, a stalled call or its hard stop
		if c, ok := passed(q, cutSlack); ok {
			return c
		}
		return pages.Unavailable
	}
	h.d.Log.Warn("transfer: the router refused", "transfer", q.short, "placement", q.placement,
		"code", code.String())
	return pages.Unavailable
}

// ended is the answer for a transfer its lease or hard stop ended, false for any other end
func ended(ctx context.Context) (pages.Code, bool) {
	if reason := lease.Reason(ctx); reason != "" {
		return byLease(reason), true
	}
	// Only the max_duration hard stop puts a deadline on a transfer's context
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return pages.TooLong, true
	}
	return pages.Code{}, false
}

// passed is the answer for a transfer whose hard stop is within slack of now, false for none
func passed(q *request, slack time.Duration) (pages.Code, bool) {
	now := time.Now().Add(slack)
	switch {
	case !q.stop.IsZero() && !now.Before(q.stop):
		return pages.TooLong, true
	case q.lease != nil && !now.Before(q.lease.State().Deadline):
		return pages.SandboxEnded, true
	}
	return pages.Code{}, false
}

func byLease(reason string) pages.Code {
	if reason == lease.ReasonBudget {
		return pages.TrafficLimit
	}
	return pages.SandboxEnded
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

func cmpErr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

/* Requests */

// tokenOf is the path's first segment, a following /<name> being only for the client's file name
func tokenOf(r *http.Request) string {
	token, _, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	return token
}

// clientIP is the address PROXY v2 gave the connection, IPv4-mapped addresses as IPv4
func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
