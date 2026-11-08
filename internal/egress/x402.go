package egress

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

var errByteCap = errors.New("egress: the unpaid byte cap of the host is reached")

// HasX402 says whether the placement's cached answer holds x402 services
func (s *Server) HasX402(placement string) bool {
	s.placesMu.Lock()
	p := s.places[placement+kindSuffix(false)]
	s.placesMu.Unlock()
	if p == nil {
		return false
	}
	v := p.view()
	return v != nil && len(v.x402.Services) > 0
}

// sellerReq is one request on an x402 host, from its first check to its event
type sellerReq struct {
	s     *Server
	w     *statusWriter
	r     *http.Request
	p     *placement
	cfg   x402.Config
	host  string
	start time.Time
	ev    *routerv1.X402Event
	svc   x402.Service

	targetOK bool
	reached  atomic.Bool
	answered bool
	cut      atomic.Bool
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

// serveX402 is XS 6.6 for a host with x402 services, after the data-plane steps 1 to 3
func (s *Server) serveX402(
	w *statusWriter, r *http.Request, p *placement, st *reqState, cfg x402.Config,
) {
	q := &sellerReq{
		s: s, w: w, r: r, p: p, cfg: cfg, host: st.host, start: s.now(),
		ev: &routerv1.X402Event{Host: st.host, Method: r.Method},
	}
	defer q.end()
	if x402.IsUpgrade(r) {
		q.refuse(x402.CodeUpgradeRefused, x402.Facts{}, nil)
		return
	}
	t, ok := x402.CheckTarget(r.RequestURI)
	if !ok {
		q.refuse(x402.CodePathRefused, x402.Facts{}, nil)
		return
	}
	q.targetOK, q.ev.Path = true, t.Path
	svc, ok := x402.Match(cfg.OnHost(st.host), t.Path, r.Method)
	if !ok {
		q.refuse(x402.CodePathNotEnabled, x402.Facts{}, nil)
		return
	}
	q.svc, q.ev.ServiceId = svc, svc.ID
	x402.DropDummyKey(r.Header)
	pay := x402.Payability(svc, t.Path, r.Method, r.Header)
	if s.counters.Over(p.id, st.host, cfg.Caps) {
		q.refuse(x402.CodeUnpaidCap, x402.Facts{}, nil)
		return
	}
	if !s.hostRate.Admit(st.host, p.id, false) {
		q.refuse(x402.CodeHostRate, x402.Facts{}, nil)
		return
	}
	q.forward(t, pay)
}

// facts are the numbers a refusal body may carry
func (q *sellerReq) facts() x402.Facts {
	f := x402.Facts{Host: q.host}
	if q.svc.ID != "" {
		f.MaxMicros = &q.svc.MaxPriceMicros
	}
	if q.ev.AskedMicros > 0 {
		f.AskedMicros = &q.ev.AskedMicros
	}
	return f
}

// refuse answers with XS 6.13's body, seller carrying the seller's headers it keeps
func (q *sellerReq) refuse(code x402.Code, f x402.Facts, seller http.Header) {
	row, _ := x402.Lookup(code)
	if f.Host == "" {
		f = q.facts()
	}
	if wait := x402.RetryAfter(code, q.s.now()); wait > 0 {
		f.RetryAfterSeconds = &wait
	}
	body := x402.Body(code, f, q.s.cfg.X402)
	h := q.w.Header()
	clear(h)
	for k, vs := range seller {
		h[k] = vs
	}
	h.Set(x402.HeaderError, string(code))
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if f.RetryAfterSeconds != nil {
		h.Set("Retry-After", strconv.Itoa(*f.RetryAfterSeconds))
	}
	q.ev.Status, q.ev.Reason = row.EventStatus, string(code)
	q.w.WriteHeader(row.HTTPStatus)
	_, _ = q.w.Write(body)
}

// forward is XS 6.6 steps 8 to 10 for a request that passed the checks
func (q *sellerReq) forward(t x402.Target, pay x402.Pay) {
	r := q.r
	hdr := r.Header.Clone()
	x402.StripHopByHop(hdr, true)
	x402.StripBugnet(hdr)
	if _, ok := hdr["User-Agent"]; !ok {
		hdr.Set("User-Agent", "")
	}
	trace := &httptrace.ClientTrace{WroteHeaders: func() { q.reached.Store(true) }}
	out := (&http.Request{
		Method: r.Method, Host: q.host, Header: hdr, ContentLength: r.ContentLength,
		URL: &url.URL{
			Scheme: "https", Host: q.host, Opaque: t.Path, RawQuery: t.RawQuery,
			ForceQuery: t.HasQuery && t.RawQuery == "",
		},
	}).WithContext(httptrace.WithClientTrace(r.Context(), trace))
	if r.Body != nil && r.Body != http.NoBody {
		out.Body = &capBody{q: q, rc: r.Body}
	}
	resp, err := q.s.seller.RoundTrip(out)
	if err != nil {
		if q.cut.Load() {
			q.ev.StreamCut = true
			q.refuse(x402.CodeUnpaidCap, x402.Facts{}, nil)
			return
		}
		q.s.log.Debug("egress: the seller could not be reached", "placement", q.p.short)
		q.refuse(x402.CodeUpstreamUnreachable, x402.Facts{}, nil)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	q.answered = true
	q.ev.HttpStatus = uint32(resp.StatusCode)
	x402.StripHopByHop(resp.Header, false)
	x402.StripBugnet(resp.Header)
	if resp.StatusCode == http.StatusPaymentRequired && pay != x402.SelfPaid {
		q.unpayable(resp, pay)
		return
	}
	q.stream(resp, pay == x402.SelfPaid)
}

// stream copies the answer, counting its bytes as they flow and cutting it at the byte cap
func (q *sellerReq) stream(resp *http.Response, selfPaid bool) {
	q.ev.Status = x402.EventFree
	if selfPaid {
		q.ev.Status = x402.EventSelfPaid
	}
	h := q.w.Header()
	clear(h)
	for k, vs := range resp.Header {
		h[k] = vs
	}
	q.w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(q.w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := q.w.Write(buf[:n]); werr != nil {
				q.ev.StreamCut = true
				return
			}
			q.bytesIn.Add(uint64(n))
			_ = rc.Flush()
			if q.s.counters.AddBytes(q.p.id, q.host, int64(n), q.cfg.Caps) {
				q.ev.Status, q.ev.Reason, q.ev.StreamCut = x402.EventRefusedCap,
					string(x402.CodeUnpaidCap), true
				panic(http.ErrAbortHandler)
			}
		}
		if err != nil {
			q.ev.StreamCut = !errors.Is(err, io.EOF)
			break
		}
	}
	for k, vs := range resp.Trailer {
		if !isBugnet(k) {
			h[http.TrailerPrefix+k] = vs
		}
	}
}

func isBugnet(k string) bool {
	return len(k) >= 7 && http.CanonicalHeaderKey(k[:7]) == "Bugnet-"
}

// unpayable is XS 6.9's 402 steps 1 to 4 on a request Bugnet may not pay, or not yet
func (q *sellerReq) unpayable(resp *http.Response, pay x402.Pay) {
	s := q.s.cfg.X402
	values := resp.Header.Values("Payment-Required")
	var code x402.Code
	switch {
	case pay == x402.MethodNotEnabled:
		code = x402.CodeMethodNotEnabled
	case pay == x402.PathNotPaid:
		code = x402.CodePathNotPaid
	case !q.cfg.Enabled:
		code = x402.CodeX402Disabled
	}
	var req x402.Required
	if code == "" && len(values) == 0 {
		code = q.readV1(resp)
	} else if code == "" {
		req, code = x402.ParseRequired(values, int64(s.PaymentRequiredMax))
	}
	if code == "" {
		_, code = x402.Precheck(req, q.svc)
	}
	if e, ok := x402.Offered(req, q.svc); ok {
		q.ev.AskedMicros, q.ev.Asset, q.ev.Network = e.AmountMicros, e.Asset, e.Network
		q.ev.Scheme, q.ev.PayTo, q.ev.X402Version = e.Scheme, e.PayTo, uint32(req.Version)
	}
	if code == "" {
		// Payments is called from Task X31 on, so a payable request cannot be paid yet
		code = x402.CodePaymentsUnavailable
	}
	keep := http.Header{}
	if len(values) == 1 && int64(len(values[0])) <= int64(s.PaymentRequiredMax) {
		keep["Payment-Required"] = values
	}
	q.refuse(code, q.facts(), keep)
}

// readV1 reads at most 64 KiB of a 402 body that has no header, counting it as unpaid bytes
func (q *sellerReq) readV1(resp *http.Response) x402.Code {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, x402.V1BodyMax))
	q.bytesIn.Add(uint64(len(b)))
	q.s.counters.AddBytes(q.p.id, q.host, int64(len(b)), q.cfg.Caps)
	if x402.ParseV1Body(b) {
		return x402.CodeVersionUnsupported
	}
	return x402.CodeNotX402
}

// end counts the request, fills the host bucket and queues the event, on every way out
func (q *sellerReq) end() {
	ev := q.ev
	if ev.Status == "" {
		ev.Status, ev.StreamCut = x402.EventFree, true
	}
	ev.At = timestamppb.New(q.start)
	ev.DurationMs = uint32(min(time.Since(q.start).Milliseconds(), 1<<31))
	ev.BytesIn, ev.BytesOut = q.bytesIn.Load(), q.bytesOut.Load()
	if x402.CountsRequest(q.reached.Load(), ev.Status, x402.Code(ev.Reason)) {
		q.s.counters.AddRequest(q.p.id, q.host)
	}
	q.s.hostRate.Ended(q.host, q.answered, ev.Status, false)
	if q.s.events != nil {
		x402.Shape(ev, q.targetOK)
		q.s.events.Add(q.p.id, ev)
	}
}

// capBody counts the request body as it flows and fails the read at the byte cap
type capBody struct {
	q  *sellerReq
	rc io.ReadCloser
}

func (b *capBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.q.bytesOut.Add(uint64(n))
		if b.q.s.counters.AddBytes(b.q.p.id, b.q.host, int64(n), b.q.cfg.Caps) {
			b.q.cut.Store(true)
			return 0, errByteCap
		}
	}
	return n, err
}

func (b *capBody) Close() error {
	return b.rc.Close()
}
