package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"time"

	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// key is the cache key of XS 6.11 for this request, once its body is kept
func (q *sellerReq) key() x402.Key {
	return x402.Key{
		Placement: q.p.id, Method: q.r.Method, Host: q.host, Target: q.r.RequestURI,
		BodySum: q.hold.rp.Sum,
	}
}

// listed says the service is still in the placement's X402Config
func (q *sellerReq) listed(serviceID string) bool {
	for _, s := range q.cfg.Services {
		if s.ID == serviceID {
			return true
		}
	}
	return false
}

// waitCtx starts the deadline the wait and the paid retry share, on its first call
func (q *sellerReq) waitCtx() (context.Context, context.CancelFunc) {
	if q.deadline.IsZero() {
		q.deadline = q.s.now().Add(time.Duration(q.s.cfg.X402.PaidHeaderTimeout))
	}
	return context.WithDeadline(q.r.Context(), q.deadline)
}

// holdKey takes the paid attempt of the key, false when the wait ran out first
func (q *sellerReq) holdKey(ctx context.Context) bool {
	if q.att != nil {
		return true
	}
	a, err := q.s.cache.Begin(ctx, q.key())
	if err != nil {
		return false
	}
	q.att = a
	return true
}

// finishAttempt lets the key go on every way out, keeping a payload that was not settled
func (q *sellerReq) finishAttempt() {
	if q.att != nil {
		q.att.Finish(x402.EndOther)
	}
}

// tryResend is XS 6.6 step 7: a cached payload goes straight to the paid retry, true when served
func (q *sellerReq) tryResend(t x402.Target) bool {
	rp := q.hold.rp
	if rp == nil || !q.s.cache.HasTarget(q.p.id, q.r.Method, q.host, q.r.RequestURI) {
		return false
	}
	if rp.Wait(q.r.Context()) != nil || rp.Mark != "" || !q.s.cache.Has(q.key()) {
		return false
	}
	wait, cancel := q.waitCtx()
	defer cancel()
	if !q.holdKey(wait) {
		q.refuse(x402.CodeBufferBusy, x402.Facts{}, nil)
		return true
	}
	pl := q.att.Attach(q.cfg.Enabled, q.listed)
	if pl == nil {
		return false
	}
	if !q.s.hostRate.Admit(q.host, q.p.id, true) {
		q.refuse(x402.CodeHostRate, x402.Facts{}, nil)
		return true
	}
	q.ev.Ref = x402.NewRef()
	q.paidRetry(*pl, t, true)
	return true
}

// paidRetry is XS 6.6 step 11: one send with the payment header and the kept body
func (q *sellerReq) paidRetry(pl x402.Payload, t x402.Target, resend bool) {
	q.resend = resend
	ev := q.ev
	ev.AmountMicros, ev.PaymentRef, ev.AllowanceLeftMicros = pl.AmountMicros, pl.PaymentRef,
		pl.LeftMicros
	hdr := q.r.Header.Clone()
	x402.StripHopByHop(hdr, true)
	x402.StripBugnet(hdr)
	if _, ok := hdr["User-Agent"]; !ok {
		hdr.Set("User-Agent", "")
	}
	hdr.Set("Payment-Signature", string(pl.Value))
	kept := q.hold.rp.Kept
	ctx, cancel := context.WithCancel(q.r.Context())
	defer cancel()
	var wrote, late atomic.Bool
	trace := &httptrace.ClientTrace{WroteHeaders: func() {
		wrote.Store(true)
		q.reached.Store(true)
	}}
	out := (&http.Request{
		Method: q.r.Method, Host: q.host, Header: hdr, ContentLength: int64(len(kept)),
		URL: &url.URL{
			Scheme: "https", Host: q.host, Opaque: t.Path, RawQuery: t.RawQuery,
			ForceQuery: t.HasQuery && t.RawQuery == "",
		},
	}).WithContext(httptrace.WithClientTrace(ctx, trace))
	if len(kept) > 0 {
		out.Body = io.NopCloser(bytes.NewReader(kept))
	}
	timer := time.AfterFunc(max(time.Until(q.deadline), 0), func() {
		late.Store(true)
		cancel()
	})
	resp, err := q.s.seller.RoundTrip(out)
	stopped := timer.Stop()
	q.hold.release()
	if err != nil || !stopped {
		if resp != nil {
			_ = resp.Body.Close()
		}
		q.noAnswer(pl, wrote.Load() || late.Load())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	q.answered = true
	ev.HttpStatus = uint32(resp.StatusCode)
	x402.StripHopByHop(resp.Header, false)
	x402.StripBugnet(resp.Header)
	x402.ScrubValue(resp.Header, string(pl.Value))
	if resp.StatusCode == http.StatusPaymentRequired {
		q.rejected(resp, pl)
		return
	}
	q.paidStream(resp, x402.ParseResponse(resp.Header.Values("Payment-Response")), pl)
}

// report builds the ReportOutcome of an attempt that has no hint of its own
func (q *sellerReq) report(
	pl x402.Payload, hint paymentsv1.SellerHint, status int,
) *paymentsv1.ReportOutcomeRequest {
	return &paymentsv1.ReportOutcomeRequest{
		PaymentId: pl.PaymentID, Ref: pl.PaymentRef, HttpStatus: uint32(status), Hint: hint,
		Resend: q.resend,
	}
}

// noAnswer ends an attempt whose headers never came, the payload staying for a resend
func (q *sellerReq) noAnswer(pl x402.Payload, sent bool) {
	q.ev.HttpStatus, q.ev.StreamCut = 0, true
	r := q.report(pl, paymentsv1.SellerHint_SELLER_HINT_ABSENT, 0)
	r.StreamCut = true
	q.s.signer.Report(r)
	q.att.Finish(x402.EndOther)
	f := q.facts()
	left := pl.LeftMicros
	f.LeftMicros = &left
	if !sent {
		q.refuse(x402.CodeUpstreamUnreachable, f, nil)
		return
	}
	q.annotate = func(h http.Header) {
		x402.PaidHeaders(h, x402.StatusUncertain, pl.AmountMicros, &left)
	}
	q.refuse(x402.CodePaidNoAnswer, f, nil)
}

// rejected ends an attempt the seller answered with a 402 again, dropping the payload
func (q *sellerReq) rejected(resp *http.Response, pl x402.Payload) {
	q.s.signer.Report(q.report(pl, paymentsv1.SellerHint_SELLER_HINT_REJECTED,
		http.StatusPaymentRequired))
	q.att.Finish(x402.EndRejected)
	keep := http.Header{}
	vs := resp.Header.Values("Payment-Required")
	if len(vs) == 1 && len(vs[0]) <= int(q.s.cfg.X402.PaymentRequiredMax) {
		keep["Payment-Required"] = vs
	}
	f := q.facts()
	left := pl.LeftMicros
	f.LeftMicros = &left
	q.annotate = func(h http.Header) {
		x402.PaidHeaders(h, x402.StatusRejected, pl.AmountMicros, &left)
	}
	q.refuse(x402.CodePaymentRejected, f, keep)
}

// hintOf maps the seller's PAYMENT-RESPONSE to the hint Payments takes
func hintOf(k x402.HintKind) paymentsv1.SellerHint {
	switch k {
	case x402.HintSuccess:
		return paymentsv1.SellerHint_SELLER_HINT_SUCCESS
	case x402.HintFailure:
		return paymentsv1.SellerHint_SELLER_HINT_FAILURE
	}
	return paymentsv1.SellerHint_SELLER_HINT_ABSENT
}

// paidStream copies the answer as it comes, holding back only what tells the code the body ended
// when the end is clean, and reports the outcome
func (q *sellerReq) paidStream(resp *http.Response, h x402.Hint, pl x402.Payload) {
	status, evStatus := x402.StatusUncertain, x402.EventUncertain
	if h.Kind == x402.HintSuccess {
		status, evStatus = x402.StatusPaid, x402.EventPaid
	}
	q.ev.Status = evStatus
	hd := q.w.Header()
	clear(hd)
	for k, vs := range resp.Header {
		hd[k] = vs
	}
	left := pl.LeftMicros
	x402.PaidHeaders(hd, status, pl.AmountMicros, &left)
	req := q.report(pl, hintOf(h.Kind), resp.StatusCode)
	req.HintTx, req.HintError = h.Tx, h.Error
	clean := resp.StatusCode >= 200 && resp.StatusCode < 400 && h.Kind == x402.HintSuccess
	empty := resp.Body == http.NoBody || resp.ContentLength == 0
	if clean && empty {
		q.commit(req)
	}
	q.w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(q.w)
	_ = rc.Flush()
	var held byte
	var hasHeld, cut bool
	var got int64
	buf := make([]byte, 32<<10)
	for !clean || !empty {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			got += int64(n)
			q.bytesIn.Add(uint64(n))
			chunk := buf[:n]
			if clean && resp.ContentLength > 0 && got == resp.ContentLength {
				held, hasHeld, chunk = chunk[n-1], true, chunk[:n-1]
			}
			if len(chunk) > 0 {
				if _, werr := q.w.Write(chunk); werr != nil {
					cut = true
					break
				}
				_ = rc.Flush()
			}
		}
		if err != nil {
			cut = !errors.Is(err, io.EOF)
			break
		}
	}
	q.ev.StreamCut = cut
	switch {
	case clean && empty:
	case clean && !cut:
		q.commit(req)
		if hasHeld {
			if _, err := q.w.Write([]byte{held}); err != nil {
				q.ev.StreamCut = true
			}
		}
	default:
		req.StreamCut = cut
		q.s.signer.Report(req)
		q.att.Finish(x402.EndOther)
	}
	for k, vs := range resp.Trailer {
		if !isBugnet(k) {
			hd[http.TrailerPrefix+k] = vs
		}
	}
}

// commit sends the clean-end report before the code can see the end, then drops the payload
func (q *sellerReq) commit(req *paymentsv1.ReportOutcomeRequest) {
	if left, ok := q.s.signer.ReportClean(q.r.Context(), req); ok {
		q.ev.AllowanceLeftMicros = left
	}
	q.att.Finish(x402.EndClean)
}
