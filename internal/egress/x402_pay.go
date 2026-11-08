package egress

import (
	"io"
	"net/http"
	"sync"
	"time"

	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// openCount is how many signed payments each placement has open
type openCount struct {
	mu sync.Mutex
	n  map[string]int
}

func newOpenCount() *openCount {
	return &openCount{n: map[string]int{}}
}

// take counts one more open payment of the placement, false at limit
func (o *openCount) take(placement string, limit int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n[placement] >= limit {
		return false
	}
	o.n[placement]++
	return true
}

func (o *openCount) release(placement string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n[placement]--; o.n[placement] <= 0 {
		delete(o.n, placement)
	}
}

// hold is the room one payable request keeps for its body until it is paid or given up
type hold struct {
	slot  *x402.Slot
	rp    *x402.Replay
	mark  x402.Code
	first time.Duration

	mu      sync.Mutex
	timer   *time.Timer
	settled bool
	slow    bool
}

// takeHold takes a slot of the body's size and starts keeping the body, false when it refused
func (q *sellerReq) takeHold() bool {
	cfg := q.s.cfg.X402
	size, ok := x402.SlotSize(q.r.ContentLength, int64(cfg.ReplayBodyMax))
	if !ok {
		q.hold.mark = x402.CodeBodyTooLarge
		return true
	}
	slot, ok := q.s.buffers.Take(q.p.id, size)
	if !ok {
		q.refuse(x402.CodeBufferBusy, x402.Facts{}, nil)
		return false
	}
	q.hold.slot, q.hold.first = slot, time.Duration(cfg.FirstHeaderTimeout)
	q.hold.rp = x402.ReadReplay(q.r.Body, size, q.start.Add(time.Duration(cfg.BodyReadTimeout)))
	q.hold.rp.FreeOnMark(slot)
	return true
}

// body is what the first send reads, the kept body when there is one
func (h *hold) body(rc io.ReadCloser) io.ReadCloser {
	if h.rp == nil {
		return rc
	}
	return io.NopCloser(h.rp.Upstream)
}

// release gives the slot back and ends the kept body, however often it is called
func (h *hold) release() {
	if h.rp != nil {
		h.rp.Close()
	}
	h.slot.Free()
}

// startFirstAnswer frees the slot when the first answer is slower than first_header_timeout
func (h *hold) startFirstAnswer() {
	if h.rp == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.settled {
		return
	}
	h.timer = time.AfterFunc(h.first, func() {
		h.mu.Lock()
		if h.settled {
			h.mu.Unlock()
			return
		}
		h.slow = true
		h.mu.Unlock()
		h.release()
	})
}

// settle ends the wait for a first answer and says whether it came too late
func (h *hold) settle() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.settled = true
	if h.timer != nil {
		h.timer.Stop()
	}
	return h.slow
}

// payable is XS 6.6 step 10 for a 402 on a request with a kept body, up to the signed payment
func (q *sellerReq) payable(resp *http.Response, t x402.Target) {
	rp := q.hold.rp
	if err := rp.Wait(q.r.Context()); err != nil {
		q.refuse(x402.CodeBodySlow, x402.Facts{}, nil)
		return
	}
	_, code, keep := q.judge(resp, x402.Payable, rp.Mark)
	if code != "" {
		q.refuse(code, x402.Facts{}, keep)
		return
	}
	if !q.s.open.take(q.p.id, q.s.cfg.X402.MaxOpenSignedPerPlacement) {
		q.refuse(x402.CodeTooManyOpenPayments, x402.Facts{}, keep)
		return
	}
	defer q.s.open.release(q.p.id)
	q.ev.Ref = x402.NewRef()
	res, err := q.s.signer.Reserve(q.r.Context(), &paymentsv1.ReserveAndSignRequest{
		AccountId: q.cfg.AccountID, PlacementId: q.p.id, Ref: q.ev.Ref, ServiceId: q.svc.ID,
		Method: q.r.Method, Host: q.host, Path: t.Path, BodySha256: rp.Sum[:],
		PaymentRequired: resp.Header.Get("Payment-Required"),
		TargetSha256:    x402.TargetSHA256(q.p.id, q.r.RequestURI),
	})
	if err != nil {
		q.refuse(x402.CodePaymentsUnavailable, x402.Facts{}, keep)
		return
	}
	if rf := res.GetRefused(); rf != nil {
		q.refused(rf, keep)
		return
	}
	q.signed(res.GetSigned(), keep)
}

// refused passes Payments' refusal on with XS 6.13's status
func (q *sellerReq) refused(rf *paymentsv1.Refused, keep http.Header) {
	code := x402.Code(rf.GetReason())
	if _, ok := x402.Lookup(code); !ok {
		code = x402.CodePaymentsUnavailable
	}
	f := q.facts()
	left := rf.GetAllowanceLeftMicros()
	f.LeftMicros = &left
	q.ev.AllowanceLeftMicros = left
	if v := rf.GetAskedMicros(); v > 0 {
		f.AskedMicros = &v
	}
	if v := rf.GetMaxMicros(); v > 0 {
		f.MaxMicros = &v
	}
	q.refuse(code, f, keep)
}

// signed hands a signed payment to the paid retry, which Task X32 sends
func (q *sellerReq) signed(sg *paymentsv1.Signed, keep http.Header) {
	q.s.signer.Report(&paymentsv1.ReportOutcomeRequest{
		PaymentId: sg.GetPaymentId(), Ref: sg.GetPaymentRef(),
		Hint: paymentsv1.SellerHint_SELLER_HINT_ABSENT,
	})
	f := q.facts()
	left := sg.GetAllowanceLeftMicros()
	f.LeftMicros = &left
	q.ev.AllowanceLeftMicros = left
	q.refuse(x402.CodePaymentsUnavailable, f, keep)
}
