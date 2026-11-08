package egress

import (
	"bufio"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/fakeseller"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// paidEnv is an x402 proxy in front of the fake seller, paying through the fake Payments
type paidEnv struct {
	*payEnv
	ledger *fakeseller.Ledger
}

func startPaid(t *testing.T, tune func(*x402.Settings)) *paidEnv {
	t.Helper()
	e := startPay(t, func(c *routerv1.X402Config) {
		for _, m := range []string{"ok", "redirect", "silent", "reject", "slow", "settle500",
			"echo", "stream"} {
			c.Services = append(c.Services, &routerv1.X402Service{
				ServiceId: "xs_" + m, Host: "api.example", Prefix: "/" + m + "/", Method: "GET",
				MaxPriceMicros: 10000, PayTo: sellerPin,
			})
		}
	}, tune)
	ledger := fakeseller.InMemory()
	e.h.sell = fakeseller.New(fakeseller.Config{
		PayTo: sellerPin, FeePayer: x402.Encode58(make([]byte, 32)), Settler: ledger,
		BugnetFeePayer: x402.Encode58([]byte("0123456789abcdef0123456789abcdef")),
		Late:           100 * time.Millisecond, Slow: 2 * time.Second,
	}).ServeHTTP
	return &paidEnv{payEnv: e, ledger: ledger}
}

func (e *paidEnv) events(t *testing.T) []*routerv1.X402Event {
	t.Helper()
	e.stopEv()
	return e.h.router.x402Events
}

func TestPaidCall(t *testing.T) {
	e := startPaid(t, nil)
	c := e.h.client(e.p.token)
	resp := e.get(t, c, "/ok/", nil)
	eq(t, resp.StatusCode, 200)
	eq(t, resp.Header.Get(x402.HeaderStatus), "paid")
	eq(t, resp.Header.Get(x402.HeaderPaidUSD), "0.001")
	eq(t, len(e.ledger.Transfers()), 1)
	reps := e.pay.Reports()
	eq(t, len(reps), 1)
	eq(t, reps[0].Hint, paymentsv1.SellerHint_SELLER_HINT_SUCCESS)
	eq(t, reps[0].HttpStatus, uint32(200))
	evs := e.events(t)
	eq(t, len(evs), 1)
	eq(t, evs[0].Status, x402.EventPaid)
	eq(t, evs[0].AmountMicros, int64(1000))
	eq(t, evs[0].PaymentRef, reps[0].Ref)
}

func TestPaidRetryFollowsNoRedirect(t *testing.T) {
	e := startPaid(t, nil)
	resp := e.get(t, e.h.client(e.p.token), "/redirect/", nil)
	eq(t, resp.StatusCode, 302)
	eq(t, resp.Header.Get(x402.HeaderStatus), "paid")
}

func TestSellerAnswerTable(t *testing.T) {
	e := startPaid(t, nil)
	c := e.h.client(e.p.token)
	resp := e.get(t, c, "/silent/", nil)
	eq(t, resp.Header.Get(x402.HeaderStatus), "uncertain")
	resp = e.get(t, c, "/reject/", nil)
	eq(t, resp.StatusCode, 402)
	eq(t, resp.Header.Get(x402.HeaderStatus), "rejected")
	eq(t, resp.Header.Get(x402.HeaderError), "payment_rejected")
	eq(t, resp.Header.Get(x402.HeaderPaidUSD), "")
	within(t, "two reports", func() bool { return len(e.pay.Reports()) == 2 })
	hints := map[paymentsv1.SellerHint]bool{}
	for _, r := range e.pay.Reports() {
		hints[r.Hint] = true
	}
	eq(t, hints[paymentsv1.SellerHint_SELLER_HINT_ABSENT], true)
	eq(t, hints[paymentsv1.SellerHint_SELLER_HINT_REJECTED], true)
	var got []string
	for _, ev := range e.events(t) {
		got = append(got, ev.Status)
	}
	eq(t, got, []string{x402.EventUncertain, x402.EventPaymentFailed})
}

func TestPaidNoAnswer(t *testing.T) {
	e := startPaid(t, func(s *x402.Settings) {
		s.PaidHeaderTimeout = settings.Duration(400 * time.Millisecond)
	})
	c := e.h.client(e.p.token)
	resp := e.get(t, c, "/slow/", nil)
	eq(t, resp.StatusCode, 502)
	eq(t, resp.Header.Get(x402.HeaderStatus), "uncertain")
	eq(t, resp.Header.Get(x402.HeaderPaidUSD), "0.01")
	eq(t, resp.Header.Get(x402.HeaderError), "paid_no_answer")
	var ev *routerv1.X402Event
	for _, v := range e.events(t) {
		ev = v
	}
	eq(t, ev.HttpStatus, uint32(0))
	eq(t, ev.StreamCut, true)
	eq(t, ev.AmountMicros, int64(10000))
}

func TestResendFromCache(t *testing.T) {
	e := startPaid(t, nil)
	c := e.h.client(e.p.token)
	eq(t, e.get(t, c, "/settle500/", nil).StatusCode, 500)
	// The seller refuses the duplicate payload, so the resend ends rejected
	eq(t, e.get(t, c, "/settle500/", nil).StatusCode, 402)
	eq(t, e.pay.Signings(), 1)
	eq(t, len(e.ledger.Transfers()), 1)
	rs := e.pay.Reserves()
	eq(t, len(rs), 1)
	within(t, "two reports", func() bool { return len(e.pay.Reports()) == 2 })
	reps := e.pay.Reports()
	eq(t, reps[0].Resend, false)
	eq(t, reps[1].Resend, true)
	evs := e.events(t)
	eq(t, len(evs), 2)
	eq(t, evs[1].PaymentRef, evs[0].PaymentRef)
}

func TestEchoScrubbed(t *testing.T) {
	e := startPaid(t, nil)
	resp := e.get(t, e.h.client(e.p.token), "/echo/", nil)
	eq(t, resp.Header.Get("Echo-Payment-Signature"), x402.PaymentScrubbed)
}

func TestParallelIdenticalRequests(t *testing.T) {
	e := startPaid(t, nil)
	c := e.h.client(e.p.token)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { eq(t, e.get(t, c, "/ok/", nil).StatusCode, 200) })
	}
	wg.Wait()
	eq(t, e.pay.Signings(), 2)
	eq(t, len(e.ledger.Transfers()), 2)
}

func TestPaidStreamIsNotHeldBack(t *testing.T) {
	e := startPaid(t, nil)
	fake := e.h.sell
	done := base64.StdEncoding.EncodeToString([]byte(`{"success":true}`))
	e.h.sell = func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/stream/") {
			fake(w, r)
			return
		}
		if r.Header.Get("Payment-Signature") == "" {
			r.URL.Path = "/ok/"
			fake(w, r)
			return
		}
		w.Header().Set("Payment-Response", done)
		w.WriteHeader(200)
		rc := http.NewResponseController(w)
		_, _ = io.WriteString(w, "one\n")
		_ = rc.Flush()
		time.Sleep(500 * time.Millisecond)
		_, _ = io.WriteString(w, "two\n")
	}
	resp := get0(t, e.h.client(e.p.token), "https://api.example/stream/")
	defer func() { _ = resp.Body.Close() }()
	rd := bufio.NewReader(resp.Body)
	start := time.Now()
	line, _ := rd.ReadString('\n')
	eq(t, line, "one\n")
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("the first event came after %v", d)
	}
	_, _ = io.Copy(io.Discard, rd)
	eq(t, len(e.pay.Reports()), 1)
	eq(t, e.pay.Reports()[0].Hint, paymentsv1.SellerHint_SELLER_HINT_SUCCESS)
}

func get0(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
