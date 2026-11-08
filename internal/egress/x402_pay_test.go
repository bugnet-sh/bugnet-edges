package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
	"github.com/bugnet-sh/bugnet-edges/internal/x402/x402test"
)

// payEnv is an x402 proxy whose signer talks to a fake Payments over mutual TLS
type payEnv struct {
	*xenv
	pay     *x402test.Payments
	release chan struct{}
}

// paySeller answers 402 on /post/ paths as an x402 seller does, without reading the body
func (e *payEnv) paySeller(w http.ResponseWriter, r *http.Request) {
	req := paymentRequired(10000)
	switch {
	case strings.HasPrefix(r.RequestURI, "/post/bait"):
		req = paymentRequired(20000)
	case strings.HasPrefix(r.RequestURI, "/post/base"):
		req = x402.EncodeRequired(x402.Required{Version: 2, Accepts: []x402.Entry{{
			Scheme: "exact", Network: "eip155:8453", Asset: "0xusdc", PayTo: "0xabc",
			AmountMicros: 10000, AmountOK: true,
		}}}, "https://api.example/post/base", nil)
	case strings.HasPrefix(r.RequestURI, "/post/stall"):
		select {
		case <-e.release:
		case <-r.Context().Done():
		}
	case strings.HasPrefix(r.RequestURI, "/post/late"):
		time.Sleep(300 * time.Millisecond)
	}
	w.Header().Set("Payment-Required", req)
	w.Header().Set("X-Seller-Secret", "seller-only")
	w.WriteHeader(http.StatusPaymentRequired)
}

func startPay(
	t *testing.T, mod func(*routerv1.X402Config), tune func(*x402.Settings),
) *payEnv {
	t.Helper()
	ca := x402test.NewCA(t)
	dir := t.TempDir()
	ca.WriteDev(t, dir)
	fake := x402test.StartPayments(t, ca)
	e := &payEnv{pay: fake, release: make(chan struct{})}
	t.Cleanup(func() { close(e.release) })
	e.xenv = startX402(t, mod, func(cfg *Config, d *Deps) {
		st := cfg.X402
		st.PaymentsURL = fake.URL
		st.PaymentsCAFile = dir + "/" + x402test.CAFile
		st.PaymentsClientCertFile = dir + "/" + x402test.ClientCertFile
		st.PaymentsTimeout = settings.Duration(2 * time.Second)
		if tune != nil {
			tune(&st)
		}
		cfg.X402 = st
		sg, err := x402.NewSigner(st, dir, nil, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		d.Signer = sg
	})
	e.h.sell = e.paySeller
	return e
}

func refusal402(reason string, left int64) *paymentsv1.ReserveAndSignResponse {
	rf := &paymentsv1.Refused{Reason: reason, AllowanceLeftMicros: left}
	return &paymentsv1.ReserveAndSignResponse{
		Result: &paymentsv1.ReserveAndSignResponse_Refused{Refused: rf},
	}
}

func (e *payEnv) post(t *testing.T, c *http.Client, path string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://api.example"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func (e *payEnv) neverSigned(t *testing.T) {
	t.Helper()
	e.h.mu.Lock()
	defer e.h.mu.Unlock()
	for _, r := range e.h.seen {
		if r.Header.Get("Payment-Signature") != "" {
			t.Fatal("the seller saw a PAYMENT-SIGNATURE")
		}
	}
}

func TestPayableAsksPaymentsWithTheRequest(t *testing.T) {
	e := startPay(t, nil, nil)
	e.pay.OnReserve(func(_ context.Context, _ *paymentsv1.ReserveAndSignRequest) (
		*paymentsv1.ReserveAndSignResponse, error,
	) {
		return refusal402("allowance_spent", 2500), nil
	})
	c := e.h.client(e.p.token)
	resp := e.post(t, c, "/post/x?a=1", strings.NewReader("hello"))
	eq(t, resp.StatusCode, 402)
	eq(t, resp.Header.Get(x402.HeaderError), "allowance_spent")
	eq(t, resp.Header.Get("Payment-Required"), paymentRequired(10000))
	eq(t, resp.Header.Get("X-Seller-Secret"), "")
	rs := e.pay.Reserves()
	eq(t, len(rs), 1)
	r := rs[0]
	sum := sha256.Sum256([]byte("hello"))
	eq(t, r.AccountId, "order-1")
	eq(t, r.ServiceId, "xs_post")
	eq(t, r.Method, "POST")
	eq(t, r.Host, "api.example")
	eq(t, r.Path, "/post/x")
	eq(t, r.BodySha256, sum[:])
	eq(t, r.PaymentRequired, paymentRequired(10000))
	eq(t, r.PlacementId, e.p.id.String())
	eq(t, r.TargetSha256, x402.TargetSHA256(e.p.id.String(), "/post/x?a=1"))
	eq(t, regexp.MustCompile(`^[a-z2-7]{16}$`).MatchString(r.Ref), true)
	e.neverSigned(t)
	e.stopEv()
	ev := e.h.router.x402Events[0]
	eq(t, ev.Ref, r.Ref)
	eq(t, ev.Status, x402.EventRefusedCap)
	eq(t, ev.AllowanceLeftMicros, int64(2500))
	eq(t, e.h.router.x402Events[0].AskedMicros, int64(10000))
}

func TestPaymentsRefusalsKeepTheirStatus(t *testing.T) {
	e := startPay(t, nil, nil)
	reasons := map[string]struct {
		status int
		retry  string
	}{
		"allowance_spent": {402, ""}, "rate_cap": {429, ""}, "too_many_open_payments": {429, "2"},
		"payments_unavailable": {503, "5"},
	}
	var reason string
	e.pay.OnReserve(func(_ context.Context, _ *paymentsv1.ReserveAndSignRequest) (
		*paymentsv1.ReserveAndSignResponse, error,
	) {
		return refusal402(reason, 500000), nil
	})
	c := e.h.client(e.p.token)
	for reason = range reasons {
		resp := e.post(t, c, "/post/x", nil)
		want := reasons[reason]
		eq(t, resp.StatusCode, want.status)
		eq(t, resp.Header.Get(x402.HeaderError), reason)
		if want.retry != "" {
			eq(t, resp.Header.Get("Retry-After"), want.retry)
		}
		eq(t, resp.Header.Get("Payment-Required"), paymentRequired(10000))
	}
	e.neverSigned(t)
}

func TestEarly402BeforeTheBodyIsRead(t *testing.T) {
	e := startPay(t, nil, nil)
	body := bytes.Repeat([]byte("0123456789abcdef"), 32<<10)
	for _, protos := range [][]string{{"http/1.1"}, {"h2", "http/1.1"}} {
		c := e.h.client(e.p.token, protos...)
		pr, pw := io.Pipe()
		go func() {
			for i := range 4 {
				_, _ = pw.Write(body[i*len(body)/4 : (i+1)*len(body)/4])
				time.Sleep(75 * time.Millisecond)
			}
			_ = pw.Close()
		}()
		resp := e.post(t, c, "/post/early", pr)
		eq(t, resp.StatusCode, 503)
		eq(t, resp.Header.Get(x402.HeaderError), "payments_unavailable")
	}
	sum := sha256.Sum256(body)
	rs := e.pay.Reserves()
	eq(t, len(rs), 2)
	for _, r := range rs {
		eq(t, r.BodySha256, sum[:])
	}
}

func TestPaidPathIgnoresTheQuery(t *testing.T) {
	e := startPay(t, func(c *routerv1.X402Config) {
		c.Services = append(c.Services, &routerv1.X402Service{
			ServiceId: "xs_search", Host: "api.example", Prefix: "/search/", Method: "GET",
			MaxPriceMicros: 10000, PayTo: sellerPin, PaidPath: "/search",
		})
	}, nil)
	e.h.sell = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Payment-Required", paymentRequired(10000))
		w.WriteHeader(http.StatusPaymentRequired)
	}
	c := e.h.client(e.p.token)
	eq(t, e.get(t, c, "/search?q=weather%20in%20Paris", nil).Header.Get(x402.HeaderError),
		"payments_unavailable")
	e.get(t, c, "/search?q=rome", nil)
	eq(t, e.get(t, c, "/search/other", nil).Header.Get(x402.HeaderError), "path_not_paid")
	rs := e.pay.Reserves()
	eq(t, len(rs), 2)
	eq(t, rs[0].Path, "/search")
	eq(t, rs[1].Path, "/search")
	eq(t, bytes.Equal(rs[0].TargetSha256, rs[1].TargetSha256), false)
}

func TestPrecheckRefusalsMakeNoCall(t *testing.T) {
	e := startPay(t, nil, nil)
	c := e.h.client(e.p.token)
	eq(t, e.post(t, c, "/post/bait", nil).Header.Get(x402.HeaderError), "price_above_max")
	eq(t, e.post(t, c, "/post/base", nil).Header.Get(x402.HeaderError), "network_unsupported")
	eq(t, len(e.pay.Reserves()), 0)
	var out strings.Builder
	_, _ = e.h.server.reg.WriteTo(&out)
	eq(t, strings.Contains(out.String(),
		`egress_x402_network_unsupported_total{namespace="eip155"} 1`), true)
}

func TestBufferBusyAndTooLarge(t *testing.T) {
	e := startPay(t, nil, func(s *x402.Settings) {
		s.ReplayBodyMax, s.BufferPerPlacement, s.BufferBudget = 1024, 4096, 1<<20
	})
	c := e.h.client(e.p.token)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.post(t, c, "/post/stall", bytes.NewReader(make([]byte, 1024)))
		}()
	}
	within(t, "four held slots", func() bool {
		return e.h.server.buffers.Held(e.p.id.String()) == 4096
	})
	resp := e.post(t, c, "/post/x", bytes.NewReader(make([]byte, 1024)))
	eq(t, resp.StatusCode, 503)
	eq(t, resp.Header.Get(x402.HeaderError), "buffer_busy")
	eq(t, resp.Header.Get("Retry-After"), "2")
	e.release <- struct{}{}
	e.release <- struct{}{}
	e.release <- struct{}{}
	e.release <- struct{}{}
	wg.Wait()
	eq(t, e.h.server.buffers.Held(e.p.id.String()), int64(0))
	asked := len(e.pay.Reserves())
	resp = e.post(t, c, "/post/x", bytes.NewReader(make([]byte, 2048)))
	eq(t, resp.Header.Get(x402.HeaderError), "body_too_large")
	eq(t, len(e.pay.Reserves()), asked)
}

func TestFirstAnswerSlowFreesTheSlot(t *testing.T) {
	e := startPay(t, nil, func(s *x402.Settings) {
		s.FirstHeaderTimeout = settings.Duration(100 * time.Millisecond)
	})
	c := e.h.client(e.p.token)
	resp := e.post(t, c, "/post/late", strings.NewReader("x"))
	eq(t, resp.Header.Get(x402.HeaderError), "first_answer_slow")
	eq(t, e.h.server.buffers.Held(e.p.id.String()), int64(0))
	eq(t, len(e.pay.Reserves()), 0)
}

func TestPaymentsTimeoutIs503(t *testing.T) {
	e := startPay(t, nil, func(s *x402.Settings) {
		s.PaymentsTimeout = settings.Duration(300 * time.Millisecond)
	})
	e.pay.Delay(400 * time.Millisecond)
	c := e.h.client(e.p.token)
	resp := e.post(t, c, "/post/x", nil)
	eq(t, resp.StatusCode, 503)
	eq(t, resp.Header.Get(x402.HeaderError), "payments_unavailable")
	eq(t, resp.Header.Get("Retry-After"), "5")
	e.neverSigned(t)
}

func TestTooManyOpenPaymentsIs429(t *testing.T) {
	e := startPay(t, nil, func(s *x402.Settings) { s.MaxOpenSignedPerPlacement = 2 })
	e.pay.Hold()
	c := e.h.client(e.p.token)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.post(t, c, "/post/x", nil)
		}()
	}
	within(t, "two open payments", func() bool { return len(e.pay.Reserves()) == 2 })
	resp := e.post(t, c, "/post/x", nil)
	eq(t, resp.StatusCode, 429)
	eq(t, resp.Header.Get(x402.HeaderError), "too_many_open_payments")
	eq(t, resp.Header.Get("Retry-After"), "2")
	eq(t, len(e.pay.Reserves()), 2)
	e.pay.Release()
	wg.Wait()
}
