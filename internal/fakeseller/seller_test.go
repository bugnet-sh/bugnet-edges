package fakeseller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-edges/internal/x402"
	"github.com/oynozan/bugnet-edges/internal/x402/x402test"
)

func TestOkSettlesOnce(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	w, value := paid(t, h, "/ok/x", "r1")
	eq(t, w.Code, http.StatusOK)
	sum := sha512.Sum512([]byte("fake-r1"))
	sig := x402.Encode58(sum[:])
	eq(t, settle(t, w), map[string]any{
		"success": true, "transaction": sig, "network": x402.SolanaMainnet,
	})
	eq(t, signatures(ledger), []string{sig})
	eq(t, ledger.Transfers()[0].Accepted, x402.Entry{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint, PayTo: payTo,
		AmountMicros: 1000, AmountOK: true,
	})
	eq(t, ledger.Transfers()[0].Transaction, "fake-r1")

	again := send(h, http.MethodGet, "/ok/x", paying(value), "")
	required(t, again)
	eq(t, settle(t, again), map[string]any(nil))
	eq(t, len(ledger.Transfers()), 1)

	_, entry := required(t, first(h, "/ok/x"))
	other := bytes.Replace(entry, []byte(`"1000"`), []byte(`"999"`), 1)
	w = send(h, http.MethodGet, "/ok/x", paying(x402test.PaymentSignature(other, "r2")), "")
	required(t, w)
	w = send(h, http.MethodGet, "/cents/x", paying(x402test.PaymentSignature(entry, "r3")), "")
	required(t, w)
	eq(t, len(ledger.Transfers()), 1)
}

func TestRepeatedPayloadGetsA402(t *testing.T) {
	for _, target := range []string{"/ok/x", "/late/x", "/lie/x", "/slow/x", "/silent/x"} {
		t.Run(strings.Split(target, "/")[1], func(t *testing.T) {
			p := &probe{ledger: InMemory()}
			h := probed(p)
			w, value := paid(t, h, target, "r1")
			eq(t, w.Code, http.StatusOK)
			if target != "/lie/x" {
				within(t, func() bool { return len(p.calls()) == 1 })
			}
			calls := len(p.calls())
			again := send(h, http.MethodGet, target, paying(value), "")
			required(t, again)
			eq(t, settle(t, again), map[string]any(nil))
			if target == "/late/x" {
				time.Sleep(100 * time.Millisecond)
			}
			eq(t, len(p.calls()), calls)
		})
	}
}

func TestSettleOutlivesTheCaller(t *testing.T) {
	p := &probe{ledger: InMemory()}
	h := probed(p)
	value := pay(t, first(h, "/ok/x"), "r1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/ok/x", nil)
	r.Header.Set("Payment-Signature", value)
	h.ServeHTTP(httptest.NewRecorder(), r)
	eq(t, p.calls(), []error{nil})
	eq(t, len(p.ledger.Transfers()), 1)
}

func TestSwitchTakesAnEarlierPayTo(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	_, older := required(t, first(h, "/switch/x"))
	_, newer := required(t, first(h, "/switch/x"))
	w := send(h, http.MethodGet, "/switch/x", paying(x402test.PaymentSignature(older, "r1")), "")
	eq(t, w.Code, http.StatusOK)
	eq(t, settle(t, w)["success"], any(true))
	eq(t, ledger.Transfers()[0].Accepted.PayTo, fields(t, older)["payTo"].(string))

	for range maxOffered {
		required(t, first(h, "/switch/x"))
	}
	w = send(h, http.MethodGet, "/switch/x", paying(x402test.PaymentSignature(newer, "r2")), "")
	required(t, w)
	eq(t, len(ledger.Transfers()), 1)
}

func TestPaidAnswerCountsTheBody(t *testing.T) {
	h := New(config(InMemory()))
	value := pay(t, send(h, http.MethodPost, "/cent/x", nil, "abc"), "r1")
	w := send(h, http.MethodPost, "/cent/x", paying(value), "hello")
	eq(t, w.Code, http.StatusOK)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello"))
	eq(t, body, map[string]any{
		"mode": "cent", "body_bytes": float64(5), "body_sha256": hex.EncodeToString(sum[:]),
	})
}

func TestBadPaymentsGetA402(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	_, entry := required(t, first(h, "/ok/x"))
	v1 := base64.StdEncoding.EncodeToString([]byte(
		`{"x402Version":1,"accepted":` + string(entry) + `,"payload":{"transaction":"fake-a"}}`))
	oversized := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepted":` +
		string(entry) + `,"payload":{"transaction":"fake-big"},"pad":"` +
		strings.Repeat("a", maxPayload) + `"}`))
	for _, value := range []string{
		"", "%%%", base64.StdEncoding.EncodeToString([]byte(`[]`)), v1,
		base64.RawStdEncoding.EncodeToString([]byte(`{"x402Version":2}`)), oversized,
	} {
		required(t, send(h, http.MethodGet, "/ok/x", paying(value), ""))
	}
	twice := http.Header{"Payment-Signature": {
		x402test.PaymentSignature(entry, "b"), x402test.PaymentSignature(entry, "c"),
	}}
	required(t, send(h, http.MethodGet, "/ok/x", twice, ""))
	eq(t, len(ledger.Transfers()), 0)
}

// pidPayment is the fixed test payment with a payment-identifier id
func pidPayment(entry json.RawMessage, ref, id string) string {
	return base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepted":` +
		string(entry) + `,"payload":{"transaction":"fake-` + ref + `"},"extensions":` +
		`{"payment-identifier":{"info":{"required":false,"id":"` + id + `"}}}}`))
}

func TestPidAnswersFromCache(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	_, entry := required(t, first(h, "/pid/x"))
	id := "bn_0123456789abcdef0123456789abcdef"
	w := send(h, http.MethodGet, "/pid/x", paying(pidPayment(entry, "r1", id)), "")
	eq(t, w.Code, http.StatusOK)
	eq(t, settle(t, w)["success"], any(true))
	for _, value := range []string{pidPayment(entry, "r1", id), pidPayment(entry, "r2", id)} {
		again := send(h, http.MethodGet, "/pid/x", paying(value), "")
		eq(t, again.Code, http.StatusOK)
		eq(t, again.Header().Get("Payment-Response"), w.Header().Get("Payment-Response"))
		eq(t, again.Body.String(), w.Body.String())
	}
	eq(t, len(ledger.Transfers()), 1)

	plain := x402test.PaymentSignature(entry, "r3")
	w = send(h, http.MethodGet, "/pid/x", paying(plain), "")
	eq(t, w.Code, http.StatusOK)
	again := send(h, http.MethodGet, "/pid/x", paying(plain), "")
	eq(t, again.Code, http.StatusOK)
	eq(t, again.Header().Get("Payment-Response"), w.Header().Get("Payment-Response"))
	eq(t, len(ledger.Transfers()), 2)

	short := pidPayment(entry, "r4", "too-short")
	eq(t, send(h, http.MethodGet, "/pid/x", paying(short), "").Code, http.StatusOK)
	eq(t, send(h, http.MethodGet, "/pid/x", paying(short), "").Code, http.StatusOK)
	eq(t, len(ledger.Transfers()), 3)
}

func TestLieNeverSettles(t *testing.T) {
	ledger := InMemory()
	c := config(ledger)
	c.TestToken = "tok"
	h := New(c)
	w, _ := paid(t, h, "/lie/x", "r1")
	eq(t, w.Code, http.StatusOK)
	got := settle(t, w)
	eq(t, got["success"], any(true))
	sig, ok := x402.Decode58(got["transaction"].(string))
	eq(t, ok && len(sig) == 64, true)
	time.Sleep(100 * time.Millisecond)
	eq(t, len(ledger.Transfers()), 0)
	eq(t, testList(t, h, "/__test/settled"), []string{})
}

func TestSilentSettlesWithoutHeader(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	w, _ := paid(t, h, "/silent/x", "r1")
	eq(t, w.Code, http.StatusOK)
	eq(t, w.Result().Header.Values("Payment-Response"), []string(nil))
	eq(t, len(ledger.Transfers()), 1)
}

func TestSettleThen500And429(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	for target, status := range map[string]int{"/settle500/x": 500, "/settle429/x": 429} {
		w, _ := paid(t, h, target, target)
		eq(t, w.Code, status)
		eq(t, w.Header().Get("Retry-After"), "")
		got := settle(t, w)
		eq(t, got["success"], any(true))
		sigs := signatures(ledger)
		eq(t, got["transaction"], any(sigs[len(sigs)-1]))
	}
	eq(t, len(ledger.Transfers()), 2)
}

func TestWaitVariantsSetRetryAfter(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	for target, status := range map[string]int{
		"/settle500-wait/x": 500, "/settle429-wait/x": 429,
	} {
		w, _ := paid(t, h, target, target)
		eq(t, w.Code, status)
		eq(t, w.Header().Get("Retry-After"), "15")
		eq(t, settle(t, w)["success"], any(true))
	}
	eq(t, len(ledger.Transfers()), 2)
}

func TestRejectAnswers402(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	w, _ := paid(t, h, "/reject/x", "r1")
	_, entry := required(t, w)
	exact(t, entry, "10000")
	eq(t, len(ledger.Transfers()), 0)
}

func TestEchoEchoesHeaders(t *testing.T) {
	h := New(config(InMemory()))
	ask := http.Header{"X-Thing": {"a", "b"}}
	w := send(h, http.MethodGet, "/echo/x", ask, "")
	required(t, w)
	eq(t, w.Result().Header.Values("Echo-X-Thing"), []string{"a", "b"})

	value := pay(t, w, "r1")
	ask.Set("Payment-Signature", value)
	w = send(h, http.MethodGet, "/echo/x?q=1", ask, "")
	eq(t, w.Code, http.StatusOK)
	eq(t, settle(t, w)["success"], any(true))
	eq(t, w.Result().Header.Values("Echo-X-Thing"), []string{"a", "b"})
	eq(t, w.Header().Get("Echo-Payment-Signature"), value)
	var body struct {
		Method, Host, Target string
		Headers              map[string][]string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	eq(t, body.Method, http.MethodGet)
	eq(t, body.Host, "example.com")
	eq(t, body.Target, "/echo/x?q=1")
	eq(t, body.Headers["X-Thing"], []string{"a", "b"})
	sum := sha256.Sum256([]byte(value))
	eq(t, body.Headers["Payment-Signature"], []string{"sha256:" + hex.EncodeToString(sum[:])})
	eq(t, strings.Contains(w.Body.String(), value), false)
}

func TestRedirectOnPaidRetry(t *testing.T) {
	ledger := InMemory()
	c := config(ledger)
	c.RedirectTo = "https://other.example/landing"
	h := New(c)
	w := first(h, "/redirect/x")
	required(t, w)
	eq(t, w.Header().Get("Location"), "")
	w, _ = paid(t, h, "/redirect/x", "r1")
	eq(t, w.Code, http.StatusFound)
	eq(t, w.Header().Get("Location"), "https://other.example/landing")
	eq(t, settle(t, w)["success"], any(true))
	eq(t, len(ledger.Transfers()), 1)

	w, _ = paid(t, New(config(InMemory())), "/redirect/x", "r1")
	eq(t, w.Header().Get("Location"), "https://example.com/")
}

func TestDelaysAreOptions(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	start := time.Now()
	required(t, first(h, "/stall/x"))
	if d := time.Since(start); d < 50*time.Millisecond || d > time.Second {
		t.Fatalf("/stall/ held the first send %v, want about 50ms", d)
	}
	value := pay(t, first(h, "/stall/x"), "s1")
	w := send(h, http.MethodGet, "/stall/x", paying(value), "")
	eq(t, w.Code, http.StatusOK)

	value = pay(t, first(h, "/late/x"), "l1")
	start = time.Now()
	w = send(h, http.MethodGet, "/late/x", paying(value), "")
	eq(t, w.Code, http.StatusOK)
	got := settle(t, w)
	eq(t, got["success"], any(false))
	eq(t, got["errorReason"], any("settle_exact_svm_transaction_confirmation_timed_out"))
	eq(t, len(ledger.Transfers()), 1)
	within(t, func() bool { return len(ledger.Transfers()) == 2 })
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("/late/ settled after %v, want at least 50ms", d)
	}
	eq(t, ledger.Transfers()[1].Transaction, "fake-l1")
}

func TestSlowSettlesEvenWhenTheCallerLeft(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	value := pay(t, first(h, "/slow/x"), "w1")
	start := time.Now()
	w := send(h, http.MethodGet, "/slow/x", paying(value), "")
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("/slow/ answered after %v, want at least 50ms", d)
	}
	eq(t, w.Code, http.StatusOK)
	eq(t, settle(t, w)["transaction"], any(signatures(ledger)[0]))

	value = pay(t, first(h, "/slow/x"), "w2")
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/slow/x", nil)
	r.Header.Set("Payment-Signature", value)
	lw := newLogWriter()
	cancel()
	h.ServeHTTP(lw, r)
	eq(t, len(lw.log()), 0)
	eq(t, len(ledger.Transfers()), 1)
	within(t, func() bool { return len(ledger.Transfers()) == 2 })
}

func TestHoldAnswersAfterItsSeconds(t *testing.T) {
	h := New(config(InMemory()))
	w := newLogWriter()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/hold/3/", nil))
	log := w.log()
	if len(log) == 0 || log[0].kind != "header" || log[0].data != "OK" {
		t.Fatalf("/hold/3/ wrote %+v, want a 200", log)
	}
	if log[0].at < 30*time.Millisecond || log[0].at > time.Second {
		t.Fatalf("/hold/3/ wrote its first byte after %v, want about 30ms", log[0].at)
	}
	for _, target := range []string{"/hold/0/", "/hold/301/"} {
		eq(t, first(h, target).Code, http.StatusNotFound)
	}
}

func TestSSEFlushesEachEvent(t *testing.T) {
	h := New(config(InMemory()))
	w := newLogWriter()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sse/", nil))
	log := w.log()
	eq(t, w.Header().Get("Content-Type"), "text/event-stream")
	if len(log) < 2 || log[0].kind != "header" || log[1].kind != "flush" {
		t.Fatalf("/sse/ began with %+v, want its header flushed at once", log)
	}
	events := log[2:]
	eq(t, len(events), 10)
	for i := 0; i < len(events); i += 2 {
		eq(t, events[i].kind, "write")
		eq(t, events[i].data, "data: "+string(rune('1'+i/2))+"\n\n")
		eq(t, events[i+1].kind, "flush")
	}
	if last := events[len(events)-1].at; last < 50*time.Millisecond {
		t.Fatalf("/sse/ ended after %v, want SSEFor", last)
	}
}

func TestSSEStopsWhenTheCallerLeaves(t *testing.T) {
	h := New(config(InMemory()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := newLogWriter()
	h.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/sse/", nil))
	eq(t, len(w.log()), 2)
}

func TestEarly402BeforeTheBody(t *testing.T) {
	srv := httptest.NewServer(New(config(InMemory())))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pr, pw := io.Pipe()
	defer func() { _ = pr.CloseWithError(io.ErrClosedPipe) }()
	go func() {
		// One chunk, then the body neither grows nor ends
		if _, err := pw.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
			return
		}
		<-ctx.Done()
		_ = pw.CloseWithError(ctx.Err())
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/cent/x", pr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("no 402 before the body ended: %v", err)
	}
	eq(t, res.StatusCode, http.StatusPaymentRequired)
	eq(t, len(res.Header.Values("Payment-Required")), 1)
	cancel()
	_ = res.Body.Close()
}

func TestInMemoryTakesOnlyTheTestFormat(t *testing.T) {
	ledger := InMemory()
	entry := json.RawMessage(`{"scheme":"exact","network":"` + x402.SolanaMainnet +
		`","asset":"` + x402.USDCMint + `","amount":"1000","payTo":"` + payTo + `"}`)
	want := x402.Entry{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint, PayTo: payTo,
		AmountMicros: 1000, AmountOK: true,
	}
	ctx := context.Background()
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for name, p := range map[string]Payment{
		"other entry": {Value: x402test.PaymentSignature(entry, "a"), Accepted: x402.Entry{}},
		"not base64":  {Value: "%%%", Accepted: want},
		"no fake": {Value: b64(`{"x402Version":2,"accepted":` + string(entry) +
			`,"payload":{"transaction":"AQID"}}`), Accepted: want},
		"version 1": {Value: b64(`{"x402Version":1,"accepted":` + string(entry) +
			`,"payload":{"transaction":"fake-a"}}`), Accepted: want},
	} {
		if _, err := ledger.Settle(ctx, p); err == nil {
			t.Errorf("%s settled", name)
		}
	}
	sig, err := ledger.Settle(ctx, Payment{Value: x402test.PaymentSignature(entry, "a"),
		Accepted: want})
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := x402.Decode58(sig)
	eq(t, ok, true)
	sum := sha512.Sum512([]byte("fake-a"))
	eq(t, raw, sum[:])
	_, err = ledger.Settle(ctx, Payment{Value: x402test.PaymentSignature(entry, "a"),
		Accepted: want})
	if err == nil {
		t.Fatal("one transaction settled twice")
	}
	eq(t, len(ledger.Transfers()), 1)
}

func TestKeptForgetsTheOldest(t *testing.T) {
	k := newKept[string, int](2)
	k.put("a", 1)
	k.put("b", 2)
	k.put("a", 3)
	v, ok := k.get("a")
	eq(t, v, 3)
	eq(t, ok, true)
	k.put("c", 4)
	_, ok = k.get("a")
	eq(t, ok, false)
	for key, want := range map[string]int{"b": 2, "c": 4} {
		v, ok = k.get(key)
		eq(t, v, want)
		eq(t, ok, true)
	}
	eq(t, len(k.m), 2)
}

func TestSellerKeepsAtMostItsLimit(t *testing.T) {
	ledger := InMemory()
	c := config(ledger)
	c.TestToken = "tok"
	s := newSeller(c, 3)
	_, entry := required(t, first(s, "/ok/x"))
	_, pidEntry := required(t, first(s, "/pid/x"))
	values := []string{}
	for i := range 5 {
		ref := "r" + strconv.Itoa(i)
		value := x402test.PaymentSignature(entry, ref)
		values = append(values, value)
		eq(t, send(s, http.MethodGet, "/ok/x", paying(value), "").Code, http.StatusOK)
		id := "bn_" + strings.Repeat(strconv.Itoa(i), 16)
		w := send(s, http.MethodGet, "/pid/x", paying(pidPayment(pidEntry, "p"+ref, id)), "")
		eq(t, w.Code, http.StatusOK)
	}
	eq(t, len(testList(t, s, "/__test/payloads")), 3)
	eq(t, testList(t, s, "/__test/settled"), signatures(ledger)[7:])
	eq(t, len(s.seen.m), 3)
	eq(t, len(s.cached.m), 3)
	eq(t, slices.Contains(testList(t, s, "/__test/payloads"), values[0]), false)
}
