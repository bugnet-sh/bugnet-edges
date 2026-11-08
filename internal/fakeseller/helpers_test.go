package fakeseller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
	"github.com/bugnet-sh/bugnet-edges/internal/x402/x402test"
)

// eq fails the test when got and want differ
func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// The test addresses, base58 of 32 bytes each
var (
	payTo     = x402.Encode58(bytes.Repeat([]byte{1}, 32))
	feePayer  = x402.Encode58(bytes.Repeat([]byte{3}, 32))
	bugnetFee = x402.Encode58(bytes.Repeat([]byte{4}, 32))
)

// config is a seller paying payTo and settling in ledger, with every delay short
func config(ledger *Ledger) Config {
	return Config{
		PayTo: payTo, FeePayer: feePayer, BugnetFeePayer: bugnetFee, Settler: ledger,
		Late: 50 * time.Millisecond, Slow: 50 * time.Millisecond, Stall: 50 * time.Millisecond,
		Second: 10 * time.Millisecond, SSEEvery: 10 * time.Millisecond,
		SSEFor: 50 * time.Millisecond,
	}
}

// send serves one request to h and records the answer
func send(
	h http.Handler, method, target string, header http.Header, body string,
) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// paying is a header carrying one PAYMENT-SIGNATURE value
func paying(value string) http.Header {
	return http.Header{"Payment-Signature": {value}}
}

// required decodes a 402's PAYMENT-REQUIRED into its top object and its one accepts entry
func required(
	t *testing.T, w *httptest.ResponseRecorder,
) (map[string]json.RawMessage, json.RawMessage) {
	t.Helper()
	eq(t, w.Code, http.StatusPaymentRequired)
	values := w.Result().Header.Values("Payment-Required")
	eq(t, len(values), 1)
	raw, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	var accepts []json.RawMessage
	if err := json.Unmarshal(top["accepts"], &accepts); err != nil {
		t.Fatal(err)
	}
	eq(t, len(accepts), 1)
	eq(t, string(top["x402Version"]), "2")
	return top, accepts[0]
}

// fields decodes an accepts entry into its keys
func fields(t *testing.T, entry json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(entry, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// extra is an accepts entry's extra object
func extra(t *testing.T, entry json.RawMessage) map[string]any {
	t.Helper()
	m, _ := fields(t, entry)["extra"].(map[string]any)
	return m
}

// pay is x402test's fixed test payment for the entry of the 402 in w
func pay(t *testing.T, w *httptest.ResponseRecorder, ref string) string {
	t.Helper()
	_, entry := required(t, w)
	return x402test.PaymentSignature(entry, ref)
}

// paid asks for the 402 at target, then pays it with ref, answering the paid retry
func paid(
	t *testing.T, h http.Handler, target, ref string,
) (*httptest.ResponseRecorder, string) {
	t.Helper()
	value := pay(t, send(h, http.MethodGet, target, nil, ""), ref)
	return send(h, http.MethodGet, target, paying(value), ""), value
}

// settle decodes a PAYMENT-RESPONSE, nil when there is none
func settle(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	values := w.Result().Header.Values("Payment-Response")
	if len(values) == 0 {
		return nil
	}
	eq(t, len(values), 1)
	raw, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// probe settles in a Ledger, keeping each call's context error
type probe struct {
	ledger *Ledger
	// fail is answered in place of settling when not nil
	fail error

	mu   sync.Mutex
	errs []error
}

// Settle records the call, then fails or settles
func (p *probe) Settle(ctx context.Context, pm Payment) (string, error) {
	p.mu.Lock()
	p.errs = append(p.errs, ctx.Err())
	p.mu.Unlock()
	if p.fail != nil {
		return "", p.fail
	}
	return p.ledger.Settle(ctx, pm)
}

// calls lists each call's context error, in order
func (p *probe) calls() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]error{}, p.errs...)
}

// probed is a seller settling through p
func probed(p *probe) http.Handler {
	c := config(p.ledger)
	c.Settler = p
	return New(c)
}

// signatures lists the signatures a ledger answered, in order
func signatures(l *Ledger) []string {
	out := []string{}
	for _, tr := range l.Transfers() {
		out = append(out, tr.Signature)
	}
	return out
}

// within polls ok until it holds or 2 s pass
func within(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("the condition never held")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// step is one call a logWriter saw, at its time since the writer was made
type step struct {
	kind string
	at   time.Duration
	data string
}

// logWriter records each header, write and flush with its time
type logWriter struct {
	start  time.Time
	header http.Header

	mu    sync.Mutex
	steps []step
}

func newLogWriter() *logWriter {
	return &logWriter{start: time.Now(), header: http.Header{}}
}

func (w *logWriter) Header() http.Header { return w.header }

func (w *logWriter) WriteHeader(code int) {
	w.add("header", http.StatusText(code))
}

func (w *logWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	wrote := len(w.steps) > 0
	w.mu.Unlock()
	if !wrote {
		w.WriteHeader(http.StatusOK)
	}
	w.add("write", string(b))
	return len(b), nil
}

func (w *logWriter) Flush() { w.add("flush", "") }

func (w *logWriter) add(kind, data string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.steps = append(w.steps, step{kind: kind, at: time.Since(w.start), data: data})
}

func (w *logWriter) log() []step {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]step(nil), w.steps...)
}
