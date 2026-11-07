package fakeseller

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oynozan/bugnet-edges/internal/x402"
)

// update rewrites the facilitator goldens from what the test posts
var update = flag.Bool("update", false, "rewrite testdata's facilitator goldens")

// facilitatorCall is one request a fake facilitator received
type facilitatorCall struct {
	path, contentType string
	body              []byte
}

// fakeFacilitator is a fake x402 facilitator answering fixed bodies and recording each call
type fakeFacilitator struct {
	*httptest.Server

	mu    sync.Mutex
	calls []facilitatorCall
	// answers holds each path's status and body
	answers map[string]facilitatorAnswer
}

// facilitatorAnswer is what a fake facilitator answers on one path
type facilitatorAnswer struct {
	status int
	body   string
}

// newFacilitator starts a fake that answers verify valid and settle with sig
func newFacilitator(t *testing.T, sig string) *fakeFacilitator {
	f := &fakeFacilitator{answers: map[string]facilitatorAnswer{
		"/verify": {http.StatusOK, `{"isValid":true,"payer":"x"}`},
		"/settle": {http.StatusOK, `{"success":true,"transaction":"` + sig +
			`","network":"` + x402.SolanaMainnet + `","payer":"x"}`},
	}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, facilitatorCall{
			path: r.URL.Path, contentType: r.Header.Get("Content-Type"), body: body,
		})
		a, ok := f.answers[r.URL.Path]
		f.mu.Unlock()
		if !ok || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}))
	t.Cleanup(f.Close)
	return f
}

// answer sets what path answers
func (f *fakeFacilitator) answer(path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[path] = facilitatorAnswer{status, body}
}

// list is every call received, in order
func (f *fakeFacilitator) list() []facilitatorCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// paths lists the paths called, in order
func (f *fakeFacilitator) paths() []string {
	out := []string{}
	for _, c := range f.list() {
		out = append(out, c.path)
	}
	return out
}

// settledSig is a made-up 64-byte transaction signature in base58
var settledSig = func() string {
	sum := sha512.Sum512([]byte("fakeseller test settled"))
	return x402.Encode58(sum[:])
}()

// decodeJSON decodes raw JSON into a generic value
func decodeJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// golden compares a JSON body with a testdata file, rewriting the file with -update
func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		var b bytes.Buffer
		if err := json.Indent(&b, got, "", "    "); err != nil {
			t.Fatal(err)
		}
		b.WriteByte('\n')
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, decodeJSON(t, got), decodeJSON(t, want))
}

// facilitatorSeller is the fixture's seller settling through the facilitator at url
func facilitatorSeller(f fixture, url string) http.Handler {
	return New(Config{
		PayTo: f.PayTo, FeePayer: f.FeePayer, BugnetFeePayer: bugnetFee,
		Settler: Facilitator(url), Slow: 10 * time.Millisecond,
	})
}

func TestFacilitatorOrder(t *testing.T) {
	f := paymentsFixture(t)
	wire, err := base64.StdEncoding.DecodeString(f.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	fac := newFacilitator(t, settledSig)
	h := facilitatorSeller(f, fac.URL)
	target := "https://seller.test/ok/x"
	first := send(h, http.MethodGet, target, nil, "")
	_, entry := required(t, first)
	value := payment(t, first, wire)
	w := send(h, http.MethodGet, target, paying(value), "")
	eq(t, w.Code, http.StatusOK)
	eq[any](t, settle(t, w)["transaction"], settledSig)
	eq(t, fac.paths(), []string{"/verify", "/settle"})
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fac.list() {
		eq(t, c.contentType, "application/json")
		var body struct {
			Version      json.RawMessage `json:"x402Version"`
			Payload      json.RawMessage `json:"paymentPayload"`
			Requirements json.RawMessage `json:"paymentRequirements"`
		}
		if err := json.Unmarshal(c.body, &body); err != nil {
			t.Fatal(err)
		}
		eq(t, string(body.Version), "2")
		eq(t, decodeJSON(t, body.Payload), decodeJSON(t, raw))
		eq(t, decodeJSON(t, body.Requirements), decodeJSON(t, entry))
	}
	calls := fac.list()
	golden(t, "testdata/facilitator-verify.json", calls[0].body)
	golden(t, "testdata/facilitator-settle.json", calls[1].body)

	lie := payment(t, send(h, http.MethodGet, "https://seller.test/lie/x", nil, ""), wire)
	w = send(h, http.MethodGet, "https://seller.test/lie/x", paying(lie), "")
	eq(t, w.Code, http.StatusOK)
	eq(t, settle(t, w)["success"], true)
	eq(t, len(fac.list()), 2)
}

func TestFacilitatorRefusals(t *testing.T) {
	f := paymentsFixture(t)
	wire, err := base64.StdEncoding.DecodeString(f.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	invalid := `{"isValid":false,"invalidReason":"invalid_exact_svm_payload_amount_mismatch"}`
	failed := `{"success":false,"errorReason":"invalid_exact_svm_transaction_failed",` +
		`"transaction":"","network":"` + x402.SolanaMainnet + `"}`
	cases := []struct {
		name, path, body string
		status           int
		paths            []string
		reason           string
	}{
		{"invalid", "/verify", invalid, http.StatusOK, []string{"/verify"},
			"invalid_exact_svm_payload_amount_mismatch"},
		{"invalid as 400", "/verify", invalid, http.StatusBadRequest, []string{"/verify"},
			"invalid_exact_svm_payload_amount_mismatch"},
		{"verify error", "/verify", `{"error":"boom"}`, http.StatusInternalServerError,
			[]string{"/verify"}, unexpectedReason},
		{"settle failed", "/settle", failed, http.StatusBadRequest,
			[]string{"/verify", "/settle"}, "invalid_exact_svm_transaction_failed"},
		{"settle no signature", "/settle", `{"success":true,"transaction":"abc"}`,
			http.StatusOK, []string{"/verify", "/settle"}, unexpectedReason},
		{"settle not json", "/settle", "<html>", http.StatusBadGateway,
			[]string{"/verify", "/settle"}, unexpectedReason},
	}
	for _, c := range cases {
		fac := newFacilitator(t, settledSig)
		fac.answer(c.path, c.status, c.body)
		h := facilitatorSeller(f, fac.URL)
		value := payment(t, send(h, http.MethodGet, "https://seller.test/ok/x", nil, ""), wire)
		w := send(h, http.MethodGet, "https://seller.test/ok/x", paying(value), "")
		if w.Code != http.StatusPaymentRequired {
			t.Errorf("%s: status %d", c.name, w.Code)
		}
		eq(t, fac.paths(), c.paths)
		slow := payment(t, send(h, http.MethodGet, "https://seller.test/slow/x", nil, ""), wire)
		w = send(h, http.MethodGet, "https://seller.test/slow/x", paying(slow), "")
		eq(t, w.Code, http.StatusOK)
		s := settle(t, w)
		if s["success"] != false || s["errorReason"] != c.reason {
			t.Errorf("%s: PAYMENT-RESPONSE %v", c.name, s)
		}
	}
}
