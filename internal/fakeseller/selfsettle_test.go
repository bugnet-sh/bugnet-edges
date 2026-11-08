package fakeseller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// rpcCall is one JSON-RPC request a chain received
type rpcCall struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// chain is a fake Solana JSON-RPC answering sendTransaction with the first signature
type chain struct {
	*httptest.Server

	mu    sync.Mutex
	calls []rpcCall
	// fail answers every call with a JSON-RPC error
	fail bool
	// lie answers every call with another signature
	lie bool
}

// newChain starts a chain that closes when the test ends
func newChain(t *testing.T) *chain {
	c := &chain{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call rpcCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.calls = append(c.calls, call)
		fail, lie := c.fail, c.lie
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fail {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32002,` +
				`"message":"Transaction simulation failed: Blockhash not found"}}`))
			return
		}
		var b64 string
		_ = json.Unmarshal(call.Params[0], &b64)
		wire, _ := base64.StdEncoding.DecodeString(b64)
		sig := ""
		if len(wire) > 65 {
			sig = x402.Encode58(wire[1:65])
		}
		if lie {
			sig = settledSig
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": sig})
	}))
	t.Cleanup(c.Close)
	return c
}

// setFail makes every later call fail, or succeed again
func (c *chain) setFail(fail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = fail
}

// setLie makes every later call answer another signature, or its own again
func (c *chain) setLie(lie bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lie = lie
}

// list is every call received, in order
func (c *chain) list() []rpcCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// payment is a PAYMENT-SIGNATURE value paying the 402 in w with wire, as Payments writes one
func payment(t *testing.T, w *httptest.ResponseRecorder, wire []byte) string {
	t.Helper()
	top, entry := required(t, w)
	tx, err := json.Marshal(base64.StdEncoding.EncodeToString(wire))
	if err != nil {
		t.Fatal(err)
	}
	b := `{"x402Version":2,"resource":` + string(top["resource"]) + `,"accepted":` +
		string(entry) + `,"payload":{"transaction":` + string(tx) + `}}`
	return base64.StdEncoding.EncodeToString([]byte(b))
}

// selfSeller is a seller paid to dest, settling to the chain at url
func selfSeller(url string, dest []byte) http.Handler {
	return New(Config{
		PayTo: x402.Encode58(pub(payToKey)), FeePayer: x402.Encode58(pub(feeKey)),
		BugnetFeePayer: bugnetFee, Settler: SelfSettle(url, feeKey, x402.Encode58(dest)),
		Slow: 10 * time.Millisecond,
	})
}

// offByOne is key with its last byte one higher
func offByOne(key []byte) []byte {
	out := slices.Clone(key)
	out[len(out)-1]++
	return out
}

func TestSelfSettleCoSignsAndSends(t *testing.T) {
	dest := made("destination")
	for _, legacy := range []bool{true, false} {
		c := newChain(t)
		h := selfSeller(c.URL, dest)
		target := "https://seller.test/ok/x"
		value := payment(t, send(h, http.MethodGet, target, nil, ""),
			usdcTransfer(legacy, dest, 1_000))
		w := send(h, http.MethodGet, target, paying(value), "")
		eq(t, w.Code, http.StatusOK)
		calls := c.list()
		eq(t, len(calls), 1)
		eq(t, calls[0].Method, "sendTransaction")
		eq(t, len(calls[0].Params), 2)
		eq(t, string(calls[0].Params[1]), `{"encoding":"base64"}`)
		var b64 string
		if err := json.Unmarshal(calls[0].Params[0], &b64); err != nil {
			t.Fatal(err)
		}
		wire, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := parseTx(wire)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, tx.signedBy(0), true)
		eq(t, tx.signedBy(1), true)
		s := settle(t, w)
		eq(t, s["success"], true)
		eq[any](t, s["transaction"], x402.Encode58(wire[1:65]))
	}
}

func TestSelfSettleRefusesAWrongTransfer(t *testing.T) {
	dest := made("destination")
	usdc := key58(x402.USDCMint)
	authority := pub(allowanceKey)
	twice := transferIxs(authority, made("source"), dest, usdc, 1_000, 6)
	twice = append(twice, twice[2])
	cases := map[string][]byte{
		"amount below": usdcTransfer(false, dest, 999),
		"amount above": usdcTransfer(false, dest, 1_001),
		"destination":  usdcTransfer(false, offByOne(dest), 1_000),
		"mint": build(false, pub(feeKey),
			transferIxs(authority, made("source"), dest, offByOne(usdc), 1_000, 6),
			allowanceKey),
		"two transfers": build(false, pub(feeKey), twice, allowanceKey),
	}
	for name, wire := range cases {
		c := newChain(t)
		h := selfSeller(c.URL, dest)
		target := "https://seller.test/ok/x"
		value := payment(t, send(h, http.MethodGet, target, nil, ""), wire)
		w := send(h, http.MethodGet, target, paying(value), "")
		if w.Code != http.StatusPaymentRequired || len(c.list()) != 0 {
			t.Errorf("%s: status %d after %d sends", name, w.Code, len(c.list()))
		}
	}
}

func TestSelfSettleOncePerTransaction(t *testing.T) {
	dest := made("destination")
	c := newChain(t)
	h := selfSeller(c.URL, dest)
	wire := usdcTransfer(false, dest, 1_000)
	first := payment(t, send(h, http.MethodGet, "https://seller.test/ok/a", nil, ""), wire)
	second := payment(t, send(h, http.MethodGet, "https://seller.test/ok/b", nil, ""), wire)
	eq(t, first == second, false)
	eq(t, send(h, http.MethodGet, "https://seller.test/ok/a", paying(first), "").Code,
		http.StatusOK)
	eq(t, send(h, http.MethodGet, "https://seller.test/ok/b", paying(second), "").Code,
		http.StatusPaymentRequired)
	eq(t, len(c.list()), 1)
}

func TestSelfSettleChainErrorFreesTheTransaction(t *testing.T) {
	dest := made("destination")
	c := newChain(t)
	c.setFail(true)
	h := selfSeller(c.URL, dest)
	wire := usdcTransfer(false, dest, priceDefault)
	first := payment(t, send(h, http.MethodGet, "https://seller.test/slow/a", nil, ""), wire)
	w := send(h, http.MethodGet, "https://seller.test/slow/a", paying(first), "")
	eq(t, w.Code, http.StatusOK)
	s := settle(t, w)
	eq(t, s["success"], false)
	eq(t, s["errorReason"], reasonTransactionFailed)
	c.setFail(false)
	second := payment(t, send(h, http.MethodGet, "https://seller.test/slow/b", nil, ""), wire)
	w = send(h, http.MethodGet, "https://seller.test/slow/b", paying(second), "")
	eq(t, settle(t, w)["success"], true)
	eq(t, len(c.list()), 2)
}

// carrying is a PAYMENT-SIGNATURE value holding wire and an accepted entry, all a settler reads
func carrying(t *testing.T, wire []byte) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"accepted": map[string]string{"scheme": "exact"},
		"payload":  map[string]string{"transaction": base64.StdEncoding.EncodeToString(wire)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// usdcEntry is the entry usdcTransfer pays with amount 1,000
var usdcEntry = x402.Entry{
	Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint,
	AmountMicros: 1_000, AmountOK: true,
}

func TestSelfSettleWantsItsOwnSignature(t *testing.T) {
	dest := made("destination")
	c := newChain(t)
	c.setLie(true)
	s := SelfSettle(c.URL, feeKey, x402.Encode58(dest))
	p := Payment{Value: carrying(t, usdcTransfer(false, dest, 1_000)), Accepted: usdcEntry}
	_, err := s.Settle(context.Background(), p)
	var se *SettleError
	if err == nil || errors.As(err, &se) {
		t.Fatalf("another signature settled: %v", err)
	}
	c.setLie(false)
	sig, err := s.Settle(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, sig == settledSig, false)
	eq(t, len(c.list()), 2)
}

// redirecting is a server sending every request on to the same path at to
func redirecting(t *testing.T, to string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSettlersFollowNoRedirect(t *testing.T) {
	dest := made("destination")
	c := newChain(t)
	fac := newFacilitator(t, settledSig)
	settlers := map[string]Settler{
		"self":        SelfSettle(redirecting(t, c.URL), feeKey, x402.Encode58(dest)),
		"facilitator": Facilitator(redirecting(t, fac.URL)),
	}
	for name, s := range settlers {
		p := Payment{Value: carrying(t, usdcTransfer(false, dest, 1_000)), Accepted: usdcEntry}
		if _, err := s.Settle(context.Background(), p); err == nil {
			t.Errorf("%s: settled through a redirect", name)
		}
	}
	eq(t, len(c.list()), 0)
	eq(t, len(fac.list()), 0)
}
