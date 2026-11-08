package fakeseller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// exact checks an entry is exact Solana USDC asking amount of to, or of payTo when none is given
func exact(t *testing.T, entry json.RawMessage, amount string, to ...string) {
	t.Helper()
	f := fields(t, entry)
	eq(t, f["scheme"], any("exact"))
	eq(t, f["network"], any(x402.SolanaMainnet))
	eq(t, f["asset"], any(x402.USDCMint))
	eq(t, f["amount"], any(amount))
	want := append(to, payTo)[0]
	eq(t, f["payTo"], any(want))
	key, ok := x402.Decode58(want)
	eq(t, ok && len(key) == 32, true)
	eq(t, extra(t, entry)["feePayer"], any(feePayer))
}

// first sends one GET without a payment
func first(h http.Handler, target string) *httptest.ResponseRecorder {
	return send(h, http.MethodGet, target, nil, "")
}

func TestEveryModeFirstAnswer(t *testing.T) {
	h := New(config(InMemory()))
	cases := []struct {
		target string
		check  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{"/ok/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			top, entry := required(t, w)
			exact(t, entry, "1000")
			var res map[string]any
			if err := json.Unmarshal(top["resource"], &res); err != nil {
				t.Fatal(err)
			}
			eq(t, res["url"], any("http://example.com/ok/x"))
			eq(t, fields(t, entry)["maxTimeoutSeconds"], any(float64(60)))
			r, code := x402.ParseRequired(w.Result().Header.Values("Payment-Required"), 32<<10)
			eq(t, code, x402.Code(""))
			_, code = x402.Precheck(r, x402.Service{MaxPriceMicros: 1000, PayTo: payTo})
			eq(t, code, x402.Code(""))
		}},
		{"/cents/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "20000")
		}},
		{"/cent/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/bait/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000000")
		}},
		{"/switch/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			to := fields(t, entry)["payTo"]
			_, next := required(t, first(h, "/switch/x"))
			eq(t, to == fields(t, next)["payTo"], false)
			eq(t, to == any(payTo) || fields(t, next)["payTo"] == any(payTo), false)
			for _, e := range []json.RawMessage{entry, next} {
				exact(t, e, "10000", fields(t, e)["payTo"].(string))
			}
		}},
		{"/splits/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			splits, _ := extra(t, entry)["splits"].([]any)
			if len(splits) == 0 {
				t.Fatalf("splits are %v, want some", extra(t, entry)["splits"])
			}
		}},
		{"/upto/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			eq(t, fields(t, entry)["scheme"], any("upto"))
		}},
		{"/escrow/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			eq(t, fields(t, entry)["scheme"], any("escrow"))
		}},
		{"/upfront/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
			eq(t, extra(t, entry)["paymentFlow"], any("upfront"))
		}},
		{"/ata/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			eq(t, extra(t, entry)["ataCreationRequired"], any(true))
		}},
		{"/feepayer-bugnet/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			eq(t, extra(t, entry)["feePayer"], any(bugnetFee))
		}},
		{"/memo/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
			memo, _ := extra(t, entry)["memo"].(string)
			eq(t, len(memo), 32)
		}},
		{"/memo-long/40/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			memo, _ := extra(t, entry)["memo"].(string)
			eq(t, len(memo), 40)
		}},
		{"/hints/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
			hash, _ := extra(t, entry)["recentBlockhash"].(string)
			key, ok := x402.Decode58(hash)
			eq(t, ok && len(key) == 32, true)
			eq(t, extra(t, entry)["lastValidBlockHeight"], any(float64(1)))
		}},
		{"/late/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/lie/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/silent/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/settle500/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/settle429/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/settle500-wait/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/settle429-wait/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/reject/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/slow/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/stall/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/pid/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			top, entry := required(t, w)
			exact(t, entry, "10000")
			var ext map[string]struct {
				Info   map[string]any `json:"info"`
				Schema map[string]any `json:"schema"`
			}
			if err := json.Unmarshal(top["extensions"], &ext); err != nil {
				t.Fatal(err)
			}
			pid, ok := ext["payment-identifier"]
			eq(t, ok, true)
			eq(t, pid.Info, map[string]any{"required": false})
			eq(t, pid.Schema["type"], any("object"))
		}},
		{"/echo/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/redirect/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/post400/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			exact(t, entry, "10000")
		}},
		{"/v1only/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			eq(t, w.Code, http.StatusPaymentRequired)
			eq(t, w.Result().Header.Values("Payment-Required"), []string(nil))
			eq(t, x402.ParseV1Body(w.Body.Bytes()), true)
		}},
		{"/base/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			_, entry := required(t, w)
			eq(t, fields(t, entry)["network"], any("eip155:8453"))
			r, _ := x402.ParseRequired(w.Result().Header.Values("Payment-Required"), 32<<10)
			_, code := x402.Precheck(r, x402.Service{MaxPriceMicros: 1 << 40, PayTo: payTo})
			eq(t, code, x402.CodeNetworkUnsupported)
		}},
		{"/free/x", func(t *testing.T, w *httptest.ResponseRecorder) {
			eq(t, w.Code, http.StatusOK)
			eq(t, w.Result().Header.Values("Payment-Required"), []string(nil))
		}},
		{"/hold/1/", func(t *testing.T, w *httptest.ResponseRecorder) {
			eq(t, w.Code, http.StatusOK)
			eq(t, w.Result().Header.Values("Payment-Required"), []string(nil))
		}},
		{"/sse/", func(t *testing.T, w *httptest.ResponseRecorder) {
			eq(t, w.Code, http.StatusOK)
			eq(t, w.Header().Get("Content-Type"), "text/event-stream")
			eq(t, strings.Count(w.Body.String(), "data: "), 5)
		}},
	}
	for _, c := range cases {
		t.Run(strings.Split(c.target, "/")[1], func(t *testing.T) {
			c.check(t, first(h, c.target))
		})
	}
}

func TestPost400(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	eq(t, send(h, http.MethodPost, "/post400/x", nil, "").Code, http.StatusBadRequest)
	eq(t, send(h, http.MethodGet, "/post400/x", nil, "").Code, http.StatusPaymentRequired)
	w := send(h, http.MethodPost, "/post400/x", nil, "{}")
	value := pay(t, w, "p1")
	eq(t, send(h, http.MethodPost, "/post400/x", paying(value), "").Code, http.StatusBadRequest)
	eq(t, len(ledger.Transfers()), 0)
	w = send(h, http.MethodPost, "/post400/x", paying(value), "{}")
	eq(t, w.Code, http.StatusOK)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	eq(t, body["body_bytes"], any(float64(2)))
	eq(t, len(ledger.Transfers()), 1)
}

func TestFreeIs200(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		w := send(h, m, "/free/a?b=c", nil, "body")
		eq(t, w.Code, http.StatusOK)
		eq(t, w.Header().Get("Payment-Required"), "")
		eq(t, w.Header().Get("Content-Type"), "application/json")
	}
	w := send(h, http.MethodGet, "/free/", paying("not-a-payment"), "")
	eq(t, w.Code, http.StatusOK)
	eq(t, len(ledger.Transfers()), 0)
}

func TestMemoModes(t *testing.T) {
	h := New(config(InMemory()))
	for target, n := range map[string]int{
		"/memo/x": 32, "/memo-long/33/x": 33, "/memo-long/100/x": 100, "/memo-long/256/": 256,
	} {
		_, entry := required(t, first(h, target))
		memo, _ := extra(t, entry)["memo"].(string)
		eq(t, len(memo), n)
		eq(t, utf8.ValidString(memo), true)
	}
	for _, target := range []string{
		"/memo-long/32/x", "/memo-long/257/x", "/memo-long/033/x", "/memo-long/x/", "/memo-long/40",
	} {
		eq(t, first(h, target).Code, http.StatusNotFound)
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	h := New(config(InMemory()))
	for _, target := range []string{
		"/", "/nope/x", "/ok", "/OK/x", "/hold/", "/hold/0/", "/hold/301/", "/hold/5", "/hold/05/",
		"/__test/payloads",
	} {
		eq(t, first(h, target).Code, http.StatusNotFound)
	}
}

func TestNewNeedsASettler(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New took a Config without a Settler")
		}
	}()
	New(Config{PayTo: payTo})
}

func TestV1OnlyNeverTakesAV2Payment(t *testing.T) {
	ledger := InMemory()
	h := New(config(ledger))
	value := pay(t, first(h, "/ok/x"), "r1")
	w := send(h, http.MethodGet, "/v1only/x", paying(value), "")
	eq(t, w.Code, http.StatusPaymentRequired)
	eq(t, w.Result().Header.Values("Payment-Required"), []string(nil))
	eq(t, x402.ParseV1Body(w.Body.Bytes()), true)
	eq(t, len(ledger.Transfers()), 0)
}
