package x402

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// requiredMax is XS 6.16's payment_required_max
const requiredMax = 32 << 10

// The test payees, base58 of 32 bytes each
var (
	pin      = Encode58(bytes.Repeat([]byte{1}, 32))
	otherPay = Encode58(bytes.Repeat([]byte{2}, 32))
	short31  = Encode58(bytes.Repeat([]byte{7}, 31))
)

// payable is a POST service at 0.01 paying pin
var payable = Service{
	ID: "xs_aaaaaaaaaaaaaaaa", Host: "api.example.com", Prefix: "/v1/", Method: "POST",
	MaxPriceMicros: 10000, PayTo: pin,
}

// sol is an exact Solana USDC entry asking amount of payTo
func sol(amount any, payTo string) map[string]any {
	return map[string]any{
		"scheme": "exact", "network": SolanaMainnet, "asset": USDCMint, "amount": amount,
		"payTo": payTo, "maxTimeoutSeconds": 60,
	}
}

// base is an exact USDC entry on Base
func base() map[string]any {
	return map[string]any{
		"scheme": "exact", "network": "eip155:8453",
		"asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "amount": "10000",
		"payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "maxTimeoutSeconds": 60,
	}
}

// with is a copy of e with key set to v
func with(e map[string]any, key string, v any) map[string]any {
	c := make(map[string]any, len(e)+1)
	for k, x := range e {
		c[k] = x
	}
	c[key] = v
	return c
}

// header is the standard padded base64 of v as JSON
func header(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// v2 is a version 2 PAYMENT-REQUIRED object with these entries
func v2(entries ...map[string]any) map[string]any {
	accepts := make([]any, len(entries))
	for i, e := range entries {
		accepts[i] = e
	}
	return map[string]any{"x402Version": 2, "accepts": accepts}
}

// parsed decodes a version 2 header of these entries, failing on a code
func parsed(t *testing.T, entries ...map[string]any) Required {
	t.Helper()
	r, code := ParseRequired([]string{header(t, v2(entries...))}, requiredMax)
	eq(t, code, Code(""))
	return r
}

// fixture reads a file under testdata/required
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/required/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sized is a valid version 2 header exactly n characters long, n a multiple of 4
func sized(t *testing.T, n int) string {
	t.Helper()
	head := `{"x402Version":2,"accepts":[],"pad":"`
	raw := head + strings.Repeat("x", n/4*3-len(head)-2) + `"}`
	h := base64.StdEncoding.EncodeToString([]byte(raw))
	eq(t, len(h), n)
	return h
}

func TestParseRequiredV2(t *testing.T) {
	h := base64.StdEncoding.EncodeToString(fixture(t, "v2-two-entries.json"))
	r, code := ParseRequired([]string{h}, requiredMax)
	eq(t, code, Code(""))
	eq(t, r, Required{Version: 2, Accepts: []Entry{
		{
			Scheme: "exact", Network: "eip155:8453",
			Asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			PayTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", AmountMicros: 20000,
			AmountOK: true,
		},
		{
			Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin,
			AmountMicros: 10000, AmountOK: true,
		},
	}})
}

func TestParseRequiredBase64Forms(t *testing.T) {
	raw := fixture(t, "v2-two-entries.json")
	padded := base64.StdEncoding.EncodeToString(raw)
	if !strings.HasSuffix(padded, "=") || !strings.ContainsAny(padded, "+/") {
		t.Fatal("the fixture must encode with padding and with + or /")
	}
	r, code := ParseRequired([]string{padded}, requiredMax)
	eq(t, code, Code(""))
	eq(t, len(r.Accepts), 2)

	// The last character before the padding with a stray low bit set
	last := strings.TrimRight(padded, "=")
	loose := last[:len(last)-1] + string(last[len(last)-1]+1) + padded[len(last):]
	for name, v := range map[string]string{
		"unpadded":         strings.TrimRight(padded, "="),
		"url alphabet":     base64.URLEncoding.EncodeToString(raw),
		"url unpadded":     base64.RawURLEncoding.EncodeToString(raw),
		"trailing newline": padded + "\n",
		"inner newline":    padded[:76] + "\r\n" + padded[76:],
		"leading space":    " " + padded,
		"loose pad bits":   loose,
		"bangs":            "!!!",
		"empty":            "",
		"raw json":         string(raw),
	} {
		got, code := ParseRequired([]string{v}, requiredMax)
		if code != CodeNotX402 || got.Version != 0 || got.Accepts != nil {
			t.Errorf("%s gives %+v %q, want not_x402", name, got, code)
		}
	}
}

func TestParseRequiredRefusals(t *testing.T) {
	ok := header(t, v2(sol("10000", pin)))
	many := func(n int) []map[string]any {
		out := make([]map[string]any, n)
		for i := range out {
			out[i] = sol("10000", pin)
		}
		return out
	}
	std := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	version := func(v any) string {
		return header(t, with(v2(sol("10000", pin)), "x402Version", v))
	}
	cases := []struct {
		name   string
		values []string
		want   Code
	}{
		{"missing", nil, CodeNotX402},
		{"two values", []string{ok, ok}, CodeNotX402},
		{"32 KiB plus 1", []string{strings.Repeat("A", requiredMax+1)}, CodeNotX402},
		{"valid past the max", []string{sized(t, requiredMax+4)}, CodeNotX402},
		{"33 entries", []string{header(t, v2(many(33)...))}, CodeNotX402},
		{"not json", []string{std("{")}, CodeNotX402},
		{"an array", []string{std(`[{"x402Version":2}]`)}, CodeNotX402},
		{"null", []string{std("null")}, CodeNotX402},
		{"accepts not a list", []string{std(`{"x402Version":2,"accepts":{}}`)}, CodeNotX402},
		{"bad utf-8", []string{std("{\"x402Version\":2,\"x\":\"\xff\"}")}, CodeNotX402},
		{"version 1 with 33", []string{header(t, with(v2(many(33)...), "x402Version", 1))},
			CodeNotX402},
		{"version 1", []string{version(1)}, CodeVersionUnsupported},
		{"version 3", []string{version(3)}, CodeVersionUnsupported},
		{"version as text", []string{version("2")}, CodeVersionUnsupported},
		{"version 2.5", []string{version(2.5)}, CodeVersionUnsupported},
		{"no version", []string{std(`{"accepts":[]}`)}, CodeVersionUnsupported},
		{"version key in capitals", []string{std(`{"X402VERSION":2}`)}, CodeVersionUnsupported},
	}
	for _, c := range cases {
		got, code := ParseRequired(c.values, requiredMax)
		if code != c.want || got.Version != 0 || got.Accepts != nil {
			t.Errorf("%s gives %+v %q, want %q", c.name, got, code, c.want)
		}
	}

	_, code := ParseRequired([]string{std(`{"x402Version":2.0,"accepts":[]}`)}, requiredMax)
	eq(t, code, Code(""))
	r, code := ParseRequired([]string{header(t, v2(many(32)...))}, requiredMax)
	eq(t, code, Code(""))
	eq(t, len(r.Accepts), 32)

	_, code = ParseRequired([]string{sized(t, requiredMax)}, requiredMax)
	eq(t, code, Code(""))
	_, code = ParseRequired([]string{sized(t, 400)}, 396)
	eq(t, code, CodeNotX402)
}

func TestParseRequiredFieldShapes(t *testing.T) {
	r := parsed(t,
		sol("1.5", pin), sol(10000, pin), sol("0", pin), sol("-5", pin), sol("+5", pin),
		sol("99999999999999999999", pin), sol("007", pin),
		map[string]any{"scheme": 1, "network": true, "payTo": nil},
		with(with(sol("10000", pin), "payto", otherPay), "PayTo", otherPay),
	)
	got := make([]Entry, len(r.Accepts))
	copy(got, r.Accepts)
	usdc := Entry{Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin}
	eq(t, got, []Entry{
		usdc, usdc,
		{Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin, AmountOK: true},
		usdc, usdc, usdc,
		{
			Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin,
			AmountMicros: 7, AmountOK: true,
		},
		{},
		{
			Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin,
			AmountMicros: 10000, AmountOK: true,
		},
	})

	h := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepts":[5,null,"x"]}`))
	r, code := ParseRequired([]string{h}, requiredMax)
	eq(t, code, Code(""))
	eq(t, r.Accepts, []Entry{{}, {}, {}})
}

func TestEncodeRequired(t *testing.T) {
	want := Required{Version: 2, Accepts: []Entry{
		{
			Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin,
			AmountMicros: 10000, AmountOK: true,
		},
		{Scheme: "upto", Network: SolanaMainnet, Asset: USDCMint, PayTo: otherPay},
	}}
	extra := map[string]any{"feePayer": otherPay, "memo": "m"}
	h := EncodeRequired(want, "https://api.example.com/v1/search", extra)
	got, code := ParseRequired([]string{h}, requiredMax)
	eq(t, code, Code(""))
	eq(t, got, want)

	raw, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Resource map[string]any   `json:"resource"`
		Accepts  []map[string]any `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	eq(t, doc.Resource, map[string]any{
		"url": "https://api.example.com/v1/search", "description": "", "mimeType": "",
	})
	eq(t, doc.Accepts[0]["amount"], any("10000"))
	eq(t, doc.Accepts[0]["extra"], any(map[string]any{"feePayer": otherPay, "memo": "m"}))
	eq(t, doc.Accepts[0]["maxTimeoutSeconds"], any(float64(60)))
	_, hasAmount := doc.Accepts[1]["amount"]
	eq(t, hasAmount, false)

	plain := EncodeRequired(Required{Version: 1}, "https://seller.test/ok/x", nil)
	raw, _ = base64.StdEncoding.DecodeString(plain)
	eq(t, string(raw), `{"x402Version":1,"resource":{"url":"https://seller.test/ok/x",`+
		`"description":"","mimeType":""},"accepts":[]}`)
}

func TestEncodeRequiredPanicsOnExtraJSONCannotHold(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an extra holding a channel did not panic")
		}
	}()
	EncodeRequired(Required{Version: 2, Accepts: []Entry{{}}}, "https://seller.test/ok/x",
		map[string]any{"c": make(chan int)})
}

func TestParseV1Body(t *testing.T) {
	eq(t, ParseV1Body(fixture(t, "v1-body.json")), true)
	noise := bytes.Repeat([]byte("noise "), (64<<10)/6+1)[:64<<10]
	padded := append(bytes.TrimRight(fixture(t, "v1-body.json"), "\n}"), '}')
	padded = append(padded, bytes.Repeat([]byte(" "), (64<<10)+1-len(padded))...)
	if !json.Valid(padded) {
		t.Fatal("the padded body must stay valid JSON")
	}
	for name, b := range map[string][]byte{
		"empty object":  []byte(`{}`),
		"noise":         noise,
		"empty":         nil,
		"version 2":     []byte(`{"x402Version":2,"accepts":[{}]}`),
		"version text":  []byte(`{"x402Version":"1","accepts":[{}]}`),
		"no accepts":    []byte(`{"x402Version":1}`),
		"empty accepts": []byte(`{"x402Version":1,"accepts":[]}`),
		"accepts 1":     []byte(`{"x402Version":1,"accepts":1}`),
		"an array":      []byte(`[{"x402Version":1,"accepts":[{}]}]`),
		"past 64 KiB":   padded,
	} {
		if ParseV1Body(b) {
			t.Errorf("%s reads as a v1 body", name)
		}
	}
	eq(t, ParseV1Body(padded[:64<<10]), true)
}

func TestPrecheckEachCode(t *testing.T) {
	upto := with(sol("10000", pin), "scheme", "upto")
	devnet := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	cases := []struct {
		name    string
		entries []map[string]any
		want    Code
	}{
		{"base only", []map[string]any{base()}, CodeNetworkUnsupported},
		{"no entries", nil, CodeNetworkUnsupported},
		{"solana not usdc", []map[string]any{with(sol("1", pin), "asset", pin)},
			CodeNetworkUnsupported},
		{"devnet usdc", []map[string]any{with(sol("1", pin), "network", devnet)},
			CodeNetworkUnsupported},
		{"upto only", []map[string]any{upto}, CodeFlowUnsupported},
		{"over the max", []map[string]any{sol("10000000", pin)}, CodePriceAboveMax},
		{"another payTo", []map[string]any{sol("10000", otherPay)}, CodePayeeChanged},
		{"amount 1.5", []map[string]any{sol("1.5", pin)}, CodePriceAboveMax},
		{"amount 0", []map[string]any{sol("0", pin)}, CodePriceAboveMax},
		{"amount a number", []map[string]any{sol(10000, pin)}, CodePriceAboveMax},
		{"amount past int64", []map[string]any{sol("99999999999999999999", pin)},
			CodePriceAboveMax},
		{"furthest is price", []map[string]any{sol("10001", pin), base()}, CodePriceAboveMax},
		{"furthest is payee", []map[string]any{upto, sol("10000", otherPay), base()},
			CodePayeeChanged},
		{"furthest is flow", []map[string]any{base(), upto}, CodeFlowUnsupported},
	}
	for _, c := range cases {
		got, code := Precheck(parsed(t, c.entries...), payable)
		if code != c.want || got != (Entry{}) {
			t.Errorf("%s gives %+v %q, want %q", c.name, got, code, c.want)
		}
	}

	got, code := Precheck(parsed(t, sol("10000", pin)), payable)
	eq(t, code, Code(""))
	eq(t, got.AmountMicros, int64(10000))

	noPin := payable
	noPin.PayTo = ""
	_, code = Precheck(parsed(t, sol("10000", "")), noPin)
	eq(t, code, CodePayeeChanged)

	_, code = Precheck(Required{Version: 3, Accepts: []Entry{
		{Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin, AmountMicros: 1,
			AmountOK: true},
	}}, payable)
	eq(t, code, CodeVersionUnsupported)
}

func TestPrecheckFirstPassingEntry(t *testing.T) {
	r := parsed(t, base(), sol("20000", pin), sol("9000", pin), sol("8000", pin))
	got, code := Precheck(r, payable)
	eq(t, code, Code(""))
	eq(t, got, r.Accepts[2])
	eq(t, got.AmountMicros, int64(9000))
}

func TestOfferedFields(t *testing.T) {
	_, ok := Offered(parsed(t, base()), payable)
	eq(t, ok, false)
	_, ok = Offered(parsed(t, base(), with(sol("10000", pin), "scheme", "upto")), payable)
	eq(t, ok, false)

	got, ok := Offered(parsed(t, sol("10000", short31)), payable)
	eq(t, ok, true)
	eq(t, got, Entry{
		Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, AmountMicros: 10000,
		AmountOK: true,
	})

	got, ok = Offered(parsed(t, sol("0x10", pin)), payable)
	eq(t, ok, true)
	eq(t, got, Entry{Scheme: "exact", Network: SolanaMainnet, Asset: USDCMint, PayTo: pin})

	r := parsed(t, base(), sol("20000", pin), sol("9000", pin))
	got, ok = Offered(r, payable)
	eq(t, ok, true)
	eq(t, got, r.Accepts[2])

	r = parsed(t, with(sol("10000", pin), "scheme", "upto"), sol("20000", otherPay),
		sol("30000", pin))
	got, ok = Offered(r, payable)
	eq(t, ok, true)
	eq(t, got, r.Accepts[1])

	_, ok = Offered(Required{Version: 1, Accepts: []Entry{r.Accepts[1]}}, payable)
	eq(t, ok, false)
}

func TestNamespace(t *testing.T) {
	devnet := "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	for network, want := range map[string]string{
		SolanaMainnet: "solana",
		devnet:        "solana",
		"eip155:8453": "eip155",
		"eip155:1":    "eip155",
		"base":        "other",
		"solana":      "other",
		"cosmos:x":    "other",
		"Solana:x":    "other",
		"":            "other",
		"x:solana:y":  "other",
	} {
		eq(t, Namespace(network), want)
	}
}
