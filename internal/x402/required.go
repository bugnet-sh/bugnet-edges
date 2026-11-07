package x402

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SolanaMainnet is the CAIP-2 network Bugnet pays on
const SolanaMainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

// USDCMint is the only asset Bugnet pays in
const USDCMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

// V1BodyMax is the most of a 402 body egress reads, only when PAYMENT-REQUIRED is missing
const V1BodyMax = 64 << 10

// schemeExact is the one x402 scheme Bugnet pays with
const schemeExact = "exact"

// maxAccepts is the most accepts entries a 402 may list, as Payments reads it
const maxAccepts = 32

// encodedTimeout is the maxTimeoutSeconds of each entry EncodeRequired writes
const encodedTimeout = 60

// Entry is one accepts entry, the fields egress reads
type Entry struct {
	Scheme, Network, Asset, PayTo string
	AmountMicros                  int64
	AmountOK                      bool
}

// Required is a decoded PAYMENT-REQUIRED header
type Required struct {
	Version int
	Accepts []Entry
}

// ParseRequired decodes the header values, the code empty when it decoded
func ParseRequired(values []string, limit int64) (Required, Code) {
	if len(values) != 1 || int64(len(values[0])) > limit {
		return Required{}, CodeNotX402
	}
	// Only padded standard base64, so egress never passes Payments a header Payments refuses
	top, ok := decodeObject(values[0], base64.StdEncoding)
	if !ok {
		return Required{}, CodeNotX402
	}
	var accepts []json.RawMessage
	if raw, ok := top["accepts"]; ok {
		if json.Unmarshal(raw, &accepts) != nil || len(accepts) > maxAccepts {
			return Required{}, CodeNotX402
		}
	}
	if !numberIs(top["x402Version"], 2) {
		return Required{}, CodeVersionUnsupported
	}
	r := Required{Version: 2}
	for _, raw := range accepts {
		r.Accepts = append(r.Accepts, entryOf(raw))
	}
	return r, ""
}

// decodeObject reads a header value in one of encs as base64 of a UTF-8 JSON object
func decodeObject(v string, encs ...*base64.Encoding) (map[string]json.RawMessage, bool) {
	for _, enc := range encs {
		raw, err := enc.DecodeString(v)
		// The round trip refuses what Go's decoder forgives, newlines and stray low bits
		if err != nil || enc.EncodeToString(raw) != v {
			continue
		}
		// No two forms decode one value to different bytes, so the first match decides
		var top map[string]json.RawMessage
		if !utf8.Valid(raw) || json.Unmarshal(raw, &top) != nil || top == nil {
			return nil, false
		}
		return top, true
	}
	return nil, false
}

// numberIs says whether raw is a JSON number equal to want
func numberIs(raw json.RawMessage, want float64) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	n, ok := v.(float64)
	return ok && n == want
}

// text is raw as a JSON string, empty for any other value
func text(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// entryOf reads one accepts entry by its exact keys, empty when it is not an object
func entryOf(raw json.RawMessage) Entry {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return Entry{}
	}
	e := Entry{
		Scheme:  text(m["scheme"]),
		Network: text(m["network"]),
		Asset:   text(m["asset"]),
		PayTo:   text(m["payTo"]),
	}
	e.AmountMicros, e.AmountOK = amount(text(m["amount"]))
	return e
}

// amount reads a decimal integer string of atomic USDC units, which are micros
func amount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// wireEntry is an accepts entry as EncodeRequired writes it
type wireEntry struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Asset             string         `json:"asset"`
	Amount            string         `json:"amount,omitempty"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// EncodeRequired builds a header value with extra in every entry, for the fake seller and tests
func EncodeRequired(r Required, extra map[string]any) string {
	w := struct {
		Version int         `json:"x402Version"`
		Accepts []wireEntry `json:"accepts"`
	}{Version: r.Version, Accepts: make([]wireEntry, 0, len(r.Accepts))}
	for _, e := range r.Accepts {
		we := wireEntry{
			Scheme: e.Scheme, Network: e.Network, Asset: e.Asset, PayTo: e.PayTo,
			MaxTimeoutSeconds: encodedTimeout, Extra: extra,
		}
		if e.AmountOK {
			we.Amount = strconv.FormatInt(e.AmountMicros, 10)
		}
		w.Accepts = append(w.Accepts, we)
	}
	raw, err := json.Marshal(w)
	if err != nil {
		panic("x402: EncodeRequired cannot write its extra: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// ParseV1Body says whether a 402 body read up to 64 KiB is an x402 v1 body
func ParseV1Body(b []byte) bool {
	if len(b) > V1BodyMax {
		return false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil || !numberIs(top["x402Version"], 1) {
		return false
	}
	var accepts []json.RawMessage
	return json.Unmarshal(top["accepts"], &accepts) == nil && len(accepts) > 0
}

// stages are Precheck's checks in order, each named by the code its failure gives
var stages = []Code{
	CodeNetworkUnsupported, CodeFlowUnsupported, CodePriceAboveMax, CodePayeeChanged,
}

// passed is how many of stages e passes before its first failure
func passed(e Entry, s Service) int {
	switch {
	case e.Network != SolanaMainnet || e.Asset != USDCMint:
		return 0
	case e.Scheme != schemeExact:
		return 1
	case !e.AmountOK || e.AmountMicros <= 0 || e.AmountMicros > s.MaxPriceMicros:
		return 2
	case s.PayTo == "" || e.PayTo != s.PayTo:
		return 3
	}
	return len(stages)
}

// Precheck is XS 6.9 step 4, the first entry passing every check
func Precheck(r Required, s Service) (Entry, Code) {
	if r.Version != 2 {
		return Entry{}, CodeVersionUnsupported
	}
	furthest := 0
	for _, e := range r.Accepts {
		n := passed(e, s)
		if n == len(stages) {
			return e, ""
		}
		furthest = max(furthest, n)
	}
	return Entry{}, stages[furthest]
}

// Offered is the entry events and bodies describe, false when none is exact Solana USDC
func Offered(r Required, s Service) (Entry, bool) {
	e, code := Precheck(r, s)
	if code != "" {
		var ok bool
		if e, ok = firstUSDC(r); !ok {
			return Entry{}, false
		}
	}
	if key, ok := Decode58(e.PayTo); !ok || len(key) != 32 {
		e.PayTo = ""
	}
	return e, true
}

// firstUSDC is the first exact Solana USDC entry of a version 2 header
func firstUSDC(r Required) (Entry, bool) {
	if r.Version != 2 {
		return Entry{}, false
	}
	for _, e := range r.Accepts {
		if exactUSDC(e) {
			return e, true
		}
	}
	return Entry{}, false
}

// exactUSDC says e is exact USDC on Solana mainnet, the only entry an event describes
func exactUSDC(e Entry) bool {
	return e.Network == SolanaMainnet && e.Asset == USDCMint && e.Scheme == schemeExact
}

// Namespace is the metric label of a network, solana, eip155 or other
func Namespace(network string) string {
	ns, _, found := strings.Cut(network, ":")
	if found && (ns == "solana" || ns == "eip155") {
		return ns
	}
	return "other"
}
