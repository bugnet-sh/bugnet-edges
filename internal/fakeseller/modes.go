package fakeseller

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// The prices of XS 11.2 in micros, and $0.01 for a mode the table prices not
const (
	priceOK      = 1_000
	priceCents   = 20_000
	priceBait    = 10_000_000
	priceDefault = 10_000
)

// The bounds of /hold/'s seconds and /memo-long/'s bytes
const (
	holdMin, holdMax         = 1, 300
	memoBytes                = 32
	memoLongMin, memoLongMax = 33, 256
)

// The terms /base/ offers, USDC on Base to a made-up address
const (
	baseNetwork = "eip155:8453"
	baseUSDC    = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	basePayTo   = "0x4242424242424242424242424242424242424242"
)

// memoText fills a memo, ASCII so any cut of it is UTF-8
const memoText = "bugnet fake seller memo "

// modes are the prefixes that take no number, each a mode of XS 11.2 or one the live rows add
var modes = map[string]bool{
	"ok": true, "cents": true, "cent": true, "bait": true, "switch": true, "splits": true,
	"upto": true, "escrow": true, "upfront": true, "ata": true, "feepayer-bugnet": true,
	"memo": true, "hints": true, "late": true, "lie": true, "silent": true, "settle500": true,
	"settle429": true, "settle500-wait": true, "settle429-wait": true, "reject": true,
	"slow": true, "stall": true, "pid": true, "echo": true, "v1only": true, "base": true,
	"redirect": true, "post400": true, "free": true, "sse": true,
}

// pidOffer is the payment-identifier extension /pid/ offers, as the x402 extension declares it
var pidOffer = map[string]any{
	"info": map[string]any{"required": false},
	"schema": map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object",
		"properties": map[string]any{
			"required": map[string]any{"type": "boolean"},
			"id": map[string]any{
				"type": "string", "minLength": 16, "maxLength": 128,
				"pattern": "^[a-zA-Z0-9_-]+$",
			},
		},
		"required": []any{"required"},
	},
}

// route is a request's mode, its prefix and the number of /hold/ or /memo-long/
type route struct {
	name, prefix string
	n            int
}

// parse finds the mode of a path, false for a path no mode serves
func parse(path string) (route, bool) {
	name, rest, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok || !strings.HasPrefix(path, "/") {
		return route{}, false
	}
	if modes[name] {
		return route{name: name, prefix: "/" + name + "/"}, true
	}
	lo, hi := holdMin, holdMax
	switch name {
	case "hold":
	case "memo-long":
		lo, hi = memoLongMin, memoLongMax
	default:
		return route{}, false
	}
	digits, _, ok := strings.Cut(rest, "/")
	n, err := strconv.Atoi(digits)
	if !ok || err != nil || strconv.Itoa(n) != digits || n < lo || n > hi {
		return route{}, false
	}
	return route{name: name, prefix: "/" + name + "/" + digits + "/", n: n}, true
}

// terms is the accepts entry and extra a mode's 402 offers
func (s *seller) terms(rt route) (x402.Entry, map[string]any) {
	e := x402.Entry{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint, PayTo: s.c.PayTo,
		AmountMicros: price(rt.name), AmountOK: true,
	}
	extra := map[string]any{"feePayer": s.c.FeePayer}
	switch rt.name {
	case "switch":
		s.mu.Lock()
		s.switches++
		n := s.switches
		s.mu.Unlock()
		e.PayTo = s.derive("switch " + strconv.Itoa(n))
	case "splits":
		extra["splits"] = []any{map[string]any{"payTo": s.derive("split"), "amount": "5000"}}
	case "upto", "escrow":
		e.Scheme = rt.name
	case "upfront":
		extra["paymentFlow"] = "upfront"
	case "ata":
		extra["ataCreationRequired"] = true
	case "feepayer-bugnet":
		extra["feePayer"] = s.c.BugnetFeePayer
	case "memo":
		extra["memo"] = memo(memoBytes)
	case "memo-long":
		extra["memo"] = memo(rt.n)
	case "hints":
		extra["recentBlockhash"] = s.derive("blockhash")
		extra["lastValidBlockHeight"] = 1
	case "base":
		e.Network, e.Asset, e.PayTo = baseNetwork, baseUSDC, basePayTo
		extra = map[string]any{"name": "USD Coin", "version": "2"}
	}
	return e, extra
}

// price is a mode's amount in micros
func price(name string) int64 {
	switch name {
	case "ok":
		return priceOK
	case "cents":
		return priceCents
	case "bait":
		return priceBait
	}
	return priceDefault
}

// derive is made-up base58 of 32 bytes for label, as an address never PayTo and holding nothing
func (s *seller) derive(label string) string {
	sum := sha256.Sum256([]byte("fakeseller " + label + " " + s.c.PayTo))
	return x402.Encode58(sum[:])
}

// memo is n bytes of memo text
func memo(n int) string {
	return strings.Repeat(memoText, n/len(memoText)+1)[:n]
}

// v1 is /v1only/'s x402 v1 body, the only place its terms appear
func (s *seller) v1(r *http.Request) map[string]any {
	return map[string]any{
		"x402Version": 1,
		"error":       "X-PAYMENT header is required",
		"accepts": []any{map[string]any{
			"scheme": "exact", "network": "solana",
			"maxAmountRequired": strconv.Itoa(priceDefault), "resource": resourceOf(r),
			"description": "", "mimeType": "application/json", "payTo": s.c.PayTo,
			"maxTimeoutSeconds": 60, "asset": x402.USDCMint,
			"extra": map[string]any{"feePayer": s.c.FeePayer},
		}},
	}
}
