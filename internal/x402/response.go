package x402

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
)

// HintKind is what the seller's PAYMENT-RESPONSE says
type HintKind int

// The values of HintKind, absent first so a Hint built by hand reads as uncertain
const (
	HintAbsent HintKind = iota
	HintSuccess
	HintFailure
)

// responseMax is the largest PAYMENT-RESPONSE egress reads, XS 6.12
const responseMax = 4 << 10

// errorReason is the shape a seller's errorReason must have to reach Payments
var errorReason = regexp.MustCompile(`^[a-z_]{1,64}$`)

// hintEncodings are every base64 form, lenient since Payments decides money from the chain
var hintEncodings = []*base64.Encoding{
	base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
}

// Hint is the seller's PAYMENT-RESPONSE, shape-checked
type Hint struct {
	Kind  HintKind
	Tx    string
	Error string
}

// ParseResponse reads one PAYMENT-RESPONSE value of at most 4 KiB, any other is absent
func ParseResponse(values []string) Hint {
	if len(values) != 1 || len(values[0]) > responseMax {
		return Hint{Kind: HintAbsent}
	}
	top, ok := decodeObject(values[0], hintEncodings...)
	if !ok {
		return Hint{Kind: HintAbsent}
	}
	var success any
	if json.Unmarshal(top["success"], &success) != nil {
		return Hint{Kind: HintAbsent}
	}
	settled, ok := success.(bool)
	if !ok {
		return Hint{Kind: HintAbsent}
	}
	h := Hint{Kind: HintFailure}
	if settled {
		h.Kind = HintSuccess
	}
	tx := text(top["transaction"])
	if sig, ok := Decode58(tx); ok && len(sig) == 64 {
		h.Tx = tx
	}
	if reason := text(top["errorReason"]); errorReason.MatchString(reason) {
		h.Error = reason
	}
	return h
}
