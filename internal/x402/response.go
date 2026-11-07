package x402

import (
	"encoding/json"
	"regexp"
)

// HintKind is what the seller's PAYMENT-RESPONSE says
type HintKind int

// The values of HintKind, XS 6.12's hints
const (
	HintSuccess HintKind = iota
	HintFailure
	HintAbsent
)

// responseMax is the largest PAYMENT-RESPONSE egress reads, XS 6.12
const responseMax = 4 << 10

// errorReason is the shape a seller's errorReason must have to reach Payments
var errorReason = regexp.MustCompile(`^[a-z_]{1,64}$`)

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
	top, ok := decodeObject(values[0])
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
	if sig, ok := Decode58(text(top["transaction"])); ok && len(sig) == 64 {
		h.Tx = text(top["transaction"])
	}
	if reason := text(top["errorReason"]); errorReason.MatchString(reason) {
		h.Error = reason
	}
	return h
}
