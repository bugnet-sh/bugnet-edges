package fakeseller

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// fakeTx starts the transaction of x402test.PaymentSignature, fake- and the request's ref
const fakeTx = "fake-"

// The reasons InMemory refuses to settle, each answered to the payer as a new 402
var (
	errNotTestFormat = errors.New("fakeseller: the payment is not in the fixed test format")
	errOtherEntry    = errors.New("fakeseller: the payment accepted an entry never offered")
	errSettled       = errors.New("fakeseller: the transaction was settled before")
)

// Ledger settles in memory with no chain and records each transfer
type Ledger struct {
	mu        sync.Mutex
	done      map[string]bool
	transfers []Transfer
}

// Transfer is one payment a Ledger settled
type Transfer struct {
	// Transaction is the payload's transaction and Signature what Settle answered for it
	Transaction, Signature string
	Accepted               x402.Entry
}

// InMemory settles with no chain and records each transfer
func InMemory() *Ledger {
	return &Ledger{done: map[string]bool{}}
}

// Settle takes a test format payment once per transaction, answering base58 of its SHA-512
func (l *Ledger) Settle(_ context.Context, p Payment) (string, error) {
	tx, accepted, ok := testFormat(p.Value)
	if !ok {
		return "", errNotTestFormat
	}
	if accepted != p.Accepted {
		return "", errOtherEntry
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done[tx] {
		return "", errSettled
	}
	l.done[tx] = true
	sum := sha512.Sum512([]byte(tx))
	sig := x402.Encode58(sum[:])
	l.transfers = append(l.transfers, Transfer{Transaction: tx, Signature: sig, Accepted: accepted})
	return sig, nil
}

// Transfers lists the settled transfers in order
func (l *Ledger) Transfers() []Transfer {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Transfer(nil), l.transfers...)
}

// testFormat reads a value of the fixed test format, its transaction and accepted entry
func testFormat(value string) (string, x402.Entry, bool) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", x402.Entry{}, false
	}
	var p struct {
		Version  int `json:"x402Version"`
		Accepted struct {
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
			Asset   string `json:"asset"`
			Amount  string `json:"amount"`
			PayTo   string `json:"payTo"`
		} `json:"accepted"`
		Payload struct {
			Transaction string `json:"transaction"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Version != 2 ||
		!strings.HasPrefix(p.Payload.Transaction, fakeTx) || p.Payload.Transaction == fakeTx {
		return "", x402.Entry{}, false
	}
	a := p.Accepted
	e := x402.Entry{Scheme: a.Scheme, Network: a.Network, Asset: a.Asset, PayTo: a.PayTo}
	if n, err := strconv.ParseInt(a.Amount, 10, 64); err == nil && n >= 0 &&
		strconv.FormatInt(n, 10) == a.Amount {
		e.AmountMicros, e.AmountOK = n, true
	}
	return p.Payload.Transaction, e, true
}
