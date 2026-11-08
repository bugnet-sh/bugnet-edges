package fakeseller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

const (
	// tokenProgram is the SPL token program USDC lives in
	tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	// token2022Program is the other token program, whose instructions a payment never holds
	token2022Program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	// computeBudgetProgram sets the compute unit limit and price the fee payer pays for
	computeBudgetProgram = "ComputeBudget111111111111111111111111111111"
	// setComputeUnitLimit is the compute budget's SetComputeUnitLimit, then a 4-byte limit
	setComputeUnitLimit = 2
	// setComputeUnitPrice is the compute budget's SetComputeUnitPrice, then an 8-byte price
	setComputeUnitPrice = 3
	// maxComputeUnits is the x402 SVM facilitator's default cap on the compute unit limit
	maxComputeUnits = 400_000
	// maxComputeUnitPrice is the x402 SVM facilitator's cap on the price, in micro-lamports
	maxComputeUnitPrice = 5_000_000
	// transferChecked is the token program's TransferChecked, then amount and decimals
	transferChecked = 12
	// transferCheckedBytes is TransferChecked's data, its tag, an 8-byte amount and decimals
	transferCheckedBytes = 10
	// usdcDecimals is USDC's decimals, which TransferChecked repeats
	usdcDecimals = 6
	// callTimeout bounds each call to a chain or a facilitator, whose settle waits for a slot
	callTimeout = 60 * time.Second
	// maxAnswer bounds what a settler reads of a chain's or a facilitator's answer
	maxAnswer = 64 << 10
)

// selfSettler completes a payer's transfer as its fee payer and sends it to a chain
type selfSettler struct {
	rpcURL string
	key    ed25519.PrivateKey
	dest   string
	client *http.Client

	mu sync.Mutex
	// sent holds the SHA-256 of each message sent or being sent, so each lands once
	sent *kept[[sha256.Size]byte, bool]
}

// SelfSettle co-signs as the fee payer and sends with sendTransaction to a JSON-RPC URL
func SelfSettle(rpcURL string, feePayer ed25519.PrivateKey, payToTokenAccount string) Settler {
	if len(feePayer) != ed25519.PrivateKeySize {
		panic("fakeseller: SelfSettle needs a whole Ed25519 key")
	}
	return &selfSettler{
		rpcURL: rpcURL, key: feePayer, dest: payToTokenAccount,
		client: &http.Client{Timeout: callTimeout, CheckRedirect: noRedirect},
		sent:   newKept[[sha256.Size]byte, bool](maxKept),
	}
}

// noRedirect keeps a settler's call at the URL it was given
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// Settle checks the transfer, signs the fee payer's slot and sends it, answering its signature
func (s *selfSettler) Settle(ctx context.Context, p Payment) (string, error) {
	tx, err := transactionOf(p.Value)
	if err != nil {
		return "", err
	}
	feePayer := s.key.Public().(ed25519.PublicKey)
	if err := checkTransfer(tx, p.Accepted, feePayer, s.dest); err != nil {
		return "", err
	}
	id := sha256.Sum256(tx.message)
	s.mu.Lock()
	if _, ok := s.sent.get(id); ok {
		s.mu.Unlock()
		return "", refuse(reasonDuplicate)
	}
	s.sent.put(id, true)
	s.mu.Unlock()
	tx.sign(0, s.key)
	sig := x402.Encode58(tx.signature(0))
	if err := s.send(ctx, tx.wire, sig); err != nil {
		s.mu.Lock()
		s.sent.forget(id)
		s.mu.Unlock()
		return "", err
	}
	return sig, nil
}

// rpcAnswer is a JSON-RPC answer, a result or an error
type rpcAnswer struct {
	Result *string `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

// send calls sendTransaction with the wire in base64, which must answer sig
func (s *selfSettler) send(ctx context.Context, wire []byte, sig string) error {
	body := mustJSON(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
		"params": []any{
			base64.StdEncoding.EncodeToString(wire), map[string]string{"encoding": "base64"},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.rpcURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("fakeseller: sendTransaction: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fakeseller: sendTransaction: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	var a rpcAnswer
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAnswer)).Decode(&a); err != nil {
		return fmt.Errorf("fakeseller: sendTransaction answered %d, not JSON-RPC", res.StatusCode)
	}
	switch {
	case a.Error != nil:
		return refuse(reasonTransactionFailed)
	case a.Result == nil || *a.Result != sig:
		return errors.New("fakeseller: sendTransaction answered another signature")
	}
	return nil
}

// transactionOf decodes the transaction a PAYMENT-SIGNATURE value carries
func transactionOf(value string) (*solanaTx, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, refuse(reasonUndecodable)
	}
	var p struct {
		Payload struct {
			Transaction string `json:"transaction"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, refuse(reasonUndecodable)
	}
	wire, err := base64.StdEncoding.DecodeString(p.Payload.Transaction)
	if err != nil {
		return nil, refuse(reasonUndecodable)
	}
	return parseTx(wire)
}

// checkTransfer passes a transaction paying exactly e to dest with feePayer's slot left to sign
func checkTransfer(tx *solanaTx, e x402.Entry, feePayer ed25519.PublicKey, dest string) error {
	switch {
	case e.Scheme != "exact":
		return refuse(reasonScheme)
	case e.Network != x402.SolanaMainnet:
		return refuse(reasonNetwork)
	case tx.lookups > 0:
		// A lookup table's accounts are on chain, so no check here could read them
		return refuse(reasonTransaction)
	case !bytes.Equal(tx.keys[0], feePayer):
		return refuse(reasonFeePayerNotManaged)
	}
	for i := 1; i < tx.required; i++ {
		if !tx.signedBy(i) {
			return refuse(reasonSignature)
		}
	}
	var transfer *instruction
	limited, priced := false, false
	for i := range tx.instructions {
		in := &tx.instructions[i]
		if in.program == 0 || slices.Contains(in.accounts, 0) {
			return refuse(reasonFeePayerTransferring)
		}
		program := tx.key(in.program)
		if program == computeBudgetProgram {
			if err := checkBudget(in.data); err != nil {
				return err
			}
			limited = limited || in.data[0] == setComputeUnitLimit
			priced = priced || in.data[0] == setComputeUnitPrice
			continue
		}
		if program != tokenProgram && program != token2022Program {
			continue
		}
		if program != tokenProgram || transfer != nil || len(in.accounts) < 4 ||
			len(in.data) != transferCheckedBytes || in.data[0] != transferChecked {
			return refuse(reasonNoTransfer)
		}
		transfer = in
	}
	switch {
	case priced && !limited:
		// Without a limit the chain charges the price for its default units, above the cap
		return refuse(reasonComputeLimit)
	case transfer == nil:
		return refuse(reasonNoTransfer)
	}
	amount := binary.LittleEndian.Uint64(transfer.data[1:9])
	switch {
	case !e.AmountOK || e.AmountMicros <= 0 || amount != uint64(e.AmountMicros) ||
		transfer.data[9] != usdcDecimals:
		return refuse(reasonAmount)
	case e.Asset != x402.USDCMint || tx.key(transfer.accounts[1]) != x402.USDCMint:
		return refuse(reasonMint)
	case tx.key(transfer.accounts[2]) != dest:
		return refuse(reasonRecipient)
	}
	return nil
}

// checkBudget refuses a compute budget instruction the fee payer would pay too much for
func checkBudget(data []byte) error {
	switch {
	case len(data) == 0:
		return refuse(reasonTransaction)
	case data[0] == setComputeUnitLimit && len(data) != 5:
		return refuse(reasonComputeLimit)
	case data[0] == setComputeUnitLimit && binary.LittleEndian.Uint32(data[1:]) > maxComputeUnits:
		return refuse(reasonComputeLimitTooHigh)
	case data[0] == setComputeUnitPrice && len(data) != 9:
		return refuse(reasonComputePrice)
	case data[0] == setComputeUnitPrice &&
		binary.LittleEndian.Uint64(data[1:]) > maxComputeUnitPrice:
		return refuse(reasonComputePriceTooHigh)
	}
	return nil
}
