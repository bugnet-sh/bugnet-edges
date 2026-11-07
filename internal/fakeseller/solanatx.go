package fakeseller

import (
	"crypto/ed25519"

	"github.com/oynozan/bugnet-edges/internal/x402"
)

const (
	// maxTxBytes is Solana's packet size, the largest transaction a validator takes
	maxTxBytes = 1232
	// sigBytes is the size of one Ed25519 signature
	sigBytes = 64
	// keyBytes is the size of one account key and of a blockhash
	keyBytes = 32
	// versioned marks a versioned message's first byte, which a legacy header never sets
	versioned = 0x80
)

// The reasons a settle is refused, named as the x402 SVM facilitator names them
const (
	reasonUndecodable          = "invalid_exact_svm_payload_transaction_could_not_be_decoded"
	reasonVersion              = "unsupported_transaction_version"
	reasonSize                 = "invalid_exact_svm_payload_transaction_size_exceeded"
	reasonTransaction          = "invalid_exact_svm_payload_transaction"
	reasonScheme               = "invalid_exact_svm_unsupported_scheme"
	reasonNetwork              = "invalid_exact_svm_network_mismatch"
	reasonFeePayerNotManaged   = "invalid_exact_svm_fee_payer_not_managed_by_facilitator"
	reasonSignature            = "invalid_exact_svm_payload_signature_invalid"
	reasonFeePayerTransferring = "invalid_exact_svm_payload_transaction_fee_payer_" +
		"transferring_funds"
	reasonNoTransfer        = "invalid_exact_svm_payload_no_transfer_instruction"
	reasonAmount            = "invalid_exact_svm_payload_amount_mismatch"
	reasonMint              = "invalid_exact_svm_payload_mint_mismatch"
	reasonRecipient         = "invalid_exact_svm_payload_recipient_mismatch"
	reasonTransactionFailed = "invalid_exact_svm_transaction_failed"
	reasonDuplicate         = "duplicate_settlement"
	reasonComputeLimit      = "invalid_exact_svm_payload_transaction_instructions_" +
		"compute_limit_instruction"
	reasonComputeLimitTooHigh = "invalid_exact_svm_payload_transaction_instructions_" +
		"compute_limit_instruction_too_high"
	reasonComputePrice = "invalid_exact_svm_payload_transaction_instructions_" +
		"compute_price_instruction"
	reasonComputePriceTooHigh = "invalid_exact_svm_payload_transaction_instructions_" +
		"compute_price_instruction_too_high"
)

// refuse is a settle refused for reason
func refuse(reason string) error {
	return &SettleError{Reason: reason}
}

// solanaTx is a legacy or version 0 wire transaction, its signatures and the message they sign
type solanaTx struct {
	wire []byte
	// sigAt is where the first signature starts in wire
	sigAt   int
	numSigs int
	message []byte
	// required, readonlySigned and readonlyUnsigned are the message header
	required, readonlySigned, readonlyUnsigned int
	keys                                       [][]byte
	blockhash                                  []byte
	instructions                               []instruction
	// lookups counts the address table lookups of a version 0 message
	lookups int
}

// instruction is one compiled instruction, its program and accounts as indexes into keys
type instruction struct {
	program  int
	accounts []int
	data     []byte
}

// reader walks bytes, remembering the first short or malformed field
type reader struct {
	b   []byte
	at  int
	bad bool
}

// next is the next byte
func (r *reader) next() int {
	if r.at >= len(r.b) {
		r.bad = true
		return 0
	}
	r.at++
	return int(r.b[r.at-1])
}

// take is the next n bytes
func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b)-r.at {
		r.bad = true
		return nil
	}
	r.at += n
	return r.b[r.at-n : r.at]
}

// length reads a compact-u16 in its one canonical form of at most 3 bytes
func (r *reader) length() int {
	n := 0
	for i := range 3 {
		c := r.next()
		n |= (c & 0x7f) << (7 * i)
		if c&0x80 == 0 {
			if i > 0 && c == 0 || n > 0xffff {
				r.bad = true
			}
			return n
		}
	}
	r.bad = true
	return 0
}

// parseTx decodes a wire transaction whose signature count matches its header
func parseTx(wire []byte) (*solanaTx, error) {
	if len(wire) > maxTxBytes {
		return nil, refuse(reasonSize)
	}
	tx := &solanaTx{wire: wire}
	r := &reader{b: wire}
	tx.numSigs = r.length()
	tx.sigAt = r.at
	r.take(sigBytes * tx.numSigs)
	if r.bad {
		return nil, refuse(reasonUndecodable)
	}
	tx.message = wire[r.at:]
	v0 := false
	if first := r.next(); first&versioned != 0 {
		if first != versioned {
			return nil, refuse(reasonVersion)
		}
		v0 = true
		tx.required = r.next()
	} else {
		tx.required = first
	}
	tx.readonlySigned, tx.readonlyUnsigned = r.next(), r.next()
	for range r.length() {
		tx.keys = append(tx.keys, r.take(keyBytes))
		if r.bad {
			return nil, refuse(reasonUndecodable)
		}
	}
	tx.blockhash = r.take(keyBytes)
	for range r.length() {
		in := instruction{program: r.next()}
		for _, a := range r.take(r.length()) {
			in.accounts = append(in.accounts, int(a))
		}
		in.data = r.take(r.length())
		if r.bad {
			return nil, refuse(reasonUndecodable)
		}
		tx.instructions = append(tx.instructions, in)
	}
	loaded := 0
	if v0 {
		for range r.length() {
			r.take(keyBytes)
			loaded += len(r.take(r.length()))
			loaded += len(r.take(r.length()))
			tx.lookups++
			if r.bad {
				return nil, refuse(reasonUndecodable)
			}
		}
	}
	if r.bad || r.at != len(wire) || !tx.shaped(loaded) {
		return nil, refuse(reasonUndecodable)
	}
	return tx, nil
}

// shaped checks the header against the keys and every index against the accounts it can name
func (tx *solanaTx) shaped(loaded int) bool {
	n := len(tx.keys)
	if tx.numSigs != tx.required || tx.required < 1 || tx.required > n ||
		tx.readonlySigned >= tx.required || tx.readonlyUnsigned > n-tx.required {
		return false
	}
	for _, in := range tx.instructions {
		// A program is always a static key, never one a lookup table loads
		if in.program >= n {
			return false
		}
		for _, a := range in.accounts {
			if a >= n+loaded {
				return false
			}
		}
	}
	return true
}

// key is account key i in base58
func (tx *solanaTx) key(i int) string {
	return x402.Encode58(tx.keys[i])
}

// signature is slot i of the signatures, inside wire
func (tx *solanaTx) signature(i int) []byte {
	at := tx.sigAt + sigBytes*i
	return tx.wire[at : at+sigBytes]
}

// sign writes k's signature of the message into slot i
func (tx *solanaTx) sign(i int, k ed25519.PrivateKey) {
	copy(tx.signature(i), ed25519.Sign(k, tx.message))
}

// signedBy says whether slot i holds key i's signature of the message
func (tx *solanaTx) signedBy(i int) bool {
	return ed25519.Verify(tx.keys[i], tx.message, tx.signature(i))
}
