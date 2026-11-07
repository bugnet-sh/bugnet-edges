package fakeseller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/oynozan/bugnet-edges/internal/x402"
)

// The programs a seller payment calls, as Payments' signer builds it
const (
	computeBudgetProgram = "ComputeBudget111111111111111111111111111111"
	memoProgram          = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
)

// testKey is a test-only Ed25519 key from a label, the same in every run and in the fixture script
func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("bugnet fakeseller test " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// The test keys of a seller payment
var (
	feeKey       = testKey("fee payer")
	allowanceKey = testKey("allowance")
	payToKey     = testKey("pay to")
)

// pub is a key's public half
func pub(k ed25519.PrivateKey) []byte {
	return k.Public().(ed25519.PublicKey)
}

// made is 32 made-up bytes for a label, an account no key controls
func made(label string) []byte {
	sum := sha256.Sum256([]byte("bugnet fakeseller test account " + label))
	return sum[:]
}

// key58 decodes a base58 key the test names
func key58(s string) []byte {
	b, ok := x402.Decode58(s)
	if !ok || len(b) != 32 {
		panic("fakeseller test: not a key " + s)
	}
	return b
}

// meta is an account an instruction names, with its roles
type meta struct {
	key              []byte
	signer, writable bool
}

// ix is an instruction before it is compiled
type ix struct {
	program  []byte
	accounts []meta
	data     []byte
}

// shortvec is Solana's compact-u16 length
func shortvec(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// compile is the message of ixs with feePayer first, as a legacy or version 0 message
func compile(legacy bool, feePayer []byte, blockhash []byte, ixs []ix) ([]byte, int) {
	all := []meta{{key: feePayer, signer: true, writable: true}}
	add := func(m meta) {
		for i := range all {
			if bytes.Equal(all[i].key, m.key) {
				all[i].signer = all[i].signer || m.signer
				all[i].writable = all[i].writable || m.writable
				return
			}
		}
		all = append(all, m)
	}
	for _, in := range ixs {
		for _, m := range in.accounts {
			add(m)
		}
		add(meta{key: in.program})
	}
	rank := func(m meta) int {
		switch {
		case m.signer && m.writable:
			return 0
		case m.signer:
			return 1
		case m.writable:
			return 2
		}
		return 3
	}
	rest := all[1:]
	slices.SortStableFunc(rest, func(a, b meta) int { return rank(a) - rank(b) })
	required, roSigned, roUnsigned := 0, 0, 0
	for _, m := range all {
		switch rank(m) {
		case 0:
			required++
		case 1:
			required++
			roSigned++
		case 3:
			roUnsigned++
		}
	}
	index := func(key []byte) byte {
		for i, m := range all {
			if bytes.Equal(m.key, key) {
				return byte(i)
			}
		}
		panic("fakeseller test: no such account")
	}
	var msg []byte
	if !legacy {
		msg = append(msg, 0x80)
	}
	msg = append(msg, byte(required), byte(roSigned), byte(roUnsigned))
	msg = append(msg, shortvec(len(all))...)
	for _, m := range all {
		msg = append(msg, m.key...)
	}
	msg = append(msg, blockhash...)
	msg = append(msg, shortvec(len(ixs))...)
	for _, in := range ixs {
		msg = append(msg, index(in.program))
		msg = append(msg, shortvec(len(in.accounts))...)
		for _, m := range in.accounts {
			msg = append(msg, index(m.key))
		}
		msg = append(msg, shortvec(len(in.data))...)
		msg = append(msg, in.data...)
	}
	if !legacy {
		msg = append(msg, shortvec(0)...)
	}
	return msg, required
}

// build is a wire transaction of ixs signed by signers, with the fee payer's slot left empty
func build(legacy bool, feePayer []byte, ixs []ix, signers ...ed25519.PrivateKey) []byte {
	msg, required := compile(legacy, feePayer, made("blockhash"), ixs)
	head := shortvec(required)
	wire := slices.Concat(head, make([]byte, 64*required), msg)
	for _, k := range signers {
		for i := 0; i < required; i++ {
			if bytes.Equal(accountKey(msg, legacy, i), pub(k)) {
				copy(wire[len(head)+64*i:], ed25519.Sign(k, msg))
			}
		}
	}
	return wire
}

// accountKey is the ith account key of a message compile wrote, which has under 128 keys
func accountKey(msg []byte, legacy bool, i int) []byte {
	at := 4
	if !legacy {
		at = 5
	}
	return msg[at+32*i : at+32*(i+1)]
}

// transferIxs are Payments' signer's four instructions, paying amount from source to dest
func transferIxs(authority, source, dest, mint []byte, amount uint64, decimals byte) []ix {
	limit := binary.LittleEndian.AppendUint32([]byte{2}, 20_000)
	price := binary.LittleEndian.AppendUint64([]byte{3}, 1)
	data := binary.LittleEndian.AppendUint64([]byte{transferChecked}, amount)
	return []ix{
		{program: key58(computeBudgetProgram), data: limit},
		{program: key58(computeBudgetProgram), data: price},
		{
			program: key58(tokenProgram),
			accounts: []meta{
				{key: source, writable: true},
				{key: mint},
				{key: dest, writable: true},
				{key: authority, signer: true},
			},
			data: append(data, decimals),
		},
		{program: key58(memoProgram), data: []byte("0123456789abcdef0123456789abcdef")},
	}
}

// usdcTransfer is Payments' signer's transaction paying amount to dest, signed by the allowance
func usdcTransfer(legacy bool, dest []byte, amount uint64) []byte {
	ixs := transferIxs(pub(allowanceKey), made("source"), dest, key58(x402.USDCMint), amount, 6)
	return build(legacy, pub(feeKey), ixs, allowanceKey)
}

func TestParseReadsBothMessageForms(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		wire := usdcTransfer(legacy, made("destination"), 1_000)
		tx, err := parseTx(wire)
		if err != nil {
			t.Fatal(legacy, err)
		}
		eq(t, tx.numSigs, 2)
		eq(t, tx.keys[0], pub(feeKey))
		eq(t, tx.keys[1], pub(allowanceKey))
		eq(t, len(tx.instructions), 4)
		eq(t, tx.signedBy(1), true)
		eq(t, tx.signedBy(0), false)
		tx.sign(0, feeKey)
		eq(t, tx.signedBy(0), true)
		eq(t, ed25519.Verify(pub(feeKey), tx.message, tx.wire[tx.sigAt:tx.sigAt+64]), true)
	}
}

func TestParseRefusesMalformedTransactions(t *testing.T) {
	good := usdcTransfer(false, made("destination"), 1_000)
	at := 1 + 2*64
	cases := map[string][]byte{
		"empty":         {},
		"short":         good[:len(good)-1],
		"trailing":      append(slices.Clone(good), 0),
		"version 1":     slices.Concat(good[:at], []byte{0x81}, good[at+1:]),
		"one signature": slices.Concat([]byte{1}, good[1:1+64], good[at:]),
		"too big":       make([]byte, maxTxBytes+1),
		"long shortvec": slices.Concat([]byte{0x82, 0x00}, good[1:]),
	}
	for name, wire := range cases {
		if _, err := parseTx(wire); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// fixture is a seller payment Payments' own builder and signer made, by testdata's script
type fixture struct {
	MadeWith    string `json:"made_with"`
	Transaction string `json:"transaction"`
	FeePayer    string `json:"fee_payer"`
	Authority   string `json:"authority"`
	PayTo       string `json:"pay_to"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Amount      int64  `json:"amount"`
	Blockhash   string `json:"blockhash"`
}

// paymentsFixture reads testdata/payments-transfer.json
func paymentsFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/payments-transfer.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSolanaTxFixture(t *testing.T) {
	f := paymentsFixture(t)
	eq(t, f.FeePayer, x402.Encode58(pub(feeKey)))
	eq(t, f.Authority, x402.Encode58(pub(allowanceKey)))
	eq(t, f.PayTo, x402.Encode58(pub(payToKey)))
	wire, err := base64.StdEncoding.DecodeString(f.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := parseTx(wire)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, x402.Encode58(tx.blockhash), f.Blockhash)
	entry := x402.Entry{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint, PayTo: f.PayTo,
		AmountMicros: f.Amount, AmountOK: true,
	}
	if err := checkTransfer(tx, entry, pub(feeKey), f.Destination); err != nil {
		t.Fatal(err)
	}
	eq(t, x402.Encode58(tx.keys[tx.instructions[2].accounts[0]]), f.Source)
	tx.sign(0, feeKey)
	eq(t, tx.signedBy(0), true)
	eq(t, tx.signedBy(1), true)
	again, err := parseTx(tx.wire)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, again.signedBy(0), true)
}

func TestCheckTransferRefusals(t *testing.T) {
	dest := made("destination")
	entry := x402.Entry{
		Scheme: "exact", Network: x402.SolanaMainnet, Asset: x402.USDCMint,
		PayTo: x402.Encode58(pub(payToKey)), AmountMicros: 1_000, AmountOK: true,
	}
	usdc := key58(x402.USDCMint)
	authority := pub(allowanceKey)
	twice := transferIxs(authority, made("source"), dest, usdc, 1_000, 6)
	twice = append(twice, twice[2])
	byFee := transferIxs(pub(feeKey), made("source"), dest, usdc, 1_000, 6)
	plain := transferIxs(authority, made("source"), dest, usdc, 1_000, 6)
	plain[2].data = binary.LittleEndian.AppendUint64([]byte{3}, 1_000)
	cases := map[string]struct {
		wire   []byte
		entry  x402.Entry
		reason string
	}{
		"amount below": {wire: usdcTransfer(false, dest, 999), reason: reasonAmount},
		"amount above": {wire: usdcTransfer(false, dest, 1_001), reason: reasonAmount},
		"destination": {
			wire: usdcTransfer(false, made("other"), 1_000), reason: reasonRecipient,
		},
		"mint": {
			wire: build(false, pub(feeKey),
				transferIxs(authority, made("source"), dest, made("mint"), 1_000, 6),
				allowanceKey),
			reason: reasonMint,
		},
		"decimals": {
			wire: build(false, pub(feeKey),
				transferIxs(authority, made("source"), dest, usdc, 1_000, 7), allowanceKey),
			reason: reasonAmount,
		},
		"two transfers": {
			wire: build(false, pub(feeKey), twice, allowanceKey), reason: reasonNoTransfer,
		},
		"plain transfer": {
			wire: build(false, pub(feeKey), plain, allowanceKey), reason: reasonNoTransfer,
		},
		"fee payer moves funds": {
			wire: build(false, pub(feeKey), byFee), reason: reasonFeePayerTransferring,
		},
		"another fee payer": {
			wire: build(false, made("fee"),
				transferIxs(authority, made("source"), dest, usdc, 1_000, 6), allowanceKey),
			reason: reasonFeePayerNotManaged,
		},
		"unsigned": {
			wire: build(false, pub(feeKey),
				transferIxs(authority, made("source"), dest, usdc, 1_000, 6)),
			reason: reasonSignature,
		},
		"upto": {
			wire:   usdcTransfer(false, dest, 1_000),
			entry:  x402.Entry{Scheme: "upto", Network: x402.SolanaMainnet},
			reason: reasonScheme,
		},
		"base": {
			wire:   usdcTransfer(false, dest, 1_000),
			entry:  x402.Entry{Scheme: "exact", Network: "eip155:8453"},
			reason: reasonNetwork,
		},
	}
	for name, c := range cases {
		tx, err := parseTx(c.wire)
		if err != nil {
			t.Fatal(name, err)
		}
		e := entry
		if c.entry.Scheme != "" {
			e = c.entry
		}
		err = checkTransfer(tx, e, pub(feeKey), x402.Encode58(dest))
		var se *SettleError
		if !errors.As(err, &se) || se.Reason != c.reason {
			t.Errorf("%s: got %v, want %s", name, err, c.reason)
		}
	}
}
