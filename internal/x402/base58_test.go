package x402

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

// vectors58 are Bitcoin Core's base58 cases and the token program's address
var vectors58 = []struct{ hex, text string }{
	{"61", "2g"},
	{"626262", "a3gV"},
	{"636363", "aPEr"},
	{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
	{"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
	{"516b6fcd0f", "ABnLTmg"},
	{"bf4f89001e670274dd", "3SEo3LWLoPntC"},
	{"572e4794", "3EFU7m"},
	{"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
	{"10c8511e", "Rt5zm"},
	{"00000000000000000000", "1111111111"},
	{"06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9",
		"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
	{"c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", USDCMint},
}

func TestDecode58(t *testing.T) {
	got, ok := Decode58(strings.Repeat("1", 32))
	eq(t, ok, true)
	eq(t, got, make([]byte, 32))

	for _, v := range vectors58 {
		got, ok := Decode58(v.text)
		if !ok || hex.EncodeToString(got) != v.hex {
			t.Errorf("%s decodes to %x %v, want %s", v.text, got, ok, v.hex)
		}
	}

	for _, s := range []string{
		"0", "O", "I", "l", "", " 1", "1 ", "1\n", "2g\x00", "+2g", "-2g", "2g=", "é", "２g",
		"Tokenkeg QfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", strings.Repeat("1", 89),
		strings.Repeat("z", 89),
	} {
		if got, ok := Decode58(s); ok || got != nil {
			t.Errorf("%q decodes to %x %v", s, got, ok)
		}
	}

	got, ok = Decode58(strings.Repeat("1", 88))
	eq(t, ok, true)
	eq(t, len(got), 88)
}

func TestDecode58LeadingOnes(t *testing.T) {
	key := append([]byte{0}, bytes.Repeat([]byte{0x42}, 31)...)
	text := Encode58(key)
	eq(t, text[0], byte('1'))

	got, ok := Decode58(text)
	eq(t, ok, true)
	eq(t, got, key)

	for _, s := range []string{text[1:], "1" + text, "1" + USDCMint} {
		got, ok := Decode58(s)
		if !ok || len(got) == 32 {
			t.Errorf("%s decodes to %d bytes, never 32", s, len(got))
		}
	}
}

func TestEncode58(t *testing.T) {
	for _, v := range vectors58 {
		raw, _ := hex.DecodeString(v.hex)
		eq(t, Encode58(raw), v.text)
	}
	eq(t, Encode58(nil), "")

	sum := sha512.Sum512([]byte("bugnet"))
	for _, zeros := range []int{0, 1, 3} {
		for n := 0; zeros+n <= 64; n++ {
			b := append(make([]byte, zeros), sum[:n]...)
			got, ok := Decode58(Encode58(b))
			if len(b) == 0 {
				eq(t, ok, false)
				continue
			}
			if !ok || !bytes.Equal(got, b) {
				t.Errorf("%x comes back as %x %v", b, got, ok)
			}
		}
	}
}
