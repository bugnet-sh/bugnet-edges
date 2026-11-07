package x402

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// settled is a PAYMENT-RESPONSE value of this JSON text
func settled(text string) []string {
	return []string{base64.StdEncoding.EncodeToString([]byte(text))}
}

// padResponse is a PAYMENT-RESPONSE value exactly n characters long, n a multiple of 4
func padResponse(t *testing.T, n int) []string {
	t.Helper()
	head := `{"success":true,"pad":"`
	v := settled(head + strings.Repeat("x", n/4*3-len(head)-2) + `"}`)
	eq(t, len(v[0]), n)
	return v
}

func TestParseResponse(t *testing.T) {
	sig86 := Encode58(append([]byte{0, 1}, bytes.Repeat([]byte{0xa5}, 62)...))
	sig63 := Encode58(bytes.Repeat([]byte{9}, 63))
	eq(t, len(sig86), 86)
	eq(t, len(sig63), 86)
	sig88 := Encode58(bytes.Repeat([]byte{0xff}, 64))

	cases := []struct {
		name   string
		values []string
		want   Hint
	}{
		{"success", settled(`{"success":true,"transaction":"` + sig88 + `"}`),
			Hint{Kind: HintSuccess, Tx: sig88}},
		{"failure", settled(`{"success":false,"errorReason":"insufficient_funds"}`),
			Hint{Kind: HintFailure, Error: "insufficient_funds"}},
		{"missing", nil, Hint{Kind: HintAbsent}},
		{"empty list", []string{}, Hint{Kind: HintAbsent}},
		{"4 KiB plus 1", []string{strings.Repeat("A", 4<<10+1)}, Hint{Kind: HintAbsent}},
		{"valid past 4 KiB", padResponse(t, 4<<10+4), Hint{Kind: HintAbsent}},
		{"two values", append(settled(`{"success":true}`), settled(`{"success":true}`)...),
			Hint{Kind: HintAbsent}},
		{"86 characters of 64 bytes", settled(`{"success":true,"transaction":"` + sig86 + `"}`),
			Hint{Kind: HintSuccess, Tx: sig86}},
		{"63 bytes", settled(`{"success":true,"transaction":"` + sig63 + `"}`),
			Hint{Kind: HintSuccess}},
		{"error with capitals", settled(`{"success":false,"errorReason":"Bad Thing"}`),
			Hint{Kind: HintFailure}},
		{"error of 65", settled(`{"success":false,"errorReason":"` + strings.Repeat("a", 65) +
			`"}`), Hint{Kind: HintFailure}},
		{"error of 64", settled(`{"success":false,"errorReason":"` + strings.Repeat("a", 64) +
			`"}`), Hint{Kind: HintFailure, Error: strings.Repeat("a", 64)}},
		{"error on success", settled(`{"success":true,"errorReason":"late_fee"}`),
			Hint{Kind: HintSuccess, Error: "late_fee"}},
		{"tx on failure", settled(`{"success":false,"transaction":"` + sig88 + `"}`),
			Hint{Kind: HintFailure, Tx: sig88}},
		{"tx not text", settled(`{"success":true,"transaction":5}`), Hint{Kind: HintSuccess}},
		{"success as text", settled(`{"success":"true"}`), Hint{Kind: HintAbsent}},
		{"no success", settled(`{"transaction":"` + sig88 + `"}`), Hint{Kind: HintAbsent}},
		{"success in capitals", settled(`{"Success":true}`), Hint{Kind: HintAbsent}},
		{"not json", settled(`{`), Hint{Kind: HintAbsent}},
		{"an array", settled(`[true]`), Hint{Kind: HintAbsent}},
		{"raw json", []string{`{"success":true}`}, Hint{Kind: HintAbsent}},
		{"url alphabet", []string{base64.URLEncoding.EncodeToString(
			[]byte(`{"success":true,"errorReason":"???~~~"}`))}, Hint{Kind: HintAbsent}},
	}
	for _, c := range cases {
		if got := ParseResponse(c.values); got != c.want {
			t.Errorf("%s gives %+v, want %+v", c.name, got, c.want)
		}
	}

	eq(t, ParseResponse(padResponse(t, 4<<10)), Hint{Kind: HintSuccess})
}
