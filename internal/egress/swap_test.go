package egress

import (
	"crypto/sha256"
	"net/http"
	"testing"
)

func testSet(host string, headers ...string) (*secretSet, string) {
	ph := newPlaceholder()
	x := &secret{name: "N", hosts: map[string]bool{host: true}, value: []byte("val")}
	set := &secretSet{
		byHash:  map[[32]byte]*secret{hashOf(ph): x},
		headers: map[string][]string{host: headers},
	}
	return set, ph
}

func hashOf(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

func TestSwapHeadersOnlyInAuthorizationAndNamedHeaders(t *testing.T) {
	set, ph := testSet("h.example", "x-api-key")
	h := http.Header{
		"Authorization": {"Bearer " + ph}, "X-Api-Key": {ph}, "X-Other": {ph}, "Cookie": {ph},
	}
	got := swapHeaders(h, "h.example", set)
	eq(t, h.Get("Authorization"), "Bearer val")
	eq(t, h.Get("X-Api-Key"), "val")
	eq(t, h.Get("X-Other"), ph)
	eq(t, h.Get("Cookie"), ph)
	eq(t, got.names, []string{"N"})
}

func TestSwapNeedsToken68AndAKnownHost(t *testing.T) {
	set, ph := testSet("h.example")
	for _, v := range []string{`Digest response="` + ph + `"`, "Bearer a b " + ph, "Bearer", ""} {
		h := http.Header{"Authorization": {v}}
		eq(t, swapHeaders(h, "h.example", set).did(), false)
		eq(t, h.Get("Authorization"), v)
	}
	h := http.Header{"Authorization": {"Bearer " + ph}}
	eq(t, swapHeaders(h, "other.example", set).did(), false)
	eq(t, h.Get("Authorization"), "Bearer "+ph)
}

func TestSwapReportsAPlaceholderItDoesNotHold(t *testing.T) {
	set, _ := testSet("h.example")
	h := http.Header{"Authorization": {"Bearer " + newPlaceholder()}}
	got := swapHeaders(h, "h.example", set)
	eq(t, got.missing, true)
	eq(t, got.did(), false)
}

func TestSwapRefusesAValueWithControlCharactersOrAZeroedSecret(t *testing.T) {
	for _, val := range []string{"a\rb", "a\nb", "a\x00b"} {
		set, ph := testSet("h.example")
		for _, x := range set.byHash {
			x.value = []byte(val)
		}
		h := http.Header{"Authorization": {"Bearer " + ph}}
		eq(t, swapHeaders(h, "h.example", set).did(), false)
		eq(t, h.Get("Authorization"), "Bearer "+ph)
	}
	set, ph := testSet("h.example")
	set.zero()
	h := http.Header{"Authorization": {"Bearer " + ph}}
	eq(t, swapHeaders(h, "h.example", set).did(), false)
	eq(t, h.Get("Authorization"), "Bearer "+ph)
}

func TestScrubReplacesTheValueInEveryHeaderValue(t *testing.T) {
	h := http.Header{"A": {"x val y", "val"}, "B": {"none"}}
	scrubHeader(h, []pair{{"val", "bnsec_x"}})
	eq(t, h["A"], []string{"x bnsec_x y", "bnsec_x"})
	eq(t, h["B"], []string{"none"})
}
