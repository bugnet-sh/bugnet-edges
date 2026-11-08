package egress

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBindingGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/binding.txt")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, Binding(uuid.MustParse("00000000-0000-0000-0000-000000000001")),
		strings.TrimSpace(string(want)))
	eq(t, len(Binding(uuid.New())), 52)
}

func TestBoxKeyFileIsPrivateAndOpensSealedBoxes(t *testing.T) {
	dir := t.TempDir()
	pub, err := NewBoxKey(dir, "k7")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "egress_box_k7")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, st.Mode().Perm(), os.FileMode(0o600))
	raw, _ := os.ReadFile(path)
	k, err := ParseBoxKey("k7", raw)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, k.Public(), pub)
	// A second key never replaces the first
	_, err = NewBoxKey(dir, "k7")
	eq(t, err != nil, true)
	_, err = NewBoxKey(dir, "bad id")
	eq(t, err != nil, true)
	_, err = ParseBoxKey("k7", []byte(base64.StdEncoding.EncodeToString([]byte("short"))))
	eq(t, err != nil, true)
}

func TestKeysOpenWithTheListedID(t *testing.T) {
	a, b := newBoxKey(t, "a"), newBoxKey(t, "b")
	h := &harness{key: a}
	es, _ := h.secret(t, uuid.New(),
		secretSpec{name: "N", value: "v", hosts: []string{"x.example"}})
	keys := NewKeys(b, a)
	pl, err := keys.openPayload("a", es.GetValue().GetBox())
	if err != nil {
		t.Fatal(err)
	}
	eq(t, pl.Value, "v")
	_, err = keys.openPayload("b", es.GetValue().GetBox())
	eq(t, err != nil, true)
	_, err = keys.openPayload("zz", es.GetValue().GetBox())
	eq(t, err != nil, true)
	_, err = keys.openPayload("a", bytes.Repeat([]byte{1}, 80))
	eq(t, err != nil, true)
}

func TestPayloadMatchesHostsAndHeadersAsSets(t *testing.T) {
	p := Payload{V: 1, Binding: "B", Name: "N", Hosts: []string{"b.example", "A.example."},
		Headers: []string{"X-Key"}}
	eq(t, p.matches("B", "N", []string{"a.example", "b.example"}, []string{"x-key"}, false), true)
	eq(t, p.matches("B", "N", []string{"a.example"}, []string{"x-key"}, false), false)
	eq(t, p.matches("B", "N", []string{"a.example", "b.example", "c.example"},
		[]string{"x-key"}, false), false)
	eq(t, p.matches("B", "N", []string{"a.example", "b.example"}, nil, false), false)
	eq(t, p.matches("B", "N", []string{"a.example", "b.example"}, []string{"x-key"}, true), false)
	eq(t, p.matches("OTHER", "N", []string{"a.example", "b.example"}, []string{"x-key"}, false),
		false)
	eq(t, p.matches("B", "M", []string{"a.example", "b.example"}, []string{"x-key"}, false), false)
	p.V = 2
	eq(t, p.matches("B", "N", []string{"a.example", "b.example"}, []string{"x-key"}, false), false)
}
