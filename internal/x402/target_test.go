package x402

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/oynozan/bugnet-proto/vectors"
)

// pathVectors is paths.json from bugnet-proto, the cases every implementation shares
type pathVectors struct {
	V     int `json:"v"`
	Paths []struct {
		Path string `json:"path"`
		OK   bool   `json:"ok"`
	} `json:"paths"`
	Queries []struct {
		Query string `json:"query"`
		OK    bool   `json:"ok"`
	} `json:"queries"`
}

func TestSharedPathVectors(t *testing.T) {
	raw, err := vectors.X402.ReadFile("x402/paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var f pathVectors
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	eq(t, f.V, 1)
	if len(f.Paths) == 0 || len(f.Queries) == 0 {
		t.Fatal("paths.json has no cases")
	}
	for _, c := range f.Paths {
		got, ok := CheckTarget(c.Path)
		if ok != c.OK {
			t.Errorf("path %q gives ok %v, the vectors say %v", c.Path, ok, c.OK)
			continue
		}
		if ok {
			eq(t, got, Target{Path: c.Path})
		}
	}
	for _, c := range f.Queries {
		got, ok := CheckTarget("/search?" + c.Query)
		if ok != c.OK {
			t.Errorf("query %q gives ok %v, the vectors say %v", c.Query, ok, c.OK)
			continue
		}
		if ok {
			eq(t, got, Target{Path: "/search", RawQuery: c.Query, HasQuery: true})
		}
	}
}

func TestQuerySplit(t *testing.T) {
	for raw, want := range map[string]Target{
		"/a?b?c":  {Path: "/a", RawQuery: "b?c", HasQuery: true},
		"/a?":     {Path: "/a", HasQuery: true},
		"/a":      {Path: "/a"},
		"/a/?x=%": {Path: "/a/", RawQuery: "x=%", HasQuery: true},
	} {
		got, ok := CheckTarget(raw)
		if !ok {
			t.Errorf("%q refused", raw)
			continue
		}
		eq(t, got, want)
	}
}

func TestCheckTargetRefusals(t *testing.T) {
	for _, raw := range []string{
		"", "?a=1", "/a/..?x=1", "/a?q=a b", "/a?q=\x7f", "/a?q=\x00", "/a%2e%2e?x", "/a%", "/a%g0",
		"/a%0g", "/%2E%2E/x", "/a/.", "/a/./", "./a", "//a", "/a\x80",
	} {
		if got, ok := CheckTarget(raw); ok {
			t.Errorf("%q passed as %+v", raw, got)
		}
	}
}

func TestTargetSHA256Golden(t *testing.T) {
	const want = "66847c155303d7d6bf0e12b41c13398febdeb5fb9fe18ca4063656e57543accd"
	const placement = "00000000-0000-0000-0000-000000000001"
	got := TargetSHA256(placement, "/v1/auto/chat/completions?stream=true")
	eq(t, hex.EncodeToString(got), want)

	upper := TargetSHA256("0000000A-0000-0000-0000-00000000000B", "/x")
	eq(t, upper, TargetSHA256("0000000a-0000-0000-0000-00000000000b", "/x"))

	base := TargetSHA256(placement, "/search?q=a")
	for _, other := range [][]byte{
		TargetSHA256(placement, "/search?q=b"),
		TargetSHA256(placement, "/search?q=a&"),
		TargetSHA256(placement, "/search"),
		TargetSHA256("00000000-0000-0000-0000-000000000002", "/search?q=a"),
	} {
		if string(other) == string(base) {
			t.Errorf("two targets share the hash %x", base)
		}
	}
}
