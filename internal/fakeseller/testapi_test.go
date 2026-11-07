package fakeseller

import (
	"encoding/json"
	"net/http"
	"testing"
)

// testList reads one list of the test API with the token tok
func testList(t *testing.T, h http.Handler, path string) []string {
	t.Helper()
	w := send(h, http.MethodGet, path, http.Header{"Authorization": {"Bearer tok"}}, "")
	eq(t, w.Code, http.StatusOK)
	eq(t, w.Header().Get("Content-Type"), "application/json")
	var out []string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTestAPINeedsItsToken(t *testing.T) {
	closed := New(config(InMemory()))
	for _, path := range []string{"/__test/payloads", "/__test/settled"} {
		w := send(closed, http.MethodGet, path, http.Header{"Authorization": {"Bearer tok"}}, "")
		eq(t, w.Code, http.StatusNotFound)
	}

	ledger := InMemory()
	c := config(ledger)
	c.TestToken = "tok"
	h := New(c)
	for _, auth := range []string{"", "Bearer", "Bearer to", "Bearer tok2", "Basic tok", "tok"} {
		header := http.Header{}
		if auth != "" {
			header.Set("Authorization", auth)
		}
		w := send(h, http.MethodGet, "/__test/payloads", header, "")
		eq(t, w.Code, http.StatusUnauthorized)
		eq(t, w.Header().Get("WWW-Authenticate"), "Bearer")
	}
	eq(t, testList(t, h, "/__test/payloads"), []string{})
	eq(t, testList(t, h, "/__test/settled"), []string{})

	_, value := paid(t, h, "/ok/x", "r1")
	send(h, http.MethodGet, "/ok/x", paying(value), "")
	eq(t, testList(t, h, "/__test/payloads"), []string{value, value})
	eq(t, testList(t, h, "/__test/settled"), signatures(ledger))
	eq(t, len(signatures(ledger)), 1)

	header := http.Header{"Authorization": {"bearer tok"}}
	eq(t, send(h, http.MethodGet, "/__test/settled", header, "").Code, http.StatusOK)
	header = http.Header{"Authorization": {"Bearer tok"}}
	eq(t, send(h, http.MethodPost, "/__test/settled", header, "").Code,
		http.StatusMethodNotAllowed)
	eq(t, send(h, http.MethodGet, "/__test/other", header, "").Code, http.StatusNotFound)
}
