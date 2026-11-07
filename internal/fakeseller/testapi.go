package fakeseller

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// testPrefix starts every path of the test API
const testPrefix = "/__test/"

// testAPI lists the payloads received and the signatures settled, only for the bearer TestToken
func (s *seller) testAPI(w http.ResponseWriter, r *http.Request) {
	if s.c.TestToken == "" {
		http.NotFound(w, r)
		return
	}
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") ||
		subtle.ConstantTimeCompare([]byte(token), []byte(s.c.TestToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var list *[]string
	switch r.URL.Path {
	case testPrefix + "payloads":
		list = &s.payloads
	case testPrefix + "settled":
		list = &s.settled
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	out := append([]string{}, (*list)...)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}
