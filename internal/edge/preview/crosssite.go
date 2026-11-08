package preview

import (
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// cookieAllowed is DP 8.2.3's rule for a request whose only token is the cookie
func cookieAllowed(r *http.Request, host string) bool {
	origin := "https://" + host
	up := isUpgrade(r)
	site := r.Header.Get("Sec-Fetch-Site")
	if site == "" {
		if r.Method != http.MethodGet || up {
			o := r.Header.Get("Origin")
			return o == "" || o == origin
		}
		return true
	}
	ok := site == "same-origin" || site == "none" ||
		r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
			r.Header.Get("Sec-Fetch-Dest") == "document"
	if ok && up {
		ok = r.Header.Get("Origin") == origin
	}
	return ok
}

// isUpgrade reports a request asking to switch protocols, a WebSocket in practice
func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" &&
		httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade")
}

// browserLoad reports a browser loading a page, the only request the interstitial stops
func browserLoad(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe", "frame", "embed", "object":
		return true
	case "":
	default:
		return false
	}
	for name := range r.Header {
		if strings.HasPrefix(name, "Sec-Fetch-") {
			return false
		}
	}
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}
