package preview

import (
	"net/http"
	"regexp"
	"strings"
)

// The names a preview token travels under, DP 8.2.1
const (
	queryName   = "bugnet_token"
	headerName  = "Bugnet-Token"
	cookieName  = "__Host-bnp"
	tokenPrefix = "bnp_"
	skipHeader  = "Bugnet-Skip-Warning"
)

// tokenShape is bnp_ and 256 bits in base64url without padding, DP 4.4
var tokenShape = regexp.MustCompile(`^bnp_[A-Za-z0-9_-]{43}$`)

// source is where a request's token came from
type source int

const (
	fromNone source = iota
	fromQuery
	fromHeader
	fromCookie
)

// stripToken drops each bugnet_token pair holding a bnp_ value and keeps the rest byte for byte
func stripToken(raw string) (rest, token string) {
	if !strings.Contains(raw, queryName) {
		return raw, ""
	}
	pairs := strings.Split(raw, "&")
	kept := pairs[:0]
	for _, p := range pairs {
		k, v, _ := strings.Cut(p, "=")
		if k == queryName && strings.HasPrefix(v, tokenPrefix) {
			if token == "" {
				token = v
			}
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&"), token
}

// findToken looks in the query, then the header, then the cookie
func findToken(r *http.Request) (string, source) {
	if _, t := stripToken(r.URL.RawQuery); t != "" {
		return t, fromQuery
	}
	if t := r.Header.Get(headerName); t != "" {
		return t, fromHeader
	}
	if t := cookieToken(r); t != "" {
		return t, fromCookie
	}
	return "", fromNone
}

func cookieToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// cookieFor is the session cookie that carries tok on the preview's later requests
func cookieFor(tok string) string {
	return (&http.Cookie{
		Name: cookieName, Value: tok, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}).String()
}

// target is the request's path and query without the token, where Continue sends the browser
func target(r *http.Request) string {
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	if rest, _ := stripToken(r.URL.RawQuery); rest != "" {
		p += "?" + rest
	}
	return p
}
