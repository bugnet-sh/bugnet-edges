package x402

import (
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Service is one x402 service as ResolveTunnel carries it
type Service struct {
	ID, Host, Prefix, Method string
	MaxPriceMicros           int64
	PayTo, PaidPath          string
}

// Match picks the service for path and method on one host, XS 6.6 step 3
func Match(services []Service, path, method string) (Service, bool) {
	var under []Service
	byMethod := false
	for _, s := range services {
		if prefixShaped(s.Prefix) && strings.HasPrefix(path+"/", s.Prefix) {
			under = append(under, s)
			byMethod = byMethod || s.Method == method
		}
	}
	var best Service
	found := false
	for _, s := range under {
		if byMethod && s.Method != method {
			continue
		}
		longer := len(s.Prefix) > len(best.Prefix)
		if !found || longer || len(s.Prefix) == len(best.Prefix) && s.ID < best.ID {
			best, found = s, true
		}
	}
	return best, found
}

// prefixShaped is the router's prefix shape, so a malformed one never enables a whole host
func prefixShaped(p string) bool {
	return len(p) >= 3 && p[0] == '/' && p[len(p)-1] == '/'
}

// Pay is what a matched service can do for this request
type Pay int

// The values of Pay, in the order Payability checks them
const (
	Payable Pay = iota
	SelfPaid
	MethodNotEnabled
	PathNotPaid
)

// Payability says whether Bugnet may pay this request, path being the target without its query
func Payability(s Service, path, method string, h http.Header) Pay {
	switch {
	case len(values(h, "payment-signature")) > 0 || len(values(h, "x-payment")) > 0:
		return SelfPaid
	case method != s.Method:
		return MethodNotEnabled
	case s.PaidPath != "" && s.PaidPath != path:
		return PathNotPaid
	}
	return Payable
}

// IsUpgrade is XS 6.6 step 1
func IsUpgrade(r *http.Request) bool {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		return true
	}
	for _, name := range []string{"upgrade", "http2-settings", ":protocol"} {
		if len(values(r.Header, name)) > 0 {
			return true
		}
	}
	return httpguts.HeaderValuesContainsToken(values(r.Header, "connection"), "upgrade")
}

// DropDummyKey deletes each Authorization value that is exactly Bearer x402, scheme in any case
func DropDummyKey(h http.Header) bool {
	dropped := false
	for k, vs := range h {
		if strings.ToLower(k) != "authorization" {
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(vs), isDummyKey)
		if len(kept) == len(vs) {
			continue
		}
		dropped = true
		if len(kept) == 0 {
			delete(h, k)
		} else {
			h[k] = kept
		}
	}
	return dropped
}

// isDummyKey is the placeholder key, one space and the token case-sensitive
func isDummyKey(v string) bool {
	scheme, token, ok := strings.Cut(v, " ")
	return ok && token == "x402" && strings.EqualFold(scheme, "bearer")
}
