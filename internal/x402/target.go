package x402

import (
	"crypto/sha256"
	"strings"
)

// Target is a request target that passed XS 6.7, split at the first question mark
type Target struct {
	Path, RawQuery string
	HasQuery       bool
}

// CheckTarget applies XS 6.7 to the raw target, r.RequestURI or the HTTP/2 :path
func CheckTarget(raw string) (Target, bool) {
	path, query, hasQuery := strings.Cut(raw, "?")
	if !pathOK(path) || !printable(query) {
		return Target{}, false
	}
	return Target{Path: path, RawQuery: query, HasQuery: hasQuery}, true
}

// pathOK is XS 6.7's path rule, which an absolute-form target or an asterisk fails at once
func pathOK(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || !printable(p) {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case ';', '\\':
			return false
		case '%':
			if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
				return false
			}
			if b := unhex(p[i+1])<<4 | unhex(p[i+2]); b < 0x20 || b >= 0x7f ||
				strings.IndexByte(`/\.;%`, b) >= 0 {
				return false
			}
			i += 2
		}
	}
	return true
}

// printable is true when every byte is visible ASCII, 0x21 to 0x7e
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// unhex is the value of a byte isHex accepted
func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// TargetSHA256 is SHA-256 of the lower-case placement id, a zero byte and the full raw target
func TargetSHA256(placementID, rawTarget string) []byte {
	sum := sha256.Sum256([]byte(strings.ToLower(placementID) + "\x00" + rawTarget))
	return sum[:]
}
