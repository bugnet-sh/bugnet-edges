package egress

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// placeholderShape is the placeholder every secret gets, bnsec_ and 26 base32 characters
var placeholderShape = regexp.MustCompile(`bnsec_[a-z2-7]{26}`)

// token68 is RFC 7235's token68, the credentials of Bearer, token and the like
var token68 = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

// secret is one opened secret of a placement, its value zeroed when the placement lets it go
type secret struct {
	name  string
	hosts map[string]bool

	// print is the fingerprint of the record and box the value came from
	print [32]byte

	mu    sync.RWMutex
	value []byte
	dead  bool
}

// read returns the value, false once the secret was zeroed
func (s *secret) read() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.value), !s.dead
}

func (s *secret) zero() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.value)
	s.value = nil
	s.dead = true
}

// secretSet is a placement's openable secrets by the SHA-256 of their placeholders
type secretSet struct {
	byHash map[[32]byte]*secret
	// headers are the names the host's secrets list, besides Authorization, in canonical form
	headers map[string][]string
}

func (s *secretSet) zero() {
	if s == nil {
		return
	}
	for _, x := range s.byHash {
		x.zero()
	}
}

// pair replaces a value the response may echo with the placeholder it came from
type pair struct{ value, placeholder string }

// swapped is what one request's swap did
type swapped struct {
	names []string
	scrub []pair
	// missing is set when a placeholder matched the shape but belongs to no secret held
	missing bool
}

func (w swapped) did() bool {
	return len(w.names) > 0
}

// swapHeaders replaces placeholders in Authorization and the host's named headers
func swapHeaders(h http.Header, host string, set *secretSet) swapped {
	var out swapped
	if set == nil {
		return out
	}
	for i, v := range h["Authorization"] {
		h["Authorization"][i] = swapAuthorization(v, host, set, &out)
	}
	for _, name := range set.headers[host] {
		key := textproto.CanonicalMIMEHeaderKey(name)
		if key == "Authorization" {
			continue
		}
		for i, v := range h[key] {
			h[key][i] = swapText(v, host, set, &out)
		}
	}
	return out
}

// swapAuthorization handles Basic by its decoded text and every other scheme by its token68
func swapAuthorization(v, host string, set *secretSet, out *swapped) string {
	scheme, cred, ok := strings.Cut(v, " ")
	cred = strings.TrimLeft(cred, " ")
	if !ok || scheme == "" || cred == "" {
		return v
	}
	if strings.EqualFold(scheme, "basic") {
		raw, err := base64.StdEncoding.DecodeString(cred)
		if err != nil {
			return v
		}
		var inner swapped
		text := swapText(string(raw), host, set, &inner)
		out.merge(inner)
		if !inner.did() {
			return v
		}
		built := base64.StdEncoding.EncodeToString([]byte(text))
		out.scrub = append(out.scrub, pair{built, firstPlaceholder(string(raw))})
		return scheme + " " + built
	}
	if !token68.MatchString(cred) {
		out.noteMissing(cred, set)
		return v
	}
	return scheme + " " + swapText(cred, host, set, out)
}

func (w *swapped) merge(o swapped) {
	w.names = append(w.names, o.names...)
	w.scrub = append(w.scrub, o.scrub...)
	w.missing = w.missing || o.missing
}

// noteMissing sets missing when text holds a placeholder shape no secret owns
func (w *swapped) noteMissing(text string, set *secretSet) {
	for _, m := range placeholderShape.FindAllString(text, -1) {
		if set.byHash[sha256.Sum256([]byte(m))] == nil {
			w.missing = true
		}
	}
}

func firstPlaceholder(text string) string {
	return placeholderShape.FindString(text)
}

// swapText replaces each placeholder the host may use, leaving every other match as it is
func swapText(text, host string, set *secretSet, out *swapped) string {
	return placeholderShape.ReplaceAllStringFunc(text, func(m string) string {
		s := set.byHash[sha256.Sum256([]byte(m))]
		if s == nil {
			out.missing = true
			return m
		}
		if !s.hosts[host] {
			return m
		}
		val, ok := s.read()
		if !ok || strings.ContainsAny(val, "\r\n\x00") {
			return m
		}
		if !slices.Contains(out.names, s.name) {
			out.names = append(out.names, s.name)
		}
		out.scrub = append(out.scrub, pair{val, m})
		return val
	})
}

// scrubHeader replaces every echoed value in h with its placeholder, longest value first
func scrubHeader(h http.Header, pairs []pair) {
	if len(pairs) == 0 {
		return
	}
	pairs = slices.Clone(pairs)
	slices.SortStableFunc(pairs, func(a, b pair) int { return len(b.value) - len(a.value) })
	for _, vs := range h {
		for i, v := range vs {
			for _, p := range pairs {
				if p.value != "" && strings.Contains(v, p.value) {
					v = strings.ReplaceAll(v, p.value, p.placeholder)
				}
			}
			vs[i] = v
		}
	}
}
