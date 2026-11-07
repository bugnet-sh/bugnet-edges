// Package fakeseller is the fake x402 seller of XS 11.2, each mode chosen by path prefix
package fakeseller

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oynozan/bugnet-edges/internal/x402"
)

// Payment is the transfer a payer sent, as the seller decoded it
type Payment struct {
	Value    string
	Accepted x402.Entry
}

// Settler completes and submits a payer's transfer, answering its signature
type Settler interface {
	Settle(ctx context.Context, p Payment) (string, error)
}

// SettleError is a failed settle with the errorReason a facilitator gave
type SettleError struct {
	Reason string
}

// Error names the reason
func (e *SettleError) Error() string {
	return "fakeseller: settle failed with " + e.Reason
}

// Config is one seller
type Config struct {
	PayTo, PayToTokenAccount string
	FeePayer, BugnetFeePayer string
	Settler                  Settler
	// Late, Slow and Stall are the mode delays, 20 s, 120 s (XS 11.2) and 40 s by default
	Late, Slow, Stall time.Duration
	// Second is the unit of /hold/, 1 s by default
	Second time.Duration
	// SSEEvery and SSEFor pace /sse/, 5 s and 3 minutes by default
	SSEEvery, SSEFor time.Duration
	// TestToken opens the test API when not empty
	TestToken string
	// RedirectTo is the other host's URL /redirect/ sends a paid retry to, example.com by default
	RedirectTo string
}

// The defaults of Config
const (
	defaultLate     = 20 * time.Second
	defaultSlow     = 120 * time.Second
	defaultStall    = 40 * time.Second
	defaultSecond   = time.Second
	defaultSSEEvery = 5 * time.Second
	defaultSSEFor   = 3 * time.Minute
	defaultRedirect = "https://example.com/"
)

const (
	// maxOffered bounds the entries kept per prefix, which only /switch/ grows
	maxOffered = 64
	// maxKept bounds the payloads seen, the /pid/ answers and each test API list
	maxKept = 1024
	// maxPayload bounds a PAYMENT-SIGNATURE value taken as a payment, far above a real one
	maxPayload = 16 << 10
	// maxBody bounds what a paid answer reads of a body, above the most egress keeps for a retry
	maxBody = 8 << 20
	// lateReason is the errorReason /late/ answers, a facilitator's confirmation timeout
	lateReason = "settle_exact_svm_transaction_confirmation_timed_out"
	// unexpectedReason is the errorReason of a failed settle that gave none
	unexpectedReason = "unexpected_settle_error"
)

// pidID is the shape of a payment-identifier id, as the x402 extension's schema allows
var pidID = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,128}$`)

// seller serves one Config
type seller struct {
	c Config

	mu sync.Mutex
	// switches counts the 402s /switch/ offered
	switches int
	// offered holds the accepts entries put in 402s, by mode prefix
	offered map[string][]offer
	// seen holds the SHA-256 of the payloads a paid mode took
	seen *kept[[sha256.Size]byte, bool]
	// cached holds /pid/'s answers by payment id, or by payload hash without one
	cached *kept[string, answer]
	// limit bounds each test API list
	limit int
	// payloads and settled are the test API's lists, kept only with a TestToken
	payloads, settled []string
}

// kept is a map that forgets its oldest key once it holds limit keys
type kept[K comparable, V any] struct {
	limit int
	m     map[K]V
	order []K
}

// newKept makes a kept of at most limit keys
func newKept[K comparable, V any](limit int) *kept[K, V] {
	return &kept[K, V]{limit: limit, m: map[K]V{}}
}

// get is the value kept for key
func (k *kept[K, V]) get(key K) (V, bool) {
	v, ok := k.m[key]
	return v, ok
}

// put keeps v for key, forgetting the oldest key when full
func (k *kept[K, V]) put(key K, v V) {
	if _, ok := k.m[key]; !ok {
		if len(k.order) >= k.limit {
			delete(k.m, k.order[0])
			k.order = k.order[1:]
		}
		k.order = append(k.order, key)
	}
	k.m[key] = v
}

// appendKept appends v to list, dropping the oldest past limit
func appendKept(list []string, v string, limit int) []string {
	if len(list) >= limit {
		list = slices.Delete(list, 0, 1)
	}
	return append(list, v)
}

// offer is one accepts entry a 402 carried, decoded for a deep comparison
type offer struct {
	json  any
	entry x402.Entry
}

// answer is a paid answer as written, kept by /pid/ for repeats
type answer struct {
	status int
	header http.Header
	body   []byte
}

// New serves the modes of XS 11.2 by path prefix
func New(c Config) http.Handler {
	return newSeller(c, maxKept)
}

// newSeller is a seller keeping at most limit entries in each store
func newSeller(c Config, limit int) *seller {
	if c.Settler == nil {
		panic("fakeseller: Config.Settler is nil")
	}
	c.Late = orDefault(c.Late, defaultLate)
	c.Slow = orDefault(c.Slow, defaultSlow)
	c.Stall = orDefault(c.Stall, defaultStall)
	c.Second = orDefault(c.Second, defaultSecond)
	c.SSEEvery = orDefault(c.SSEEvery, defaultSSEEvery)
	c.SSEFor = orDefault(c.SSEFor, defaultSSEFor)
	if c.RedirectTo == "" {
		c.RedirectTo = defaultRedirect
	}
	return &seller{
		c:       c,
		offered: map[string][]offer{},
		seen:    newKept[[sha256.Size]byte, bool](limit),
		cached:  newKept[string, answer](limit),
		limit:   limit,
	}
}

// orDefault is d, or def when d is not positive
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (s *seller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Else net/http reads up to 256 KiB of an unread body before the first header
	_ = http.NewResponseController(w).EnableFullDuplex()
	if strings.HasPrefix(r.URL.Path, testPrefix) {
		s.testAPI(w, r)
		return
	}
	values := r.Header.Values("Payment-Signature")
	for _, v := range values {
		if _, ok := decodePayload(v); ok {
			s.receive(v)
		}
	}
	value := ""
	if len(values) == 1 {
		value = values[0]
	}
	rt, ok := parse(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rt.name == "echo" {
		for name, vs := range r.Header {
			for _, v := range vs {
				w.Header().Add("Echo-"+name, v)
			}
		}
	}
	switch rt.name {
	case "free":
		writeJSON(w, http.StatusOK, map[string]any{"mode": rt.name})
		return
	case "hold":
		if wait(r.Context(), time.Duration(rt.n)*s.c.Second) {
			writeJSON(w, http.StatusOK, map[string]any{"mode": rt.name, "seconds": rt.n})
		}
		return
	case "sse":
		s.sse(w, r)
		return
	case "v1only":
		writeJSON(w, http.StatusPaymentRequired, s.v1(r))
		return
	}
	var body *bodySum
	if rt.name == "post400" {
		body = readBody(r)
		if r.Method == http.MethodPost && body.n == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty body"})
			return
		}
	}
	if len(values) == 0 {
		if rt.name != "stall" || wait(r.Context(), s.c.Stall) {
			s.require(w, r, rt)
		}
		return
	}
	s.pay(w, r, rt, value, body)
}

// require answers 402 with the mode's terms and remembers the entry it offered
func (s *seller) require(w http.ResponseWriter, r *http.Request, rt route) {
	entry, extra := s.terms(rt)
	req := x402.Required{Version: 2, Accepts: []x402.Entry{entry}}
	header := x402.EncodeRequired(req, resourceOf(r), extra)
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		panic("fakeseller: EncodeRequired wrote other than base64: " + err.Error())
	}
	var top map[string]json.RawMessage
	var accepts []json.RawMessage
	if json.Unmarshal(raw, &top) != nil || json.Unmarshal(top["accepts"], &accepts) != nil ||
		len(accepts) != 1 {
		panic("fakeseller: EncodeRequired wrote other than one accepts entry")
	}
	if rt.name == "pid" {
		top["extensions"] = mustJSON(map[string]any{"payment-identifier": pidOffer})
		raw = mustJSON(top)
		header = base64.StdEncoding.EncodeToString(raw)
	}
	s.remember(rt.prefix, accepts[0], entry)
	w.Header().Set("Payment-Required", header)
	writeRaw(w, http.StatusPaymentRequired, raw)
}

// remember keeps an offered entry for its prefix, dropping the oldest past maxOffered
func (s *seller) remember(prefix string, raw json.RawMessage, entry x402.Entry) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.offered[prefix]
	for _, o := range list {
		if reflect.DeepEqual(o.json, v) {
			return
		}
	}
	if len(list) >= maxOffered {
		list = slices.Delete(list, 0, 1)
	}
	s.offered[prefix] = append(list, offer{json: v, entry: entry})
}

// offeredEntry is the entry offered on prefix that accepted deeply equals
func (s *seller) offeredEntry(prefix string, accepted json.RawMessage) (x402.Entry, bool) {
	var v any
	if len(accepted) == 0 || json.Unmarshal(accepted, &v) != nil {
		return x402.Entry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.offered[prefix] {
		if reflect.DeepEqual(o.json, v) {
			return o.entry, true
		}
	}
	return x402.Entry{}, false
}

// payload is a PAYMENT-SIGNATURE value's fields the seller reads
type payload struct {
	Version    int             `json:"x402Version"`
	Accepted   json.RawMessage `json:"accepted"`
	Extensions struct {
		PID struct {
			Info struct {
				ID string `json:"id"`
			} `json:"info"`
		} `json:"payment-identifier"`
	} `json:"extensions"`
}

// decodePayload reads a PAYMENT-SIGNATURE value as padded standard base64 of a v2 payload
func decodePayload(value string) (payload, bool) {
	var p payload
	if len(value) > maxPayload {
		return payload{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(raw, &p) != nil || p.Version != 2 {
		return payload{}, false
	}
	return p, true
}

// pay serves a request carrying a payment, a new 402 for one seen before or never offered
func (s *seller) pay(
	w http.ResponseWriter, r *http.Request, rt route, value string, body *bodySum,
) {
	p, ok := decodePayload(value)
	sum := sha256.Sum256([]byte(value))
	key := "payload:" + hex.EncodeToString(sum[:])
	if id := p.Extensions.PID.Info.ID; pidID.MatchString(id) {
		key = "id:" + id
	}
	if rt.name == "pid" {
		if a, hit := s.cachedAnswer(key); hit {
			a.write(w)
			return
		}
	}
	if !ok || !s.firstSight(sum) {
		s.require(w, r, rt)
		return
	}
	entry, ok := s.offeredEntry(rt.prefix, p.Accepted)
	if !ok {
		s.require(w, r, rt)
		return
	}
	payment := Payment{Value: value, Accepted: entry}
	if body == nil {
		body = readBody(r)
	}
	switch rt.name {
	case "reject":
		s.require(w, r, rt)
		return
	case "lie":
		made := sha512.Sum512([]byte("fakeseller lie " + value))
		s.paid(rt, r, body, entry.Network, x402.Encode58(made[:])).write(w)
		return
	case "late":
		time.AfterFunc(s.c.Late, func() {
			_, _ = s.settle(context.Background(), payment)
		})
		s.unsettled(rt, r, body, entry.Network, lateReason).write(w)
		return
	case "slow":
		t := time.NewTimer(s.c.Slow)
		select {
		case <-t.C:
		case <-r.Context().Done():
			go func() {
				<-t.C
				_, _ = s.settle(context.Background(), payment)
			}()
			return
		}
	}
	sig, err := s.settle(context.WithoutCancel(r.Context()), payment)
	switch {
	case err != nil && rt.name == "slow":
		s.unsettled(rt, r, body, entry.Network, reasonOf(err)).write(w)
		return
	case err != nil:
		s.require(w, r, rt)
		return
	}
	a := s.paid(rt, r, body, entry.Network, sig)
	if rt.name == "pid" {
		s.mu.Lock()
		s.cached.put(key, a)
		s.mu.Unlock()
	}
	a.write(w)
}

// reasonOf is the errorReason of a failed settle, the Settler's own when it gave one
func reasonOf(err error) string {
	var se *SettleError
	if errors.As(err, &se) && se.Reason != "" {
		return se.Reason
	}
	return unexpectedReason
}

// unsettled is a mode's 200 whose PAYMENT-RESPONSE says success false with reason
func (s *seller) unsettled(
	rt route, r *http.Request, body *bodySum, network, reason string,
) answer {
	a := s.paid(rt, r, body, network, "")
	a.header.Set("Payment-Response", settleHeader("", network, reason))
	return a
}

// paid is a mode's answer to a paid retry, sig empty for none in PAYMENT-RESPONSE
func (s *seller) paid(rt route, r *http.Request, body *bodySum, network, sig string) answer {
	a := answer{status: http.StatusOK, header: http.Header{}}
	if sig != "" && rt.name != "silent" {
		a.header.Set("Payment-Response", settleHeader(sig, network, ""))
	}
	switch rt.name {
	case "settle500", "settle500-wait":
		a.status = http.StatusInternalServerError
	case "settle429", "settle429-wait":
		a.status = http.StatusTooManyRequests
	case "redirect":
		a.status = http.StatusFound
		a.header.Set("Location", s.c.RedirectTo)
	}
	if strings.HasSuffix(rt.name, "-wait") {
		a.header.Set("Retry-After", "15")
	}
	if rt.name == "echo" {
		a.body = mustJSON(echo(r))
		return a
	}
	a.body = mustJSON(map[string]any{
		"mode": rt.name, "body_bytes": body.n, "body_sha256": hex.EncodeToString(body.sum[:]),
	})
	return a
}

// echo is what /echo/ saw, PAYMENT-SIGNATURE only as its SHA-256 so no payload reaches a body
func echo(r *http.Request) map[string]any {
	headers := map[string][]string{}
	for name, vs := range r.Header {
		for _, v := range vs {
			if name == "Payment-Signature" {
				sum := sha256.Sum256([]byte(v))
				v = "sha256:" + hex.EncodeToString(sum[:])
			}
			headers[name] = append(headers[name], v)
		}
	}
	return map[string]any{
		"method": r.Method, "host": r.Host, "target": r.URL.RequestURI(), "headers": headers,
	}
}

// settle runs the Settler and lists what it answered for the test API
func (s *seller) settle(ctx context.Context, p Payment) (string, error) {
	sig, err := s.c.Settler.Settle(ctx, p)
	if err != nil {
		return "", err
	}
	if s.c.TestToken != "" {
		s.mu.Lock()
		s.settled = appendKept(s.settled, sig, s.limit)
		s.mu.Unlock()
	}
	return sig, nil
}

// receive lists a PAYMENT-SIGNATURE value for the test API
func (s *seller) receive(value string) {
	if s.c.TestToken == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads = appendKept(s.payloads, value, s.limit)
}

// firstSight marks a payload's SHA-256 seen, false when it was seen before
func (s *seller) firstSight(sum [sha256.Size]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.seen.get(sum); seen {
		return false
	}
	s.seen.put(sum, true)
	return true
}

// cachedAnswer is /pid/'s answer for key
func (s *seller) cachedAnswer(key string) (answer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cached.get(key)
}

// sse writes one event every SSEEvery for SSEFor, flushing each at once
func (s *seller) sse(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	tick := time.NewTicker(s.c.SSEEvery)
	defer tick.Stop()
	for i := 1; i <= int(s.c.SSEFor/s.c.SSEEvery); i++ {
		select {
		case <-tick.C:
		case <-r.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "data: "+strconv.Itoa(i)+"\n\n"); err != nil {
			return
		}
		if rc.Flush() != nil {
			return
		}
	}
}

// write sends a kept answer
func (a answer) write(w http.ResponseWriter) {
	for name, vs := range a.header {
		w.Header()[name] = slices.Clone(vs)
	}
	writeRaw(w, a.status, a.body)
}

// bodySum is a request body's length and SHA-256
type bodySum struct {
	n   int64
	sum [sha256.Size]byte
}

// readBody reads at most maxBody of a request's body
func readBody(r *http.Request) *bodySum {
	h := sha256.New()
	n, _ := io.CopyN(h, r.Body, maxBody)
	b := &bodySum{n: n}
	h.Sum(b.sum[:0])
	return b
}

// settleResponse is x402 v2's PAYMENT-RESPONSE
type settleResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
}

// settleHeader is a PAYMENT-RESPONSE value, a failure when reason is not empty
func settleHeader(sig, network, reason string) string {
	res := settleResponse{
		Success: reason == "", ErrorReason: reason, Transaction: sig, Network: network,
	}
	return base64.StdEncoding.EncodeToString(mustJSON(res))
}

// resourceOf is the URL a 402 protects, its path without the query as x402 servers write it
func resourceOf(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}

// wait sleeps d, false when the request ends first
func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// writeJSON answers v as JSON with its length
func writeJSON(w http.ResponseWriter, status int, v any) {
	writeRaw(w, status, mustJSON(v))
}

// writeRaw answers JSON bytes with their length
func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// mustJSON marshals a value the seller built, which cannot fail
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("fakeseller: " + err.Error())
	}
	return b
}
