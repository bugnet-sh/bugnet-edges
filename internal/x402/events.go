package x402

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The longest fields of XS 8.1
const (
	maxEventPath   = 80
	maxEventHost   = 253
	maxEventMethod = 10
	maxRefusedName = 63
)

// maxRefusedNames is how many names a placement's refused_host rows carry a minute
const maxRefusedNames = 10

// otherMethod stands for a method outside ^[A-Z]{1,10}$
const otherMethod = "OTHER"

// NewRef is 16 random lower-case base32 characters
func NewRef() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(base32.StdEncoding.EncodeToString(b[:]))
}

// isRef says s has NewRef's shape
func isRef(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// Shape puts an event in XS 8's shape before it is queued
func Shape(ev *routerv1.X402Event, targetPassed bool) {
	if !targetPassed {
		ev.Path = ""
	}
	shape(ev)
}

// shape holds every rule of Shape that needs no word from the caller
func shape(ev *routerv1.X402Event) {
	switch {
	case ev.Status == EventRefusedHost:
		ev.Method, ev.Path = "", ""
	case !methodShaped(ev.Method):
		ev.Method = otherMethod
	}
	if r := Code(ev.Reason); r == CodePathRefused || r == CodeUpgradeRefused {
		ev.Path = ""
	}
	ev.Path, _, _ = strings.Cut(ev.Path, "?")
	ev.Path = visible(ev.Path, maxEventPath)
	ev.Host = visible(ev.Host, maxEventHost)
	if ev.Network != SolanaMainnet || ev.Asset != USDCMint || ev.Scheme != schemeExact {
		ev.AskedMicros, ev.Asset, ev.Network, ev.Scheme, ev.X402Version = 0, "", "", "", 0
		ev.PayTo = ""
	}
	if key, ok := Decode58(ev.PayTo); !ok || len(key) != 32 {
		ev.PayTo = ""
	}
}

// methodShaped says m matches ^[A-Z]{1,10}$
func methodShaped(m string) bool {
	if m == "" || len(m) > maxEventMethod {
		return false
	}
	for i := 0; i < len(m); i++ {
		if m[i] < 'A' || m[i] > 'Z' {
			return false
		}
	}
	return true
}

// visible is s cut to n bytes, empty when any byte is outside visible ASCII
func visible(s string, n int) string {
	if !printable(s) {
		return ""
	}
	return s[:min(len(s), n)]
}

// cleanName is a handshake's name lower-cased and cut to 63, false unless it is a-z, 0-9, . and -
func cleanName(sni string) (string, bool) {
	if sni == "" {
		return "", false
	}
	b := []byte(sni)
	for i, c := range b {
		switch {
		case 'A' <= c && c <= 'Z':
			b[i] = c + 'a' - 'A'
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '.', c == '-':
		default:
			return "", false
		}
	}
	return string(b[:min(len(b), maxRefusedName)]), true
}

// CanInvolveMoney is status paid, uncertain or payment_failed, or an amount above 0
func CanInvolveMoney(ev *routerv1.X402Event) bool {
	switch ev.GetStatus() {
	case EventPaid, EventUncertain, EventPaymentFailed:
		return true
	}
	return ev.GetAmountMicros() > 0
}

// PlacementHash is a placement id as logs carry it, the first 16 hex of its SHA-256
func PlacementHash(placement string) string {
	sum := sha256.Sum256([]byte(placement))
	return hex.EncodeToString(sum[:8])
}

// Events queues each placement's x402 rows, folds the rows that cannot involve money and sends them
type Events struct {
	send  Append
	flush time.Duration
	now   func() time.Time
	log   *slog.Logger
	// full wakes Run once a placement holds a whole batch never sent
	full chan struct{}
	// tick stands in for Run's flush ticker in tests
	tick <-chan time.Time
	// minuteAfter stands in for Run's minute timer in tests, firing once after d
	minuteAfter func(d time.Duration) <-chan time.Time

	mu          sync.Mutex
	places      map[string]*placeEvents
	hasServices func(placement string) bool
}

// NewEvents sends through send every flush, 2 s when flush is not above 0, on the clock now
func NewEvents(send Append, flush time.Duration, now func() time.Time, log *slog.Logger) *Events {
	if flush <= 0 {
		flush = maxFlush
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Events{
		send:   send,
		flush:  flush,
		now:    now,
		log:    log,
		full:   make(chan struct{}, 1),
		places: map[string]*placeEvents{},
	}
}

// SetServices gives RefusedHost its check that a placement has x402 services
func (e *Events) SetServices(has func(placement string) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hasServices = has
}

// Add queues one request's event, folding a row that cannot involve money
func (e *Events) Add(placement string, ev *routerv1.X402Event) {
	ev = proto.CloneOf(ev)
	shape(ev)
	ev.Count = 1
	if !isRef(ev.Ref) {
		ev.Ref = NewRef()
	}
	if ev.At == nil {
		ev.At = timestamppb.New(e.now())
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if CanInvolveMoney(ev) {
		e.enqueue(e.place(placement), ev, true)
		return
	}
	e.fold(placement, keyOf(ev), ev)
}

// RefusedHost records a failed inner handshake on a placement with x402 services
func (e *Events) RefusedHost(placement, sni string, at time.Time) {
	e.mu.Lock()
	has := e.hasServices
	e.mu.Unlock()
	// The check runs outside the lock, so it may take the caller's own locks
	if has == nil || !has(placement) {
		return
	}
	if at.IsZero() {
		at = e.now()
	}
	name, named := cleanName(sni)
	ev := &routerv1.X402Event{
		At: timestamppb.New(at), Ref: NewRef(), Host: name, Status: EventRefusedHost, Count: 1,
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refused(placement, named, ev)
}
