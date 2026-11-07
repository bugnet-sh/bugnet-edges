package x402

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	routerv1 "github.com/oynozan/bugnet-proto/gen/go/bugnet/router/v1"
)

func TestRefShape(t *testing.T) {
	shape := regexp.MustCompile(`^[a-z2-7]{16}$`)
	seen := map[string]bool{}
	for range 1000 {
		r := NewRef()
		if !shape.MatchString(r) {
			t.Fatalf("ref %q is not 16 lower-case base32 characters", r)
		}
		if seen[r] {
			t.Fatalf("ref %q made twice", r)
		}
		seen[r] = true
	}
}

func TestShapeMethod(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"PATCH", "PATCH"},
		{"GET", "GET"},
		{"ABCDEFGHIJ", "ABCDEFGHIJ"},
		{"patch", "OTHER"},
		{"ABCDEFGHIJK", "OTHER"},
		{"", "OTHER"},
		{"GET1", "OTHER"},
		{"GÉT", "OTHER"},
	} {
		ev := &routerv1.X402Event{Method: c.in, Status: EventFree}
		Shape(ev, true)
		if ev.GetMethod() != c.want {
			t.Fatalf("method %q shaped to %q, want %q", c.in, ev.GetMethod(), c.want)
		}
	}

	ev := &routerv1.X402Event{Method: "GET", Path: "/v1/x", Status: EventRefusedHost}
	Shape(ev, true)
	eq(t, ev.GetMethod(), "")
	eq(t, ev.GetPath(), "")
}

func TestShapePath(t *testing.T) {
	long := "/" + strings.Repeat("a", 119)
	for _, c := range []struct {
		name   string
		status string
		reason Code
		passed bool
		path   string
		want   string
	}{
		{"kept", EventFree, "", true, "/v1/auto/chat", "/v1/auto/chat"},
		{"120 characters cut to 80", EventFree, "", true, long, long[:80]},
		{"the target failed", EventRefusedRequest, CodePathNotEnabled, false, "/v1/x", ""},
		{"path_refused", EventRefusedRequest, CodePathRefused, true, "/v1/x", ""},
		{"upgrade_refused", EventRefusedRequest, CodeUpgradeRefused, true, "/ws", ""},
		{"text past visible ASCII", EventFree, "", true, "/café", ""},
		{"a space", EventFree, "", true, "/a b", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := &routerv1.X402Event{
				Method: "GET", Path: c.path, Status: c.status, Reason: string(c.reason),
			}
			Shape(ev, c.passed)
			eq(t, ev.GetPath(), c.want)
			eq(t, len(ev.GetPath()) <= 80, true)
		})
	}
}

func TestShapeHost(t *testing.T) {
	long := strings.Repeat("a.", 150) + "com"
	ev := &routerv1.X402Event{Host: long, Method: "GET", Status: EventFree}
	Shape(ev, true)
	eq(t, ev.GetHost(), long[:253])

	ev = &routerv1.X402Event{Host: "api.example.com", Method: "GET", Status: EventFree}
	Shape(ev, true)
	eq(t, ev.GetHost(), "api.example.com")

	ev = &routerv1.X402Event{Host: "bücher.example", Method: "GET", Status: EventFree}
	Shape(ev, true)
	eq(t, ev.GetHost(), "")
}

// offered is an event whose 402 offered exact USDC on Solana
func offered() *routerv1.X402Event {
	return &routerv1.X402Event{
		Host: "api.example.com", Method: "POST", Status: EventRefusedPrice,
		Reason: string(CodePriceAboveMax), AskedMicros: 20000, Asset: USDCMint,
		Network: SolanaMainnet, Scheme: schemeExact, X402Version: 2, PayTo: testPayTo,
	}
}

func TestShapePayTo(t *testing.T) {
	ev := offered()
	Shape(ev, true)
	eq(t, ev.GetPayTo(), testPayTo)

	signature := Encode58(bytes.Repeat([]byte{7}, 64))
	for _, payTo := range []string{signature, "0OIl", "not base58 at all", ""} {
		ev := offered()
		ev.PayTo = payTo
		Shape(ev, true)
		eq(t, ev.GetPayTo(), "")
		eq(t, ev.GetAskedMicros(), int64(20000))
	}
}

func TestShapeKeepsOnlyExactSolanaUSDC(t *testing.T) {
	ev := offered()
	Shape(ev, true)
	eq(t, []any{ev.GetAskedMicros(), ev.GetAsset(), ev.GetNetwork(), ev.GetScheme(),
		ev.GetX402Version()}, []any{int64(20000), USDCMint, SolanaMainnet, "exact", uint32(2)})

	for name, change := range map[string]func(*routerv1.X402Event){
		"another network": func(ev *routerv1.X402Event) { ev.Network = "eip155:8453" },
		"another asset":   func(ev *routerv1.X402Event) { ev.Asset = testPayTo },
		"another scheme":  func(ev *routerv1.X402Event) { ev.Scheme = "upto" },
		"no entry": func(ev *routerv1.X402Event) {
			ev.Asset, ev.Network, ev.Scheme = "", "", ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			ev := offered()
			ev.AmountMicros = 5
			change(ev)
			Shape(ev, true)
			eq(t, []any{ev.GetAskedMicros(), ev.GetAsset(), ev.GetNetwork(), ev.GetScheme(),
				ev.GetX402Version(), ev.GetPayTo()}, []any{int64(0), "", "", "", uint32(0), ""})
			eq(t, ev.GetAmountMicros(), int64(5))
		})
	}
}

func TestCanInvolveMoney(t *testing.T) {
	for _, status := range []string{EventPaid, EventUncertain, EventPaymentFailed} {
		eq(t, CanInvolveMoney(&routerv1.X402Event{Status: status}), true)
	}
	for _, status := range []string{
		EventFree, EventSelfPaid, EventRefusedCap, EventRefusedPrice, EventRefusedPayee,
		EventRefusedNetwork, EventRefusedTerms, EventRefusedRequest, EventRefusedHost,
		EventNotPaid, EventUpstreamError,
	} {
		eq(t, CanInvolveMoney(&routerv1.X402Event{Status: status}), false)
		eq(t, CanInvolveMoney(&routerv1.X402Event{Status: status, AmountMicros: 1}), true)
	}
	eq(t, CanInvolveMoney(&routerv1.X402Event{Status: EventNotPaid, AskedMicros: 1}), false)
}

func TestPlacementHash(t *testing.T) {
	h := PlacementHash("pl_01HXYZ")
	eq(t, regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(h), true)
	eq(t, PlacementHash("pl_01HXYZ"), h)
	eq(t, PlacementHash("pl_01HXYW") != h, true)
	eq(t, strings.Contains(h, "01HXYZ"), false)
}
