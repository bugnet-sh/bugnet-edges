package strangers

import (
	"crypto/sha256"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

var (
	ip    = netip.MustParseAddr("203.0.113.9")
	other = netip.MustParseAddr("203.0.113.10")
	ip6   = netip.MustParseAddr("2001:db8::9")
)

func TestGuardMarksAfterTwentyFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		for range 20 {
			g.Failed(ip)
		}
		eq(t, g.Marked(ip), false)
		g.Failed(ip)
		eq(t, g.Marked(ip), true)
		eq(t, g.Marked(other), false)
		time.Sleep(10*time.Minute - time.Second)
		eq(t, g.Marked(ip), true)
		time.Sleep(2 * time.Second)
		eq(t, g.Marked(ip), false)
	})
}

func TestGuardCountsFailuresPerMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		for range 20 {
			g.Failed(ip)
		}
		time.Sleep(time.Minute)
		for range 20 {
			g.Failed(ip)
		}
		eq(t, g.Marked(ip), false)

		// Twenty a minute is one every 3 s, so the next failure 3 s on is still within it
		time.Sleep(3 * time.Second)
		g.Failed(ip)
		eq(t, g.Marked(ip), false)
		g.Failed(ip)
		eq(t, g.Marked(ip), true)
	})
}

func TestGuardFailurePastTheLimitWhileMarkedExtendsTheMark(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		for range 21 {
			g.Failed(ip)
		}
		time.Sleep(9 * time.Minute)
		g.Failed(ip)
		time.Sleep(2 * time.Minute)
		eq(t, g.Marked(ip), false)

		for range 21 {
			g.Failed(ip)
		}
		time.Sleep(9 * time.Minute)
		for range 21 {
			g.Failed(ip)
		}
		time.Sleep(2 * time.Minute)
		eq(t, g.Marked(ip), true)
		time.Sleep(8*time.Minute + time.Second)
		eq(t, g.Marked(ip), false)
	})
}

func TestGuardMarkedAddressAsksOnceASecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		eq(t, g.MayAsk(ip), true)
		eq(t, g.MayAsk(ip), true)
		for range 21 {
			g.Failed(ip)
		}
		eq(t, g.MayAsk(ip), true)
		eq(t, g.MayAsk(ip), false)
		eq(t, g.MayAsk(other), true)
		time.Sleep(999 * time.Millisecond)
		eq(t, g.MayAsk(ip), false)
		time.Sleep(time.Millisecond)
		eq(t, g.MayAsk(ip), true)
		eq(t, g.MayAsk(ip), false)
	})
}

func TestGuardRemembersUnknownTokensTenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		a := sha256.Sum256([]byte("bnp_a"))
		b := sha256.Sum256([]byte("bnp_b"))
		eq(t, g.KnownUnknown(a), false)
		g.RememberUnknown(a)
		eq(t, g.KnownUnknown(a), true)
		eq(t, g.KnownUnknown(b), false)
		time.Sleep(10*time.Second - time.Millisecond)
		eq(t, g.KnownUnknown(a), true)
		time.Sleep(time.Millisecond)
		eq(t, g.KnownUnknown(a), false)
	})
}

func TestGuardMappedAddressIsTheIPv4One(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		mapped := netip.AddrFrom16(ip.As16())
		for range 21 {
			g.Failed(mapped)
		}
		eq(t, g.Marked(ip), true)

		for range 21 {
			g.Failed(ip6)
		}
		eq(t, g.Marked(ip6.WithZone("eth0")), true)
		eq(t, g.Marked(netip.MustParseAddr("2001:db8::a")), false)
	})
}

func TestGuardForgetsQuietAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		for i := range 100 {
			g.Failed(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
			g.RememberUnknown(sha256.Sum256([]byte{byte(i)}))
		}
		for range 21 {
			g.Failed(ip)
		}
		eq(t, g.size(), 101)
		time.Sleep(2 * time.Minute)
		g.Failed(other)
		eq(t, g.size(), 2)
		eq(t, len(g.unknown), 0)
		eq(t, g.Marked(ip), true)
	})
}

func TestGuardHoldsAtMostItsCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(20, 10*time.Minute, 10*time.Second)
		g.ips.max = 50
		g.maxUnknown = 50
		for i := range 200 {
			g.Failed(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}))
			g.RememberUnknown(sha256.Sum256([]byte{byte(i >> 8), byte(i)}))
		}
		eq(t, g.size(), 50)
		eq(t, len(g.unknown), 50)
	})
}

func TestGuardAtItsCapSweepsAtMostOnceASecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(1, 10*time.Minute, time.Hour)
		g.ips.max = 50
		g.maxUnknown = 50
		addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }
		token := func(i int) [32]byte { return sha256.Sum256([]byte{byte(i)}) }
		for i := range 50 {
			g.Failed(addr(i))
			g.Failed(addr(i))
			g.RememberUnknown(token(i))
		}
		start := time.Now()
		swept := func(at time.Duration) {
			t.Helper()
			eq(t, g.ips.swept, start.Add(at))
			eq(t, g.swept, start.Add(at))
		}

		// Every address is marked, so a sweep frees nothing and one entry gives way instead
		time.Sleep(30 * time.Second)
		g.Failed(addr(100))
		g.RememberUnknown(token(100))
		swept(30 * time.Second)
		time.Sleep(time.Second - time.Millisecond)
		g.Failed(addr(101))
		g.RememberUnknown(token(101))
		swept(30 * time.Second)
		time.Sleep(time.Millisecond)
		g.Failed(addr(102))
		g.RememberUnknown(token(102))
		swept(31 * time.Second)
		eq(t, g.size(), 50)
		eq(t, len(g.unknown), 50)
	})
}

func TestGuardZeroIsOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGuard(0, 10*time.Minute, 10*time.Second)
		for range 100 {
			g.Failed(ip)
		}
		eq(t, g.Marked(ip), false)
		eq(t, g.MayAsk(ip), true)
		eq(t, g.MayAsk(ip), true)
		eq(t, g.size(), 0)

		a := sha256.Sum256([]byte("bnp_a"))
		g.RememberUnknown(a)
		eq(t, g.KnownUnknown(a), true)
	})
}

func TestPerIPAllowsItsRateAMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := NewPerIP(60)
		for range 60 {
			eq(t, l.Allow(ip), true)
		}
		eq(t, l.Allow(ip), false)
		eq(t, l.Allow(other), true)
		time.Sleep(time.Second)
		eq(t, l.Allow(ip), true)
		eq(t, l.Allow(ip), false)
		time.Sleep(time.Minute)
		for range 60 {
			eq(t, l.Allow(ip), true)
		}
		eq(t, l.Allow(ip), false)
	})
}

func TestPerIPZeroIsOff(t *testing.T) {
	l := NewPerIP(0)
	for range 1000 {
		eq(t, l.Allow(ip), true)
	}
	eq(t, l.ips.len(), 0)
}

func TestPerIPForgetsFullBuckets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := NewPerIP(60)
		for i := range 100 {
			l.Allow(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
		}
		eq(t, l.ips.len(), 100)
		time.Sleep(2 * time.Minute)
		l.Allow(ip)
		eq(t, l.ips.len(), 1)
	})
}
