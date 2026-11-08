package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers every A and AAAA question with addr, and counts the questions
type fakeDNS struct {
	addr      netip.Addr
	questions atomic.Int32
	pc        net.PacketConn
}

func startDNS(t *testing.T, addr string) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{addr: netip.MustParseAddr(addr), pc: pc}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			f.questions.Add(1)
			q := m.Questions[0]
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true},
				Questions: m.Questions,
			}
			h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
			switch {
			case q.Type == dnsmessage.TypeA && f.addr.Is4():
				h.Type = dnsmessage.TypeA
				resp.Answers = []dnsmessage.Resource{{Header: h,
					Body: &dnsmessage.AResource{A: f.addr.As4()}}}
			case q.Type == dnsmessage.TypeAAAA && f.addr.Is6():
				h.Type = dnsmessage.TypeAAAA
				resp.Answers = []dnsmessage.Resource{{Header: h,
					Body: &dnsmessage.AAAAResource{AAAA: f.addr.As16()}}}
			}
			if out, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return f
}

func (f *fakeDNS) addrString() string {
	return f.pc.LocalAddr().String()
}

var refusedAddrs = []string{"127.0.0.1", "0.0.0.0", "0.1.2.3", "10.0.0.1", "169.254.169.254",
	"100.64.0.1", "fd00::1", "64:ff9b::7f00:1", "64:ff9b:1::a00:1", "::ffff:127.0.0.1",
	"::ffff:10.0.0.1"}

func dialDirect(t *testing.T, addr string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	c, err := NewDialer(nil).DialContext(ctx, "tcp", net.JoinHostPort(addr, "443"))
	if err == nil {
		_ = c.Close()
	}
	return err
}

func dialViaDNS(t *testing.T, addr string) error {
	t.Helper()
	dns := startDNS(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	c, err := NewDialer([]string{dns.addrString()}).DialContext(ctx, "tcp", "victim.example:443")
	if err == nil {
		_ = c.Close()
	}
	return err
}

func TestDialerRefusals(t *testing.T) {
	for _, a := range refusedAddrs {
		t.Run(a, func(t *testing.T) {
			direct, viaDNS := dialDirect(t, a), dialViaDNS(t, a)
			eq(t, errors.Is(direct, errRefused), true)
			eq(t, errors.Is(viaDNS, errRefused), true)
		})
	}
}

func TestControlHookRefusesWhateverTheNameLedTo(t *testing.T) {
	d := NewDialer(nil)
	for _, a := range refusedAddrs {
		ap := netip.AddrPortFrom(netip.MustParseAddr(a), 443)
		eq(t, errors.Is(d.control("tcp", ap.String(), nil), errRefused), true)
	}
	eq(t, d.control("tcp", "93.184.216.34:443", nil), nil)
}

func TestPublicAddressesAreNotRefused(t *testing.T) {
	for _, a := range []string{"93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "172.32.0.1"} {
		eq(t, Refused(netip.MustParseAddr(a)), false)
	}
}

func TestDialerRefusesItsOwnAddresses(t *testing.T) {
	d := NewDialer(nil)
	d.ownAddrs = func() ([]net.Addr, error) {
		own := &net.IPNet{IP: net.ParseIP("93.184.216.99"), Mask: net.CIDRMask(32, 32)}
		return []net.Addr{own}, nil
	}
	eq(t, d.refuses(netip.MustParseAddr("93.184.216.99")), true)
	eq(t, d.refuses(netip.MustParseAddr("93.184.216.34")), false)
}

func TestResolvingUsesTheResolversOnly(t *testing.T) {
	dns := startDNS(t, "93.184.216.34")
	d := NewDialer([]string{dns.addrString()})
	ctx, cancel := context.WithTimeout(context.Background(), shortWait)
	defer cancel()
	// /etc/hosts maps localhost to 127.0.0.1, which a resolver of the system's would return
	got, err := d.lookup(ctx, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, got, []netip.Addr{netip.MustParseAddr("93.184.216.34")})
	eq(t, dns.questions.Load() >= 1, true)
}

func TestDialerGivesUpWithNoResolverAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	d := NewDialer([]string{pc.LocalAddr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "silent.example:443")
	eq(t, err != nil, true)
}
