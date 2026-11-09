package proxyproto

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

func mustListen(t *testing.T, trusted []netip.Prefix) net.Listener {
	t.Helper()
	ln, err := Listen("127.0.0.1:0", trusted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// header is a PROXY header of the given version naming src as the client
func header(t *testing.T, version byte, src string) []byte {
	t.Helper()
	from := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(src))
	to := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
	b, err := pp.HeaderProxyFromAddrs(version, from, to).Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func withHeader(t *testing.T, src string) []byte { return header(t, 2, src) }

// dial connects to ln and sends head followed by one byte of payload
func dial(t *testing.T, ln net.Listener, head []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write(append(head, 'x')); err != nil {
		t.Fatal(err)
	}
	return c
}

// accept waits for the next connection ln hands out
func accept(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// remoteOf sends head on a new connection and reports the client address the server sees
func remoteOf(t *testing.T, ln net.Listener, head []byte) string {
	t.Helper()
	dial(t, ln, head)
	c := accept(t, ln)
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	eq(t, string(b), "x")
	return c.RemoteAddr().String()
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// closedByServer reports whether the server ended the client's connection
func closedByServer(t *testing.T, c net.Conn) bool {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	return err != nil && !timedOut(err)
}

// refused sends head from a trusted source and reports whether the server failed and closed it
func refused(t *testing.T, ln net.Listener, head []byte) bool {
	t.Helper()
	client := dial(t, ln, head)
	c := accept(t, ln)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, first := c.Read(make([]byte, 1))
	_, second := c.Read(make([]byte, 1))
	if timedOut(first) || timedOut(second) {
		t.Fatalf("the server waited for more data instead of refusing (%v, %v)", first, second)
	}
	return first != nil && second != nil && closedByServer(t, client)
}

// noHeader is a request that opens without a PROXY header
const noHeader = "GET / HTTP/1.1\r\nHost: a\r\n\r\n"

func closedWithoutHeader(t *testing.T, ln net.Listener) bool {
	return refused(t, ln, []byte(noHeader))
}

func TestProxyProtoTrustedOnly(t *testing.T) {
	ln := mustListen(t, loopback)
	eq(t, remoteOf(t, ln, withHeader(t, "203.0.113.9:4000")), "203.0.113.9:4000")
	eq(t, closedWithoutHeader(t, ln), true)
}

func TestProxyProtoIPv6Client(t *testing.T) {
	ln := mustListen(t, loopback)
	eq(t, remoteOf(t, ln, withHeader(t, "[2001:db8::7]:4000")), "[2001:db8::7]:4000")
}

func TestProxyProtoVersionOneRefused(t *testing.T) {
	ln := mustListen(t, loopback)
	eq(t, refused(t, ln, header(t, 1, "203.0.113.9:4000")), true)
}

func TestProxyProtoEveryFailedCallCloses(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(c net.Conn) error
	}{
		{"Write", func(c net.Conn) error {
			_, err := c.Write([]byte("y"))
			return err
		}},
		{"WriteTo", func(c net.Conn) error {
			_, err := io.Copy(io.Discard, c)
			return err
		}},
		{"ReadFrom", func(c net.Conn) error {
			_, err := c.(io.ReaderFrom).ReadFrom(strings.NewReader("y"))
			return err
		}},
	} {
		ln := mustListen(t, loopback)
		client := dial(t, ln, []byte(noHeader))
		if err := tc.call(accept(t, ln)); err == nil {
			t.Fatalf("%s succeeded without a header", tc.name)
		}
		if !closedByServer(t, client) {
			t.Fatalf("%s failed and left the connection open", tc.name)
		}
	}
}

func TestProxyProtoSilentClientClosedAfterTheHeaderWait(t *testing.T) {
	eq(t, headerTimeout, 10*time.Second)
	headerTimeout = 200 * time.Millisecond
	t.Cleanup(func() { headerTimeout = 10 * time.Second })
	ln := mustListen(t, loopback)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	c := accept(t, ln)
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		read <- err
	}()
	if !closedByServer(t, client) {
		t.Fatal("a silent client stayed open past the header wait")
	}
	eq(t, errors.Is(<-read, pp.ErrNoProxyProtocol), true)
}

func TestProxyProtoUntrustedSourceClosed(t *testing.T) {
	ln := mustListen(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client := dial(t, ln, withHeader(t, "203.0.113.9:4000"))
	eq(t, closedByServer(t, client), true)
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("an untrusted connection reached Accept")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxyProtoNoTrustedSourcesClosesAll(t *testing.T) {
	ln := mustListen(t, nil)
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	eq(t, closedByServer(t, dial(t, ln, withHeader(t, "203.0.113.9:4000"))), true)
}

func TestTrustedMatchesMappedAddresses(t *testing.T) {
	policy := trust(loopback)
	for _, tc := range []struct {
		ip   string
		want pp.Policy
		err  bool
	}{
		{"127.0.0.1", pp.REQUIRE, false},
		{"::ffff:127.0.0.1", pp.REQUIRE, false},
		{"127.0.0.2", pp.REJECT, true},
		{"::1", pp.REJECT, true},
	} {
		got, err := policy(pp.ConnPolicyOptions{
			Upstream: &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 5000},
		})
		eq(t, got, tc.want)
		eq(t, err != nil, tc.err)
		if err != nil {
			eq(t, errors.Is(err, pp.ErrInvalidUpstream), true)
		}
	}
	_, err := policy(pp.ConnPolicyOptions{Upstream: &net.UnixAddr{Name: "/tmp/s", Net: "unix"}})
	eq(t, errors.Is(err, pp.ErrInvalidUpstream), true)
}

func TestListenSharesThePortWithReusePort(t *testing.T) {
	first := mustListen(t, loopback)
	second, err := Listen(first.Addr().String(), loopback)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, second.Close(), nil)
}

func TestListenRefusesBadPrefixes(t *testing.T) {
	_, err := Listen("127.0.0.1:0", []netip.Prefix{{}})
	eq(t, err != nil, true)
}

func TestProxySource(t *testing.T) {
	v6 := func(src string) []byte {
		from := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(src))
		to := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
		b, err := pp.HeaderProxyFromAddrs(2, from, to).Format()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	local, err := (&pp.Header{Version: 2, Command: pp.LOCAL}).Format()
	if err != nil {
		t.Fatal(err)
	}
	unspec := []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x00\x00\x00")
	cases := []struct {
		name string
		head []byte
		want string
	}{
		{"v4", withHeader(t, "203.0.113.10:5000"), "203.0.113.10"},
		{"v6", v6("[2001:db8::5]:5000"), "2001:db8::5"},
		{"mapped", v6("[::ffff:203.0.113.10]:5000"), "203.0.113.10"},
		{"local", local, ""},
		{"unspec", unspec, ""},
	}
	for _, tc := range cases {
		ln := mustListen(t, loopback)
		dial(t, ln, tc.head)
		c := accept(t, ln)
		// The library refuses an UNSPEC header, so its read fails and no source is left
		_, err := io.ReadFull(c, make([]byte, 1))
		if err != nil && tc.name != "unspec" {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := Source(c)
		if tc.want == "" {
			eq(t, got.IsValid(), false)
			continue
		}
		eq(t, got.String(), tc.want)
	}
	eq(t, Source(nil).IsValid(), false)
}
