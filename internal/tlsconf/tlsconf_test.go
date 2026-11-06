package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	previewHost  = "preview.example.test"
	transferHost = "transfer.example.test"
	hooksHost    = "hooks.example.test"
	previewName  = "k3f9x2q7mak3f9x2.preview.example.test"
	wildcardName = "*.preview.example.test"
)

var (
	day0  = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	both  = []string{"h2", "http/1.1"}
	plain = []string{"http/1.1"}
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// pair is a self-signed certificate for names and its key, both PEM
func pair(t *testing.T, serial int64, notAfter time.Time, names ...string) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := day0
	if now := time.Now(); now.Before(notBefore) {
		notBefore = now
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// writePair writes fullchain.pem and key.pem into dir, both stamped with mtime
func writePair(t *testing.T, dir string, chain, key []byte, mtime time.Time) {
	t.Helper()
	for name, b := range map[string][]byte{"fullchain.pem": chain, "key.pem": key} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

// writeCache stores a pair under key in autocert's directory cache format
func writeCache(t *testing.T, stateDir, key string, chain, priv []byte) {
	t.Helper()
	b := append(append([]byte{}, priv...), chain...)
	if err := os.WriteFile(filepath.Join(stateDir, key), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// serve returns the address of a TLS listener using cfg for every connection
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				s := tls.Server(c, cfg)
				_ = s.SetDeadline(time.Now().Add(5 * time.Second))
				if s.Handshake() == nil {
					_, _ = s.Read(make([]byte, 1))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// handshake connects to addr with the given SNI and ALPN offer
func handshake(t *testing.T, addr, sni string, alpn ...string) (tls.ConnectionState, error) {
	t.Helper()
	return handshakeUpTo(t, tls.VersionTLS13, addr, sni, alpn...)
}

// handshakeUpTo is handshake from a client that offers TLS 1.0 up to top
func handshakeUpTo(
	t *testing.T, top uint16, addr, sni string, alpn ...string,
) (tls.ConnectionState, error) {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         top,
	})
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = c.Close() }()
	return c.ConnectionState(), nil
}

// servedSerial is the serial of the leaf served for sni
func servedSerial(t *testing.T, addr, sni string) int64 {
	t.Helper()
	st, err := handshake(t, addr, sni, both...)
	if err != nil {
		t.Fatal(err)
	}
	return st.PeerCertificates[0].SerialNumber.Int64()
}

func names() []Name {
	return []Name{
		{Host: previewHost, ALPN: both},
		{Host: transferHost, ALPN: plain},
		{Host: hooksHost, ALPN: both},
	}
}

// staticOptions serves every name from one pair in a new directory
func staticOptions(t *testing.T, notAfter time.Time) Options {
	t.Helper()
	dir := t.TempDir()
	chain, key := pair(t, 1, notAfter, previewHost, transferHost, hooksHost, wildcardName)
	writePair(t, dir, chain, key, day0)
	return Options{
		Names:    names(),
		Wildcard: &Wildcard{Suffix: previewHost, ALPN: both},
		Static:   dir,
	}
}

// acmeOptions turns ACME on with an empty state directory and a wildcard pair
func acmeOptions(t *testing.T, c *clock, wildNotAfter time.Time) Options {
	t.Helper()
	wild := t.TempDir()
	chain, key := pair(t, 1, wildNotAfter, wildcardName)
	writePair(t, wild, chain, key, day0)
	return Options{
		Names:    names(),
		Wildcard: &Wildcard{Suffix: previewHost, Dir: wild, ALPN: both},
		ACME: ACME{
			Enabled:   true,
			Directory: "http://127.0.0.1:1/directory",
			StateDir:  t.TempDir(),
		},
		now: c.Now,
	}
}

func mustNew(t *testing.T, o Options) *tls.Config {
	t.Helper()
	cfg, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTLSUnknownSNIFails(t *testing.T) {
	addr := serve(t, mustNew(t, staticOptions(t, day0.AddDate(0, 0, 90))))
	for _, sni := range []string{
		"unknown.example", "", "a.b.preview.example.test", ".preview.example.test",
		"preview.example.test.evil.example", "example.test",
	} {
		if _, err := handshake(t, addr, sni, both...); err == nil {
			t.Fatalf("%q was served", sni)
		}
	}
	for _, sni := range []string{
		previewHost, "TRANSFER.example.test", previewName, hooksHost + ".",
	} {
		if _, err := handshake(t, addr, sni, both...); err != nil {
			t.Fatalf("%q: %v", sni, err)
		}
	}
}

func TestTLSALPNPerName(t *testing.T) {
	addr := serve(t, mustNew(t, staticOptions(t, day0.AddDate(0, 0, 90))))
	for sni, want := range map[string]string{
		transferHost: "http/1.1", previewName: "h2", previewHost: "h2", hooksHost: "h2",
	} {
		st, err := handshake(t, addr, sni, both...)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, st.NegotiatedProtocol, want)
	}
	_, err := handshake(t, addr, transferHost, "h2")
	eq(t, err != nil, true)
	_, err = handshake(t, addr, transferHost, acme.ALPNProto)
	eq(t, err != nil, true)
}

func TestTLSBelowOneTwoFails(t *testing.T) {
	static := mustNew(t, staticOptions(t, day0.AddDate(0, 0, 90)))
	eq(t, static.MinVersion, uint16(tls.VersionTLS12))
	o := acmeOptions(t, &clock{t: day0}, time.Now().AddDate(0, 0, 60))
	chain, key := pair(t, 9, time.Now().AddDate(0, 0, 1), transferHost)
	writeCache(t, o.ACME.StateDir, transferHost+"+token", chain, key)
	staticAddr, acmeAddr := serve(t, static), serve(t, mustNew(t, o))
	for _, tc := range []struct {
		addr, sni string
		alpn      []string
	}{
		{staticAddr, transferHost, plain},
		{staticAddr, previewName, both},
		{acmeAddr, previewName, both},
		{acmeAddr, transferHost, []string{acme.ALPNProto}},
	} {
		_, err := handshakeUpTo(t, tls.VersionTLS11, tc.addr, tc.sni, tc.alpn...)
		if err == nil || !strings.Contains(err.Error(), "protocol version") {
			t.Fatalf("%s %v over TLS 1.1 gave %v", tc.sni, tc.alpn, err)
		}
		if _, err := handshakeUpTo(t, tls.VersionTLS12, tc.addr, tc.sni, tc.alpn...); err != nil {
			t.Fatalf("%s %v over TLS 1.2: %v", tc.sni, tc.alpn, err)
		}
	}
}

func TestStaticPairServesEveryName(t *testing.T) {
	addr := serve(t, mustNew(t, staticOptions(t, day0.AddDate(0, 0, 90))))
	for _, sni := range []string{previewHost, transferHost, hooksHost, previewName} {
		eq(t, servedSerial(t, addr, sni), 1)
	}
}

func TestWildcardReloadOnModTime(t *testing.T) {
	c := &clock{t: day0}
	o := acmeOptions(t, c, time.Now().AddDate(0, 0, 60))
	addr := serve(t, mustNew(t, o))
	eq(t, servedSerial(t, addr, previewName), 1)

	chain, key := pair(t, 2, time.Now().AddDate(0, 0, 90), wildcardName)
	writePair(t, o.Wildcard.Dir, chain, key, day0.Add(time.Hour))
	c.Advance(59 * time.Second)
	eq(t, servedSerial(t, addr, previewName), 1)
	c.Advance(2 * time.Second)
	eq(t, servedSerial(t, addr, previewName), 2)

	// A half-written pair keeps the last good one until a later check
	other, _ := pair(t, 3, time.Now().AddDate(0, 0, 90), wildcardName)
	writePair(t, o.Wildcard.Dir, other, key, day0.Add(2*time.Hour))
	c.Advance(time.Minute)
	eq(t, servedSerial(t, addr, previewName), 2)
}

func TestACMEServesCachedCertificate(t *testing.T) {
	c := &clock{t: day0}
	o := acmeOptions(t, c, time.Now().AddDate(0, 0, 60))
	chain, key := pair(t, 7, time.Now().AddDate(0, 0, 80), transferHost)
	writeCache(t, o.ACME.StateDir, transferHost, chain, key)
	addr := serve(t, mustNew(t, o))
	st, err := handshake(t, addr, transferHost, both...)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, st.PeerCertificates[0].SerialNumber.Int64(), 7)
	eq(t, st.NegotiatedProtocol, "http/1.1")
}

func TestACMEChallengeOnlyForExactNames(t *testing.T) {
	c := &clock{t: day0}
	o := acmeOptions(t, c, time.Now().AddDate(0, 0, 60))
	chain, key := pair(t, 9, time.Now().AddDate(0, 0, 1), transferHost)
	writeCache(t, o.ACME.StateDir, transferHost+"+token", chain, key)
	addr := serve(t, mustNew(t, o))
	st, err := handshake(t, addr, transferHost, acme.ALPNProto)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, st.NegotiatedProtocol, acme.ALPNProto)
	eq(t, st.PeerCertificates[0].SerialNumber.Int64(), 9)
	_, err = handshake(t, addr, previewName, acme.ALPNProto)
	eq(t, err != nil, true)
}

func TestDaysLeftPerName(t *testing.T) {
	c := &clock{t: day0}
	o := acmeOptions(t, c, day0.AddDate(0, 0, 50))
	chain, key := pair(t, 4, day0.AddDate(0, 0, 20), transferHost)
	writeCache(t, o.ACME.StateDir, transferHost, chain, key)
	chain, key = pair(t, 5, day0.AddDate(0, 0, 30).Add(time.Hour), previewHost)
	writeCache(t, o.ACME.StateDir, previewHost+"+rsa", chain, key)
	cfg := mustNew(t, o)
	eq(t, DaysLeft(cfg, day0), map[string]int{
		transferHost: 20, previewHost: 30, wildcardName: 50,
	})
	eq(t, DaysLeft(cfg, day0.AddDate(0, 0, 21)), map[string]int{
		transferHost: -1, previewHost: 9, wildcardName: 29,
	})

	chain, key = pair(t, 6, day0.AddDate(0, 0, 80), wildcardName)
	writePair(t, o.Wildcard.Dir, chain, key, day0.Add(time.Hour))
	c.Advance(time.Minute)
	eq(t, DaysLeft(cfg, day0)[wildcardName], 80)

	static := mustNew(t, staticOptions(t, day0.AddDate(0, 0, 40)))
	eq(t, DaysLeft(static, day0), map[string]int{
		previewHost: 40, transferHost: 40, hooksHost: 40, wildcardName: 40,
	})
	eq(t, len(DaysLeft(&tls.Config{}, day0)), 0)
}

func TestNewRefusesBadOptions(t *testing.T) {
	c := &clock{t: day0}
	cases := map[string]func(o *Options){
		"no names": func(o *Options) { o.Names, o.Wildcard = nil, nil },
		"no state": func(o *Options) { o.ACME.StateDir = "" },
		"no dir":   func(o *Options) { o.ACME.Directory = "" },
		"no ALPN":  func(o *Options) { o.Names[1].ALPN = nil },
		"no host":  func(o *Options) { o.Names[1].Host = "" },
		"star":     func(o *Options) { o.Names[1].Host = "*.example.test" },
		"twice":    func(o *Options) { o.Names[1].Host = "PREVIEW.example.test" },
		"no wild":  func(o *Options) { o.Wildcard.Dir = t.TempDir() },
		"suffix":   func(o *Options) { o.Wildcard.Suffix = "" },
		"wild ALPN": func(o *Options) {
			o.Wildcard.ALPN = nil
		},
		"static off": func(o *Options) {
			o.ACME.Enabled = false
		},
		"static missing": func(o *Options) {
			o.ACME.Enabled, o.Static = false, t.TempDir()
		},
	}
	for name, change := range cases {
		o := acmeOptions(t, c, day0.AddDate(0, 0, 60))
		change(&o)
		if _, err := New(o); err == nil {
			t.Fatalf("%s: New accepted it", name)
		}
	}
	if _, err := New(acmeOptions(t, c, day0.AddDate(0, 0, 60))); err != nil {
		t.Fatal(err)
	}
}
