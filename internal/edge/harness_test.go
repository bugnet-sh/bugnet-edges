package edge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"

	"github.com/oynozan/bugnet-edges/internal/settings"
)

const (
	previewDomain = "preview.bugnet.sh"
	transferHost  = "transfer.bugnet.sh"
	hooksHost     = "hooks.bugnet.sh"
	previewHost   = "k3fz2q7mak3fz2q7.preview.bugnet.sh"
	otherPreview  = "abcdefghijklmnop.preview.bugnet.sh"
)

// staticPair writes one self-signed pair for every edge name and the secrets host into a new dir
func staticPair(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{previewDomain, transferHost, hooksHost, "*." + previewDomain,
		"secrets.bugnet.sh"}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 90),
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
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		"fullchain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem":       pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// testConfig is an edge on loopback ports chosen by the kernel, serving one static pair
func testConfig(t *testing.T) Config {
	t.Helper()
	c := Defaults()
	c.EdgeID = "edge-test"
	c.TLSListenAddr = "127.0.0.1:0"
	c.RedirectListenAddr = "127.0.0.1:0"
	c.MetricsListenAddr = "127.0.0.1:0"
	c.ProxyProtocolFrom = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	c.Drain = settings.Duration(time.Second)
	c.Names = Names{PreviewDomain: previewDomain, TransferHost: transferHost, HooksHost: hooksHost}
	c.Previews.AbuseContact = "abuse@bugnet.sh"
	c.ACME = ACME{StaticDir: staticPair(t)}
	return c
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// named answers 200 with its name, so a test sees which route served a request
func named(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, name)
	})
}

func fakeDeps() Deps {
	return Deps{
		Preview: named("preview"), Transfer: named("transfer"), Hooks: named("hooks"),
		Landing: named("landing"), Log: quiet(),
	}
}

// get sends a request straight to the server's handler, its TLS name the same as its host
func get(t *testing.T, s *Server, host, path string) *http.Response {
	t.Helper()
	return call(t, s, "GET", host, host, path)
}

// call sends a request straight to the server's handler with a TLS name and a host header
func call(t *testing.T, s *Server, method, sni, host, path string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(method, "https://"+host+path, nil)
	r.TLS.ServerName = sni
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	return w.Result()
}

// served is the name of the fake route that answered, or the status when none did
func served(t *testing.T, s *Server, method, host, path string) string {
	t.Helper()
	res := call(t, s, method, host, host, path)
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return res.Status
	}
	return string(b)
}

// start runs s until the test ends and waits for its listeners
func start(t *testing.T, s *Server) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-s.started:
	case err := <-done:
		cancel()
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the server never started")
	}
	stopped := false
	stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			t.Fatal("Run did not return")
			return nil
		}
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// proxyHeader is a PROXY v2 header naming src as the client
func proxyHeader(t *testing.T, src string) []byte {
	t.Helper()
	from := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(src))
	to := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
	b, err := pp.HeaderProxyFromAddrs(2, from, to).Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dialTLS opens a connection to the edge as HAProxy would, then a TLS session with sni
func dialTLS(t *testing.T, addr, sni string, alpn ...string) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Write(proxyHeader(t, "203.0.113.9:4000")); err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// client sends requests to the edge's TLS listener with the SNI of each request's host
func client(t *testing.T, addr string, h2 bool) *http.Client {
	t.Helper()
	alpn := []string{"http/1.1"}
	var p http.Protocols
	p.SetHTTP1(true)
	if h2 {
		alpn = []string{"h2", "http/1.1"}
		p.SetHTTP2(true)
	}
	tr := &http.Transport{
		Protocols: &p,
		DialTLSContext: func(_ context.Context, _, hostPort string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(hostPort)
			return dialTLS(t, addr, host, alpn...)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
}

func fetch(t *testing.T, c *http.Client, method, url string, header ...string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// plainGet sends one HTTP/1.1 request to the redirect listener with the URL's host
func plainGet(t *testing.T, s *Server, url string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", s.addr("redirect"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(c); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res
}

func metricsGet(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	res, err := http.Get("http://" + s.addr("metrics") + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}
