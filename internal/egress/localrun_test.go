//go:build localrun

package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalrunSeams(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "seller"},
		DNSNames: []string{"seller.x402.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	hello := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("seller")) }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(hello))
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(roots, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	body := `egress_host = "egress.example.com"` + "\n[localrun]\n" +
		`upstream_roots_file = "` + roots + `"` + "\n[localrun.upstream_addrs]\n" +
		`"seller.x402.test" = "` + strings.TrimPrefix(srv.URL, "https://") + `"` + "\n"
	cfg, err := Load(write(t, body), env(goodEnv))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, Deps{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://seller.x402.test/", nil)
	resp, err := s.seller.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	eq(t, string(got), "seller")
}
