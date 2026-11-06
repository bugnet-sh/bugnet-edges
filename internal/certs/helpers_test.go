package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// eq fails the test when got and want differ
func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

var day0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// pemPair is a self-signed certificate valid from notBefore to notAfter, and its key
func pemPair(t *testing.T, notBefore, notAfter time.Time, names ...string) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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

func certValid(t *testing.T, from time.Time, life time.Duration) *x509.Certificate {
	t.Helper()
	chain, _ := pemPair(t, from, from.Add(life), "x.example.test")
	b, _ := pem.Decode(chain)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// logs collects JSON log lines for assertions
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, nil))
}

// errors lists the error records, each as its decoded attributes
func (l *logs) errors(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["level"] == "ERROR" {
			out = append(out, rec)
		}
	}
	return out
}

func (l *logs) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func writeFile(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certs.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
