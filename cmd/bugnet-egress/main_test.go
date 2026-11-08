package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/egress"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"other"}, {"serve"}, {"serve", "-config"}, {"ca"},
		{"ca", "init"}, {"box-key", "new", "--id", "k1"}, {"ca", "init", "--out", "x", "y"}} {
		err := run(t.Context(), quiet(), args, os.LookupEnv, io.Discard)
		if err != errUsage {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestCAInitWritesTheKeyPrivate(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run(t.Context(), quiet(), []string{"ca", "init", "--out", dir}, os.LookupEnv,
		&out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "egress-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, st.Mode().Perm(), os.FileMode(0o600))
	if _, err := os.Stat(filepath.Join(dir, "egress-ca.pem")); err != nil {
		t.Fatal(err)
	}
	eq(t, strings.Contains(out.String(), "BEGIN"), false)
	// A second run never replaces the key
	err = run(t.Context(), quiet(), []string{"ca", "init", "--out", dir}, os.LookupEnv, io.Discard)
	eq(t, err != nil, true)
}

func TestBoxKeyNewPrintsIDAndPublicKeyOnce(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run(t.Context(), quiet(),
		[]string{"box-key", "new", "--id", "k2", "--out", dir}, os.LookupEnv, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	eq(t, len(lines), 2)
	eq(t, lines[0], "id: k2")
	pub, ok := strings.CutPrefix(lines[1], "public_key: ")
	b, err := base64.StdEncoding.DecodeString(pub)
	eq(t, ok && err == nil && len(b) == 32, true)
	raw, _ := os.ReadFile(filepath.Join(dir, "egress_box_k2"))
	eq(t, strings.Contains(out.String(), strings.TrimSpace(string(raw))), false)
	st, _ := os.Stat(filepath.Join(dir, "egress_box_k2"))
	eq(t, st.Mode().Perm(), os.FileMode(0o600))
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func TestServeStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	if err := egress.InitCA(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	creds := t.TempDir()
	key, _ := os.ReadFile(filepath.Join(dir, "egress-ca.key"))
	if err := os.WriteFile(filepath.Join(creds, "egress_ca_key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := egress.NewBoxKey(creds, "k1"); err != nil {
		t.Fatal(err)
	}
	pair := t.TempDir()
	writePair(t, pair)
	listen, metrics := freePort(t), freePort(t)
	conf := filepath.Join(t.TempDir(), "egress.toml")
	body := fmt.Sprintf(`egress_host = "egress.bugnet.sh"
listen_addr = %q
metrics_listen_addr = %q
acme_enabled = false
static_dir = %q
ca_cert_file = %q
`, listen, metrics, pair, filepath.Join(dir, "egress-ca.pem"))
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"BUGNET_EGRESS_TOKEN": strings.Repeat("t", 40), "CREDENTIALS_DIRECTORY": creds,
	}
	getenv := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, quiet(), []string{"serve", "-config", conf}, getenv, io.Discard)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + metrics + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the proxy did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		eq(t, err, nil)
	case <-time.After(15 * time.Second):
		t.Fatal("the proxy did not stop")
	}
}

func TestServeNamesAMissingSetting(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "egress.toml")
	if err := os.WriteFile(conf, []byte("# empty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), quiet(), []string{"serve", "-config", conf}, os.LookupEnv, io.Discard)
	eq(t, err != nil && strings.Contains(err.Error(), "egress_host"), true)
}

func writePair(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "egress.bugnet.sh"},
		DNSNames:  []string{"egress.bugnet.sh"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	for name, b := range map[string]*pem.Block{
		"fullchain.pem": {Type: "CERTIFICATE", Bytes: der},
		"key.pem":       {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
