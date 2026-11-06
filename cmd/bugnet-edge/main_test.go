package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"
)

// TestMain runs main itself when a test starts this binary as bugnet-edge
func TestMain(m *testing.M) {
	if os.Getenv("BUGNET_EDGE_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

var secrets = env(map[string]string{
	"BUGNET_EDGE_TOKEN":       "edge-token-0123456789abcdefghijklmnop",
	"BUGNET_HOOK_PATH_SECRET": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	"BUGNET_SECRETS_TOKEN":    "secrets-token-0123456789abcdefghijklmn",
})

// freePort is a loopback address no listener holds right now
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// pairDir writes a self-signed pair for names into a new directory
func pairDir(t *testing.T, names ...string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 30),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(k)
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

func writeFile(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// waitReady polls /readyz until the process answers 200
func waitReady(t *testing.T, metrics string, done <-chan error) {
	t.Helper()
	for range 200 {
		select {
		case err := <-done:
			t.Fatalf("run returned %v", err)
		default:
		}
		if res, err := http.Get("http://" + metrics + "/readyz"); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("never ready")
}

// fetchTLS sends one GET through a PROXY v2 header and TLS, as HAProxy would pass it
func fetchTLS(t *testing.T, addr, host, path string) (int, string) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4000}
	head, _ := pp.HeaderProxyFromAddrs(2, src, raw.LocalAddr()).Format()
	if _, err := raw.Write(head); err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true,
		NextProtos: []string{"http/1.1"}})
	req, _ := http.NewRequest("GET", "https://"+host+path, nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"-config"}, {"-config", "x", "extra"}, {"-config", "x", "--role", "other"},
		{"--role", "edge"},
	} {
		err := run(t.Context(), quiet(), args, secrets)
		if !errors.Is(err, errUsage) {
			t.Errorf("%v: got %v", args, err)
		}
	}
	err := run(t.Context(), quiet(), []string{"-config", "/nonexistent.toml"}, secrets)
	if err == nil || errors.Is(err, errUsage) {
		t.Fatalf("got %v", err)
	}
}

func TestEdgeRoleServesTheLandingPage(t *testing.T) {
	tlsAddr, metrics := freePort(t), freePort(t)
	path := writeFile(t, fmt.Sprintf(`
tls_listen_addr = %q
redirect_listen_addr = ""
metrics_listen_addr = %q
drain = "1s"
[names]
preview_domain = "preview.example.test"
transfer_host = "transfer.example.test"
hooks_host = "hooks.example.test"
[previews]
abuse_contact = "abuse@example.test"
[acme]
enabled = false
static_dir = %q
`, tlsAddr, metrics, pairDir(t, "preview.example.test", "transfer.example.test",
		"hooks.example.test", "*.preview.example.test")))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx, quiet(), []string{"-config", path}, secrets) }()
	waitReady(t, metrics, done)
	code, body := fetchTLS(t, tlsAddr, "preview.example.test", "/")
	if code != 200 || !strings.Contains(body, "mailto:abuse@example.test") {
		t.Fatalf("%d\n%s", code, body)
	}
	code, _ = fetchTLS(t, tlsAddr, "transfer.example.test", "/bnx_abc")
	if code != 404 {
		t.Fatalf("an unbuilt route answered %d", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSecretsRoleStartsWithItsOwnSettings(t *testing.T) {
	tlsAddr, metrics := freePort(t), freePort(t)
	path := writeFile(t, fmt.Sprintf(`
tls_listen_addr = %q
metrics_listen_addr = %q
host = "secrets.example.test"
acme_enabled = false
static_dir = %q
`, tlsAddr, metrics, pairDir(t, "secrets.example.test")))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, quiet(), []string{"-config", path, "--role", "secrets"}, secrets)
	}()
	waitReady(t, metrics, done)
	code, _ := fetchTLS(t, tlsAddr, "secrets.example.test", "/l/abc")
	if code != 404 {
		t.Fatalf("got %d", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), quiet(), []string{"-config", path, "--role", "secrets"}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "BUGNET_SECRETS_TOKEN") {
		t.Fatalf("got %v", err)
	}
}

// openConnection completes a TLS handshake and sends no request, which Shutdown waits on for 5 s
func openConnection(t *testing.T, addr, host string) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4000}
	head, _ := pp.HeaderProxyFromAddrs(2, src, raw.LocalAddr()).Format()
	if _, err := raw.Write(head); err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true,
		NextProtos: []string{"http/1.1"}})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
}

// lockedBuffer is a bytes.Buffer a child process writes while the test reads it
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// readyz is the status /readyz answers, 0 when nothing answers
func readyz(metrics string) int {
	res, err := http.Get("http://" + metrics + "/readyz")
	if err != nil {
		return 0
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestSecondSignalKillsDuringTheDrain(t *testing.T) {
	tlsAddr, metrics := freePort(t), freePort(t)
	path := writeFile(t, fmt.Sprintf(`
tls_listen_addr = %q
redirect_listen_addr = ""
metrics_listen_addr = %q
drain = "10m"
[names]
preview_domain = "preview.example.test"
transfer_host = "transfer.example.test"
hooks_host = "hooks.example.test"
[previews]
abuse_contact = "abuse@example.test"
[acme]
enabled = false
static_dir = %q
`, tlsAddr, metrics, pairDir(t, "preview.example.test", "transfer.example.test",
		"hooks.example.test", "*.preview.example.test")))
	cmd := exec.Command(os.Args[0], "-config", path)
	cmd.Env = append(os.Environ(), "BUGNET_EDGE_TEST_MAIN=1")
	for _, name := range []string{"BUGNET_EDGE_TOKEN", "BUGNET_HOOK_PATH_SECRET"} {
		v, _ := secrets(name)
		cmd.Env = append(cmd.Env, name+"="+v)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitReady(t, metrics, done)
	openConnection(t, tlsAddr, "preview.example.test")

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	for i := 0; readyz(metrics) != 503; i++ {
		select {
		case err := <-done:
			t.Fatalf("exited with %v before the drain showed\n%s", err, stderr.String())
		default:
		}
		if i == 200 {
			t.Fatalf("the first signal never started the drain\n%s", stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if code := readyz(metrics); code != 503 {
		t.Fatalf("the open connection did not hold the drain, /readyz %d\n%s", code,
			stderr.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("exited with %v\n%s", err, stderr.String())
		}
		ws := exit.Sys().(syscall.WaitStatus)
		if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Fatalf("exited with %v, not killed by the second signal\n%s", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("still draining 3 s after the second signal\n%s", stderr.String())
	}
}
