package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// needle and feeLine are the files' secret lines, whose values no output may hold
const (
	needle  = "tskey-auth-NEEDLE"
	feeLine = "TESTSELLER_FEE_PAYER_KEY=feeNEEDLE"
)

// TestMain runs the stub facilitator when the test binary is started as one
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "stub-facilitator" {
		stubFacilitator(os.Args[2])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "stub-exit" {
		os.Exit(3)
	}
	os.Exit(m.Run())
}

// stubFacilitator writes the names of its environment to out and answers /health
func stubFacilitator(out string) {
	var names []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	_ = os.WriteFile(out, []byte(strings.Join(names, "\n")), 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(_ http.ResponseWriter, _ *http.Request) {})
	_ = http.ListenAndServe(os.Getenv("FACILITATOR_ADDR"), mux)
}

// testCert is a self-signed certificate for 127.0.0.1
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fakeNode serves TLS on 127.0.0.1:0 in place of a Funnel listener
type fakeNode struct {
	full   string
	cert   tls.Certificate
	mu     sync.Mutex
	protos [][]string
	addr   string
	closed bool
}

func (f *fakeNode) listenFunnel(protos []string) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protos = append(f.protos, protos)
	f.addr = ln.Addr().String()
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{f.cert}, NextProtos: protos, MinVersion: tls.VersionTLS12,
	}), nil
}

func (f *fakeNode) name() string { return f.full }

func (f *fakeNode) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// fakes starts fakeNodes named from tail and remembers them by host
type fakes struct {
	t     *testing.T
	cert  tls.Certificate
	tails map[string]string
	mu    sync.Mutex
	nodes map[string]*fakeNode
	dirs  map[string]string
}

func newFakes(t *testing.T) *fakes {
	cert, _ := testCert(t)
	return &fakes{
		t: t, cert: cert, tails: map[string]string{},
		nodes: map[string]*fakeNode{}, dirs: map[string]string{},
	}
}

func (f *fakes) start(_ context.Context, host, dir, key string) (node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if key != needle {
		f.t.Errorf("auth key not passed on, got %d bytes", len(key))
	}
	full := host + ".tail0000.ts.net"
	if t, ok := f.tails[host]; ok {
		full = t
	}
	n := &fakeNode{full: full, cert: f.cert}
	f.nodes[host], f.dirs[host] = n, dir
	return n, nil
}

// writeFile writes content at mode, whatever the umask
func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// testSettings is settings in a temp directory, with a stub facilitator and good files
func testSettings(t *testing.T) settings {
	t.Helper()
	dir := t.TempDir()
	auth, env := filepath.Join(dir, "tailscale.env"), filepath.Join(dir, "testseller.env")
	writeFile(t, auth, "TS_AUTHKEY="+needle+"\n", 0o600)
	writeFile(t, env, feeLine+"\n", 0o600)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	exe, _ := os.Executable()
	addr58 := "ApP993TBkpkUVFtYibkjmKGr1EsipdJwfxyFQg26wrxg"
	return settings{
		Nodes: []nodeSettings{
			{Name: "x402-seller-a", StateDir: filepath.Join(dir, "state", "a")},
			{Name: "x402-seller-b", StateDir: filepath.Join(dir, "state", "b")},
		},
		EnvFile: env, TailscaleEnvFile: auth,
		PayTo: addr58, PayToTokenAccount: addr58, FeePayer: addr58, BugnetFeePayer: addr58,
		FacilitatorCmd:  []string{exe, "stub-facilitator", filepath.Join(dir, "names")},
		FacilitatorAddr: addr, RPCURL: "https://rpc.example", dir: dir,
	}
}

// running starts run in the background and returns its output once it lists n names
type running struct {
	out    *syncBuf
	cancel context.CancelFunc
	done   chan error
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func start(t *testing.T, s settings, f *fakes) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{out: &syncBuf{}, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- run(ctx, s, f.start, r.out) }()
	t.Cleanup(func() { cancel(); <-r.done })
	return r
}

// waitLines waits until the output holds n lines, or run ends
func (r *running) waitLines(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		lines := strings.Fields(r.out.String())
		if len(lines) >= n {
			return lines
		}
		select {
		case err := <-r.done:
			r.done <- err
			t.Fatalf("run ended early: %v", err)
		case <-deadline:
			t.Fatalf("no %d lines, got %q", n, r.out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// stop ends run and returns its error
func (r *running) stop() error {
	r.cancel()
	err := <-r.done
	r.done <- err
	return err
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
	}}
}

func TestServesBothNames(t *testing.T) {
	f := newFakes(t)
	r := start(t, testSettings(t), f)
	lines := r.waitLines(t, 2)
	want := []string{
		"https://x402-seller-a.tail0000.ts.net", "https://x402-seller-b.tail0000.ts.net",
	}
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Fatalf("output %v, want %v", lines, want)
	}
	for _, host := range []string{"x402-seller-a", "x402-seller-b"} {
		res, err := client().Get("https://" + f.nodes[host].addr + "/free/")
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("%s /free/: %v %v", host, res, err)
		}
		_ = res.Body.Close()
	}
}

func TestRefusesWithoutAuthKey(t *testing.T) {
	cases := map[string]func(path string){
		"missing":  func(p string) { _ = os.Remove(p) },
		"mode 644": func(p string) { writeFile(t, p, "TS_AUTHKEY="+needle+"\n", 0o644) },
		"no key":   func(p string) { writeFile(t, p, "OTHER=x\n", 0o600) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := testSettings(t)
			mutate(s.TailscaleEnvFile)
			var out bytes.Buffer
			err := run(context.Background(), s, newFakes(t).start, &out)
			if err == nil || !strings.Contains(err.Error(), s.TailscaleEnvFile) {
				t.Fatalf("got %v, want an error naming the file", err)
			}
			if strings.Contains(err.Error()+out.String(), "NEEDLE") {
				t.Fatal("a secret leaked")
			}
		})
	}
}

func TestRefusesABadEnvFile(t *testing.T) {
	cases := map[string]func(path string){
		"missing":  func(p string) { _ = os.Remove(p) },
		"mode 644": func(p string) { writeFile(t, p, feeLine+"\n", 0o644) },
		"no key":   func(p string) { writeFile(t, p, "OTHER=x\n", 0o600) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := testSettings(t)
			mutate(s.EnvFile)
			var out bytes.Buffer
			err := run(context.Background(), s, newFakes(t).start, &out)
			if err == nil || !strings.Contains(err.Error(), s.EnvFile) {
				t.Fatalf("got %v, want an error naming the file", err)
			}
			if strings.Contains(err.Error()+out.String(), "NEEDLE") {
				t.Fatal("a secret leaked")
			}
		})
	}
}

func TestStateDirsKept(t *testing.T) {
	f := newFakes(t)
	s := testSettings(t)
	r := start(t, s, f)
	r.waitLines(t, 2)
	for _, host := range []string{"x402-seller-a", "x402-seller-b"} {
		info, err := os.Stat(f.dirs[host])
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s state dir: %v %v", host, info, err)
		}
	}
	if f.dirs["x402-seller-a"] == f.dirs["x402-seller-b"] {
		t.Fatal("the nodes share a state dir")
	}
	keep := filepath.Join(s.Nodes[0].StateDir, "node.key")
	if err := os.WriteFile(keep, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	r2 := start(t, s, newFakes(t))
	r2.waitLines(t, 2)
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the file did not survive: %v", err)
	}
	if err := os.Chmod(s.Nodes[1].StateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	_ = r2.stop()
	err := run(context.Background(), s, newFakes(t).start, io.Discard)
	if err == nil || !strings.Contains(err.Error(), s.Nodes[1].StateDir) {
		t.Fatalf("got %v, want the readable state dir refused", err)
	}
}

func TestNameFromCertDomains(t *testing.T) {
	t.Run("kept name", func(t *testing.T) {
		f := newFakes(t)
		f.tails["x402-seller-a"] = "x402-seller-a.tail0000.ts.net"
		s := testSettings(t)
		s.Nodes = s.Nodes[:1]
		r := start(t, s, f)
		if got := r.waitLines(t, 1)[0]; got != "https://x402-seller-a.tail0000.ts.net" {
			t.Fatalf("got %s", got)
		}
	})
	t.Run("renamed", func(t *testing.T) {
		f := newFakes(t)
		f.tails["x402-seller-a"] = "x402-seller-a-1.tail0000.ts.net"
		var out bytes.Buffer
		err := run(context.Background(), testSettings(t), f.start, &out)
		if err == nil || !strings.Contains(err.Error(), "x402-seller-a-1.tail0000.ts.net") ||
			!strings.Contains(err.Error(), "x402-seller-a ") {
			t.Fatalf("got %v, want both names", err)
		}
		if out.Len() != 0 {
			t.Fatalf("printed %q", out.String())
		}
	})
}

func TestKeepAliveOnlyWhenSet(t *testing.T) {
	for _, on := range []bool{false, true} {
		f := newFakes(t)
		s := testSettings(t)
		s.KeepalivePings = on
		r := start(t, s, f)
		r.waitLines(t, 2)
		got := f.nodes["x402-seller-a"].protos
		if on {
			if fmt.Sprint(got) != "[[h2 http/1.1]]" {
				t.Fatalf("on: protos %v", got)
			}
		} else if len(got) != 1 || len(got[0]) != 0 {
			t.Fatalf("off: protos %v", got)
		}
		srv := newServer(http.NotFoundHandler(), on)
		if on != (srv.HTTP2 != nil) {
			t.Fatalf("keepalive %v, HTTP2 %v", on, srv.HTTP2)
		}
		if on && srv.HTTP2.SendPingTimeout != 20*time.Second {
			t.Fatalf("ping timeout %v", srv.HTTP2.SendPingTimeout)
		}
		_ = r.stop()
	}
}

func TestServerTimeouts(t *testing.T) {
	srv := newServer(http.NotFoundHandler(), false)
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("timeouts %v %v %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout)
	}
}

func TestFacilitatorGetsOnlyItsKey(t *testing.T) {
	s := testSettings(t)
	r := start(t, s, newFakes(t))
	r.waitLines(t, 2)
	raw, err := os.ReadFile(filepath.Join(s.dir, "names"))
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Fields(string(raw))
	for _, want := range []string{
		"TESTSELLER_FEE_PAYER_KEY", "FACILITATOR_ADDR", "SOLANA_RPC_URL", "PATH", "HOME",
	} {
		if !contains(names, want) {
			t.Fatalf("the facilitator lacks %s, has %v", want, names)
		}
	}
	for _, n := range names {
		if n == "TS_AUTHKEY" || strings.HasPrefix(n, "TESTSELLER_TEST") {
			t.Fatalf("the facilitator got %s", n)
		}
	}
	if len(names) != 5 {
		t.Fatalf("environment names %v", names)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", s.FacilitatorAddr, 100*time.Millisecond)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the stub facilitator still answers after the stop")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestAFacilitatorThatExitsStopsTheStart(t *testing.T) {
	s := testSettings(t)
	exe, _ := os.Executable()
	s.FacilitatorCmd = []string{exe, "stub-exit"}
	err := run(context.Background(), s, newFakes(t).start, io.Discard)
	if err == nil {
		t.Fatal("got no error from a facilitator that never answers")
	}
}
