package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/tlsconf"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

// eq fails the test when got and want differ
func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// testKey is a test-only Ed25519 key from a label
func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("bugnet fakeseller test " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// addressOf is base58 of a key's public half
func addressOf(k ed25519.PrivateKey) string {
	return x402.Encode58(k.Public().(ed25519.PublicKey))
}

// The test seller's keys and addresses
var (
	feeKey    = testKey("fee payer")
	payTo     = addressOf(testKey("pay to"))
	payToATA  = addressOf(testKey("pay to account"))
	bugnetFee = addressOf(testKey("bugnet fee payer"))
	secret58  = x402.Encode58(feeKey)
)

// pair writes a self-signed certificate for seller.test and 127.0.0.1, answering its paths
func pair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "seller.test"},
		DNSNames:     []string{"seller.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	write(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return certFile, keyFile
}

// write writes a file the test owns
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// doc is a settings file with every required setting, each extra line replacing its key's
func doc(t *testing.T, extra ...string) string {
	t.Helper()
	certFile, keyFile := pair(t)
	lines := []string{
		`listen = "127.0.0.1:0"`,
		fmt.Sprintf("tls_cert_file = %q", certFile),
		fmt.Sprintf("tls_key_file = %q", keyFile),
		fmt.Sprintf("pay_to = %q", payTo),
		fmt.Sprintf("pay_to_token_account = %q", payToATA),
		fmt.Sprintf("fee_payer = %q", addressOf(feeKey)),
		fmt.Sprintf("bugnet_fee_payer = %q", bugnetFee),
		`chain_url = "http://127.0.0.1:8899"`,
	}
	for _, e := range extra {
		key, _, _ := strings.Cut(e, " = ")
		i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, key+" = ") })
		if i >= 0 {
			lines[i] = e
		} else {
			lines = append(lines, e)
		}
	}
	path := filepath.Join(t.TempDir(), "seller.toml")
	write(t, path, strings.Join(lines, "\n")+"\n")
	return path
}

// env is a getenv over a map
func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// withKey is an environment holding the fee payer's key in base58
var withKey = env(map[string]string{"TESTSELLER_FEE_PAYER_KEY": secret58})

// noLeak fails when an error quotes the secret
func noLeak(t *testing.T, err error, secret string) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Fatalf("the error quotes the secret: %v", err)
	}
}

func TestKeyOnlyFromTheEnvironment(t *testing.T) {
	_, err := load(doc(t, fmt.Sprintf("fee_payer_key = %q", secret58)), withKey)
	if err == nil || !strings.Contains(err.Error(), "fee_payer_key is not a setting") {
		t.Fatalf("a key in the file loaded: %v", err)
	}
	noLeak(t, err, secret58)

	_, err = load(doc(t), env(nil))
	if err == nil || !strings.Contains(err.Error(), "fee_payer_key_env") ||
		!strings.Contains(err.Error(), "TESTSELLER_FEE_PAYER_KEY") {
		t.Fatalf("a missing variable started: %v", err)
	}

	s, err := load(doc(t), withKey)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, s.config.FeePayer, addressOf(feeKey))

	ints := make([]int, len(feeKey))
	for i, b := range feeKey {
		ints[i] = int(b)
	}
	array, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	other := env(map[string]string{"OTHER_KEY": string(array)})
	if _, err := load(doc(t, `fee_payer_key_env = "OTHER_KEY"`), other); err != nil {
		t.Fatal(err)
	}

	wrong := x402.Encode58(testKey("someone else"))
	_, err = load(doc(t), env(map[string]string{"TESTSELLER_FEE_PAYER_KEY": wrong}))
	if err == nil || !strings.Contains(err.Error(), "fee_payer") {
		t.Fatalf("another key started: %v", err)
	}
	noLeak(t, err, wrong)

	half := secret58[:40]
	_, err = load(doc(t), env(map[string]string{"TESTSELLER_FEE_PAYER_KEY": half}))
	if err == nil || !strings.Contains(err.Error(), "TESTSELLER_FEE_PAYER_KEY") {
		t.Fatalf("a malformed key started: %v", err)
	}
	noLeak(t, err, half)

	if _, err := load(doc(t, `settle = "facilitator"`,
		`facilitator_url = "http://127.0.0.1:8402"`), env(nil)); err != nil {
		t.Fatalf("the facilitator mode wants a key: %v", err)
	}
}

func TestSettingsRefused(t *testing.T) {
	cases := []struct {
		want  string
		lines []string
	}{
		{"listen", []string{`listen = "nowhere"`}},
		{"or acme_hosts", []string{`tls_cert_file = ""`, `tls_key_file = ""`}},
		{"tls_key_file", []string{`tls_key_file = ""`}},
		{"acme_hosts", []string{`acme_hosts = ["seller.example.com"]`, `acme_dir = "/tmp/a"`}},
		{"acme_dir", []string{`tls_cert_file = ""`, `tls_key_file = ""`,
			`acme_hosts = ["seller.example.com"]`}},
		{"acme_dir", []string{`tls_cert_file = ""`, `tls_key_file = ""`,
			`acme_hosts = ["seller.example.com"]`, `acme_dir = "relative"`}},
		{"acme_hosts", []string{`tls_cert_file = ""`, `tls_key_file = ""`,
			`acme_hosts = ["Seller.Example.com"]`, `acme_dir = "/tmp/a"`}},
		{"pay_to", []string{`pay_to = "0OIl"`}},
		{"fee_payer", []string{`fee_payer = ""`}},
		{"bugnet_fee_payer", []string{`bugnet_fee_payer = "abc"`}},
		{"settle", []string{`settle = "chain"`}},
		{"chain_url", []string{`chain_url = "127.0.0.1:8899"`}},
		{"pay_to_token_account", []string{`pay_to_token_account = ""`}},
		{"facilitator_url", []string{`settle = "facilitator"`}},
		{"fee_payer_key_env", []string{`fee_payer_key_env = "1BAD"`}},
		{"test_token_env", []string{`test_token_env = ""`}},
		{"late", []string{`late = "0s"`}},
		{"redirect_to", []string{`redirect_to = "/elsewhere"`}},
		{"tls_cert_file", []string{`tls_cert_file = "/nonexistent/cert.pem"`}},
	}
	for _, c := range cases {
		_, err := load(doc(t, c.lines...), withKey)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.lines, err)
		}
	}
}

func TestExampleIsTheDefaults(t *testing.T) {
	var f file
	if err := settings.Load("../../example/x402-fake-seller.toml", &f); err != nil {
		t.Fatal(err)
	}
	eq(t, f, defaults())
}

func TestSettingsReachTheSeller(t *testing.T) {
	s, err := load(doc(t, `late = "1s"`, `slow = "2s"`, `stall = "3s"`,
		`redirect_to = "https://other.test/"`, `test_token_env = "TOKEN"`),
		env(map[string]string{"TESTSELLER_FEE_PAYER_KEY": secret58, "TOKEN": "t0k"}))
	if err != nil {
		t.Fatal(err)
	}
	c := s.config
	c.Settler = nil
	eq(t, c.PayTo, payTo)
	eq(t, c.PayToTokenAccount, payToATA)
	eq(t, c.BugnetFeePayer, bugnetFee)
	eq(t, []time.Duration{c.Late, c.Slow, c.Stall}, []time.Duration{time.Second,
		2 * time.Second, 3 * time.Second})
	eq(t, c.RedirectTo, "https://other.test/")
	eq(t, c.TestToken, "t0k")
	eq(t, s.listen, "127.0.0.1:0")
}

func TestServerTimeouts(t *testing.T) {
	s, err := load(doc(t), withKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(s, slog.New(slog.DiscardHandler))
	eq(t, srv.ReadHeaderTimeout, 10*time.Second)
	eq(t, srv.ReadTimeout, time.Duration(0))
	eq(t, srv.WriteTimeout, time.Duration(0))
}

func TestACMEServesTheListedHosts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	path := doc(t, `tls_cert_file = ""`, `tls_key_file = ""`,
		`acme_hosts = ["a.seller.example", "b.seller.example"]`,
		fmt.Sprintf("acme_dir = %q", dir))
	s, err := load(path, withKey)
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := tlsconf.Hosts(s.tls)
	eq(t, hosts, []string{"a.seller.example", "b.seller.example"})
	if _, err := s.tls.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "c.test"}); err == nil {
		t.Fatal("an unlisted name has a certificate")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, info.Mode().Perm(), os.FileMode(0o700))
}

func TestUsage(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	for _, args := range [][]string{nil, {"-config"}, {"-config", "a", "b"}, {"-other"}} {
		if err := run(t.Context(), log, args, withKey); err != errUsage {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestServesOverTLSThroughAFacilitator(t *testing.T) {
	sum := sha512.Sum512([]byte("settled"))
	sig := x402.Encode58(sum[:])
	posts := make(chan string, 4)
	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts <- r.URL.Path
		if r.URL.Path == "/verify" {
			_, _ = io.WriteString(w, `{"isValid":true}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"transaction":"`+sig+`"}`)
	}))
	defer fac.Close()
	path := doc(t, `settle = "facilitator"`, fmt.Sprintf("facilitator_url = %q", fac.URL))
	s, err := load(path, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var logs bytes.Buffer
	go func() { done <- serve(ctx, s, ln, slog.New(slog.NewJSONHandler(&logs, nil))) }()

	pool := x509.NewCertPool()
	pool.AddCert(s.tls.Certificates[0].Leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "seller.test"},
	}}
	base := "https://" + ln.Addr().String()
	res, err := client.Get(base + "/free/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	eq(t, res.StatusCode, http.StatusOK)

	res, err = client.Get(base + "/ok/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	eq(t, res.StatusCode, http.StatusPaymentRequired)
	raw, err := base64.StdEncoding.DecodeString(res.Header.Get("Payment-Required"))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	var accepts []json.RawMessage
	if json.Unmarshal(raw, &top) != nil || json.Unmarshal(top["accepts"], &accepts) != nil {
		t.Fatal("the 402 is not x402 v2")
	}
	value := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepted":` +
		string(accepts[0]) + `,"payload":{"transaction":"AQ=="}}`))
	req, err := http.NewRequest(http.MethodGet, base+"/ok/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Payment-Signature", value)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	eq(t, res.StatusCode, http.StatusOK)
	eq(t, []string{<-posts, <-posts}, []string{"/verify", "/settle"})

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), ln.Addr().String()) {
		t.Fatalf("the log does not name the address\n%s", logs.String())
	}
	if strings.Contains(logs.String(), value) {
		t.Fatal("the log holds the payment")
	}
}
