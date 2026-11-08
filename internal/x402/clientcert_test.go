package x402

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/x402/x402test"
	paymentsv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/payments/v1"
)

func TestSignerLoadsDevLayout(t *testing.T) {
	ca := x402test.NewCA(t)
	dir := t.TempDir()
	ca.WriteDev(t, dir)
	fake := x402test.StartPayments(t, x402test.ReadDev(t, dir))
	s := Defaults()
	s.PaymentsURL = fake.URL
	s.PaymentsCAFile = filepath.Join(dir, "internal-ca.pem")
	s.PaymentsClientCertFile = filepath.Join(dir, "egress-x402-client.pem")
	eq(t, s.PaymentsClientKeyCredential, "egress_x402_client_key")
	sig, err := NewSigner(s, dir, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reserveOK(t, sig, "aaaaaaaaaaaaaaaa")
	calls := fake.Calls()
	eq(t, len(calls), 1)
	eq(t, calls[0].Client.DNSNames, []string{"bugnet-egress.internal"})
}

func TestKeyFromCredential(t *testing.T) {
	e := newSignerEnv(t)
	moved := t.TempDir()
	keyPEM, err := os.ReadFile(filepath.Join(e.dir, x402test.ClientKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(moved, "my_key"), keyPEM)
	named := e.s
	named.PaymentsClientKeyCredential = "my_key"
	if _, err := NewSigner(named, moved, nil, time.Now); err != nil {
		t.Fatalf("a credential under its own name: %v", err)
	}

	garbage := t.TempDir()
	writeFile(t, filepath.Join(garbage, x402test.ClientKeyFile), []byte("hunter2-not-a-key"))
	certOnly := t.TempDir()
	writeFile(t, filepath.Join(certOnly, x402test.ClientKeyFile), e.ca.ClientPEM)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	for name, dir := range map[string]string{
		"unset":        os.Getenv("CREDENTIALS_DIRECTORY"),
		"missing file": t.TempDir(),
		"no key":       garbage,
		"no key block": certOnly,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewSigner(e.s, dir, nil, time.Now)
			if err == nil {
				t.Fatal("want an error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "x402.payments_client_key_credential") {
				t.Fatalf("%q does not name the setting", msg)
			}
			for _, leak := range []string{"hunter2", "PRIVATE KEY", "CERTIFICATE"} {
				if strings.Contains(msg, leak) {
					t.Fatalf("%q quotes the file", msg)
				}
			}
			if name != "unset" && strings.Contains(msg, dir) {
				t.Fatalf("%q names the path", msg)
			}
		})
	}
	_, err = NewSigner(e.s, "", nil, time.Now)
	if err == nil || !strings.Contains(err.Error(), "$CREDENTIALS_DIRECTORY") {
		t.Fatalf("got %v, want the variable named", err)
	}
}

func TestSignerFilesAtStart(t *testing.T) {
	e := newSignerEnv(t)
	keyPEM := x402test.KeyPEM(t, e.ca.ClientKey)
	for _, key := range []string{"payments_ca_file", "payments_client_cert_file"} {
		for _, tc := range []struct {
			name  string
			write func(t *testing.T, path string)
		}{
			{"missing", func(*testing.T, string) {}},
			{"unreadable", func(t *testing.T, path string) {
				if os.Geteuid() == 0 {
					t.Skip("root reads a file of mode 0")
				}
				writeFile(t, path, e.ca.PEM)
				if err := os.Chmod(path, 0); err != nil {
					t.Fatal(err)
				}
			}},
			{"no PEM", func(t *testing.T, path string) {
				writeFile(t, path, []byte("not a certificate"))
			}},
			{"a key, not a certificate", func(t *testing.T, path string) {
				writeFile(t, path, keyPEM)
			}},
		} {
			t.Run(key+" "+tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "file.pem")
				tc.write(t, path)
				s := e.s
				if key == "payments_ca_file" {
					s.PaymentsCAFile = path
				} else {
					s.PaymentsClientCertFile = path
				}
				_, err := NewSigner(s, e.dir, nil, time.Now)
				if err == nil {
					t.Fatal("want an error")
				}
				if !strings.Contains(err.Error(), "x402."+key) {
					t.Fatalf("%q does not name x402.%s", err, key)
				}
				if strings.Contains(err.Error(), path) {
					t.Fatalf("%q names the path", err)
				}
			})
		}
	}
}

func TestSignerRefusesACertificateForAnotherKey(t *testing.T) {
	e := newSignerEnv(t)
	other := x402test.NewKey(t)
	writeFile(t, e.s.PaymentsClientCertFile, e.ca.Issue(t, &other.PublicKey,
		x402test.ClientName, x509.ExtKeyUsageClientAuth, time.Now().AddDate(1, 0, 0)))
	_, err := NewSigner(e.s, e.dir, nil, time.Now)
	if err == nil || !strings.Contains(err.Error(), "x402.payments_client_cert_file") ||
		!strings.Contains(err.Error(), "x402.payments_client_key_credential") {
		t.Fatalf("got %v, want both settings named", err)
	}
}

func TestReloadKeepsKey(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	first := lastClient(t, e.fake)

	renewed := e.ca.Issue(t, &e.ca.ClientKey.PublicKey, x402test.ClientName,
		x509.ExtKeyUsageClientAuth, time.Now().AddDate(1, 0, 0))
	writeFile(t, e.s.PaymentsClientCertFile, renewed)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	reserveOK(t, s, "bbbbbbbbbbbbbbbb")
	second := lastClient(t, e.fake)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("the next handshake kept the old certificate")
	}
	eq(t, second.Raw, pemDER(t, renewed))

	other := x402test.NewKey(t)
	writeFile(t, e.s.PaymentsClientCertFile, e.ca.Issue(t, &other.PublicKey,
		x402test.ClientName, x509.ExtKeyUsageClientAuth, time.Now().AddDate(1, 0, 0)))
	err := s.Reload()
	if err == nil || !strings.Contains(err.Error(), "x402.payments_client_cert_file") {
		t.Fatalf("got %v, want a refusal naming the file setting", err)
	}
	s.current().CloseIdleConnections()
	reserveOK(t, s, "cccccccccccccccc")
	eq(t, lastClient(t, e.fake).Raw, second.Raw)
}

func TestReloadReachesABusyConnection(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	release := make(chan struct{})
	let := sync.OnceFunc(func() { close(release) })
	t.Cleanup(let)
	e.fake.OnReserve(func(ctx context.Context, r *paymentsv1.ReserveAndSignRequest) (
		*paymentsv1.ReserveAndSignResponse, error,
	) {
		if r.GetRef() == "aaaaaaaaaaaaaaaa" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return nil, nil
	})
	held := make(chan error, 1)
	go func() {
		_, err := s.Reserve(context.Background(), reserveRequest("aaaaaaaaaaaaaaaa"))
		held <- err
	}()
	waitFor(t, "the held call", func() bool { return len(e.fake.Reserves()) == 1 })
	first := lastClient(t, e.fake)

	renewed := e.ca.Issue(t, &e.ca.ClientKey.PublicKey, x402test.ClientName,
		x509.ExtKeyUsageClientAuth, time.Now().AddDate(1, 0, 0))
	writeFile(t, e.s.PaymentsClientCertFile, renewed)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	reserveOK(t, s, "bbbbbbbbbbbbbbbb")
	if !bytes.Equal(lastClient(t, e.fake).Raw, pemDER(t, renewed)) {
		t.Fatal("the next call kept the busy connection and the old certificate")
	}

	let()
	select {
	case err := <-held:
		if err != nil {
			t.Fatalf("the call in flight failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the call in flight never ended")
	}
	if !bytes.Equal(e.fake.Calls()[0].Client.Raw, first.Raw) {
		t.Fatal("the call in flight moved off its connection")
	}
}

func TestReloadKeepsTheOldCA(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	writeFile(t, e.s.PaymentsCAFile, []byte("not a certificate"))
	err := s.Reload()
	if err == nil || !strings.Contains(err.Error(), "x402.payments_ca_file") {
		t.Fatalf("got %v, want a refusal naming the CA setting", err)
	}
	reserveOK(t, s, "aaaaaaaaaaaaaaaa")
}

func TestReloadReadsTheCA(t *testing.T) {
	e := newSignerEnv(t)
	s := e.signer(t)
	reserveOK(t, s, "aaaaaaaaaaaaaaaa")
	writeFile(t, e.s.PaymentsCAFile, x402test.NewCA(t).PEM)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	_, err := s.Reserve(context.Background(), reserveRequest("bbbbbbbbbbbbbbbb"))
	if failedVerify(err) == nil {
		t.Fatalf("got %v, want the new CA to refuse the old server", err)
	}
}

func TestCertExpiryLineDaily(t *testing.T) {
	for _, tc := range []struct {
		name  string
		left  time.Duration
		lines []int
	}{
		{"29 days", 29*24*time.Hour + time.Hour, []int{1, 1, 2, 2, 3}},
		{"30 days", 30 * 24 * time.Hour, []int{1, 1, 2, 2, 3}},
		{"31 days", 31 * 24 * time.Hour, []int{0, 0, 1, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSignerEnv(t)
			start := time.Now().Truncate(time.Second)
			writeFile(t, e.s.PaymentsClientCertFile, e.ca.Issue(t, &e.ca.ClientKey.PublicKey,
				x402test.ClientName, x509.ExtKeyUsageClientAuth, start.Add(tc.left)))
			clock := &cacheClock{t: start}
			s, err := NewSigner(e.s, e.dir, e.logger(), clock.now)
			if err != nil {
				t.Fatal(err)
			}
			tick := make(chan time.Time)
			s.expiryTick = tick
			run(t, s)
			// Each step's two ticks return only once the first tick's check has run
			for i, step := range []time.Duration{
				0, 23*time.Hour + 59*time.Minute, 24 * time.Hour, 47 * time.Hour, 48 * time.Hour,
			} {
				clock.set(start.Add(step))
				tick <- time.Time{}
				tick <- time.Time{}
				got := e.logs.records(t, msgCertExpiry)
				if len(got) != tc.lines[i] {
					t.Fatalf("after %v: %d lines, want %d", step, len(got), tc.lines[i])
				}
			}
			for _, rec := range e.logs.records(t, msgCertExpiry) {
				eq(t, rec["level"], any("ERROR"))
				eq(t, rec["file"], any(e.s.PaymentsClientCertFile))
			}
			if tc.lines[0] == 1 {
				eq(t, e.logs.records(t, msgCertExpiry)[0]["days_left"], any(float64(
					tc.left/(24*time.Hour))))
			}
		})
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// lastClient is the certificate the fake's last call presented
func lastClient(t *testing.T, fake *x402test.Payments) *x509.Certificate {
	t.Helper()
	calls := fake.Calls()
	if len(calls) == 0 {
		t.Fatal("no call")
	}
	return calls[len(calls)-1].Client
}

// pemDER is the DER of the first PEM block in b
func pemDER(t *testing.T, b []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}
