package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-edges/internal/certmetric"
	"github.com/oynozan/bugnet-edges/internal/metrics"
	"github.com/oynozan/bugnet-edges/internal/tlsconf"
)

const wildcard = "*.preview.example.test"

// fakeIssuer issues self-signed pairs and records what it was asked
type fakeIssuer struct {
	t         *testing.T
	window    *Window
	windowErr error
	fail      error
	life      time.Duration
	obtained  [][]string
	replaced  []*x509.Certificate
}

func (f *fakeIssuer) Window(*x509.Certificate) (*Window, error) {
	return f.window, f.windowErr
}

func (f *fakeIssuer) Obtain(names []string, old *x509.Certificate) ([]byte, []byte, error) {
	f.obtained = append(f.obtained, names)
	f.replaced = append(f.replaced, old)
	if f.fail != nil {
		return nil, nil, f.fail
	}
	now := time.Now()
	chain, key := pemPair(f.t, now.Add(-time.Hour), now.Add(f.life), names...)
	return chain, key, nil
}

func newFake(t *testing.T) *fakeIssuer {
	return &fakeIssuer{t: t, life: 90 * 24 * time.Hour}
}

func config(dirs ...string) Config {
	c := Defaults()
	c.CertMetrics = nil
	for _, d := range dirs {
		c.Certificates = append(c.Certificates, Certificate{Names: []string{wildcard}, Dir: d})
	}
	return c
}

func leafIn(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// metricsAt serves body as /metrics and returns the listener's address
func metricsAt(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestCertsIssuesAMissingPairThenWaits(t *testing.T) {
	dir := t.TempDir()
	iss, l := newFake(t), &logs{}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	eq(t, iss.obtained, [][]string{{wildcard}})
	eq(t, iss.replaced[0] == nil, true)
	first := leafIn(t, dir)
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	eq(t, len(iss.obtained), 1)
	later := time.Now().Add(61 * 24 * time.Hour)
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), later), true)
	eq(t, len(iss.obtained), 2)
	eq(t, iss.replaced[1].SerialNumber, first.SerialNumber)
}

func TestCertsRenewsByTheARIWindow(t *testing.T) {
	dir := t.TempDir()
	iss, l := newFake(t), &logs{}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	iss.window = &Window{Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Hour)}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	eq(t, len(iss.obtained), 2)
}

func TestCertsWindowErrorFallsBackToTwoThirds(t *testing.T) {
	dir := t.TempDir()
	iss, l := newFake(t), &logs{}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	iss.window = &Window{Start: time.Now().Add(-time.Minute)}
	iss.windowErr = errors.New("acme: renewal info unavailable")
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	eq(t, len(iss.obtained), 1)
	warns := l.records(t, "WARN")
	eq(t, len(warns), 1)
	eq[any](t, warns[0]["names"], wildcard)
	eq(t, len(l.errors(t)), 0)
	later := time.Now().Add(61 * 24 * time.Hour)
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), later), true)
	eq(t, len(iss.obtained), 2)
}

func TestCertsFailedRenewalExitsOne(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	iss, l := newFake(t), &logs{}
	iss.fail = errors.New("acme: the order failed")
	eq(t, Run(t.Context(), config(a, b), iss, l.logger(), time.Now()), false)
	eq(t, len(iss.obtained), 2)
	errs := l.errors(t)
	if len(errs) < 2 || !strings.Contains(fmt.Sprint(errs[0]["names"]), wildcard) {
		t.Fatalf("errors %v", errs)
	}
	eq(t, Run(t.Context(), config(a), nil, l.logger(), time.Now()), false)
}

// pairIn fails the test unless dir holds a fullchain.pem and key.pem that form a pair
func pairIn(t *testing.T, dir string) {
	t.Helper()
	chain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		t.Fatalf("the files do not form a pair: %v", err)
	}
}

func TestCertsReissuesAMissingOrForeignKeyAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, dir string)
	}{
		{"missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "key.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign", func(t *testing.T, dir string) {
			_, other := pemPair(t, time.Now().Add(-time.Hour), time.Now().AddDate(0, 0, 90),
				wildcard)
			if err := os.WriteFile(filepath.Join(dir, "key.pem"), other, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"not a key", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("x"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			iss, l := newFake(t), &logs{}
			eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
			first := leafIn(t, dir)
			tc.spoil(t, dir)
			// Not due by the chain alone, so only the key sends it back to the CA
			eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
			eq(t, len(iss.obtained), 2)
			eq(t, iss.replaced[1].SerialNumber, first.SerialNumber)
			pairIn(t, dir)
			warns := l.records(t, "WARN")
			eq(t, len(warns), 1)
			eq[any](t, warns[0]["names"], wildcard)
			eq(t, len(l.errors(t)), 0)
		})
	}
}

func TestCertsKeyWithoutChainIsIssued(t *testing.T) {
	dir := t.TempDir()
	_, key := pemPair(t, time.Now().Add(-time.Hour), time.Now().AddDate(0, 0, 90), wildcard)
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), key, 0o640); err != nil {
		t.Fatal(err)
	}
	iss, l := newFake(t), &logs{}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	eq(t, len(iss.obtained), 1)
	eq(t, iss.replaced[0] == nil, true)
	pairIn(t, dir)
}

func TestCertsForeignKeyThatCannotBeReissuedFailsTheRun(t *testing.T) {
	dir := t.TempDir()
	iss, l := newFake(t), &logs{}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), true)
	if err := os.Remove(filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	iss.fail = errors.New("acme: the order failed")
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), false)
	var msgs []any
	for _, e := range l.errors(t) {
		msgs = append(msgs, e["msg"])
		eq[any](t, e["names"], wildcard)
	}
	eq(t, msgs, []any{"certificate renewal failed", "certificate key missing or not its pair"})
	// With no ACME client the run still names the key, never only the renewal
	l = &logs{}
	eq(t, Run(t.Context(), config(dir), nil, l.logger(), time.Now()), false)
	eq(t, len(l.errors(t)), 2)
}

func TestCertsOwnPairUnderAlertDays(t *testing.T) {
	dir := t.TempDir()
	iss, l := newFake(t), &logs{}
	iss.life = 13*24*time.Hour + time.Hour
	iss.window = &Window{Start: time.Now().Add(time.Hour)}
	eq(t, Run(t.Context(), config(dir), iss, l.logger(), time.Now()), false)
	eq(t, len(l.errors(t)), 1)
	eq[any](t, l.errors(t)[0]["days_left"], float64(13))
}

func TestCertsAlertsUnderFourteenDays(t *testing.T) {
	for _, tc := range []struct {
		days int
		ok   bool
	}{{13, false}, {14, true}, {15, true}} {
		cfg, l := config(), &logs{}
		cfg.CertMetrics = []string{metricsAt(t, fmt.Sprintf(
			"# HELP edge_cert_days_left x\n# TYPE edge_cert_days_left gauge\n"+
				"edge_cert_days_left{name=\"transfer.example.test\"} %d\n"+
				"edge_cert_days_left{name=\"hooks.example.test\"} 60\n"+
				"edge_cert_issued{name=\"transfer.example.test\"} 1\n", tc.days))}
		eq(t, Run(t.Context(), cfg, nil, l.logger(), time.Now()), tc.ok)
		errs := l.errors(t)
		if tc.ok {
			eq(t, len(errs), 0)
			continue
		}
		eq(t, len(errs), 1)
		eq[any](t, errs[0]["name"], "transfer.example.test")
		eq[any](t, errs[0]["days_left"], float64(tc.days))
		eq[any](t, errs[0]["from"], cfg.CertMetrics[0])
	}
}

func TestCertsAlertsOnANameNeverIssued(t *testing.T) {
	wild, state := t.TempDir(), t.TempDir()
	chain, key := pemPair(t, time.Now().Add(-time.Hour), time.Now().AddDate(0, 0, 60), wildcard)
	if err := Write(wild, chain, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsconf.New(tlsconf.Options{
		Names: []tlsconf.Name{{Host: "transfer.example.test", ALPN: []string{"http/1.1"}}},
		Wildcard: &tlsconf.Wildcard{
			Suffix: "preview.example.test", Dir: wild, ALPN: []string{"h2", "http/1.1"},
		},
		ACME: tlsconf.ACME{
			Enabled: true, Directory: "http://127.0.0.1:1/directory", StateDir: state,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, l := metrics.New(), &logs{}
	select {
	case <-certmetric.Export(reg, cfg, l.logger()):
	case <-time.After(10 * time.Second):
		t.Fatal("the start request never answered")
	}
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	c := config()
	c.CertMetrics = []string{strings.TrimPrefix(srv.URL, "http://")}
	eq(t, Run(t.Context(), c, nil, l.logger(), time.Now()), false)
	var never []any
	for _, e := range l.errors(t) {
		if e["msg"] == "certificate never issued" {
			never = append(never, e["name"])
		}
	}
	eq(t, never, []any{"transfer.example.test"})
}

func TestCertsUnreachableMetricsExitOne(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	retryWait = 10 * time.Millisecond
	t.Cleanup(func() { retryWait = 2 * time.Second })
	cfg, l := config(), &logs{}
	cfg.CertMetrics = []string{addr}
	eq(t, Run(t.Context(), cfg, nil, l.logger(), time.Now()), false)
	eq[any](t, l.errors(t)[0]["from"], addr)
}

func TestParseMetrics(t *testing.T) {
	days, issued, err := parseMetrics(strings.NewReader(
		"# HELP edge_cert_days_left a \\\"b\\\"\n" +
			"edge_cert_days_left{name=\"a\\\\b\\\"c\"} -2\n" +
			"edge_cert_days_left{name=\"x.example.test\"} 3.5\n" +
			"edge_cert_issued{name=\"y.example.test\"} 0\n" +
			"other_metric{name=\"z\"} 1\n" +
			"edge_cert_issued_total 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, days, map[string]int{`a\b"c`: -2, "x.example.test": 3})
	eq(t, issued, map[string]bool{"y.example.test": false})
	broken := strings.NewReader("edge_cert_days_left{name=\"x\" 3\n")
	if _, _, err := parseMetrics(broken); err == nil {
		t.Fatal("a broken line parsed")
	}
}
