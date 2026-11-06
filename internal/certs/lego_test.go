package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
)

// fakeCA answers the directory, nonces, new accounts, renewal information and new orders
type fakeCA struct {
	dir      string
	hc       *http.Client
	accounts atomic.Int32

	mu       sync.Mutex
	replaces []string // the replaces field of each new order
	refusal  string   // the ACME problem type every new order gets
	status   int
}

func (f *fakeCA) ordered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.replaces...)
}

func fakeACME(t *testing.T, ari bool, start time.Time) *fakeCA {
	t.Helper()
	f := &fakeCA{refusal: "urn:ietf:params:acme:error:malformed", status: 400}
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		d := map[string]string{
			"newNonce": base + "/nonce", "newAccount": base + "/acct",
			"newOrder": base + "/order", "revokeCert": base + "/revoke",
			"keyChange": base + "/key",
		}
		if ari {
			d["renewalInfo"] = base + "/ari"
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/acct", func(w http.ResponseWriter, _ *http.Request) {
		f.accounts.Add(1)
		w.Header().Set("Replay-Nonce", "nonce")
		w.Header().Set("Location", base+"/acct/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"status":"valid","orders":"`+base+`/orders"}`)
	})
	mux.HandleFunc("/ari/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"suggestedWindow": map[string]string{
			"start": start.Format(time.RFC3339), "end": start.Add(time.Hour).Format(time.RFC3339),
		}})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		var jws struct{ Payload string }
		var order struct{ Replaces string }
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			t.Error(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err == nil {
			err = json.Unmarshal(payload, &order)
		}
		if err != nil {
			t.Error(err)
		}
		f.mu.Lock()
		f.replaces = append(f.replaces, order.Replaces)
		f.mu.Unlock()
		w.Header().Set("Replay-Nonce", "nonce")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": f.refusal, "detail": "refused", "status": f.status,
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	f.dir, f.hc = base+"/dir", srv.Client()
	return f
}

// ariLeaf is a certificate an ARI id can name, since it carries an authority key id
func ariLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(4242),
		Subject:        pkix.Name{CommonName: wildcard},
		DNSNames:       []string{wildcard},
		NotBefore:      day0,
		NotAfter:       day0.Add(90 * 24 * time.Hour),
		AuthorityKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func legoConfig(t *testing.T, directory string) Config {
	t.Helper()
	t.Setenv("EXEC_PATH", "/bin/true")
	c := Defaults()
	c.Directory = directory
	c.StateDir = t.TempDir()
	c.DNSProvider = "exec"
	c.DNSEnv = []string{"EXEC_PATH"}
	return c
}

func TestLegoKeepsItsAccountAcrossRuns(t *testing.T) {
	start := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	ca := fakeACME(t, true, start)
	cfg := legoConfig(t, ca.dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	iss, err := newLego(cfg, log, ca.hc)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, ca.accounts.Load(), int32(1))
	entries, _ := os.ReadDir(cfg.StateDir)
	eq(t, len(entries), 1)
	acct := filepath.Join(cfg.StateDir, entries[0].Name())
	for _, name := range []string{"account.key", "account.json"} {
		fi, err := os.Stat(filepath.Join(acct, name))
		if err != nil {
			t.Fatal(err)
		}
		eq(t, fi.Mode().Perm(), os.FileMode(0o600))
	}
	if _, err := newLego(cfg, log, ca.hc); err != nil {
		t.Fatal(err)
	}
	eq(t, ca.accounts.Load(), int32(1))

	w, err := iss.Window(certValid(t, day0, 90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, w.Start.Equal(start), true)
	eq(t, w.End.Equal(start.Add(time.Hour)), true)
}

func TestLegoWithoutARIGivesNoWindow(t *testing.T) {
	ca := fakeACME(t, false, time.Time{})
	iss, err := newLego(legoConfig(t, ca.dir), slog.New(slog.DiscardHandler), ca.hc)
	if err != nil {
		t.Fatal(err)
	}
	w, err := iss.Window(certValid(t, day0, 90*24*time.Hour))
	eq(t, err, nil)
	eq(t, w == nil, true)
}

func TestLegoNeedsItsProviderBeforeAnyACMECall(t *testing.T) {
	ca := fakeACME(t, true, time.Time{})
	cfg := legoConfig(t, ca.dir)
	cfg.DNSProvider = "no-such-provider"
	_, err := newLego(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), ca.hc)
	if err == nil || !strings.Contains(err.Error(), "dns_provider") {
		t.Fatalf("got %v", err)
	}
	eq(t, ca.accounts.Load(), int32(0))
	entries, _ := os.ReadDir(cfg.StateDir)
	eq(t, len(entries), 0)
}

func TestLegoOrdersAgainWithoutReplacesWhenTheCARefusesIt(t *testing.T) {
	old := ariLeaf(t)
	id, err := certificate.MakeARICertID(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		refusal string
		status  int
		want    []string
	}{
		{"urn:ietf:params:acme:error:malformed", 400, []string{id, ""}},
		{"urn:ietf:params:acme:error:unauthorized", 403, []string{id, ""}},
		{"urn:ietf:params:acme:error:rejectedIdentifier", 400, []string{id}},
	} {
		ca := fakeACME(t, true, time.Time{})
		ca.refusal, ca.status = tc.refusal, tc.status
		l := &logs{}
		iss, err := newLego(legoConfig(t, ca.dir), l.logger(), ca.hc)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := iss.Obtain([]string{wildcard}, old); err == nil {
			t.Fatalf("%s: the order went through", tc.refusal)
		}
		eq(t, ca.ordered(), tc.want)
		eq(t, len(l.records(t, "WARN")), len(tc.want)-1)
	}
}

func TestObtainReplacingRetriesOnlyARefusedOrder(t *testing.T) {
	const newOrder = "https://ca.example.test/acme/new-order"
	old := ariLeaf(t)
	id, err := certificate.MakeARICertID(old)
	if err != nil {
		t.Fatal(err)
	}
	problem := func(typ string, status int, url string) error {
		return &acme.ProblemDetails{
			Type: "urn:ietf:params:acme:error:" + typ, HTTPStatus: status, URL: url,
		}
	}
	validation := fmt.Errorf("error: one or more domains had a problem:\n%w", errors.Join(
		fmt.Errorf("%s: %w", wildcard, problem("unauthorized", 403, ""))))
	for _, tc := range []struct {
		name    string
		old     *x509.Certificate
		answers []error
		want    []string
	}{
		{"accepted at once", old, []error{nil}, []string{id}},
		{"malformed replaces", old, []error{problem("malformed", 400, newOrder), nil},
			[]string{id, ""}},
		{"another account's certificate", old,
			[]error{problem("unauthorized", 403, newOrder), nil}, []string{id, ""}},
		{"already replaced", old, []error{problem("alreadyReplaced", 409, newOrder), nil},
			[]string{id, ""}},
		{"a conflict", old, []error{problem("orderNotReady", 409, newOrder), nil},
			[]string{id, ""}},
		{"refused twice", old, []error{problem("malformed", 400, newOrder),
			problem("malformed", 400, newOrder)}, []string{id, ""}},
		{"a failed validation", old, []error{validation}, []string{id}},
		{"an authorization fetch", old,
			[]error{problem("malformed", 400, "https://ca.example.test/acme/authz/1")},
			[]string{id}},
		{"rate limited", old, []error{problem("rateLimited", 429, newOrder)}, []string{id}},
		{"a propagation timeout", old, []error{errors.New("time limit exceeded")},
			[]string{id}},
		{"no old certificate", nil, []error{problem("malformed", 400, newOrder)}, []string{""}},
	} {
		var asked []string
		obtain := func(replaces string) (*certificate.Resource, error) {
			asked = append(asked, replaces)
			if len(asked) > len(tc.answers) {
				t.Fatalf("%s: asked %d times", tc.name, len(asked))
			}
			if err := tc.answers[len(asked)-1]; err != nil {
				return nil, err
			}
			return &certificate.Resource{}, nil
		}
		res, err := obtainReplacing(obtain, tc.old, newOrder, slog.New(slog.DiscardHandler))
		if !reflect.DeepEqual(asked, tc.want) {
			t.Errorf("%s: asked %q, want %q", tc.name, asked, tc.want)
		}
		if last := tc.answers[len(asked)-1]; err != last || (err == nil) != (res != nil) {
			t.Errorf("%s: got %v, %v, want the last answer %v", tc.name, res, err, last)
		}
	}
}
