package certs

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeACME answers the directory, nonces, new accounts and renewal information, nothing else
func fakeACME(t *testing.T, ari bool, start time.Time) (
	dir string, hc *http.Client, accounts *atomic.Int32,
) {
	t.Helper()
	accounts = &atomic.Int32{}
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
		accounts.Add(1)
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
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	return base + "/dir", srv.Client(), accounts
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
	dir, hc, accounts := fakeACME(t, true, start)
	cfg := legoConfig(t, dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	iss, err := newLego(cfg, log, hc)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, accounts.Load(), int32(1))
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
	if _, err := newLego(cfg, log, hc); err != nil {
		t.Fatal(err)
	}
	eq(t, accounts.Load(), int32(1))

	w, err := iss.Window(certValid(t, day0, 90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, w.Start.Equal(start), true)
	eq(t, w.End.Equal(start.Add(time.Hour)), true)
}

func TestLegoWithoutARIGivesNoWindow(t *testing.T) {
	dir, hc, _ := fakeACME(t, false, time.Time{})
	iss, err := newLego(legoConfig(t, dir), slog.New(slog.NewTextHandler(io.Discard, nil)), hc)
	if err != nil {
		t.Fatal(err)
	}
	w, err := iss.Window(certValid(t, day0, 90*24*time.Hour))
	eq(t, err, nil)
	eq(t, w == nil, true)
}

func TestLegoNeedsItsProviderBeforeAnyACMECall(t *testing.T) {
	dir, hc, accounts := fakeACME(t, true, time.Time{})
	cfg := legoConfig(t, dir)
	cfg.DNSProvider = "no-such-provider"
	_, err := newLego(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), hc)
	if err == nil || !strings.Contains(err.Error(), "dns_provider") {
		t.Fatalf("got %v", err)
	}
	eq(t, accounts.Load(), int32(0))
	entries, _ := os.ReadDir(cfg.StateDir)
	eq(t, len(entries), 0)
}
