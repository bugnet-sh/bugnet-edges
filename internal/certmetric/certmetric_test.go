package certmetric

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/tlsconf"
)

const (
	previewHost  = "preview.example.test"
	transferHost = "transfer.example.test"
	hooksHost    = "hooks.example.test"
	wildcardName = "*.preview.example.test"
)

var both = []string{"h2", "http/1.1"}

func names() []tlsconf.Name {
	return []tlsconf.Name{
		{Host: previewHost, ALPN: both},
		{Host: transferHost, ALPN: []string{"http/1.1"}},
		{Host: hooksHost, ALPN: both},
	}
}

func scrape(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func wait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the start requests never answered")
	}
}

func TestExportStaticPair(t *testing.T) {
	notAfter := time.Now().Add(40*24*time.Hour + 12*time.Hour)
	chain, key := pair(t, notAfter, previewHost, transferHost, hooksHost, wildcardName)
	cfg, err := tlsconf.New(tlsconf.Options{
		Names:    names(),
		Wildcard: &tlsconf.Wildcard{Suffix: previewHost, ALPN: both},
		Static:   writePair(t, chain, key),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := metrics.New()
	wait(t, Export(r, cfg, quiet()))
	got := scrape(t, r)
	for _, name := range []string{previewHost, transferHost, hooksHost, wildcardName} {
		for _, line := range []string{
			`edge_cert_days_left{name="` + name + `"} 40`,
			`edge_cert_issued{name="` + name + `"} 1`,
		} {
			if !strings.Contains(got, line+"\n") {
				t.Fatalf("%q missing from\n%s", line, got)
			}
		}
	}
}

func TestExportNameNeverIssuedShowsZero(t *testing.T) {
	wild := t.TempDir()
	chain, key := pair(t, time.Now().AddDate(0, 0, 60), wildcardName)
	for name, b := range map[string][]byte{"fullchain.pem": chain, "key.pem": key} {
		if err := os.WriteFile(filepath.Join(wild, name), b, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	state := t.TempDir()
	chain, key = pair(t, time.Now().AddDate(0, 0, 80), transferHost)
	cached := append(append([]byte{}, key...), chain...)
	if err := os.WriteFile(filepath.Join(state, transferHost), cached, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsconf.New(tlsconf.Options{
		Names:    names(),
		Wildcard: &tlsconf.Wildcard{Suffix: previewHost, Dir: wild, ALPN: both},
		ACME: tlsconf.ACME{
			Enabled: true, Directory: "http://127.0.0.1:1/directory", StateDir: state,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := metrics.New()
	wait(t, Export(r, cfg, quiet()))
	got := scrape(t, r)
	for _, line := range []string{
		`edge_cert_issued{name="` + previewHost + `"} 0`,
		`edge_cert_issued{name="` + hooksHost + `"} 0`,
		`edge_cert_issued{name="` + transferHost + `"} 1`,
		`edge_cert_issued{name="` + wildcardName + `"} 1`,
		`edge_cert_days_left{name="` + transferHost + `"} 79`,
		`edge_cert_days_left{name="` + wildcardName + `"} 59`,
	} {
		if !strings.Contains(got, line+"\n") {
			t.Fatalf("%q missing from\n%s", line, got)
		}
	}
	if strings.Contains(got, `edge_cert_days_left{name="`+hooksHost+`"}`) {
		t.Fatalf("a name never issued has days left\n%s", got)
	}
}
