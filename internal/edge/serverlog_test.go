package edge

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// records collects JSON log lines at every level for assertions
type records struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *records) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *records) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(r, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// levels lists the level of each record whose message starts with prefix
func (r *records) levels(t *testing.T, prefix string) []string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for line := range strings.Lines(r.buf.String()) {
		var rec struct{ Level, Msg string }
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(rec.Msg, prefix) {
			out = append(out, rec.Level)
		}
	}
	return out
}

// waitLevels waits for a record whose message starts with prefix and lists their levels
func (r *records) waitLevels(t *testing.T, prefix string) []string {
	t.Helper()
	for range 200 {
		if l := r.levels(t, prefix); len(l) > 0 {
			return l
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no %q record", prefix)
	return nil
}

func TestServerLogLevels(t *testing.T) {
	for msg, want := range map[string]slog.Level{
		"http: TLS handshake error from 192.0.2.1:5: EOF":                      slog.LevelDebug,
		"http2: server: error reading preface from client 192.0.2.1:5: bogus":  slog.LevelDebug,
		"timeout waiting for SETTINGS frames from 192.0.2.1:5":                 slog.LevelDebug,
		"http2: server connection error from 192.0.2.1:5: PROTOCOL_ERROR":      slog.LevelDebug,
		"http2: received GOAWAY [FrameHeader GOAWAY len=8], starting graceful": slog.LevelDebug,
		"http: panic serving 192.0.2.1:5: boom\ngoroutine 1 [running]:":        slog.LevelError,
		"http2: panic serving 192.0.2.1:5: boom\ngoroutine 1 [running]:":       slog.LevelError,
		"http: Accept error: accept tcp: too many open files; retrying in 5ms": slog.LevelWarn,
		"http: superfluous response.WriteHeader call from x.y (z.go:1)":        slog.LevelWarn,
		"http: response.Write on hijacked connection from x.y (z.go:1)":        slog.LevelWarn,
		"http: invalid Content-Length of \"x\"":                                slog.LevelWarn,
		"something net/http says one day":                                      slog.LevelWarn,
		"http: TLS handshake errors are not panic serving, this is a stranger": slog.LevelDebug,
	} {
		if got := serverLogLevel(msg); got != want {
			t.Errorf("%q: got %v, want %v", msg, got, want)
		}
	}
}

func TestPanicsLogAtErrorAndHandshakeNoiseAtDebug(t *testing.T) {
	rec := &records{}
	d := fakeDeps()
	d.Landing = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	d.Log = rec.logger()
	s := New(testConfig(t), d)
	start(t, s)

	for _, h2 := range []bool{false, true} {
		res, err := client(t, s.addr("tls"), h2).Get("https://" + previewDomain + "/")
		if err == nil {
			_ = res.Body.Close()
		}
	}
	eq(t, rec.waitLevels(t, "http: panic serving"), []string{"ERROR"})
	eq(t, rec.waitLevels(t, "http2: panic serving"), []string{"ERROR"})

	raw, err := net.DialTimeout("tcp", s.addr("tls"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Write(append(proxyHeader(t, "203.0.113.9:4000"), 0, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	eq(t, rec.waitLevels(t, "http: TLS handshake error"), []string{"DEBUG"})
}
