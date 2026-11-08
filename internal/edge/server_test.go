package edge

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

const hsts = "max-age=31536000"

func TestHostRouting(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	eq(t, get(t, s, "unknown.example", "/").StatusCode, 404)
	eq(t, get(t, s, "preview.bugnet.sh", "/").StatusCode, 200)
	eq(t, get(t, s, "preview.bugnet.sh", "/x").StatusCode, 404)
	eq(t, served(t, s, "GET", "transfer.bugnet.sh", "/bnx_abc/f.bin"), "transfer")
	eq(t, served(t, s, "GET", "k3fz2q7mak3fz2q7.preview.bugnet.sh", "/a"), "preview")
	eq(t, served(t, s, "POST", "hooks.bugnet.sh", "/hooks/e2b/s"), "hooks")

	eq(t, served(t, s, "GET", "preview.bugnet.sh", "/"), "landing")
	eq(t, served(t, s, "PUT", "transfer.bugnet.sh", "/bnx_abc"), "transfer")
	eq(t, served(t, s, "GET", "transfer.bugnet.sh", "/bnx_abc/a%2Fb.bin"), "transfer")
	eq(t, served(t, s, "GET", "K3FZ2Q7MAK3FZ2Q7.preview.bugnet.sh", "/__bugnet/continue"),
		"preview")
	eq(t, served(t, s, "GET", "k3fz2q7mak3fz2q7.preview.bugnet.sh.", "/"), "preview")
	for _, tc := range []struct{ method, host, path string }{
		{"GET", "transfer.bugnet.sh", "/"},
		{"GET", "transfer.bugnet.sh", "/bnx_abc/"},
		{"GET", "transfer.bugnet.sh", "//f.bin"},
		{"GET", "transfer.bugnet.sh", "/bnx_abc/f/g"},
		{"GET", "hooks.bugnet.sh", "/hooks/e2b/s"},
		{"POST", "hooks.bugnet.sh", "/hooks/E2B/s"},
		{"POST", "hooks.bugnet.sh", "/hooks/e2b/"},
		{"POST", "hooks.bugnet.sh", "/hooks/e2b/s/x"},
		{"POST", "hooks.bugnet.sh", "/hooks/aaaaaaaaaaaaaaaaa/s"},
		{"POST", "hooks.bugnet.sh", "/other/e2b/s"},
		{"GET", "k3fz2q7mak3fz2q.preview.bugnet.sh", "/"},
		{"GET", "k3fz2q7mak3fz2q0.preview.bugnet.sh", "/"},
		{"GET", "a.k3fz2q7mak3fz2q7.preview.bugnet.sh", "/"},
		{"GET", "bugnet.sh", "/"},
	} {
		eq(t, served(t, s, tc.method, tc.host, tc.path), "404 Not Found")
	}
}

func TestNilRoutesServeTheNotFoundPage(t *testing.T) {
	s := New(testConfig(t), Deps{Log: quiet()})
	for _, tc := range []struct{ method, host, path string }{
		{"GET", previewDomain, "/"}, {"GET", transferHost, "/bnx_abc"},
		{"GET", previewHost, "/"}, {"POST", hooksHost, "/hooks/e2b/s"},
	} {
		res := call(t, s, tc.method, tc.host, tc.host, tc.path)
		b, _ := io.ReadAll(res.Body)
		eq(t, res.StatusCode, 404)
		eq(t, strings.Contains(string(b), "No such preview"), true)
	}
}

func TestMisdirectedWhenTLSNameAndHostDiffer(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	eq(t, call(t, s, "GET", transferHost, previewHost, "/").StatusCode, 421)
	eq(t, call(t, s, "GET", previewHost, transferHost, "/bnx_abc").StatusCode, 421)
	eq(t, call(t, s, "POST", previewDomain, hooksHost, "/hooks/e2b/s").StatusCode, 421)
	eq(t, call(t, s, "GET", otherPreview, previewHost, "/").StatusCode, 200)
	eq(t, call(t, s, "GET", transferHost, "unknown.example", "/").StatusCode, 404)
}

func TestRedirectOnPort80(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	start(t, s)
	r := plainGet(t, s, "http://transfer.bugnet.sh/bnx_abc?x=1")
	eq(t, r.StatusCode, 301)
	eq(t, r.Header.Get("Location"), "https://transfer.bugnet.sh/bnx_abc?x=1")
	eq(t, r.Header.Get("Strict-Transport-Security"), "")

	r = plainGet(t, s, "http://secrets.bugnet.sh:80/l/a%2Fb?q=a%20b")
	eq(t, r.StatusCode, 301)
	eq(t, r.Header.Get("Location"), "https://secrets.bugnet.sh/l/a%2Fb?q=a%20b")
	eq(t, plainGet(t, s, "http://203.0.113.7/").StatusCode, 404)
	eq(t, plainGet(t, s, "http://localhost/").StatusCode, 404)
}

func TestHSTSOnEveryResponse(t *testing.T) {
	d := fakeDeps()
	d.Landing = nil
	d.Transfer = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0; includeSubDomains")
		w.WriteHeader(http.StatusTeapot)
	})
	d.Preview = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=0")
		_, _ = io.WriteString(w, "body first")
		_ = http.NewResponseController(w).Flush()
	})
	s := New(testConfig(t), d)
	start(t, s)
	for _, h2 := range []bool{false, true} {
		c := client(t, s.addr("tls"), h2)
		for _, url := range []string{
			"https://" + previewDomain + "/",
			"https://" + previewDomain + "/missing",
			"https://" + transferHost + "/bnx_abc",
			"https://" + previewHost + "/",
		} {
			res := fetch(t, c, "GET", url)
			eq(t, res.Header.Values("Strict-Transport-Security"), []string{hsts})
		}
		res := fetch(t, c, "GET", "https://"+previewHost+"/")
		b, _ := io.ReadAll(res.Body)
		eq(t, string(b), "body first")
	}
}

func TestServerSettings(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	hs := s.tlsServer()
	eq(t, hs.ReadHeaderTimeout, 10*time.Second)
	eq(t, hs.IdleTimeout, 2*time.Minute)
	eq(t, hs.MaxHeaderBytes, 1<<20)
	eq(t, hs.ReadTimeout, time.Duration(0))
	eq(t, hs.WriteTimeout, time.Duration(0))
	eq(t, hs.HTTP2.MaxConcurrentStreams, 128)
	rs := s.redirectServer()
	eq(t, rs.ReadHeaderTimeout, 10*time.Second)
	eq(t, rs.MaxHeaderBytes, 64<<10)

	start(t, s)
	c := client(t, s.addr("tls"), false)
	big := strings.Repeat("a", 70<<10)
	eq(t, fetch(t, c, "GET", "https://"+transferHost+"/bnx_abc", "X-Big", big).StatusCode, 431)
	eq(t, fetch(t, c, "GET", "https://"+transferHost+"/bnx_abc", "X-Small", "a").StatusCode, 200)
}

// Ruling E1: the preview names take a full bugnet.sh cookie jar, transfer and hooks 64 KiB
func TestHeaderLimitPerName(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	start(t, s)
	jar := "jar=" + strings.Repeat("a", 600<<10)
	for _, h2 := range []bool{false, true} {
		c := client(t, s.addr("tls"), h2)
		res := fetch(t, c, "GET", "https://"+previewHost+"/", "Cookie", jar)
		eq(t, res.StatusCode, 200)
		b, _ := io.ReadAll(res.Body)
		eq(t, string(b), "preview")
		res = fetch(t, c, "GET", "https://"+previewDomain+"/", "Cookie", jar)
		eq(t, res.StatusCode, 200)
	}
	c := client(t, s.addr("tls"), false)
	res := fetch(t, c, "GET", "https://"+transferHost+"/bnx_abc", "Cookie", jar)
	eq(t, res.StatusCode, 431)
	eq(t, res.Header.Get("Content-Type"), "application/json")
	eq(t, res.Close, true)
	b, _ := io.ReadAll(res.Body)
	eq(t, strings.Contains(string(b), "headers_too_large"), true)
	res = fetch(t, client(t, s.addr("tls"), true), "POST",
		"https://"+hooksHost+"/hooks/e2b/secret", "Cookie", jar)
	eq(t, res.StatusCode, 431)
	eq(t, res.Header.Get("Content-Type"), "text/html; charset=utf-8")
	// Past 1 MiB even a preview is refused by the server itself
	res = fetch(t, c, "GET", "https://"+previewHost+"/", "Cookie",
		"jar="+strings.Repeat("a", 1100<<10))
	eq(t, res.StatusCode, 431)
}

func TestALPNPerName(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	start(t, s)
	for sni, want := range map[string]string{
		transferHost: "http/1.1", previewHost: "h2", previewDomain: "h2", hooksHost: "h2",
	} {
		c, err := dialTLS(t, s.addr("tls"), sni, "h2", "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		eq(t, c.ConnectionState().NegotiatedProtocol, want)
	}
	if _, err := dialTLS(t, s.addr("tls"), "unknown.example", "h2"); err == nil {
		t.Fatal("an unknown name was served")
	}
	res := fetch(t, client(t, s.addr("tls"), true), "GET", "https://"+previewHost+"/")
	eq(t, res.ProtoMajor, 2)
}

func TestNoExtendedConnect(t *testing.T) {
	s := New(testConfig(t), fakeDeps())
	start(t, s)
	c, err := dialTLS(t, s.addr("tls"), previewHost, "h2")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, c.ConnectionState().NegotiatedProtocol, "h2")
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		streams, _ := sf.Value(http2.SettingMaxConcurrentStreams)
		eq(t, streams, uint32(128))
		_, xconnect := sf.Value(http2.SettingEnableConnectProtocol)
		eq(t, xconnect, false)
		return
	}
}

func TestRunServesThroughProxyProtocol(t *testing.T) {
	d := fakeDeps()
	d.Transfer = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RemoteAddr)
	})
	s := New(testConfig(t), d)
	start(t, s)
	res := fetch(t, client(t, s.addr("tls"), false), "GET", "https://"+transferHost+"/bnx_a")
	b, _ := io.ReadAll(res.Body)
	eq(t, string(b), "203.0.113.9:4000")
}

func TestDrainClosesHijackedAfterDrain(t *testing.T) {
	cfg := testConfig(t)
	cfg.Drain = settings.Duration(600 * time.Millisecond)
	d := fakeDeps()
	d.Preview = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, rw)
		}()
	})
	s := New(cfg, d)
	stop := start(t, s)
	c, err := dialTLS(t, s.addr("tls"), previewHost, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+previewHost+
		"\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, res.StatusCode, 101)
	echo := func() error {
		if _, err := io.WriteString(c, "ping"); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 4)
		_, err := io.ReadFull(br, b)
		return err
	}
	if err := echo(); err != nil {
		t.Fatal(err)
	}

	began := time.Now()
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	time.Sleep(200 * time.Millisecond)
	if err := echo(); err != nil {
		t.Fatalf("the hijacked connection closed before the drain ended: %v", err)
	}
	code, _ := metricsGet(t, s, "/readyz")
	eq(t, code, 503)
	if _, err := dialTLS(t, s.addr("tls"), previewHost, "http/1.1"); err == nil {
		t.Fatal("a new connection was accepted while draining")
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took < 550*time.Millisecond || took > 5*time.Second {
		t.Fatalf("Run returned after %s, want the 600ms drain", took)
	}
	if err := echo(); err == nil {
		t.Fatal("the hijacked connection outlived the drain")
	}
}

func TestDrainEndsAtOnceWithNothingOpen(t *testing.T) {
	cfg := testConfig(t)
	cfg.Drain = settings.Duration(time.Minute)
	s := New(cfg, fakeDeps())
	stop := start(t, s)
	fetch(t, client(t, s.addr("tls"), true), "GET", "https://"+previewHost+"/")
	began := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("Run took %s with nothing open", took)
	}
}

func TestMetricsListener(t *testing.T) {
	reg := metrics.New()
	d := fakeDeps()
	d.Metrics = reg
	s := New(testConfig(t), d)
	start(t, s)
	code, body := metricsGet(t, s, "/healthz")
	eq(t, code, 200)
	eq(t, body, "ok\n")
	code, _ = metricsGet(t, s, "/readyz")
	eq(t, code, 200)
	code, body = metricsGet(t, s, "/metrics")
	eq(t, code, 200)
	for _, line := range []string{
		`edge_cert_days_left{name="` + transferHost + `"} 89`,
		`edge_cert_days_left{name="*.` + previewDomain + `"} 89`,
		`edge_cert_issued{name="` + hooksHost + `"} 1`,
	} {
		if !strings.Contains(body, line+"\n") {
			t.Fatalf("%q missing from\n%s", line, body)
		}
	}
	code, _ = metricsGet(t, s, "/other")
	eq(t, code, 404)
}

func TestRunFailsOnABadPair(t *testing.T) {
	cfg := testConfig(t)
	cfg.ACME.StaticDir = t.TempDir()
	err := New(cfg, fakeDeps()).Run(t.Context())
	eq(t, err != nil, true)
}

func TestRunFailsOnATakenPort(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	cfg := testConfig(t)
	cfg.MetricsListenAddr = taken.Addr().String()
	err = New(cfg, fakeDeps()).Run(t.Context())
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestSecretsRoleServesOnlyItsHost(t *testing.T) {
	c := SecretsDefaults()
	c.TLSListenAddr, c.MetricsListenAddr = "127.0.0.1:0", "127.0.0.1:0"
	c.ProxyProtocolFrom = testConfig(t).ProxyProtocolFrom
	c.Host = "secrets.bugnet.sh"
	c.ACMEEnabled, c.StaticDir = false, staticPair(t)
	s := NewSecrets(c, SecretsDeps{Log: quiet()})
	eq(t, s.tlsServer().MaxHeaderBytes, 1<<20)
	eq(t, s.drain, time.Minute)
	start(t, s)
	eq(t, s.addr("redirect"), "")
	if _, err := dialTLS(t, s.addr("tls"), transferHost, "http/1.1"); err == nil {
		t.Fatal("the secrets route served an edge name")
	}
	hc := client(t, s.addr("tls"), true)
	res := fetch(t, hc, "GET", "https://secrets.bugnet.sh/l/abc")
	eq(t, res.StatusCode, 404)
	eq(t, res.Header.Get("Strict-Transport-Security"), hsts)
	code, body := metricsGet(t, s, "/metrics")
	eq(t, code, 200)
	eq(t, strings.Contains(body, `edge_cert_days_left{name="secrets.bugnet.sh"} 89`), true)

	s2 := NewSecrets(c, SecretsDeps{Route: named("secrets"), Log: quiet()})
	eq(t, call(t, s2, "GET", "secrets.bugnet.sh", "secrets.bugnet.sh", "/l/x").StatusCode, 200)
	eq(t, call(t, s2, "GET", "secrets.bugnet.sh", "other.bugnet.sh", "/l/x").StatusCode, 404)
}

func TestSessionsRoleServesOnlyItsHost(t *testing.T) {
	c := SessionsDefaults()
	c.TLSListenAddr, c.MetricsListenAddr = "127.0.0.1:0", "127.0.0.1:0"
	c.ProxyProtocolFrom = testConfig(t).ProxyProtocolFrom
	c.Host = "sessions.bugnet.sh"
	c.ACMEEnabled, c.StaticDir = false, staticPair(t)
	s := NewSessions(c, SessionsDeps{Route: named("sessions"), Log: quiet()})
	eq(t, s.role, "sessions")
	eq(t, s.drain, time.Minute)
	eq(t, s.addr("redirect"), "")
	hs := s.tlsServer()
	eq(t, hs.MaxHeaderBytes, 2<<20)
	eq(t, hs.WriteTimeout, time.Duration(0))
	eq(t, hs.HTTP2.MaxConcurrentStreams, 128)

	start(t, s)
	eq(t, s.addr("redirect"), "")
	if _, err := dialTLS(t, s.addr("tls"), "secrets.bugnet.sh", "http/1.1"); err == nil {
		t.Fatal("the sessions role served the secrets host")
	}
	conn, err := dialTLS(t, s.addr("tls"), "sessions.bugnet.sh", "h2", "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	eq(t, conn.ConnectionState().NegotiatedProtocol, "h2")
	_ = conn.Close()
	hc := client(t, s.addr("tls"), true)
	res := fetch(t, hc, "GET", "https://sessions.bugnet.sh/s/abc")
	eq(t, res.StatusCode, 200)
	eq(t, res.Header.Get("Strict-Transport-Security"), hsts)
	// Headers past 1 MiB reach the route, which answers them with its own 431 page
	c1 := client(t, s.addr("tls"), false)
	big := strings.Repeat("a", 1500<<10)
	eq(t, fetch(t, c1, "GET", "https://sessions.bugnet.sh/s/abc", "Cookie", big).StatusCode, 200)
	code, body := metricsGet(t, s, "/metrics")
	eq(t, code, 200)
	eq(t, strings.Contains(body, `edge_cert_days_left{name="sessions.bugnet.sh"} 89`), true)

	eq(t, call(t, s, "GET", "sessions.bugnet.sh", "other.bugnet.sh", "/s/x").StatusCode, 404)
	eq(t, served(t, NewSessions(c, SessionsDeps{Log: quiet()}), "GET", "sessions.bugnet.sh",
		"/s/x"), "404 Not Found")
}
