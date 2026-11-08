package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
)

func TestCustomHosts(t *testing.T) {
	h := start(t, func(c *Config, _ *Deps) { c.CustomHostRequestsPerMinute = 3 })
	p, phs := h.placement(t,
		secretSpec{name: "RELAY", value: "relay_secret", hosts: []string{"relay.example"},
			custom: []string{"relay.example"}},
		secretSpec{name: "HF", value: "hf_secret", hosts: []string{"hf.example"}})
	c := h.client(p.token)
	// Without a swap the answer is 403 and nothing leaves the proxy
	resp := get(t, c, "https://relay.example/", nil)
	eq(t, resp.StatusCode, http.StatusForbidden)
	eq(t, h.seenCount(), 0)
	// A placeholder for another host is no swap either
	resp = get(t, c, "https://relay.example/",
		map[string]string{"Authorization": "Bearer " + phs[1]})
	eq(t, resp.StatusCode, http.StatusForbidden)
	for range 3 {
		resp = get(t, c, "https://relay.example/",
			map[string]string{"Authorization": "Bearer " + phs[0]})
		eq(t, resp.StatusCode, 200)
		eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer relay_secret")
	}
	resp = get(t, c, "https://relay.example/",
		map[string]string{"Authorization": "Bearer " + phs[0]})
	eq(t, resp.StatusCode, http.StatusTooManyRequests)
	// A preset host is forwarded with or without a swap
	resp = get(t, c, "https://hf.example/", nil)
	eq(t, resp.StatusCode, 200)
	resp = get(t, c, "https://hf.example/", map[string]string{"Authorization": "Bearer " + phs[1]})
	eq(t, resp.StatusCode, 200)
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
}

func TestCustomHostLimitCountsAllPlacements(t *testing.T) {
	h := start(t, func(c *Config, _ *Deps) { c.CustomHostRequestsPerMinute = 2 })
	var tokens, phs []string
	for range 2 {
		p, ph := h.placement(t, secretSpec{name: "R", value: "v", hosts: []string{"relay.example"},
			custom: []string{"relay.example"}})
		tokens, phs = append(tokens, p.token), append(phs, ph[0])
	}
	codes := []int{}
	for i := range 3 {
		resp := get(t, h.client(tokens[i%2]), "https://relay.example/",
			map[string]string{"Authorization": "Bearer " + phs[i%2]})
		codes = append(codes, resp.StatusCode)
	}
	eq(t, codes, []int{200, 200, 429})
}

func TestCustomHostsOffWithin30s(t *testing.T) {
	h := start(t, func(c *Config, d *Deps) {
		c.ResolveCache = 100_000_000
		d.RefreshEvery = 10 * time.Millisecond
	})
	p, _ := h.placement(t, secretSpec{name: "R", value: "v", hosts: []string{"relay.example"},
		custom: []string{"relay.example"}})
	if _, err := h.inner(p.token, "relay.example"); err != nil {
		t.Fatalf("the custom host failed its handshake while enabled: %v", err)
	}
	// With custom hosts off the router drops the custom host from its answers
	h.router.mu.Lock()
	p.resp.Secrets, p.resp.SecretsVersion = nil, 2
	h.router.mu.Unlock()
	within(t, "the custom host to fail its handshake", func() bool {
		_, err := h.inner(p.token, "relay.example")
		return err != nil
	})
}

func TestLimits(t *testing.T) {
	t.Run("streams per tunnel", func(t *testing.T) {
		h := start(t, func(c *Config, _ *Deps) { c.MaxStreamsPerTunnel = 32 })
		p, _ := hfPlacement(t, h)
		tc, err := h.inner(p.token, "hf.example", "h2")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tc.Close() }()
		eq(t, tc.ConnectionState().NegotiatedProtocol, "h2")
		_, _ = io.WriteString(tc, http2.ClientPreface)
		fr := http2.NewFramer(tc, tc)
		if err := fr.WriteSettings(); err != nil {
			t.Fatal(err)
		}
		_ = tc.SetReadDeadline(time.Now().Add(shortWait))
		streams := uint32(0)
		for streams == 0 {
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
				v, _ := s.Value(http2.SettingMaxConcurrentStreams)
				streams = v
			}
		}
		eq(t, streams, uint32(32))
	})

	t.Run("requests in flight per placement", func(t *testing.T) {
		h := start(t)
		p, _ := hfPlacement(t, h)
		h.router.mu.Lock()
		p.resp.RequestsInFlight = 2
		h.router.mu.Unlock()
		var wg sync.WaitGroup
		codes := make(chan int, 3)
		for range 3 {
			wg.Go(func() {
				resp := get(t, h.client(p.token), "https://hf.example/block", nil)
				codes <- resp.StatusCode
			})
		}
		within(t, "two requests to reach the upstream",
			func() bool { return h.inflight.Load() == 2 })
		time.Sleep(200 * time.Millisecond)
		eq(t, h.inflight.Load(), int32(2))
		close(h.release)
		wg.Wait()
		eq(t, len(codes), 3)
	})

	t.Run("pace", func(t *testing.T) {
		h := start(t)
		p, _ := hfPlacement(t, h)
		h.router.mu.Lock()
		p.resp.BytesPerSecond = 1 << 20
		h.router.mu.Unlock()
		c := h.client(p.token)
		start := time.Now()
		resp := getStream(t, c, "https://hf.example/mid", nil)
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		eq(t, n, int64(3<<19))
		// 1.5 MiB at 1 MiB/s is about 1.4 s after the first piece goes out at once
		if took < 1100*time.Millisecond || took > 4*time.Second {
			t.Fatalf("1.5 MiB took %s at 1 MiB/s", took)
		}
	})

	t.Run("outer handshake stall", func(t *testing.T) {
		h := start(t, func(c *Config, _ *Deps) { c.HandshakeTimeout = 300_000_000 })
		raw, err := net.Dial("tcp", h.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close() }()
		hdr := pp.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1},
			raw.RemoteAddr())
		_, _ = hdr.WriteTo(raw)
		start := time.Now()
		_ = raw.SetReadDeadline(time.Now().Add(shortWait))
		_, err = bufio.NewReader(raw).ReadByte()
		eq(t, err != nil, true)
		if time.Since(start) > 3*time.Second {
			t.Fatalf("the stalled handshake closed after %s", time.Since(start))
		}
	})

	t.Run("tunnel idle", func(t *testing.T) {
		h := start(t, func(c *Config, _ *Deps) { c.TunnelIdleTimeout = 300_000_000 })
		p, _ := hfPlacement(t, h)
		c, _, err := h.tunnel(p.token, "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(shortWait))
		_, err = c.Read(make([]byte, 1))
		eq(t, err != nil, true)
	})
}

func TestFetchTokenOnlyFromLoopback(t *testing.T) {
	token := strings.Repeat("f", 40)
	h := start(t, func(c *Config, _ *Deps) { c.FetchToken = token })
	p, phs := h.placement(t,
		secretSpec{name: "PRIVATE", value: "repo_secret", hosts: []string{"github.com"},
			fetch: true})
	hdr := http.Header{"Bugnet-Placement": {p.id.String()}}
	open := func(source, tok string) error {
		c, _, err := h.tunnelWith("bnf_"+tok, source, hdr)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	eq(t, open("127.0.0.1", token), nil)
	eq(t, open("203.0.113.9", token) != nil, true)
	eq(t, open("127.0.0.1", strings.Repeat("g", 40)) != nil, true)
	// Over the fetcher's tunnel the fetch-only secret swaps, and a sandbox's never does
	c, _, err := h.tunnelWith("bnf_"+token, "127.0.0.1", hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	tc := tls.Client(c, &tls.Config{ServerName: "github.com", RootCAs: h.ca.pool()})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the fetcher's tunnel did not get its host: %v", err)
	}
	if _, err := h.inner(p.token, "github.com"); err == nil {
		t.Fatal("a sandbox's tunnel got a fetch-only host")
	}
	_ = phs
}

func TestFetchTokenIsOffWithoutOne(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	_, resp, err := h.tunnelWith("bnf_"+strings.Repeat("f", 40), "127.0.0.1",
		http.Header{"Bugnet-Placement": {p.id.String()}})
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, http.StatusUnauthorized)
}

func TestTunnelTokenFailuresPerIP(t *testing.T) {
	h := start(t)
	good, _ := hfPlacement(t, h)
	other, _ := hfPlacement(t, h)
	status := func(token, source string) (int, string) {
		_, resp, err := h.tunnel(token, source)
		if err == nil {
			t.Fatalf("the token %q opened a tunnel", token)
		}
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	for i := range 20 {
		code, _ := status(newToken(), "198.51.100.7")
		if code != 401 {
			t.Fatalf("bad token %d answered %d", i+1, code)
		}
	}
	code, after := status(newToken(), "198.51.100.7")
	eq(t, code, 429)
	eq(t, after, "600")
	// A token that resolves is never blocked for long, even from a marked address
	c, _, err := h.tunnel(good.token, "198.51.100.7")
	if err != nil {
		t.Fatalf("a resolving token was blocked: %v", err)
	}
	_ = c.Close()
	// Another address is not marked
	code, _ = status(newToken(), "198.51.100.8")
	eq(t, code, 401)
	// The marked address may ask the router once a second
	_, resp, err := h.tunnel(other.token, "198.51.100.7")
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, 429)
	eq(t, resp.Header.Get("Retry-After"), "1")
}

func TestUnknownTokenIsRememberedForTenSeconds(t *testing.T) {
	h := start(t)
	tok := newToken()
	for range 3 {
		_, _, err := h.tunnel(tok, "203.0.113.9")
		eq(t, err != nil, true)
	}
	eq(t, h.router.resolveCount(), 1)
}

func TestSixtyFifthTunnelIs429(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for i := range 64 {
		c, _, err := h.tunnel(p.token, "203.0.113.9")
		if err != nil {
			t.Fatalf("tunnel %d: %v", i+1, err)
		}
		open = append(open, c)
	}
	_, resp, err := h.tunnel(p.token, "203.0.113.9")
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, 429)
	// A closed tunnel frees its place
	_ = open[0].Close()
	within(t, "a place to free", func() bool {
		c, _, err := h.tunnel(p.token, "203.0.113.9")
		if err == nil {
			open = append(open, c)
		}
		return err == nil
	})
}

func TestOnlyTheTunnelPathIsServed(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/v1/other"}, {"POST", "/v1/tunnel"}, {"GET", "/v1/tunnel"},
		{"GET", "/metrics"},
	} {
		_, status, err := h.rawRequest(tc.method, tc.path, p.token)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, status, 404)
	}
}

// rawRequest sends one HTTP request on the outer listener and returns its status
func (h *harness) rawRequest(method, path, token string) (net.Conn, int, error) {
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = raw.Close() }()
	hdr := pp.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1},
		raw.RemoteAddr())
	if _, err := hdr.WriteTo(raw); err != nil {
		return nil, 0, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: egressHost, RootCAs: h.outer})
	req, _ := http.NewRequest(method, "https://"+egressHost+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if err := req.Write(tc); err != nil {
		return nil, 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return nil, 0, err
	}
	_ = resp.Body.Close()
	return nil, resp.StatusCode, nil
}
