package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	pp "github.com/pires/go-proxyproto"
)

// runnerDir is the bugnet-run checkout beside this one, in the workspace
const runnerDir = "../../../bugnet-run"

// buildRunner builds bugnet-run from the workspace, skipping the test when it is not there
func buildRunner(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(runnerDir, "cmd", "bugnet-run")); err != nil {
		t.Skip("no bugnet-run checkout beside bugnet-edges")
	}
	out := filepath.Join(t.TempDir(), "bugnet-run")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/bugnet-run")
	cmd.Dir = runnerDir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building bugnet-run: %v\n%s", err, b)
	}
	return out
}

// proxyFront passes each loopback connection to the proxy behind a PROXY v2 header, as HAProxy
func (h *harness) proxyFront(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				up, err := net.Dial("tcp", h.addr)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				hdr := pp.HeaderProxyFromAddrs(2, c.RemoteAddr(), up.RemoteAddr())
				if _, err := hdr.WriteTo(up); err != nil {
					return
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(up, c); close(done) }()
				_, _ = io.Copy(c, up)
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

// startRealForwarder runs bugnet-run forward for p through front, with extra config fields
func startRealForwarder(
	t *testing.T, h *harness, p *fakePlacement, front string, extra map[string]any,
) (string, *logBuffer) {
	t.Helper()
	runner := buildRunner(t)
	_, port, _ := net.SplitHostPort(front)
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "bugnet")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	pemBytes, err := os.ReadFile(filepath.Join(h.outerDir, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(etc, "roots.pem"), string(pemBytes), 0o644)
	writeFile(t, filepath.Join(etc, "egress.token"), p.token+"\n", 0o600)
	portNum, _ := strconv.Atoi(port)
	fields := map[string]any{
		"endpoint": egressHost, "ips": []string{"127.0.0.1"}, "port": portNum,
		"listen": "127.0.0.1:0", "token_file": "/etc/bugnet/egress.token",
		"hosts": []string{"hf.example"}, "roots_file": "/etc/bugnet/roots.pem",
	}
	for k, v := range extra {
		fields[k] = v
	}
	conf, _ := json.Marshal(fields)
	cfg := filepath.Join(etc, "egress.json")
	writeFile(t, cfg, string(conf), 0o644)

	cmd := exec.Command(runner, "forward", "--config", cfg, "--root", root)
	stderr := &logBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Only the PID this test started is ever killed
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	addrFile := filepath.Join(root, "run", "bugnet", "forward.addr")
	var listen string
	within(t, "the forwarder to listen", func() bool {
		b, err := os.ReadFile(addrFile)
		listen = strings.TrimSpace(string(b))
		return err == nil && listen != ""
	})
	return listen, stderr
}

// getThrough asks hf.example/echo through the forwarder at listen with the placeholder ph
func getThrough(h *harness, listen, ph string) (*http.Response, error) {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, "tcp", listen)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{ServerName: "hf.example", RootCAs: h.ca.pool()})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://hf.example/echo", nil)
	req.Header.Set("Authorization", "Bearer "+ph)
	return (&http.Client{Transport: tr, Timeout: 2 * shortWait}).Do(req)
}

// TestRealForwarderThroughRealProxy runs bugnet-run forward against the real proxy
func TestRealForwarderThroughRealProxy(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	listen, stderr := startRealForwarder(t, h, p, h.proxyFront(t), nil)
	resp, err := getThrough(h, listen, ph)
	if err != nil {
		t.Fatalf("%v\nforwarder: %s\nproxy: %s", err, stderr.String(), h.log.String())
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(bufio.NewReader(resp.Body))
	eq(t, resp.StatusCode, 200)
	eq(t, string(body), "echo")
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
	// The upstream echoed the real value and the response carries the placeholder back
	eq(t, resp.Header.Get("X-Echo"), "Bearer "+ph)
	eq(t, strings.Contains(stderr.String(), "hf_secret"), false)
}

// TestRealForwarderBoundSourceEnforce runs the forwarder with a family and a bind in enforce mode
func TestRealForwarderBoundSourceEnforce(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	h.router.setCheck(p, enforce("127.0.0.1/32"))
	front := h.proxyFront(t)
	bound := map[string]any{"family": "ipv4", "bind": "127.0.0.1"}

	// The front reports the address the forwarder dialled from, which the prefix holds
	listen, stderr := startRealForwarder(t, h, p, front, bound)
	resp, err := getThrough(h, listen, ph)
	if err != nil {
		t.Fatalf("%v\nforwarder: %s\nproxy: %s", err, stderr.String(), h.log.String())
	}
	_ = resp.Body.Close()
	eq(t, resp.StatusCode, 200)
	eq(t, h.router.sourceResolves() >= 1, true)

	// A prefix that does not hold it refuses the same forwarder at the upgrade
	h.router.setCheck(p, enforce("203.0.113.5/32"))
	h.server.secretsChanged(p.id.String())
	within(t, "the placement to follow the new check", func() bool {
		h.server.placesMu.Lock()
		v := h.server.places[p.id.String()+"/tunnel"].view()
		h.server.placesMu.Unlock()
		return len(v.src.Prefixes) == 1 && v.src.Prefixes[0].String() == "203.0.113.5/32"
	})
	if resp, err := getThrough(h, listen, ph); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a refused source still got through")
	}
	eq(t, strings.Contains(h.log.String(), "tunnel_source_refused"), true)
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}
