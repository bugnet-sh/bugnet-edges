package egress

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	pp "github.com/pires/go-proxyproto"
)

// outerHandshake does the outer TLS handshake with sni and returns its error
func outerHandshake(t *testing.T, h *harness, sni string) error {
	t.Helper()
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	hdr := pp.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1},
		raw.RemoteAddr())
	if _, err := hdr.WriteTo(raw); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	return tc.Handshake()
}

func TestOuterHandshakeRefusals(t *testing.T) {
	h := start(t)
	for _, sni := range []string{"", "203.0.113.5", "unknown.example", "transfer.bugnet.sh",
		"hf.example", "Egress.bugnet.sh.evil.example"} {
		if outerHandshake(t, h, sni) == nil {
			t.Errorf("the outer handshake for %q succeeded", sni)
		}
	}
	eq(t, outerHandshake(t, h, "egress.bugnet.sh"), nil)
}

func TestOuterListenerNeedsTheProxyHeader(t *testing.T) {
	h := start(t)
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tc := tls.Client(raw, &tls.Config{ServerName: egressHost, RootCAs: h.outer})
	eq(t, tc.Handshake() != nil, true)
}

func TestOuterListenerSpeaksHTTP11Only(t *testing.T) {
	h := start(t)
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	hdr := pp.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1},
		raw.RemoteAddr())
	_, _ = hdr.WriteTo(raw)
	tc := tls.Client(raw, &tls.Config{
		ServerName: egressHost, RootCAs: h.outer, NextProtos: []string{"h2", "http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	eq(t, tc.ConnectionState().NegotiatedProtocol, "http/1.1")
	_, _ = io.WriteString(tc, "GET /v1/tunnel HTTP/1.1\r\nHost: egress.bugnet.sh\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, resp.StatusCode, 404)
}

func TestCertDaysLeftExported(t *testing.T) {
	h := start(t)
	resp, err := http.Get("http://" + h.metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	eq(t, strings.Contains(string(body), `edge_cert_days_left{name="egress.bugnet.sh"} 99`), true)
	for _, path := range []string{"/healthz", "/readyz"} {
		r, err := http.Get("http://" + h.metrics + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		eq(t, r.StatusCode, 200)
	}
}

func TestStopClosesTunnels(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	tc, err := h.inner(p.token, "hf.example")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	h.stop()
	_, err = tc.Read(make([]byte, 1))
	eq(t, err != nil, true)
}
