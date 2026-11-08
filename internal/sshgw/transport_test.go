package sshgw

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/reuseport"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

func TestWebSocketTransportThroughTheGate(t *testing.T) {
	var mu sync.Mutex
	var seen struct{ key, cookie, proto string }
	r := newRig(t)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := websocket.Accept(w, req, &websocket.AcceptOptions{
			Subprotocols: []string{"bugnet-ssh.v1"},
		})
		if err != nil {
			return
		}
		cookie, _ := req.Cookie("_port_auth")
		mu.Lock()
		seen.key, seen.proto = req.Header.Get("Bugnet-Gate"), c.Subprotocol()
		if cookie != nil {
			seen.cookie = cookie.Value
		}
		mu.Unlock()
		nc := websocket.NetConn(req.Context(), c, websocket.MessageBinary)
		tcp, err := net.Dial("tcp", r.up.addr())
		if err != nil {
			_ = nc.Close()
			return
		}
		go func() {
			_, _ = io.Copy(tcp, nc)
			_ = tcp.Close()
		}()
		_, _ = io.Copy(nc, tcp)
		_ = nc.Close()
	}))
	t.Cleanup(gate.Close)
	r.router.upstream = func(req *routerv1.OpenSshUpstreamRequest, _ string) (
		*routerv1.OpenSshUpstreamResponse, error,
	) {
		k, _ := ssh.ParsePublicKey(req.GetGatewayPublicKey())
		r.up.authorize(k)
		return &routerv1.OpenSshUpstreamResponse{
			Transport: &routerv1.OpenSshUpstreamResponse_Websocket{
				Websocket: &routerv1.WebSocketUpstream{
					Url: "ws://" + gate.Listener.Addr().String() + "/__bugnet/ssh",
					Headers: []*routerv1.HeaderValue{
						{Name: "Bugnet-Gate", Value: "gatekey"},
					},
					Cookies: []*routerv1.HeaderValue{{Name: "_port_auth", Value: "pa"}},
				},
			},
			User: "execuser", HostKeys: []string{r.up.hostLine()},
		}, nil
	}
	s, err := r.client().NewSession()
	eq(t, err, nil)
	out, err := s.Output("echo through the gate")
	eq(t, err, nil)
	eq(t, string(out), "through the gate\n")
	mu.Lock()
	defer mu.Unlock()
	eq(t, seen.key, "gatekey")
	eq(t, seen.cookie, "pa")
	eq(t, seen.proto, "bugnet-ssh.v1")
}

// listenShared binds addr with SO_REUSEPORT, as a deploy's new process does
func listenShared(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := reuseport.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestDrainKeepsSessionsUntilDeadline(t *testing.T) {
	r := newRig(t)
	ln := listenShared(t, "127.0.0.1:0")
	r.addr = ln.Addr().String()
	r.router.setDeadline(r.placement, time.Now().Add(1500*time.Millisecond))
	first := New(testConfigWith(t, r), serveRouter(t, r.router))
	ctx1, stop1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- first.Serve(ctx1, ln) }()
	t.Cleanup(stop1)
	c := r.client()
	s, err := c.NewSession()
	eq(t, err, nil)
	out, err := s.Output("echo before")
	eq(t, err, nil)
	eq(t, string(out), "before\n")

	// the new process binds beside the old one, then the old one stops accepting
	second := New(testConfigWith(t, r), serveRouter(t, r.router))
	ctx2, stop2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- second.Serve(ctx2, listenShared(t, r.addr)) }()
	t.Cleanup(func() {
		stop2()
		<-done2
	})
	stop1()
	select {
	case <-done1:
		t.Fatal("the old process stopped with a session open")
	case <-time.After(300 * time.Millisecond):
	}

	// the open session keeps working, and the new process takes new connections
	s2, err := c.NewSession()
	eq(t, err, nil)
	out, err = s2.Output("echo during")
	eq(t, err, nil)
	eq(t, string(out), "during\n")
	fresh := r.client()
	s3, err := fresh.NewSession()
	eq(t, err, nil)
	_, err = s3.Output("echo new")
	eq(t, err, nil)
	_ = fresh.Close()

	// it ends at the placement's deadline, and then the old process is done
	if !closesWithin(c, 3*time.Second) {
		t.Fatal("the drained session outlived its deadline")
	}
	select {
	case <-done1:
	case <-time.After(3 * time.Second):
		t.Fatal("the old process never finished draining")
	}
}

func TestDrainStopsAtDrainMax(t *testing.T) {
	r := newRig(t, func(_ *rig, c *Config) {
		c.DrainMax = settings.Duration(400 * time.Millisecond)
	})
	c := r.client()
	start := time.Now()
	r.cancel()
	select {
	case <-r.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after drain_max")
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("drained for %s, less than drain_max", d)
	}
	if !closesWithin(c, time.Second) {
		t.Fatal("the session outlived drain_max")
	}
}

func TestConfigFileLoadsAtTheDefaults(t *testing.T) {
	env := func(string) (string, bool) { return strings.Repeat("t", 40), true }
	cfg, err := Load("../../example/ssh.toml", env)
	eq(t, err, nil)
	want := Defaults()
	want.Token, want.GatewayID = cfg.Token, cfg.GatewayID
	eq(t, cfg, want)
}
