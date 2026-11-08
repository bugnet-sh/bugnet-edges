package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

// rig is one gateway in front of one fake sandbox, with a registered user key
type rig struct {
	t         *testing.T
	router    *fakeRouter
	up        *upSSHD
	gw        *Gateway
	addr      string
	hostKey   ssh.Signer
	user      ssh.Signer
	alias     string
	placement string
	cancel    context.CancelFunc
	tweaks    []func(*Gateway)
	finished  chan struct{}
}

func newSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testConfig(t testing.TB) Config {
	cfg := Defaults()
	cfg.HostKeys = []ssh.Signer{newSigner(t)}
	cfg.GatewayID = "gw-test"
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.DrainMax = settings.Duration(3 * time.Second)
	cfg.UsageReportInterval = settings.Duration(50 * time.Millisecond)
	return cfg
}

// newRig starts a gateway whose settings and timings the mods may change before it serves
func newRig(t *testing.T, mods ...func(*rig, *Config)) *rig {
	t.Helper()
	r := &rig{
		t: t, router: newFakeRouter(), up: newUpSSHD(t), user: newSigner(t),
		alias: "bn-k3fz2q7max", placement: "p1",
	}
	cfg := testConfig(t)
	r.hostKey = cfg.HostKeys[0]
	r.router.register(r.alias, r.placement, r.user.PublicKey(), time.Now().Add(time.Hour))
	r.router.upstream = r.upstreamTo(r.up)
	for _, m := range mods {
		m(r, &cfg)
	}
	r.gw = New(cfg, serveRouter(t, r.router))
	r.gw.checkEvery = time.Hour
	for _, f := range r.tweaks {
		f(r.gw)
	}
	r.start()
	return r
}

// upstreamTo answers OpenSshUpstream with a TCP route to u, authorising the key it was sent
func (r *rig) upstreamTo(u *upSSHD) func(
	*routerv1.OpenSshUpstreamRequest, string,
) (*routerv1.OpenSshUpstreamResponse, error) {
	return func(req *routerv1.OpenSshUpstreamRequest, _ string) (
		*routerv1.OpenSshUpstreamResponse, error,
	) {
		k, err := ssh.ParsePublicKey(req.GetGatewayPublicKey())
		if err != nil {
			return nil, err
		}
		u.authorize(k)
		return &routerv1.OpenSshUpstreamResponse{
			Transport: &routerv1.OpenSshUpstreamResponse_Tcp{
				Tcp: &routerv1.TcpUpstream{Address: u.addr()},
			},
			User: "execuser", HostKeys: []string{u.hostLine()},
		}, nil
	}
}

// start serves on a new loopback port, using SO_REUSEPORT-free plain listening
func (r *rig) start() {
	r.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	r.serve(ln)
}

func (r *rig) serve(ln net.Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.addr = ln.Addr().String()
	r.finished = make(chan struct{})
	go func() {
		_ = r.gw.Serve(ctx, ln)
		close(r.finished)
	}()
	r.t.Cleanup(func() {
		cancel()
		select {
		case <-r.finished:
		case <-time.After(10 * time.Second):
			r.t.Error("the gateway did not stop")
		}
	})
}

// clientConfig is a client that trusts the gateway's host key and records its banners
func (r *rig) clientConfig(alias string, signer ssh.Signer, banners *[]string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            alias,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(r.hostKey.PublicKey()),
		Timeout:         5 * time.Second,
		BannerCallback: func(m string) error {
			if banners != nil {
				*banners = append(*banners, m)
			}
			return nil
		},
	}
}

func (r *rig) dialAs(alias string, signer ssh.Signer, banners *[]string) (*ssh.Client, error) {
	return ssh.Dial("tcp", r.addr, r.clientConfig(alias, signer, banners))
}

// client connects with the registered key and closes at the end of the test
func (r *rig) client() *ssh.Client {
	r.t.Helper()
	c, err := r.dialAs(r.alias, r.user, nil)
	if err != nil {
		r.t.Fatalf("dial: %v", err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

// waitFor polls cond for up to three seconds
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// closesWithin reports whether the client's connection ends within d
func closesWithin(c *ssh.Client, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = c.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func netipAddr() netip.Addr { return netip.MustParseAddr("127.0.0.1") }

func dialRaw(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 5*time.Second) }

// fakeMeta is the ConnMetadata of a callback called by hand
type fakeMeta struct{ user string }

func (m fakeMeta) User() string        { return m.user }
func (fakeMeta) SessionID() []byte     { return []byte("session") }
func (fakeMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (fakeMeta) ServerVersion() []byte { return []byte(serverVersion) }
func (fakeMeta) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (fakeMeta) LocalAddr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// withGateway changes the gateway's timings before it serves
func withGateway(f func(*Gateway)) func(*rig, *Config) {
	return func(r *rig, _ *Config) { r.tweaks = append(r.tweaks, f) }
}

// testConfigWith is the rig's settings for a second gateway beside its first
func testConfigWith(t testing.TB, r *rig) Config {
	cfg := testConfig(t)
	cfg.HostKeys = []ssh.Signer{r.hostKey}
	return cfg
}
