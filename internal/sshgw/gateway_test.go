package sshgw

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

// rawSession opens a session channel and keeps its requests from blocking the mux
func rawSession(t *testing.T, c *ssh.Client) ssh.Channel {
	t.Helper()
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	return ch
}

// openError is the reason a channel open was refused, or 0 when it opened
func openError(err error) ssh.RejectionReason {
	var oce *ssh.OpenChannelError
	if errors.As(err, &oce) {
		return oce.Reason
	}
	return 0
}

func TestRelayTable(t *testing.T) {
	r := newRig(t)
	r.up.replyFalse["env"] = true
	c := r.client()

	for _, typ := range []string{
		"pty-req", "shell", "exec", "window-change", "signal", "break", "eow@openssh.com",
	} {
		t.Run("forwards "+typ, func(t *testing.T) {
			ch := rawSession(t, c)
			ok, err := ch.SendRequest(typ, true, nil)
			eq(t, err, nil)
			eq(t, ok, true)
			_ = ch.Close()
			_, got, _, _ := r.up.seen()
			if !slices.Contains(got, typ) {
				t.Fatalf("the upstream saw %v, not %s", got, typ)
			}
		})
	}
	t.Run("passes a refusal back", func(t *testing.T) {
		ch := rawSession(t, c)
		ok, err := ch.SendRequest("env", true, ssh.Marshal(struct{ N, V string }{"A", "b"}))
		eq(t, err, nil)
		eq(t, ok, false)
	})
	t.Run("subsystem sftp only", func(t *testing.T) {
		ch := rawSession(t, c)
		ok, _ := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
		eq(t, ok, true)
		ch2 := rawSession(t, c)
		ok, _ = ch2.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"netconf"}))
		eq(t, ok, false)
		_, _, _, _ = r.up.seen()
	})
	for _, typ := range []string{"x11-req", "auth-agent-req@openssh.com"} {
		t.Run("never forwards "+typ, func(t *testing.T) {
			ch := rawSession(t, c)
			ok, err := ch.SendRequest(typ, true, nil)
			eq(t, err, nil)
			eq(t, ok, false)
			_, got, _, _ := r.up.seen()
			if slices.Contains(got, typ) {
				t.Fatalf("the upstream saw %s", typ)
			}
		})
	}
	for _, typ := range []string{
		"tcpip-forward", "streamlocal-forward@openssh.com", "keepalive@openssh.com",
	} {
		t.Run("global "+typ, func(t *testing.T) {
			ok, _, err := c.SendRequest(typ, true, nil)
			eq(t, err, nil)
			eq(t, ok, false)
		})
	}
	for _, typ := range []string{"x11", "direct-streamlocal@openssh.com", "tun@openssh.com"} {
		t.Run("channel "+typ, func(t *testing.T) {
			_, _, err := c.OpenChannel(typ, nil)
			eq(t, openError(err), ssh.UnknownChannelType)
		})
	}
	t.Run("no-more-sessions is honoured", func(t *testing.T) {
		c := r.client()
		ok, _, err := c.SendRequest("no-more-sessions@openssh.com", true, nil)
		eq(t, err, nil)
		eq(t, ok, true)
		_, _, err = c.OpenChannel("session", nil)
		eq(t, openError(err), ssh.Prohibited)
	})
}

func TestSessionAndForwardLimits(t *testing.T) {
	r := newRig(t)
	r.router.maxSess, r.router.maxFwd = 2, 2
	c := r.client()
	for range 2 {
		ch := rawSession(t, c)
		ok, _ := ch.SendRequest("exec", true, ssh.Marshal(struct{ C string }{"sleep"}))
		eq(t, ok, true)
	}
	_, _, err := c.OpenChannel("session", nil)
	eq(t, openError(err), ssh.ResourceShortage)
	for range 2 {
		_, reqs, err := c.OpenChannel("direct-tcpip", forwardPayload("127.0.0.1", 80))
		eq(t, err, nil)
		go ssh.DiscardRequests(reqs)
	}
	_, _, err = c.OpenChannel("direct-tcpip", forwardPayload("127.0.0.1", 80))
	eq(t, openError(err), ssh.ResourceShortage)
}

func forwardPayload(host string, port uint32) []byte {
	return ssh.Marshal(&directTCPIP{Host: host, Port: port, OrigHost: "127.0.0.1", OrigPort: 4000})
}

func TestDirectTCPIPLoopbackOnly(t *testing.T) {
	r := newRig(t)
	c := r.client()
	open := func(host string, port uint32) ssh.RejectionReason {
		ch, reqs, err := c.OpenChannel("direct-tcpip", forwardPayload(host, port))
		if err == nil {
			go ssh.DiscardRequests(reqs)
			_ = ch.Close()
		}
		return openError(err)
	}
	for _, host := range []string{"10.0.0.1", "example.com", "0.0.0.0", "127.0.0.2", "::2"} {
		eq(t, open(host, 80), ssh.Prohibited)
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LocalHost"} {
		eq(t, open(host, 8000), ssh.RejectionReason(0))
	}
	waitFor(t, "four forwards", func() bool {
		_, _, f, _ := r.up.seen()
		return len(f) == 4
	})
	_, _, got, _ := r.up.seen()
	slices.Sort(got)
	eq(t, got, []string{"127.0.0.1:8000", "127.0.0.1:8000", "127.0.0.1:8000", "[::1]:8000"})
}

// queryOnly offers its key and fails to sign, which is a key query and nothing more
type queryOnly struct{ ssh.Signer }

func (queryOnly) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("no signature")
}

func TestKeyQueryAloneTakesNoLease(t *testing.T) {
	r := newRig(t)
	_, err := r.dialAs(r.alias, queryOnly{r.user}, nil)
	if err == nil {
		t.Fatal("a client that cannot sign got in")
	}
	r.router.mu.Lock()
	defer r.router.mu.Unlock()
	eq(t, r.router.acquires, 0)
	if r.router.authorizes == 0 {
		t.Fatal("the query never asked the router")
	}
}

func TestPerIPAcceptAndAuthFailureLimits(t *testing.T) {
	t.Run("accepts", func(t *testing.T) {
		r := newRig(t, func(_ *rig, c *Config) { c.AcceptsPerMinutePerIP = 3 })
		for range 3 {
			r.client()
		}
		if c, err := r.dialAs(r.alias, r.user, nil); err == nil {
			_ = c.Close()
			t.Fatal("a fourth connection in a minute was accepted")
		}
	})
	t.Run("auth failures", func(t *testing.T) {
		r := newRig(t, func(_ *rig, c *Config) { c.AuthFailuresPerMinutePerIP = 2 })
		r.client()
		stranger := newSigner(t)
		for range 5 {
			_, _ = r.dialAs(r.alias, stranger, nil)
		}
		if c, err := r.dialAs(r.alias, r.user, nil); err == nil {
			_ = c.Close()
			t.Fatal("an address past its failures was accepted")
		}
	})
}

// liar says one key in the query and signs with another, the GO-2024-3321 pattern
type liar struct{ claims, signs ssh.Signer }

func (l liar) PublicKey() ssh.PublicKey { return l.claims.PublicKey() }
func (l liar) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return l.signs.Sign(rand, data)
}

func TestGO20243321Pattern(t *testing.T) {
	r := newRig(t)
	// the query is for the registered key, the signature is by one nobody registered
	if c, err := r.dialAs(r.alias, liar{claims: r.user, signs: newSigner(t)}, nil); err == nil {
		_ = c.Close()
		t.Fatal("a signature by another key was accepted")
	}
	eq(t, r.router.count(&r.router.acquires), 0)

	// acquire itself refuses a verified key other than the one checkKey passed
	c := newConn(t.Context(), r.gw, nil, netipAddr())
	good, other := r.user.PublicKey(), newSigner(t).PublicKey()
	c.rememberGrant(ssh.FingerprintSHA256(good), &routerv1.AuthorizeSshKeyResponse{GrantId: "g"})
	perms := &ssh.Permissions{Extensions: map[string]string{
		extFingerprint: ssh.FingerprintSHA256(good),
	}}
	_, err := c.acquire(fakeMeta{user: r.alias}, other, perms, "")
	var be *ssh.BannerError
	if !errors.As(err, &be) {
		t.Fatalf("acquire let a different verified key through: %v", err)
	}
	eq(t, r.router.count(&r.router.acquires), 0)
}

func TestCrossSandboxRelayFails(t *testing.T) {
	a, b := newUpSSHD(t), newUpSSHD(t)
	r := newRig(t, func(r *rig, _ *Config) { r.up = a })
	// Sandbox A's gate relays to B's sshd and reports B's host key, which takes only B's key
	r.router.upstream = func(_ *routerv1.OpenSshUpstreamRequest, _ string) (
		*routerv1.OpenSshUpstreamResponse, error,
	) {
		return &routerv1.OpenSshUpstreamResponse{
			Transport: &routerv1.OpenSshUpstreamResponse_Tcp{
				Tcp: &routerv1.TcpUpstream{Address: b.addr()},
			},
			User: "root", HostKeys: []string{b.hostLine()},
		}, nil
	}
	bKey, err := ssh.NewPublicKey(r.gw.upstreamKey("sandbox-b").Public())
	eq(t, err, nil)
	b.authorize(bKey)
	s, err := r.client().NewSession()
	eq(t, err, nil)
	var stderr bytes.Buffer
	s.Stderr = &stderr
	err = s.Run("echo hi")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 255 {
		t.Fatalf("got %v, want exit status 255", err)
	}
	if !strings.Contains(stderr.String(), "not reachable yet") {
		t.Fatalf("stderr is %q", stderr.String())
	}
	_, _, _, logins := b.seen()
	eq(t, logins, 0)
}

func TestUserIsTheRoutersNotTheSandboxs(t *testing.T) {
	r := newRig(t)
	s, err := r.client().NewSession()
	eq(t, err, nil)
	out, err := s.Output("echo hi")
	eq(t, err, nil)
	eq(t, string(out), "hi\n")
	users, _, _, _ := r.up.seen()
	eq(t, users, []string{"execuser"})
}

func TestExitStatusAfterOutputEOF(t *testing.T) {
	r := newRig(t)
	ch := rawSession(t, r.client())
	// rawSession discards requests, so open another channel that keeps them
	_ = ch.Close()
	c := r.client()
	raw, reqs, err := c.OpenChannel("session", nil)
	eq(t, err, nil)
	start := time.Now()
	ok, err := raw.SendRequest("exec", true, ssh.Marshal(struct{ C string }{"late"}))
	eq(t, err, nil)
	eq(t, ok, true)
	var exitAt time.Duration
	exited := make(chan struct{})
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				exitAt = time.Since(start)
				close(exited)
				return
			}
		}
	}()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("no exit status")
	}
	// the upstream sent it at once and its output 300 ms later
	if exitAt < 250*time.Millisecond {
		t.Fatalf("the exit status came after %s, before the output ended", exitAt)
	}
	out, _ := io.ReadAll(raw)
	eq(t, string(out), "late output")
}

func TestAtMostTwoHeldExitRequests(t *testing.T) {
	r := newRig(t)
	raw, reqs, err := r.client().OpenChannel("session", nil)
	eq(t, err, nil)
	_, _ = raw.SendRequest("exec", true, ssh.Marshal(struct{ C string }{"exits"}))
	var got []uint32
	for req := range reqs {
		if req.Type == "exit-status" {
			var s struct{ Status uint32 }
			_ = ssh.Unmarshal(req.Payload, &s)
			got = append(got, s.Status)
		}
	}
	eq(t, got, []uint32{1, 2})
}

func TestClientCloseClosesUpstream(t *testing.T) {
	r := newRig(t)
	c := r.client()
	var chans []ssh.Channel
	for range 2 {
		ch := rawSession(t, c)
		ok, _ := ch.SendRequest("exec", true, ssh.Marshal(struct{ C string }{"sleep"}))
		eq(t, ok, true)
		chans = append(chans, ch)
	}
	waitFor(t, "two upstream sessions", func() bool { return r.up.open.Load() == 2 })
	_ = chans[0].Close()
	waitFor(t, "one upstream session closed", func() bool { return r.up.open.Load() == 1 })
	eq(t, r.up.closed.Load(), int32(1))
}

func TestHostKeyMismatch(t *testing.T) {
	r := newRig(t)
	r.router.upstream = func(req *routerv1.OpenSshUpstreamRequest, _ string) (
		*routerv1.OpenSshUpstreamResponse, error,
	) {
		k, _ := ssh.ParsePublicKey(req.GetGatewayPublicKey())
		r.up.authorize(k)
		other := newUpSSHD(t)
		return &routerv1.OpenSshUpstreamResponse{
			Transport: &routerv1.OpenSshUpstreamResponse_Tcp{
				Tcp: &routerv1.TcpUpstream{Address: r.up.addr()},
			},
			User: "root", HostKeys: []string{other.hostLine()},
		}, nil
	}
	s, err := r.client().NewSession()
	eq(t, err, nil)
	var stderr bytes.Buffer
	s.Stderr = &stderr
	err = s.Run("echo hi")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 255 {
		t.Fatalf("got %v, want exit status 255", err)
	}
	eq(t, strings.TrimSpace(stderr.String()), upstreamFailed)
	users, _, _, _ := r.up.seen()
	eq(t, len(users), 0)
}

func TestDeadlineCloseAndExtension(t *testing.T) {
	t.Run("closes at the deadline", func(t *testing.T) {
		r := newRig(t)
		r.router.setDeadline(r.placement, time.Now().Add(400*time.Millisecond))
		c := r.client()
		start := time.Now()
		if !closesWithin(c, 3*time.Second) {
			t.Fatal("the connection outlived its deadline")
		}
		if d := time.Since(start); d < 200*time.Millisecond {
			t.Fatalf("closed after %s, before the deadline", d)
		}
		waitFor(t, "a lease release", func() bool {
			return r.router.count(&r.router.releases) == 1
		})
	})
	t.Run("an extension keeps it", func(t *testing.T) {
		r := newRig(t)
		r.router.setDeadline(r.placement, time.Now().Add(400*time.Millisecond))
		c := r.client()
		r.router.setDeadline(r.placement, time.Now().Add(1500*time.Millisecond))
		if closesWithin(c, 900*time.Millisecond) {
			t.Fatal("the extended connection closed at the first deadline")
		}
		if !closesWithin(c, 3*time.Second) {
			t.Fatal("the connection outlived the extended deadline")
		}
	})
	t.Run("DeadlineMoved re-arms", func(t *testing.T) {
		r := newRig(t)
		r.router.setDeadline(r.placement, time.Now().Add(500*time.Millisecond))
		c := r.client()
		later := time.Now().Add(2 * time.Second)
		r.router.setDeadline(r.placement, later)
		r.router.push(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_DeadlineMoved{
			DeadlineMoved: &routerv1.DeadlineMoved{
				PlacementId: r.placement, Deadline: timestamppb.New(later),
			},
		}})
		if closesWithin(c, 1200*time.Millisecond) {
			t.Fatal("the connection closed at the old deadline")
		}
	})
	t.Run("a router that cannot answer closes it", func(t *testing.T) {
		r := newRig(t)
		r.router.setDeadline(r.placement, time.Now().Add(300*time.Millisecond))
		c := r.client()
		r.router.mu.Lock()
		r.router.checkErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
		r.router.mu.Unlock()
		if !closesWithin(c, 6*time.Second) {
			t.Fatal("the connection outlived its deadline with the router down")
		}
	})
}

func TestRevocationEvents(t *testing.T) {
	fingerprint := func(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }
	t.Run("PlacementEnded", func(t *testing.T) {
		r := newRig(t)
		c := r.client()
		r.router.push(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
			PlacementEnded: &routerv1.PlacementEnded{PlacementId: r.placement},
		}})
		if !closesWithin(c, 2*time.Second) {
			t.Fatal("the connection survived the end of its placement")
		}
	})
	t.Run("SshKeyRemoved by fingerprint", func(t *testing.T) {
		r := newRig(t)
		second := newSigner(t)
		r.router.register(r.alias, r.placement, second.PublicKey(), time.Now().Add(time.Hour))
		first := r.client()
		other, err := r.dialAs(r.alias, second, nil)
		eq(t, err, nil)
		t.Cleanup(func() { _ = other.Close() })
		r.router.push(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_SshKeyRemoved{
			SshKeyRemoved: &routerv1.SshKeyRemoved{
				PlacementId: r.placement, Fingerprint: fingerprint(r.user),
			},
		}})
		if !closesWithin(first, 2*time.Second) {
			t.Fatal("the removed key's connection survived")
		}
		if closesWithin(other, 300*time.Millisecond) {
			t.Fatal("another key's connection closed")
		}
	})
	t.Run("BudgetSpent", func(t *testing.T) {
		r := newRig(t)
		c := r.client()
		r.router.push(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
			BudgetSpent: &routerv1.BudgetSpent{
				PlacementId: r.placement, Kind: routerv1.BudgetKind_BUDGET_KIND_EDGE,
			},
		}})
		if !closesWithin(c, 2*time.Second) {
			t.Fatal("the connection survived a spent budget")
		}
	})
	t.Run("an egress budget leaves it", func(t *testing.T) {
		r := newRig(t)
		c := r.client()
		r.router.push(&routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
			BudgetSpent: &routerv1.BudgetSpent{
				PlacementId: r.placement, Kind: routerv1.BudgetKind_BUDGET_KIND_EGRESS,
			},
		}})
		if closesWithin(c, 400*time.Millisecond) {
			t.Fatal("an egress budget closed an SSH connection")
		}
	})
	t.Run("the periodic check", func(t *testing.T) {
		r := newRig(t, withGateway(func(g *Gateway) { g.checkEvery = time.Hour }))
		c := r.client()
		r.router.mu.Lock()
		r.router.removed[grantID(r.placement, fingerprint(r.user))] = true
		r.router.mu.Unlock()
		r.gw.checkNow()
		if !closesWithin(c, 2*time.Second) {
			t.Fatal("a revoked grant survived the check")
		}
	})
}

func TestBannersUnderBatchMode(t *testing.T) {
	banner := func(r *rig, alias string, signer ssh.Signer) string {
		var got []string
		c, err := r.dialAs(alias, signer, &got)
		if err == nil {
			_ = c.Close()
			return "no refusal"
		}
		eq(t, len(got), 1)
		return strings.TrimRight(got[0], "\r\n")
	}
	r := newRig(t)
	eq(t, banner(r, "bn-unknown000", r.user),
		"bugnet: this key is not accepted for this alias, or the sandbox has ended")
	eq(t, banner(r, r.alias, newSigner(t)),
		"bugnet: this key is not accepted for this alias, or the sandbox has ended")

	r.router.mu.Lock()
	r.router.acquireErr = errInfo(connect.CodeResourceExhausted, "TOO_MANY_CONNECTIONS")
	r.router.mu.Unlock()
	eq(t, banner(r, r.alias, r.user), "bugnet: this sandbox already has 8 SSH connections")

	r.router.mu.Lock()
	r.router.acquireErr = errInfo(connect.CodeUnavailable, "SSH_PREPARING")
	r.router.mu.Unlock()
	eq(t, banner(r, r.alias, r.user), "bugnet: try again in a few seconds")
}

func TestBannerFallbackShowsInTheSession(t *testing.T) {
	r := newRig(t, func(_ *rig, c *Config) { c.BannerFallback = true })
	r.router.mu.Lock()
	r.router.acquireErr = errInfo(connect.CodeResourceExhausted, "TOO_MANY_CONNECTIONS")
	r.router.mu.Unlock()
	s, err := r.client().NewSession()
	eq(t, err, nil)
	var stderr bytes.Buffer
	s.Stderr = &stderr
	err = s.Run("echo hi")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 255 {
		t.Fatalf("got %v, want exit status 255", err)
	}
	eq(t, strings.TrimSpace(stderr.String()), "bugnet: this sandbox already has 8 SSH connections")
}

func TestLeaseIsRenewedAndReleased(t *testing.T) {
	r := newRig(t, withGateway(func(g *Gateway) { g.renewEvery = 40 * time.Millisecond }))
	c := r.client()
	waitFor(t, "two renewals", func() bool { return r.router.count(&r.router.renews) >= 2 })
	_ = c.Close()
	waitFor(t, "one release", func() bool { return r.router.count(&r.router.releases) == 1 })
}

func TestPTYWarnedSixtySecondsBeforeDeadline(t *testing.T) {
	r := newRig(t, withGateway(func(g *Gateway) { g.warnBefore = 800 * time.Millisecond }))
	r.router.setDeadline(r.placement, time.Now().Add(1500*time.Millisecond))
	c := r.client()

	pty, err := c.NewSession()
	eq(t, err, nil)
	eq(t, pty.RequestPty("xterm", 24, 80, ssh.TerminalModes{}), nil)
	ptyErr, _ := pty.StderrPipe()
	eq(t, pty.Shell(), nil)

	plain, err := c.NewSession()
	eq(t, err, nil)
	plainErr, _ := plain.StderrPipe()
	eq(t, plain.Start("sleep"), nil)

	read := func(r io.Reader) <-chan string {
		out := make(chan string, 1)
		go func() {
			b, _ := io.ReadAll(r)
			out <- string(b)
		}()
		return out
	}
	gotPTY, gotPlain := read(ptyErr), read(plainErr)
	select {
	case line := <-gotPTY:
		if strings.Count(line, "bugnet_extend extends it") != 1 ||
			!strings.HasPrefix(line, "bugnet: this sandbox ends at ") {
			t.Fatalf("the PTY session got %q", line)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the PTY session got no warning")
	}
	eq(t, <-gotPlain, "")
}

func TestBytesAreCountedAndCutAtTheBudget(t *testing.T) {
	r := newRig(t, func(r *rig, _ *Config) {
		r.router.budget = &routerv1.EdgeBudget{BytesRemaining: 100 << 10}
	})
	c := r.client()
	s, err := c.NewSession()
	eq(t, err, nil)
	_, _ = s.Output("bytes 400000")
	if !closesWithin(c, 3*time.Second) {
		t.Fatal("the connection survived a spent budget")
	}
	waitFor(t, "a usage report", func() bool {
		r.router.mu.Lock()
		defer r.router.mu.Unlock()
		var out uint64
		for _, u := range r.router.usage {
			eq(t, u.GetPlacementId(), r.placement)
			out += u.GetBytesOut()
		}
		return out >= 100<<10
	})
}

func TestUpstreamPreparingGivesTheRetryLine(t *testing.T) {
	r := newRig(t)
	r.router.upstream = nil
	s, err := r.client().NewSession()
	eq(t, err, nil)
	var stderr bytes.Buffer
	s.Stderr = &stderr
	err = s.Run("echo hi")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 255 {
		t.Fatalf("got %v, want exit status 255", err)
	}
	eq(t, strings.TrimSpace(stderr.String()), upstreamFailed)
}

func TestKeepaliveMissesCloseTheConnection(t *testing.T) {
	r := newRig(t, func(_ *rig, c *Config) {
		c.KeepaliveInterval = settings.Duration(50 * time.Millisecond)
	})
	// a client that never answers global requests
	cfg := r.clientConfig(r.alias, r.user, nil)
	nc, err := dialRaw(r.addr)
	eq(t, err, nil)
	conn, chans, reqs, err := ssh.NewClientConn(nc, r.addr, cfg)
	eq(t, err, nil)
	go rejectChannels(chans)
	// reqs is never read, so the keepalives go unanswered
	_ = reqs
	done := make(chan struct{})
	go func() {
		_ = conn.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("silent client was never cut off")
	}
}
