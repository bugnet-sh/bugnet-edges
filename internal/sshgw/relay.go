package sshgw

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// maxHeldExits is how many exit requests a session keeps, the upstream may be hostile
	maxHeldExits = 2
	// keepaliveMisses is how many unanswered keepalives close a leg
	keepaliveMisses = 3
	keepaliveType   = "keepalive@openssh.com"
)

// session is one relayed session channel
type session struct {
	c  *conn
	ch ssh.Channel

	mu     sync.Mutex
	pty    bool
	closed bool
	warned time.Time
	timer  *time.Timer
}

// serve dials the upstream and relays channels until the connection ends (DP 9.4 and 9.5)
func (c *conn) serve(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go c.globalRequests(reqs)
	up, err := c.g.dialUpstream(c.ctx, c.grantID, c.placement)
	if err != nil {
		if c.ctx.Err() == nil {
			c.g.log.Warn("ssh: the upstream did not open", "placement", c.placement,
				"reason", dialReason(err))
		}
		c.refuseSessions(chans, upstreamFailed)
		return
	}
	if !c.setUp(up) {
		return
	}
	interval := time.Duration(c.g.cfg.KeepaliveInterval)
	go keepalive(c.ctx, c.sc, interval, func() { c.close("keepalive") })
	go keepalive(c.ctx, up, interval, func() { c.close("upstream_keepalive") })
	go func() {
		_ = up.Wait()
		c.close("upstream_gone")
	}()
	for nc := range chans {
		c.channel(nc, up)
	}
}

// globalRequests answers the user's global requests by DP 9.5's table
func (c *conn) globalRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		ok := false
		if r.Type == "no-more-sessions@openssh.com" {
			c.noMoreSessions.Store(true)
			ok = true
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
}

// channel relays one channel the user opened, or rejects it
func (c *conn) channel(nc ssh.NewChannel, up ssh.Conn) {
	switch nc.ChannelType() {
	case "session":
		if c.noMoreSessions.Load() {
			_ = nc.Reject(ssh.Prohibited, "")
			return
		}
		if int(c.sessionCount.Add(1)) > c.maxSessions {
			c.sessionCount.Add(-1)
			_ = nc.Reject(ssh.ResourceShortage, "")
			return
		}
		c.relays.Go(func() {
			defer c.sessionCount.Add(-1)
			c.session(nc, up)
		})
	case "direct-tcpip":
		if int(c.forwardCount.Add(1)) > c.maxForwards {
			c.forwardCount.Add(-1)
			_ = nc.Reject(ssh.ResourceShortage, "")
			return
		}
		c.relays.Go(func() {
			defer c.forwardCount.Add(-1)
			c.forward(nc, up)
		})
	default:
		_ = nc.Reject(ssh.UnknownChannelType, "")
	}
}

// forwarded request types, passed to the upstream with their reply
var forwardedRequests = map[string]bool{
	"pty-req": true, "env": true, "shell": true, "exec": true, "window-change": true,
	"signal": true, "break": true, "eow@openssh.com": true,
}

// held is an exit-status or exit-signal request kept until the outputs end
type held struct {
	typ     string
	payload []byte
}

// session relays one session channel and its requests (DP 9.5)
func (c *conn) session(nc ssh.NewChannel, up ssh.Conn) {
	upCh, upReqs, err := up.OpenChannel("session", nil)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = upCh.Close()
		return
	}
	c.g.m.sessions.Inc()
	s := &session{c: c, ch: ch}
	if !c.addSession(s) {
		_ = ch.Close()
		_ = upCh.Close()
		return
	}
	defer c.removeSession(s)

	var outputs sync.WaitGroup
	outputs.Go(func() { _, _ = io.Copy(ch, c.counted(upCh, false)) })
	outputs.Go(func() { _, _ = io.Copy(ch.Stderr(), c.counted(upCh.Stderr(), false)) })
	go func() {
		_, _ = io.Copy(upCh, c.counted(ch, true))
		_ = upCh.CloseWrite()
	}()

	var exits []held
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		for r := range upReqs {
			switch r.Type {
			case "exit-status", "exit-signal":
				if len(exits) < maxHeldExits {
					exits = append(exits, held{r.Type, r.Payload})
				}
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()

	// The user closing first closes the upstream channel, so no idle session piles up
	userDone := make(chan struct{})
	go func() {
		defer close(userDone)
		c.sessionRequests(s, reqs, upCh)
		_ = upCh.Close()
	}()

	outputs.Wait()
	<-upDone
	for _, e := range exits {
		_, _ = ch.SendRequest(e.typ, false, e.payload)
	}
	_ = ch.Close()
	<-userDone
}

// sessionRequests forwards the user's session requests, the replies coming back
func (c *conn) sessionRequests(s *session, reqs <-chan *ssh.Request, upCh ssh.Channel) {
	for r := range reqs {
		switch {
		case r.Type == "subsystem":
			var p struct{ Name string }
			if ssh.Unmarshal(r.Payload, &p) != nil || p.Name != "sftp" {
				replyTo(r, false)
				continue
			}
			c.forwardRequest(r, upCh)
		case forwardedRequests[r.Type]:
			if c.forwardRequest(r, upCh) && r.Type == "pty-req" {
				s.setPTY(c.deadline())
			}
		default:
			// x11-req, auth-agent-req@openssh.com and every other type
			replyTo(r, false)
		}
	}
}

// forwardRequest sends r upstream and passes the reply back, true when the upstream said yes
func (c *conn) forwardRequest(r *ssh.Request, upCh ssh.Channel) bool {
	ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
	ok = ok && err == nil
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
	return ok
}

func replyTo(r *ssh.Request, ok bool) {
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

func (s *session) setPTY(end time.Time) {
	s.mu.Lock()
	s.pty = true
	s.mu.Unlock()
	if !end.IsZero() {
		s.arm(end)
	}
}

func (c *conn) addSession(s *session) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return false
	}
	c.sessions[s] = struct{}{}
	return true
}

func (c *conn) removeSession(s *session) {
	s.disarm()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, s)
}

// directTCPIP is the payload of a direct-tcpip channel open (RFC 4254 section 7.2)
type directTCPIP struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

// loopbackTarget rewrites localhost to 127.0.0.1 and accepts only the two loopback addresses (S2)
func loopbackTarget(host string) (string, bool) {
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1", true
	}
	return host, host == "127.0.0.1" || host == "::1"
}

// forward relays one direct-tcpip channel to a loopback target in the sandbox
func (c *conn) forward(nc ssh.NewChannel, up ssh.Conn) {
	var d directTCPIP
	if ssh.Unmarshal(nc.ExtraData(), &d) != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	host, ok := loopbackTarget(d.Host)
	if !ok {
		_ = nc.Reject(ssh.Prohibited, "")
		return
	}
	d.Host = host
	upCh, upReqs, err := up.OpenChannel("direct-tcpip", ssh.Marshal(&d))
	if err != nil {
		reason := ssh.ConnectionFailed
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) {
			reason = oce.Reason
		}
		_ = nc.Reject(reason, "")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = upCh.Close()
		return
	}
	go func() {
		ssh.DiscardRequests(reqs)
		_ = upCh.Close()
	}()
	go func() {
		ssh.DiscardRequests(upReqs)
		_ = ch.Close()
	}()
	var both sync.WaitGroup
	both.Go(func() {
		_, _ = io.Copy(upCh, c.counted(ch, true))
		_ = upCh.CloseWrite()
	})
	both.Go(func() {
		_, _ = io.Copy(ch, c.counted(upCh, false))
		_ = ch.CloseWrite()
	})
	both.Wait()
	_ = ch.Close()
	_ = upCh.Close()
}

// refuseSessions answers a session with text on stderr and exit status 255, DP 9.3 and 9.4
func (c *conn) refuseSessions(chans <-chan ssh.NewChannel, text string) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Go(func() { refuseSession(ch, reqs, text) })
	}
}

func refuseSession(ch ssh.Channel, reqs <-chan *ssh.Request, text string) {
	defer func() { _ = ch.Close() }()
	for r := range reqs {
		replyTo(r, true)
		switch r.Type {
		case "shell", "exec", "subsystem":
			_, _ = io.WriteString(ch.Stderr(), text+"\r\n")
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{255}))
			return
		}
	}
}

// keepalive sends keepalive@openssh.com every interval and calls dead after three misses
func keepalive(ctx context.Context, conn ssh.Conn, every time.Duration, dead func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		answer := make(chan error, 1)
		go func() {
			_, _, err := conn.SendRequest(keepaliveType, true, nil)
			answer <- err
		}()
		select {
		case <-ctx.Done():
			return
		case err := <-answer:
			if err != nil {
				dead()
				return
			}
			missed = 0
		case <-time.After(every):
			if missed++; missed >= keepaliveMisses {
				dead()
				return
			}
		}
	}
}

// rejectChannels refuses every channel the sandbox opens toward the gateway
func rejectChannels(chans <-chan ssh.NewChannel) {
	for nc := range chans {
		_ = nc.Reject(ssh.Prohibited, "")
	}
}
