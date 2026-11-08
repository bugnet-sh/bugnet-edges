package sshgw

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// upSSHD is a sandbox's sshd for tests, built on x/crypto/ssh
type upSSHD struct {
	ln      net.Listener
	hostKey ssh.Signer

	mu         sync.Mutex
	authorized map[string]bool // Marshal of each key it accepts
	users      []string        // the user of each login that succeeded
	logins     int
	requests   []string // the type of each session request, in order
	replyFalse map[string]bool
	forwards   []string // each direct-tcpip target

	open, closed atomic.Int32
}

func newUpSSHD(t *testing.T) *upSSHD {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upSSHD{
		ln: ln, hostKey: hk, authorized: map[string]bool{}, replyFalse: map[string]bool{},
	}
	t.Cleanup(func() { _ = ln.Close() })
	go u.serve()
	return u
}

func (u *upSSHD) addr() string { return u.ln.Addr().String() }

// hostLine is the host key in authorized_keys form, as the router's host_keys hold it
func (u *upSSHD) hostLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(u.hostKey.PublicKey())))
}

func (u *upSSHD) authorize(k ssh.PublicKey) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.authorized[string(k.Marshal())] = true
}

func (u *upSSHD) seen() (users, requests, forwards []string, logins int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.users...), append([]string(nil), u.requests...),
		append([]string(nil), u.forwards...), u.logins
}

func (u *upSSHD) serve() {
	for {
		nc, err := u.ln.Accept()
		if err != nil {
			return
		}
		go u.conn(nc)
	}
}

func (u *upSSHD) conn(nc net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			u.mu.Lock()
			defer u.mu.Unlock()
			if !u.authorized[string(k.Marshal())] {
				return nil, errors.New("unknown key")
			}
			u.users = append(u.users, m.User())
			u.logins++
			return nil, nil
		},
	}
	cfg.AddHostKey(u.hostKey)
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			go u.session(nch)
		case "direct-tcpip":
			var d directTCPIP
			_ = ssh.Unmarshal(nch.ExtraData(), &d)
			u.mu.Lock()
			u.forwards = append(u.forwards, net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))))
			u.mu.Unlock()
			ch, rqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(rqs)
			go func() {
				_, _ = io.Copy(ch, ch)
				_ = ch.Close()
			}()
		default:
			_ = nch.Reject(ssh.UnknownChannelType, "")
		}
	}
	_ = sc.Close()
}

func (u *upSSHD) session(nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	u.open.Add(1)
	defer func() {
		u.open.Add(-1)
		u.closed.Add(1)
	}()
	for r := range reqs {
		u.mu.Lock()
		u.requests = append(u.requests, r.Type)
		no := u.replyFalse[r.Type]
		u.mu.Unlock()
		if r.WantReply {
			_ = r.Reply(!no, nil)
		}
		if no {
			continue
		}
		switch r.Type {
		case "exec":
			var p struct{ Command string }
			_ = ssh.Unmarshal(r.Payload, &p)
			go u.run(ch, p.Command)
		case "shell":
			go u.run(ch, "sleep")
		case "subsystem":
			go u.run(ch, "cat")
		}
	}
	_ = ch.Close()
}

func exitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
}

// run executes one of the test commands
func (u *upSSHD) run(ch ssh.Channel, cmd string) {
	word, rest, _ := strings.Cut(cmd, " ")
	switch word {
	case "echo":
		_, _ = io.WriteString(ch, rest+"\n")
	case "stderr":
		_, _ = io.WriteString(ch.Stderr(), rest+"\n")
	case "exit":
		n, _ := strconv.Atoi(rest)
		exitStatus(ch, uint32(n))
		_ = ch.Close()
		return
	case "cat":
		_, _ = io.Copy(ch, ch)
	case "sleep":
		// the session stays open until the other side closes it
		return
	case "bytes":
		n, _ := strconv.Atoi(rest)
		_, _ = ch.Write(bytes.Repeat([]byte("a"), n))
	case "late":
		// exit-status first, the output 300 ms after, which a relay must not reorder
		exitStatus(ch, 7)
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(ch, "late output")
		_ = ch.Close()
		return
	case "exits":
		for i := uint32(1); i <= 5; i++ {
			exitStatus(ch, i)
		}
		_ = ch.Close()
		return
	}
	exitStatus(ch, 0)
	_ = ch.Close()
}
