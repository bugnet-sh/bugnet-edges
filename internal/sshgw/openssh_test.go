package sshgw

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"golang.org/x/crypto/ssh"
)

// osh is the host's ssh client and sshd behind a local bugnet-run gate, DP 9.10
type osh struct {
	t        *testing.T
	r        *rig
	dir      string
	identity string
	known    string
	port     string
	host     string // alias@127.0.0.1
}

// newOSH starts a real sshd and gate and a gateway in front of them, or skips the test
func newOSH(t *testing.T, mods ...func(*rig, *Config)) *osh {
	t.Helper()
	sshd := "/usr/sbin/sshd"
	for _, bin := range []string{"ssh", "ssh-keygen", "scp", "sftp"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("no %s on this host", bin)
		}
	}
	if _, err := os.Stat(sshd); err != nil {
		t.Skip("no sshd on this host")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	// A short path, since a ControlMaster socket path may not pass 104 bytes
	dir, err := os.MkdirTemp("", "bnssh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	o := &osh{t: t, dir: dir, identity: filepath.Join(dir, "id")}
	o.keygen(o.identity)
	o.keygen(filepath.Join(dir, "hk"))

	sshdPort := freePort(t)
	authorized := filepath.Join(dir, "authorized_keys")
	cfg := fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PidFile %s
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp /usr/libexec/sftp-server
AllowTcpForwarding yes
PermitUserEnvironment no
`, sshdPort, filepath.Join(dir, "hk"), authorized, filepath.Join(dir, "sshd.pid"))
	o.write("sshd_config", cfg, 0o600)
	o.write("authorized_keys", "", 0o600)
	o.spawn(sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	waitPort(t, "127.0.0.1:"+sshdPort)

	// The gate, from the real runner, in a root of its own
	runner := filepath.Join(dir, "bugnet-run")
	build := exec.Command("go", "build", "-o", runner, "./cmd/bugnet-run")
	build.Dir = filepath.Join("..", "..", "..", "bugnet-run")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build bugnet-run: %v\n%s", err, out)
	}
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(root, "etc", "bugnet"), 0o755); err != nil {
		t.Fatal(err)
	}
	keyBytes := make([]byte, 32)
	_, _ = rand.Read(keyBytes)
	gateKey := base64.RawURLEncoding.EncodeToString(keyBytes)
	gatePort := freePort(t)
	o.write("root/etc/bugnet/gate.key", gateKey, 0o600)
	o.write("root/etc/bugnet/sshd.port", sshdPort, 0o600)
	o.write("root/etc/bugnet/gate.json", fmt.Sprintf(
		`{"listen":"127.0.0.1:%s","key_file":"/etc/bugnet/gate.key",`+
			`"deny":[],"ssh_port_file":"/etc/bugnet/sshd.port"}`, gatePort), 0o600)
	o.spawn(runner, "gate", "--root", root)
	waitPort(t, "127.0.0.1:"+gatePort)

	hostLine := strings.Fields(o.read("hk.pub"))
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(o.read("id.pub")))
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, append([]func(*rig, *Config){func(r *rig, c *Config) {
		c.TotalBytesPerSecond = 0
		r.router.upstream = func(req *routerv1.OpenSshUpstreamRequest, _ string) (
			*routerv1.OpenSshUpstreamResponse, error,
		) {
			k, err := ssh.ParsePublicKey(req.GetGatewayPublicKey())
			if err != nil {
				return nil, err
			}
			line := string(ssh.MarshalAuthorizedKey(k))
			f, err := os.OpenFile(authorized, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, err
			}
			_, _ = f.WriteString(line)
			_ = f.Close()
			return &routerv1.OpenSshUpstreamResponse{
				Transport: &routerv1.OpenSshUpstreamResponse_Websocket{
					Websocket: &routerv1.WebSocketUpstream{
						Url: "ws://127.0.0.1:" + gatePort + "/__bugnet/ssh",
						Headers: []*routerv1.HeaderValue{
							{Name: "Bugnet-Gate", Value: gateKey},
						},
					},
				},
				User:     me.Username,
				HostKeys: []string{hostLine[0] + " " + hostLine[1]},
			}, nil
		}
	}}, mods...)...)
	r.router.register(r.alias, r.placement, pub, time.Now().Add(time.Hour))
	o.r = r
	_, o.port, _ = net.SplitHostPort(r.addr)
	gw := ssh.MarshalAuthorizedKey(r.hostKey.PublicKey())
	o.known = filepath.Join(dir, "known_hosts")
	o.write("known_hosts", "[127.0.0.1]:"+o.port+" "+string(gw), 0o600)
	o.host = r.alias + "@127.0.0.1"
	return o
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, addr, func() bool {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
}

func (o *osh) keygen(path string) {
	o.t.Helper()
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
		path).CombinedOutput(); err != nil {
		o.t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
}

func (o *osh) write(name, content string, mode os.FileMode) {
	o.t.Helper()
	if err := os.WriteFile(filepath.Join(o.dir, name), []byte(content), mode); err != nil {
		o.t.Fatal(err)
	}
}

func (o *osh) read(name string) string {
	o.t.Helper()
	b, err := os.ReadFile(filepath.Join(o.dir, name))
	if err != nil {
		o.t.Fatal(err)
	}
	return string(b)
}

// spawn starts a process this test owns and ends it by PID when the test ends
func (o *osh) spawn(bin string, args ...string) {
	o.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		o.t.Fatalf("start %s: %v", filepath.Base(bin), err)
	}
	o.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

// opts are the ssh options of DP 9.2's command
func (o *osh) opts() []string {
	return []string{
		"-i", o.identity, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + o.known,
	}
}

func (o *osh) sshArgs(extra ...string) []string {
	return append(append([]string{"-p", o.port}, o.opts()...), extra...)
}

// run runs a command and answers its output, failing the test on an error unless allowed
func (o *osh) run(name string, args ...string) (string, string, error) {
	o.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (o *osh) must(name string, args ...string) string {
	o.t.Helper()
	out, errOut, err := o.run(name, args...)
	if err != nil {
		o.t.Fatalf("%s %s: %v\nstdout: %s\nstderr: %s", name, strings.Join(args, " "), err, out,
			errOut)
	}
	return out
}

func sha(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (o *osh) file(name string, n int) string {
	o.t.Helper()
	p := filepath.Join(o.dir, name)
	f, err := os.Create(p)
	if err != nil {
		o.t.Fatal(err)
	}
	if _, err := io.CopyN(f, rand.Reader, int64(n)); err != nil {
		o.t.Fatal(err)
	}
	_ = f.Close()
	return p
}

// echoServer answers on a loopback port with every byte it reads
func echoServer(t *testing.T) string {
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
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// background starts a long-running ssh this test owns and ends it by PID
func (o *osh) background(args ...string) *exec.Cmd {
	o.t.Helper()
	cmd := exec.Command("ssh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		o.t.Fatal(err)
	}
	o.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func TestOpenSSHClientMatrix(t *testing.T) {
	o := newOSH(t)
	me, _ := user.Current()

	t.Run("ssh host cmd", func(t *testing.T) {
		out := o.must("ssh", o.sshArgs(o.host, "echo hello; id -un")...)
		eq(t, out, "hello\n"+me.Username+"\n")
	})
	t.Run("a PTY shell", func(t *testing.T) {
		out := o.must("ssh", o.sshArgs("-tt", o.host, "tty")...)
		if !strings.Contains(out, "/dev/") {
			t.Fatalf("tty printed %q", out)
		}
	})
	t.Run("scp default mode", func(t *testing.T) {
		src := o.file("scp-src", 3<<20+17)
		dst := filepath.Join(o.dir, "scp-dst")
		o.must("scp", append(append([]string{"-P", o.port}, o.opts()...), src,
			o.host+":"+dst)...)
		eq(t, sha(t, dst), sha(t, src))
		back := filepath.Join(o.dir, "scp-back")
		o.must("scp", append(append([]string{"-P", o.port}, o.opts()...), o.host+":"+dst, back)...)
		eq(t, sha(t, back), sha(t, src))
	})
	t.Run("scp -O", func(t *testing.T) {
		src := o.file("scpO-src", 1<<20+3)
		dst := filepath.Join(o.dir, "scpO-dst")
		o.must("scp", append(append([]string{"-O", "-P", o.port}, o.opts()...), src,
			o.host+":"+dst)...)
		eq(t, sha(t, dst), sha(t, src))
	})
	t.Run("sftp", func(t *testing.T) {
		src := o.file("sftp-src", 2<<20+5)
		dst := filepath.Join(o.dir, "sftp-dst")
		o.write("sftp.batch", fmt.Sprintf("put %s %s\n", src, dst), 0o600)
		o.must("sftp", append(append([]string{"-P", o.port}, o.opts()...), "-b",
			filepath.Join(o.dir, "sftp.batch"), o.host)...)
		eq(t, sha(t, dst), sha(t, src))
	})
	t.Run("rsync -e ssh", func(t *testing.T) {
		if _, err := exec.LookPath("rsync"); err != nil {
			t.Skip("no rsync on this host")
		}
		src := o.file("rsync-src", 1<<20+9)
		dst := filepath.Join(o.dir, "rsync-dst")
		e := "ssh " + strings.Join(o.sshArgs(), " ")
		o.must("rsync", "-e", e, src, o.host+":"+dst)
		eq(t, sha(t, dst), sha(t, src))
	})
	t.Run("ssh -L to a loopback port", func(t *testing.T) {
		target := echoServer(t)
		local := freePort(t)
		o.background(o.sshArgs("-N", "-L", local+":"+target, o.host)...)
		waitPort(t, "127.0.0.1:"+local)
		c, err := net.Dial("tcp", "127.0.0.1:"+local)
		eq(t, err, nil)
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("ping"))
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(c, buf)
		eq(t, err, nil)
		eq(t, string(buf), "ping")
	})
	t.Run("ControlMaster reuse", func(t *testing.T) {
		control := "ControlPath=" + filepath.Join(o.dir, "cm")
		args := o.sshArgs("-o", "ControlMaster=auto", "-o", control, "-o", "ControlPersist=20",
			o.host, "echo reused")
		before := o.r.router.count(&o.r.router.acquires)
		eq(t, o.must("ssh", args...), "reused\n")
		eq(t, o.must("ssh", args...), "reused\n")
		eq(t, o.r.router.count(&o.r.router.acquires)-before, 1)
		o.must("ssh", o.sshArgs("-o", control, "-O", "exit", o.host)...)
	})
}

func TestOpenSSHRefusals(t *testing.T) {
	o := newOSH(t)

	t.Run("banner under BatchMode", func(t *testing.T) {
		_, stderr, err := o.run("ssh", o.sshArgs("bn-unknown000@127.0.0.1", "true")...)
		if err == nil {
			t.Fatal("an unknown alias got in")
		}
		if !strings.Contains(stderr, bannerDenied) {
			t.Fatalf("stderr is %q", stderr)
		}
	})
	t.Run("-D to a remote host", func(t *testing.T) {
		local := freePort(t)
		o.background(o.sshArgs("-N", "-D", local, o.host)...)
		waitPort(t, "127.0.0.1:"+local)
		eq(t, socksConnect(t, "127.0.0.1:"+local, "example.com", 80) != 0, true)
		eq(t, socksConnect(t, "127.0.0.1:"+local, "10.0.0.1", 80) != 0, true)
	})
	t.Run("-R", func(t *testing.T) {
		target := echoServer(t)
		_, stderr, err := o.run("ssh", o.sshArgs("-N", "-o", "ExitOnForwardFailure=yes",
			"-R", freePort(t)+":"+target, o.host)...)
		if err == nil {
			t.Fatal("a remote forward was accepted")
		}
		if !strings.Contains(stderr, "forwarding failed") {
			t.Fatalf("stderr is %q", stderr)
		}
	})
	t.Run("-A", func(t *testing.T) {
		sock := filepath.Join(o.dir, "agent")
		ln, err := net.Listen("unix", sock)
		eq(t, err, nil)
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		cmd := exec.Command("ssh", o.sshArgs("-A", o.host, `echo "[$SSH_AUTH_SOCK]"`)...)
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
		out, err := cmd.Output()
		eq(t, err, nil)
		eq(t, strings.TrimSpace(string(out)), "[]")
	})
	t.Run("-X", func(t *testing.T) {
		xauth := filepath.Join(o.dir, "xauth")
		o.write("xauth", "#!/bin/sh\ncase \"$*\" in *list*) "+
			"echo 'h/unix:99  MIT-MAGIC-COOKIE-1  00112233445566778899aabbccddeeff';; esac\n"+
			"exit 0\n", 0o700)
		cmd := exec.Command("ssh", o.sshArgs("-X", "-o", "XAuthLocation="+xauth, o.host,
			"true")...)
		cmd.Env = append(os.Environ(), "DISPLAY=:99")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run()
		if !strings.Contains(stderr.String(), "X11 forwarding request failed") {
			t.Skipf("this ssh sent no x11-req, stderr %q", stderr.String())
		}
	})
}

// socksConnect asks a SOCKS5 proxy for a host and port and answers the reply code, 0 is success
func socksConnect(t *testing.T, proxy, host string, port int) byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	hello := make([]byte, 2)
	if _, err := io.ReadFull(c, hello); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	_, _ = c.Write(req)
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil {
		return 1
	}
	return reply[1]
}

func TestOpenSSHBulkRate(t *testing.T) {
	o := newOSH(t)
	size := 64 << 20
	if os.Getenv("BUGNET_TEST_SSH_GIB") == "1" {
		size = 1 << 30
	}
	src := o.file("bulk-src", size)
	dst := filepath.Join(o.dir, "bulk-dst")
	back := filepath.Join(o.dir, "bulk-back")
	base := append([]string{"-P", o.port}, o.opts()...)
	start := time.Now()
	o.must("scp", append(append([]string{}, base...), src, o.host+":"+dst)...)
	up := time.Since(start)
	start = time.Now()
	o.must("scp", append(append([]string{}, base...), o.host+":"+dst, back)...)
	down := time.Since(start)
	eq(t, sha(t, dst), sha(t, src))
	eq(t, sha(t, back), sha(t, src))
	mib := float64(size) / (1 << 20)
	t.Logf("%.0f MiB up in %s (%.1f MiB/s), down in %s (%.1f MiB/s)", mib,
		up.Round(time.Millisecond), mib/up.Seconds(), down.Round(time.Millisecond),
		mib/down.Seconds())
}
