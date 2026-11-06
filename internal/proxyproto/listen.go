// Package proxyproto accepts connections that HAProxy opens with a PROXY v2 header
package proxyproto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	pp "github.com/pires/go-proxyproto"
	"golang.org/x/sys/unix"
)

var (
	// headerTimeout bounds the wait for the header, which HAProxy sends at once
	headerTimeout = 10 * time.Second

	errVersion = errors.New("proxyproto: only PROXY protocol version 2 is accepted")
)

// Listen binds addr with SO_REUSEPORT and admits trusted sources that open with a PROXY v2 header
func Listen(addr string, trusted []netip.Prefix) (net.Listener, error) {
	for _, p := range trusted {
		if !p.IsValid() {
			return nil, errors.New("proxyproto: a trusted prefix is not valid")
		}
	}
	lc := net.ListenConfig{Control: reusePort}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxyproto: %w", err)
	}
	return &listener{pp.Listener{
		Listener:          ln,
		ConnPolicy:        trust(trusted),
		ValidateHeader:    versionTwo,
		ReadHeaderTimeout: headerTimeout,
	}}, nil
}

// reusePort lets a new version bind beside the old one during a deploy
func reusePort(_, _ string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	return errors.Join(err, serr)
}

// trust requires the header from trusted sources and closes connections from any other
func trust(trusted []netip.Prefix) pp.ConnPolicyFunc {
	return func(o pp.ConnPolicyOptions) (pp.Policy, error) {
		tcp, ok := o.Upstream.(*net.TCPAddr)
		if !ok {
			return pp.REJECT, fmt.Errorf("%w: not a TCP peer", pp.ErrInvalidUpstream)
		}
		ip := tcp.AddrPort().Addr().Unmap()
		for _, p := range trusted {
			if p.Contains(ip) {
				return pp.REQUIRE, nil
			}
		}
		return pp.REJECT, fmt.Errorf("%w: untrusted peer", pp.ErrInvalidUpstream)
	}
}

func versionTwo(h *pp.Header) error {
	if h.Version != 2 {
		return errVersion
	}
	return nil
}

type listener struct{ pp.Listener }

// Accept returns the next connection from a trusted source, its header still unread
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &conn{c.(*pp.Conn)}, nil
}

// conn closes itself once its header is missing or refused
type conn struct{ *pp.Conn }

func (c *conn) check(err error) error {
	if err != nil && c.ProxyHeader() == nil {
		_ = c.Close()
	}
	return err
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, c.check(err)
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, c.check(err)
}

// ReadFrom keeps the header check on the io.Copy fast path
func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	n, err := c.Conn.ReadFrom(r)
	return n, c.check(err)
}

// WriteTo keeps the header check on the io.Copy fast path
func (c *conn) WriteTo(w io.Writer) (int64, error) {
	n, err := c.Conn.WriteTo(w)
	return n, c.check(err)
}
