package egress

import (
	"context"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/pace"
)

// connQueue is the in-process listener tunnels hand their TLS connections to
type connQueue struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newConnQueue() *connQueue {
	return &connQueue{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

// push hands c to the inner server, false once the queue closed
func (q *connQueue) push(c net.Conn) bool {
	select {
	case q.ch <- c:
		return true
	case <-q.done:
		return false
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

type queueAddr struct{}

func (queueAddr) Network() string { return "egress" }
func (queueAddr) String() string  { return "egress-tunnels" }

func (q *connQueue) Addr() net.Addr { return queueAddr{} }

// tunnelConn is the WebSocket of one tunnel as a net.Conn that is paced, counted and idle-limited
type tunnelConn struct {
	net.Conn
	r     io.Reader
	w     io.Writer
	idle  time.Duration
	timer atomic.Pointer[time.Timer]

	done chan struct{}
	once sync.Once
}

// newTunnelConn paces and counts raw through the placement's lane, in toward the sandbox
func newTunnelConn(
	raw net.Conn, lane *pace.Lane, idle time.Duration, in, out func(int),
) *tunnelConn {
	c := &tunnelConn{Conn: raw, idle: idle, done: make(chan struct{})}
	c.timer.Store(time.AfterFunc(idle, func() { _ = c.Close() }))
	c.r = lane.Reader(raw, false, func(n int) {
		c.touch()
		out(n)
	})
	c.w = lane.Writer(raw, true, func(n int) {
		c.touch()
		in(n)
	})
	return c
}

func (c *tunnelConn) touch() {
	if t := c.timer.Load(); t != nil {
		t.Reset(c.idle)
	}
}

func (c *tunnelConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *tunnelConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *tunnelConn) Close() error {
	c.once.Do(func() {
		if t := c.timer.Load(); t != nil {
			t.Stop()
		}
		close(c.done)
	})
	return c.Conn.Close()
}

// errorLog sends net/http's messages to the debug log, and a panic to the error log
func (s *Server) errorLog() *stdlog.Logger {
	return stdlog.New(logWriter{s}, "", 0)
}

type logWriter struct{ s *Server }

func (w logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSuffix(string(p), "\n")
	if strings.Contains(msg, "panic serving") {
		w.s.log.Log(context.Background(), slog.LevelError, msg)
	} else {
		w.s.log.Debug(msg)
	}
	return len(p), nil
}
