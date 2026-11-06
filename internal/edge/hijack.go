package edge

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
)

// hijacks holds the connections handlers took over, which http.Server.Shutdown never waits for
type hijacks struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	gone  chan struct{}
}

func newHijacks() *hijacks {
	return &hijacks{conns: map[*trackedConn]struct{}{}, gone: make(chan struct{}, 1)}
}

// trackedConn is one accepted connection below TLS, so its hijacked form can be found and closed
type trackedConn struct {
	net.Conn
	set *hijacks
}

// Close forgets the connection before closing it
func (c *trackedConn) Close() error {
	c.set.remove(c)
	return c.Conn.Close()
}

type trackingListener struct {
	net.Listener
	set *hijacks
}

func (l trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: c, set: l.set}, nil
}

// listener wraps ln so every connection it accepts can be tracked once hijacked
func (h *hijacks) listener(ln net.Listener) net.Listener {
	return trackingListener{Listener: ln, set: h}
}

// connState is the server's ConnState hook, which records each connection a handler hijacks
func (h *hijacks) connState(c net.Conn, state http.ConnState) {
	if state != http.StateHijacked {
		return
	}
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if t, ok := c.(*trackedConn); ok {
		h.mu.Lock()
		h.conns[t] = struct{}{}
		h.mu.Unlock()
	}
}

func (h *hijacks) remove(c *trackedConn) {
	h.mu.Lock()
	_, ok := h.conns[c]
	delete(h.conns, c)
	h.mu.Unlock()
	if ok {
		select {
		case h.gone <- struct{}{}:
		default:
		}
	}
}

func (h *hijacks) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// wait returns once every hijacked connection has closed, or when ctx ends
func (h *hijacks) wait(ctx context.Context) {
	for h.count() > 0 {
		select {
		case <-h.gone:
		case <-ctx.Done():
			return
		}
	}
}

// closeAll closes every hijacked connection still open
func (h *hijacks) closeAll() {
	h.mu.Lock()
	open := make([]*trackedConn, 0, len(h.conns))
	for c := range h.conns {
		open = append(open, c)
	}
	h.mu.Unlock()
	for _, c := range open {
		_ = c.Close()
	}
}
