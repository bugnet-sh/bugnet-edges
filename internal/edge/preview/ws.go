package preview

import (
	"bufio"
	"io"
	"net"
	"net/http"

	"github.com/bugnet-sh/bugnet-edges/internal/pace"
)

// meter paces and counts a response body, and a WebSocket's bytes both ways once hijacked
type meter struct {
	http.ResponseWriter
	out  io.Writer
	lane *pace.Lane
	in   func(int)
	sent func(int)
}

func newMeter(w http.ResponseWriter, lane *pace.Lane, in, out func(int)) *meter {
	return &meter{ResponseWriter: w, out: lane.Writer(w, false, out), lane: lane, in: in, sent: out}
}

func (m *meter) Write(b []byte) (int, error) {
	return m.out.Write(b)
}

// Flush lets ReverseProxy flush server-sent events after each write
func (m *meter) Flush() {
	_ = http.NewResponseController(m.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the server's writer
func (m *meter) Unwrap() http.ResponseWriter {
	return m.ResponseWriter
}

// Hijack hands ReverseProxy a connection whose reads and writes are paced and counted
func (m *meter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(m.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// Bytes the server read ahead come first, and the 101 written through brw is not counted
	mc := &meteredConn{
		Conn: c, r: m.lane.Reader(brw.Reader, true, m.in), w: m.lane.Writer(c, false, m.sent),
	}
	return mc, bufio.NewReadWriter(bufio.NewReader(mc), brw.Writer), nil
}

type meteredConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c *meteredConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *meteredConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}
