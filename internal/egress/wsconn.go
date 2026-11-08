package egress

import (
	"context"
	"io"
	"net"

	"github.com/coder/websocket"
)

// wsChunk is the most bytes one WebSocket message carries toward the sandbox
const wsChunk = 32 << 10

// wsNetConn is the WebSocket as a net.Conn of binary messages with working deadlines
func wsNetConn(ctx context.Context, ws *websocket.Conn) net.Conn {
	// The library's own net.Conn closes the socket on a past deadline, which net/http sets
	near, far := net.Pipe()
	go func() {
		// Messages from the sandbox go into the pipe
		defer func() { _ = far.Close() }()
		for {
			_, r, err := ws.Reader(ctx)
			if err != nil {
				return
			}
			if _, err := io.Copy(far, r); err != nil {
				return
			}
		}
	}()
	go func() {
		// Bytes for the sandbox leave in messages of at most wsChunk
		defer func() { _ = ws.Close(websocket.StatusNormalClosure, "") }()
		buf := make([]byte, wsChunk)
		for {
			n, err := far.Read(buf)
			if n > 0 {
				if werr := ws.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					_ = far.Close()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		_ = ws.CloseNow()
		_ = far.Close()
	}()
	return near
}
