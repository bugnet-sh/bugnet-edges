// Package reuseport binds TCP listeners with SO_REUSEPORT, so a new version binds beside the old
package reuseport

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Listen binds addr over TCP with SO_REUSEPORT
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: Control}
	return lc.Listen(context.Background(), "tcp", addr)
}

// Control sets SO_REUSEPORT on a socket before it binds
func Control(_, _ string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	return errors.Join(err, serr)
}
