package reuseport

import (
	"net"
	"testing"
)

func TestListenSharesThePort(t *testing.T) {
	a, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := Listen(a.Addr().String())
	if err != nil {
		t.Fatalf("a second listener on the same port: %v", err)
	}
	defer func() { _ = b.Close() }()
	plain, err := net.Listen("tcp", a.Addr().String())
	if err == nil {
		_ = plain.Close()
		t.Fatal("a listener without SO_REUSEPORT took a shared port")
	}
}
