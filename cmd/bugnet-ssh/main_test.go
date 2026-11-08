package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// credentials writes a host key as a systemd credentials directory would hold it
func credentials(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key"),
		pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const token = "ssh-token-0123456789abcdefghijklmnopqrs"

func TestUsageAndMissingPieces(t *testing.T) {
	for _, args := range [][]string{nil, {"-config"}, {"-config", "x", "extra"}} {
		if err := run(t.Context(), quiet(), args, env(nil)); err != errUsage {
			t.Fatalf("args %v: got %v, want the usage error", args, err)
		}
	}
	file := filepath.Join(t.TempDir(), "ssh.toml")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(t.Context(), quiet(), []string{"-config", file}, env(nil))
	if err == nil || !strings.Contains(err.Error(), "BUGNET_SSH_TOKEN") {
		t.Fatalf("got %v, want the missing token", err)
	}
	err = run(t.Context(), quiet(), []string{"-config", file},
		env(map[string]string{"BUGNET_SSH_TOKEN": token}))
	if err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("got %v, want the missing credentials directory", err)
	}
}

func TestServesAndStopsOnItsContext(t *testing.T) {
	router := httptest.NewServer(http.NotFoundHandler())
	defer router.Close()
	listen, metrics := freeAddr(t), freeAddr(t)
	file := filepath.Join(t.TempDir(), "ssh.toml")
	doc := fmt.Sprintf("router_url = %q\nlisten_addr = %q\nmetrics_listen_addr = %q\n"+
		"proxy_protocol_from = [\"127.0.0.1/32\"]\ndrain_max = \"1s\"\n",
		router.URL, listen, metrics)
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"BUGNET_SSH_TOKEN": token, "CREDENTIALS_DIRECTORY": credentials(t),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, quiet(), []string{"-config", file}, env(vars)) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + metrics + "/metrics")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "bugnet_ssh_") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the metrics never answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after its context ended")
	}
}
