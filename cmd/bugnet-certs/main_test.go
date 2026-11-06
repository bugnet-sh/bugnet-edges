package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capture() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewJSONHandler(&b, nil)), &b
}

func TestUsageExitsTwo(t *testing.T) {
	log, _ := capture()
	for _, args := range [][]string{nil, {"-config"}, {"-config", "a", "b"}, {"-other"}} {
		if code := run(t.Context(), log, args, os.LookupEnv); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestMissingDNSVariableNamesItselfAndExitsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.toml")
	doc := "dns_env = [\"CF_DNS_API_TOKEN\"]\n[[certificates]]\n" +
		"names = [\"*.preview.example.test\"]\ndir = \"/nonexistent\"\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	log, out := capture()
	getenv := func(string) (string, bool) { return "", false }
	if code := run(t.Context(), log, []string{"-config", path}, getenv); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "CF_DNS_API_TOKEN") {
		t.Fatalf("the log does not name the variable\n%s", out)
	}
	log, out = capture()
	if code := run(t.Context(), log, []string{"-config", "/nonexistent.toml"}, getenv); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"level":"ERROR"`) {
		t.Fatalf("no error logged\n%s", out)
	}
}
