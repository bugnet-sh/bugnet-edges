// Command x402-test-seller serves the mainnet test seller on Tailscale Funnel (XS 6.17, 11.3)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := runMain(ctx, os.Args[1:], os.LookupEnv, startTS, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "x402-test-seller:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: x402-test-seller -config FILE [-only a|b]")

// runMain is the whole command
func runMain(
	ctx context.Context, args []string, getenv func(string) (string, bool), start newNode,
	out io.Writer,
) error {
	fs := flag.NewFlagSet("x402-test-seller", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	only := fs.String("only", "", "run one node, a or b")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" ||
		*only != "" && *only != "a" && *only != "b" {
		return errUsage
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	s, err := loadSettings(*path, home)
	if err != nil {
		return err
	}
	if err := s.onlyNode(*only); err != nil {
		return err
	}
	s.testToken, _ = getenv("TESTSELLER_TEST_TOKEN")
	return run(ctx, s, start, out)
}
