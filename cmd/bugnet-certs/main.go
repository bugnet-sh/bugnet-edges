// Command bugnet-certs renews the preview wildcards by DNS-01, checks every served name, and exits
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	legolog "github.com/go-acme/lego/v4/log"

	"github.com/oynozan/bugnet-edges/internal/certs"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, log, os.Args[1:], os.LookupEnv)
	stop()
	os.Exit(code)
}

// run is the whole command, answering 0 when nothing needs a person, 1 when something does
func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) int {
	fs := flag.NewFlagSet("bugnet-certs", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" {
		log.Error("usage: bugnet-certs -config FILE")
		return 2
	}
	cfg, err := certs.Load(*path)
	if err == nil {
		err = certs.CheckEnv(cfg.DNSEnv, getenv)
	}
	if err != nil {
		log.Error("bugnet-certs cannot start", "err", err)
		return 1
	}
	legolog.Logger = slog.NewLogLogger(log.Handler(), slog.LevelInfo)
	ok := true
	var iss certs.Issuer
	if i, err := certs.NewLego(cfg, log); err != nil {
		log.Error("no ACME client, so nothing renews", "err", err)
		ok = false
	} else {
		iss = i
	}
	if !certs.Run(ctx, cfg, iss, log, time.Now()) {
		ok = false
	}
	if !ok {
		return 1
	}
	log.Info("every certificate has time left")
	return 0
}
