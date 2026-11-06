// Command bugnet-edge serves the public HTTP edge, or with --role secrets the secrets route
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/oynozan/bugnet-edges/internal/edge"
	"github.com/oynozan/bugnet-edges/internal/metrics"
	"github.com/oynozan/bugnet-edges/internal/pages"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// A second signal during the drain kills the process at once
	context.AfterFunc(ctx, stop)
	if err := run(ctx, log, os.Args[1:], os.LookupEnv); err != nil {
		log.Error("bugnet-edge failed", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: bugnet-edge -config FILE [--role edge|secrets]")

func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) error {
	fs := flag.NewFlagSet("bugnet-edge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	role := fs.String("role", "edge", "edge or secrets")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" {
		return errUsage
	}
	switch *role {
	case "edge":
		cfg, err := edge.Load(*path, getenv)
		if err != nil {
			return err
		}
		return edge.New(cfg, edge.Deps{
			Landing: pages.Landing(cfg.Previews.AbuseContact),
			Log:     log.With("edge_id", cfg.EdgeID),
			Metrics: metrics.New(),
		}).Run(ctx)
	case "secrets":
		cfg, err := edge.LoadSecrets(*path, getenv)
		if err != nil {
			return err
		}
		return edge.NewSecrets(cfg, edge.SecretsDeps{Log: log, Metrics: metrics.New()}).Run(ctx)
	}
	return errUsage
}
