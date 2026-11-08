// Command bugnet-edge serves the public HTTP edge, or with --role secrets or sessions that route
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
	"time"

	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/edge"
	"github.com/bugnet-sh/bugnet-edges/internal/edge/transfer"
	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/pages"
	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
	"github.com/bugnet-sh/bugnet-edges/internal/sessionsroute"
	"github.com/bugnet-sh/bugnet-edges/internal/strangers"
	"github.com/bugnet-sh/bugnet-edges/internal/traffic"
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

var errUsage = errors.New("usage: bugnet-edge -config FILE [--role edge|secrets|sessions]")

func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) error {
	fs := flag.NewFlagSet("bugnet-edge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	role := fs.String("role", "edge", "edge, secrets or sessions")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" {
		return errUsage
	}
	switch *role {
	case "edge":
		cfg, err := edge.Load(*path, getenv)
		if err != nil {
			return err
		}
		return runEdge(ctx, cfg, log.With("edge_id", cfg.EdgeID))
	case "secrets":
		cfg, err := edge.LoadSecrets(*path, getenv)
		if err != nil {
			return err
		}
		return edge.NewSecrets(cfg, edge.SecretsDeps{Log: log, Metrics: metrics.New()}).Run(ctx)
	case "sessions":
		cfg, err := edge.LoadSessions(*path, getenv)
		if err != nil {
			return err
		}
		return runSessions(ctx, cfg, log)
	}
	return errUsage
}

// runSessions serves the session page from its bundle, read once at start
func runSessions(ctx context.Context, cfg edge.SessionsConfig, log *slog.Logger) error {
	bundle, err := sessionsroute.LoadBundle(cfg.PageDir)
	if err != nil {
		return err
	}
	router := routerv1connect.NewSessionPageServiceClient(
		routerclient.New(cfg.RouterURL, cfg.Token), cfg.RouterURL)
	// Each live stream gets its own HTTP/1.1 connection, so one stalled reader stalls no other
	newCall := func() routerv1connect.SessionPageServiceClient {
		return routerv1connect.NewSessionPageServiceClient(
			routerclient.PerCall(cfg.RouterURL, cfg.Token), cfg.RouterURL)
	}
	route := sessionsroute.New(router, newCall, sessionsroute.Options{
		Origin:               "https://" + cfg.Host,
		Bundle:               bundle,
		MaxHeaderBytes:       int(cfg.MaxHeaderBytes),
		RequestsPerMinute:    cfg.RequestsPerMinute,
		KeyFailuresPerMinute: cfg.KeyFailuresPerMinute,
		IDFailuresPerMinute:  cfg.IDFailuresPerMinute,
		LivePerRecord:        cfg.LivePerRecord,
		LivePerIP:            cfg.LivePerIP,
		LiveMax:              cfg.LiveMax,
		Log:                  log.With("role", "sessions"),
	})
	// Live streams end at the stop signal rather than hold the drain, and the page resumes them
	context.AfterFunc(ctx, route.Close)
	defer route.Close()
	return edge.NewSessions(cfg, edge.SessionsDeps{Route: route, Log: log, Metrics: metrics.New()}).
		Run(ctx)
}

// runEdge serves the edge role with one set of traffic pieces, kept running through the drain
func runEdge(ctx context.Context, cfg edge.Config, log *slog.Logger) error {
	router := routerv1connect.NewEdgeServiceClient(
		routerclient.New(cfg.RouterURL, cfg.Token), cfg.RouterURL)
	// Each transfer stream gets its own HTTP/1.1 connection, so one stalled stalls no other
	newCall := func() routerv1connect.EdgeServiceClient {
		return routerv1connect.NewEdgeServiceClient(
			routerclient.PerCall(cfg.RouterURL, cfg.Token), cfg.RouterURL)
	}
	tr := traffic.Edge(router, traffic.Settings{
		ReporterID:          cfg.EdgeID,
		ReportInterval:      time.Duration(cfg.Usage.ReportInterval),
		ReportBytes:         int64(cfg.Usage.ReportBytes),
		TotalBytesPerSecond: int64(cfg.TotalBytesPerSecond),
	}, log)
	t := cfg.Transfers
	guard := strangers.NewGuard(t.TokenFailuresPerMinute, strangers.Mark, strangers.Unknown)
	xfer := transfer.New(router, newCall, transfer.Deps{
		EdgeID:      cfg.EdgeID,
		Traffic:     tr,
		Guard:       guard,
		Conns:       strangers.NewConns(t.MaxConnectionsPerIP),
		Chunk:       int(t.Chunk),
		IdleTimeout: time.Duration(t.IdleTimeout),
		Log:         log,
	})

	// Transfers still draining keep counting, so the traffic pieces stop only after the server
	tctx, stopTraffic := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Run(tctx)
	}()
	err := edge.New(cfg, edge.Deps{
		Transfer: xfer,
		Landing:  pages.Landing(cfg.Previews.AbuseContact),
		Log:      log,
		Metrics:  metrics.New(),
	}).Run(ctx)
	stopTraffic()
	<-done
	return err
}
