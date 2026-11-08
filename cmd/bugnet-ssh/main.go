// Command bugnet-ssh serves the SSH gateway, which relays users to their sandboxes' sshd
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/proxyproto"
	"github.com/bugnet-sh/bugnet-edges/internal/reuseport"
	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
	"github.com/bugnet-sh/bugnet-edges/internal/sshgw"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// A second signal during the drain kills the process at once
	context.AfterFunc(ctx, stop)
	if err := run(ctx, log, os.Args[1:], os.LookupEnv); err != nil {
		log.Error("bugnet-ssh failed", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: bugnet-ssh -config FILE")

func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) error {
	fs := flag.NewFlagSet("bugnet-ssh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" {
		return errUsage
	}
	cfg, err := sshgw.Load(*path, getenv)
	if err != nil {
		return err
	}
	dir, _ := getenv("CREDENTIALS_DIRECTORY")
	if cfg.HostKeys, err = sshgw.LoadHostKeys(dir, cfg.HostKeyCredentials); err != nil {
		return err
	}
	cfg.Log, cfg.Metrics = log, metrics.New()
	router := routerv1connect.NewSshGatewayServiceClient(
		routerclient.New(cfg.RouterURL, cfg.Token), cfg.RouterURL)

	ln, err := proxyproto.Listen(cfg.ListenAddr, cfg.ProxyProtocolFrom)
	if err != nil {
		return err
	}
	mln, err := reuseport.Listen(cfg.MetricsListenAddr)
	if err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	mux.HandleFunc("GET /healthz", ok)
	mux.HandleFunc("GET /readyz", ok)
	mux.Handle("GET /metrics", cfg.Metrics)
	ms := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = ms.Serve(mln) }()
	defer func() { _ = ms.Close() }()

	log.Info("bugnet-ssh serving", "listen", ln.Addr().String(), "gateway_id", cfg.GatewayID)
	return sshgw.New(cfg, router).Serve(ctx, ln)
}
