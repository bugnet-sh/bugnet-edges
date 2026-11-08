// Command bugnet-egress serves the secret proxy, and makes its CA and sealing keys
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1/routerv1connect"

	"github.com/bugnet-sh/bugnet-edges/internal/egress"
	"github.com/bugnet-sh/bugnet-edges/internal/routerclient"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// A second signal during the drain kills the process at once
	context.AfterFunc(ctx, stop)
	if err := run(ctx, log, os.Args[1:], os.LookupEnv, os.Stdout); err != nil {
		log.Error("bugnet-egress failed", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: bugnet-egress serve -config FILE | ca init --out DIR | " +
	"box-key new --id ID --out DIR")

func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
	stdout io.Writer,
) error {
	switch {
	case len(args) >= 1 && args[0] == "serve":
		return serve(ctx, log, args[1:], getenv)
	case len(args) >= 2 && args[0] == "ca" && args[1] == "init":
		return caInit(args[2:], stdout)
	case len(args) >= 2 && args[0] == "box-key" && args[1] == "new":
		return boxKeyNew(args[2:], stdout)
	}
	return errUsage
}

func flags(name string, args []string, set func(*flag.FlagSet)) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	set(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errUsage
	}
	return nil
}

func serve(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) error {
	var path string
	if err := flags("serve", args, func(fs *flag.FlagSet) {
		fs.StringVar(&path, "config", "", "settings file")
	}); err != nil || path == "" {
		return errUsage
	}
	cfg, err := egress.Load(path, getenv)
	if err != nil {
		return err
	}
	// A core file would hold decrypted values
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return fmt.Errorf("no core files: %w", err)
	}
	minter, keys, err := cfg.LoadSecrets(getenv)
	if err != nil {
		return err
	}
	router := routerv1connect.NewEgressServiceClient(
		routerclient.New(cfg.RouterURL, cfg.Token), cfg.RouterURL)
	events := x402.NewEvents(x402.EventsSend(router), time.Duration(cfg.X402.EventFlushInterval),
		time.Now, log)
	counters := x402.NewCounters()
	srv := egress.New(cfg, egress.Deps{
		Router: router, Keys: keys, Minter: minter, Log: log, Events: events, Counters: counters,
		HostRate: x402.NewHostRate(cfg.CustomHostRequestsPerMinute,
			cfg.X402.HostRateFloorPerPlacement, time.Now),
	})
	events.SetServices(srv.HasX402)
	var side sync.WaitGroup
	side.Add(2)
	go func() {
		defer side.Done()
		events.Run(ctx)
	}()
	go func() {
		defer side.Done()
		counters.RunReports(ctx, x402.UnpaidSend(router, egress.ReporterID),
			time.Duration(cfg.UsageReportInterval))
	}()
	err = srv.Run(ctx)
	side.Wait()
	return err
}

// caInit writes egress-ca.key and egress-ca.pem into the directory
func caInit(args []string, stdout io.Writer) error {
	var out string
	if err := flags("ca init", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "directory for egress-ca.key and egress-ca.pem")
	}); err != nil || out == "" {
		return errUsage
	}
	if err := egress.InitCA(out, time.Now()); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "wrote %s and %s in %s\n", egress.CAKeyFile,
		egress.CACertFile, out)
	return err
}

// boxKeyNew writes a sealing key and prints its id and public half, the one time it is shown
func boxKeyNew(args []string, stdout io.Writer) error {
	var id, out string
	if err := flags("box-key new", args, func(fs *flag.FlagSet) {
		fs.StringVar(&id, "id", "", "key id")
		fs.StringVar(&out, "out", "", "directory for the key file")
	}); err != nil || id == "" || out == "" {
		return errUsage
	}
	pub, err := egress.NewBoxKey(out, id)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "id: %s\npublic_key: %s\n", id,
		base64.StdEncoding.EncodeToString(pub[:]))
	return err
}
