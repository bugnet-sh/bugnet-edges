// Command x402-fake-seller serves the fake x402 seller of XS 11.2 over TLS
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/fakeseller"
	"github.com/bugnet-sh/bugnet-edges/internal/hostname"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/tlsconf"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx, log, os.Args[1:], os.LookupEnv); err != nil {
		log.Error("x402-fake-seller failed", "err", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: x402-fake-seller -config FILE")

const (
	// readHeaderTimeout bounds a request's headers, and nothing bounds a body or an answer
	readHeaderTimeout = 10 * time.Second
	// shutdownGrace is how long a stop waits for answers in flight
	shutdownGrace = 5 * time.Second
	// acmeDirectory is Let's Encrypt's production directory
	acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

// envName is a name a settings file may give an environment variable
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// file is the seller's settings file
type file struct {
	Listen            string            `toml:"listen"`
	TLSCertFile       string            `toml:"tls_cert_file"`
	TLSKeyFile        string            `toml:"tls_key_file"`
	ACMEHosts         []string          `toml:"acme_hosts"`
	ACMEDir           string            `toml:"acme_dir"`
	PayTo             string            `toml:"pay_to"`
	PayToTokenAccount string            `toml:"pay_to_token_account"`
	FeePayer          string            `toml:"fee_payer"`
	BugnetFeePayer    string            `toml:"bugnet_fee_payer"`
	Settle            string            `toml:"settle"`
	ChainURL          string            `toml:"chain_url"`
	FacilitatorURL    string            `toml:"facilitator_url"`
	FeePayerKeyEnv    string            `toml:"fee_payer_key_env"`
	TestTokenEnv      string            `toml:"test_token_env"`
	Late              settings.Duration `toml:"late"`
	Slow              settings.Duration `toml:"slow"`
	Stall             settings.Duration `toml:"stall"`
	RedirectTo        string            `toml:"redirect_to"`
}

// defaults is every setting at its default, with no address, which each run sets
func defaults() file {
	return file{
		Listen:         "127.0.0.1:8403",
		ACMEHosts:      []string{},
		Settle:         "self",
		FeePayerKeyEnv: "TESTSELLER_FEE_PAYER_KEY",
		TestTokenEnv:   "TESTSELLER_TEST_TOKEN",
		Late:           settings.Duration(20 * time.Second),
		Slow:           settings.Duration(120 * time.Second),
		Stall:          settings.Duration(40 * time.Second),
		RedirectTo:     "https://example.com/",
	}
}

// seller is a checked settings file with its TLS and its seller ready to serve
type seller struct {
	listen string
	tls    *tls.Config
	config fakeseller.Config
}

// load reads and checks the settings file at path, taking the fee payer's key from getenv
func load(path string, getenv func(string) (string, bool)) (*seller, error) {
	f := defaults()
	if err := settings.Load(path, &f); err != nil {
		return nil, err
	}
	if err := f.check(); err != nil {
		return nil, fmt.Errorf("x402-fake-seller: %s: %w", path, err)
	}
	tlsConfig, err := f.tlsConfig()
	if err != nil {
		return nil, fmt.Errorf("x402-fake-seller: %s: %w", path, err)
	}
	settler, err := f.settler(getenv)
	if err != nil {
		return nil, fmt.Errorf("x402-fake-seller: %w", err)
	}
	token, _ := getenv(f.TestTokenEnv)
	return &seller{
		listen: f.Listen,
		tls:    tlsConfig,
		config: fakeseller.Config{
			PayTo: f.PayTo, PayToTokenAccount: f.PayToTokenAccount,
			FeePayer: f.FeePayer, BugnetFeePayer: f.BugnetFeePayer, Settler: settler,
			Late: time.Duration(f.Late), Slow: time.Duration(f.Slow),
			Stall: time.Duration(f.Stall), TestToken: token, RedirectTo: f.RedirectTo,
		},
	}, nil
}

// check refuses a setting out of its range, naming it and never its value
func (f *file) check() error {
	if host, port, err := net.SplitHostPort(f.Listen); err != nil || host == "" ||
		!numeric(port) {
		return errors.New("listen must be host:port")
	}
	files := f.TLSCertFile != "" || f.TLSKeyFile != ""
	acme := len(f.ACMEHosts) > 0
	switch {
	case files == acme:
		return errors.New("set tls_cert_file and tls_key_file, or acme_hosts and acme_dir")
	case files && (f.TLSCertFile == "" || f.TLSKeyFile == ""):
		return errors.New("tls_cert_file and tls_key_file go together")
	case acme && !filepath.IsAbs(f.ACMEDir):
		return errors.New("acme_dir must be an absolute path")
	}
	for i, h := range f.ACMEHosts {
		if !hostname.Valid(h) || slices.Contains(f.ACMEHosts[:i], h) {
			return errors.New("acme_hosts must be distinct lowercase host names")
		}
	}
	for _, a := range []named[string]{
		{"pay_to", f.PayTo}, {"fee_payer", f.FeePayer}, {"bugnet_fee_payer", f.BugnetFeePayer},
	} {
		if !address(a.value) {
			return fmt.Errorf("%s must be base58 of 32 bytes", a.name)
		}
	}
	switch f.Settle {
	case "self":
		if !address(f.PayToTokenAccount) {
			return errors.New("pay_to_token_account must be base58 of 32 bytes to settle itself")
		}
		if !webURL(f.ChainURL) {
			return errors.New("chain_url must be an http or https URL with a host")
		}
	case "facilitator":
		if !webURL(f.FacilitatorURL) {
			return errors.New("facilitator_url must be an http or https URL with a host")
		}
	default:
		return errors.New(`settle must be "self" or "facilitator"`)
	}
	for _, e := range []named[string]{
		{"fee_payer_key_env", f.FeePayerKeyEnv}, {"test_token_env", f.TestTokenEnv},
	} {
		if !envName.MatchString(e.value) {
			return fmt.Errorf("%s must be an environment variable name", e.name)
		}
	}
	for _, d := range []named[settings.Duration]{
		{"late", f.Late}, {"slow", f.Slow}, {"stall", f.Stall},
	} {
		if d.value <= 0 {
			return fmt.Errorf("%s must be above 0", d.name)
		}
	}
	if !webURL(f.RedirectTo) {
		return errors.New("redirect_to must be an http or https URL with a host")
	}
	return nil
}

// named is a setting's value with its key
type named[T any] struct {
	name  string
	value T
}

// numeric says whether s is a port number
func numeric(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 65535 && strconv.Itoa(n) == s
}

// address says whether s is base58 of 32 bytes, judged by decoding it
func address(s string) bool {
	b, ok := x402.Decode58(s)
	return ok && len(b) == 32
}

// webURL says whether s is an absolute http or https URL with a host
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

// tlsConfig serves the pair in the files, or the ACME names by TLS-ALPN-01
func (f *file) tlsConfig() (*tls.Config, error) {
	alpn := []string{"h2", "http/1.1"}
	if f.TLSCertFile != "" {
		pair, err := tls.LoadX509KeyPair(f.TLSCertFile, f.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls_cert_file and tls_key_file: %w", err)
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, NextProtos: alpn,
		}, nil
	}
	if err := os.MkdirAll(f.ACMEDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme_dir: %w", err)
	}
	names := make([]tlsconf.Name, 0, len(f.ACMEHosts))
	for _, h := range f.ACMEHosts {
		names = append(names, tlsconf.Name{Host: h, ALPN: alpn})
	}
	return tlsconf.New(tlsconf.Options{
		Names: names,
		ACME:  tlsconf.ACME{Enabled: true, Directory: acmeDirectory, StateDir: f.ACMEDir},
	})
}

// settler settles to the chain with the fee payer's key, or to the facilitator with none
func (f *file) settler(getenv func(string) (string, bool)) (fakeseller.Settler, error) {
	if f.Settle == "facilitator" {
		return fakeseller.Facilitator(f.FacilitatorURL), nil
	}
	name := f.FeePayerKeyEnv
	value, ok := getenv(name)
	if !ok || value == "" {
		return nil, fmt.Errorf("fee_payer_key_env names %s, which is not set", name)
	}
	key, ok := parseKey(value)
	if !ok {
		return nil, fmt.Errorf("%s holds no Ed25519 key of 64 bytes, base58 or a JSON array", name)
	}
	if x402.Encode58(key.Public().(ed25519.PublicKey)) != f.FeePayer {
		return nil, fmt.Errorf("the key in %s is not fee_payer's", name)
	}
	return fakeseller.SelfSettle(f.ChainURL, key, f.PayToTokenAccount), nil
}

// parseKey reads a Solana key as Payments writes one, 64 bytes whose second half is the public key
func parseKey(value string) (ed25519.PrivateKey, bool) {
	value = strings.TrimSpace(value)
	var b []byte
	if strings.HasPrefix(value, "[") {
		var ints []int
		if json.Unmarshal([]byte(value), &ints) != nil {
			return nil, false
		}
		for _, n := range ints {
			if n < 0 || n > 255 {
				return nil, false
			}
			b = append(b, byte(n))
		}
	} else {
		var ok bool
		if b, ok = x402.Decode58(value); !ok {
			return nil, false
		}
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, false
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !key.Equal(ed25519.PrivateKey(b)) {
		return nil, false
	}
	return key, true
}

// newServer is the seller's HTTP server, which never cuts a slow body or a long answer
func newServer(s *seller, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           fakeseller.New(s.config),
		TLSConfig:         s.tls,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// serve answers on ln until ctx ends, then lets answers in flight finish for a short grace
func serve(ctx context.Context, s *seller, ln net.Listener, log *slog.Logger) error {
	srv := newServer(s, log)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		grace, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if srv.Shutdown(grace) != nil {
			_ = srv.Close()
		}
	}()
	log.Info("x402-fake-seller serving", "addr", ln.Addr().String(),
		"test_api", s.config.TestToken != "")
	err := srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}

// run is the whole command
func run(
	ctx context.Context, log *slog.Logger, args []string, getenv func(string) (string, bool),
) error {
	fs := flag.NewFlagSet("x402-fake-seller", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "settings file")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *path == "" {
		return errUsage
	}
	s, err := load(*path, getenv)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("x402-fake-seller: listen: %w", err)
	}
	return serve(ctx, s, ln, log)
}
