package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/fakeseller"
	edgesettings "github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

const (
	// readHeaderTimeout bounds a request's headers, and nothing bounds a body or an answer
	readHeaderTimeout = 10 * time.Second
	// pingTimeout is the HTTP/2 ping interval while a response is silent, when keepalive is on
	pingTimeout = 20 * time.Second
	// shutdownGrace is how long a stop waits for answers in flight
	shutdownGrace = 5 * time.Second
	// feePayerKey and authKeyName are the names the two secret files hold
	feePayerKey = "TESTSELLER_FEE_PAYER_KEY"
	authKeyName = "TS_AUTHKEY"
)

// label is a node name, one DNS label
var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// nodeSettings is one Funnel node
type nodeSettings struct {
	Name     string `toml:"name"`
	StateDir string `toml:"state_dir"`
}

// settings is the seller's settings file, public addresses and paths only
type settings struct {
	Nodes             []nodeSettings `toml:"node"`
	EnvFile           string         `toml:"env_file"`
	TailscaleEnvFile  string         `toml:"tailscale_env_file"`
	PayTo             string         `toml:"pay_to"`
	PayToTokenAccount string         `toml:"pay_to_token_account"`
	FeePayer          string         `toml:"fee_payer"`
	BugnetFeePayer    string         `toml:"bugnet_fee_payer"`
	FacilitatorCmd    []string       `toml:"facilitator_cmd"`
	FacilitatorAddr   string         `toml:"facilitator_addr"`
	RPCURL            string         `toml:"rpc_url"`
	KeepalivePings    bool           `toml:"keepalive_pings"`
	CheckSSH          string         `toml:"check_ssh"`

	// dir is the settings file's directory, where facilitator_cmd runs
	dir string
	// testToken opens the seller's test API when not empty
	testToken string
}

// defaults is every setting at its default
func defaults() settings {
	return settings{
		EnvFile:          "~/.config/bugnet/testseller.env",
		TailscaleEnvFile: "~/.config/bugnet/tailscale.env",
		FacilitatorCmd:   []string{"node", "facilitator/server.mjs"},
		FacilitatorAddr:  "127.0.0.1:8402",
	}
}

// loadSettings reads and checks the settings file at path, with its paths expanded
func loadSettings(path, home string) (settings, error) {
	s := defaults()
	if err := edgesettings.Load(path, &s); err != nil {
		return settings{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return settings{}, err
	}
	s.dir = filepath.Dir(abs)
	if err := s.check(); err != nil {
		return settings{}, fmt.Errorf("x402-test-seller: %s: %w", path, err)
	}
	s.EnvFile = expand(home, s.EnvFile)
	s.TailscaleEnvFile = expand(home, s.TailscaleEnvFile)
	for i := range s.Nodes {
		if s.Nodes[i].StateDir == "" {
			s.Nodes[i].StateDir = "~/.local/share/bugnet/tsnet/" + s.Nodes[i].Name
		}
		s.Nodes[i].StateDir = expand(home, s.Nodes[i].StateDir)
	}
	return s, nil
}

// check refuses a setting out of its range, naming it and never its value
func (s *settings) check() error {
	if len(s.Nodes) == 0 {
		return errors.New("at least one [[node]] is needed")
	}
	for i, n := range s.Nodes {
		same := func(o nodeSettings) bool { return o.Name == n.Name }
		dup := slices.ContainsFunc(s.Nodes[:i], same)
		if !label.MatchString(n.Name) || dup {
			return errors.New("node names must be distinct lowercase DNS labels")
		}
	}
	for _, a := range []struct{ name, value string }{
		{"pay_to", s.PayTo}, {"pay_to_token_account", s.PayToTokenAccount},
		{"fee_payer", s.FeePayer}, {"bugnet_fee_payer", s.BugnetFeePayer},
	} {
		if b, ok := x402.Decode58(a.value); !ok || len(b) != 32 {
			return fmt.Errorf("%s must be base58 of 32 bytes", a.name)
		}
	}
	if len(s.FacilitatorCmd) == 0 || s.FacilitatorCmd[0] == "" {
		return errors.New("facilitator_cmd must name a command")
	}
	if ap, err := netip.ParseAddrPort(s.FacilitatorAddr); err != nil || !ap.Addr().IsLoopback() {
		return errors.New("facilitator_addr must be a loopback ip:port")
	}
	u, err := url.Parse(s.RPCURL)
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" ||
		u.Path != "" && u.Path != "/" {
		return errors.New("rpc_url must be an https URL with a host and no key in it")
	}
	return nil
}

// expand turns a leading ~/ into the home directory
func expand(home, p string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// onlyNode keeps the one node whose name ends in -which, for a process that runs one node
func (s *settings) onlyNode(which string) error {
	if which == "" {
		return nil
	}
	for _, n := range s.Nodes {
		if strings.HasSuffix(n.Name, "-"+which) {
			s.Nodes = []nodeSettings{n}
			return nil
		}
	}
	return fmt.Errorf("-only %s matches no node", which)
}

// stateDir makes dir 0700 when missing and refuses one that group or others can read
func stateDir(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return fmt.Errorf("state_dir %s: %w", dir, err)
	case !info.IsDir():
		return fmt.Errorf("state_dir %s is not a directory", dir)
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("state_dir %s must not be readable by group or others", dir)
	}
	return nil
}

// newServer is a node's HTTP server, which never cuts a slow body or a long answer
func newServer(h http.Handler, keepalive bool) *http.Server {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	if keepalive {
		srv.HTTP2 = &http.HTTP2Config{SendPingTimeout: pingTimeout}
	}
	return srv
}

// served is one node with its server
type served struct {
	n   node
	srv *http.Server
}

// stop lets answers in flight finish for a short grace, then leaves the tailnet
func (v *served) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if v.srv.Shutdown(ctx) != nil {
		_ = v.srv.Close()
	}
	_ = v.n.close()
}

// run serves the seller on every node until ctx ends, then stops the facilitator
func run(ctx context.Context, s settings, start newNode, out io.Writer) error {
	authKey, err := secretFile(s.TailscaleEnvFile, authKeyName)
	if err != nil {
		return err
	}
	feeKey, err := secretFile(s.EnvFile, feePayerKey)
	if err != nil {
		return err
	}
	for _, n := range s.Nodes {
		if err := stateDir(n.StateDir); err != nil {
			return err
		}
	}
	fac, err := startFacilitator(ctx, s, feeKey)
	if err != nil {
		return err
	}
	defer fac.stop()
	handler := fakeseller.New(fakeseller.Config{
		PayTo: s.PayTo, PayToTokenAccount: s.PayToTokenAccount,
		FeePayer: s.FeePayer, BugnetFeePayer: s.BugnetFeePayer,
		Settler:   fakeseller.Facilitator("http://" + s.FacilitatorAddr),
		TestToken: s.testToken,
	})
	var protos []string
	if s.KeepalivePings {
		protos = []string{"h2", "http/1.1"}
	}
	failed := make(chan error, len(s.Nodes))
	var live []*served
	defer func() {
		for _, v := range live {
			v.stop()
		}
	}()
	for _, cfg := range s.Nodes {
		v, err := serveNode(ctx, s, cfg, authKey, start, handler, protos, failed)
		if err != nil {
			return err
		}
		live = append(live, v)
		_, _ = fmt.Fprintln(out, "https://"+v.n.name())
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	case <-fac.exited:
		return errors.New("the facilitator exited")
	}
}

// serveNode starts one node, checks its name and serves the handler on its Funnel listener
func serveNode(
	ctx context.Context, s settings, cfg nodeSettings, authKey string, start newNode,
	h http.Handler, protos []string, failed chan<- error,
) (*served, error) {
	n, err := start(ctx, cfg.Name, cfg.StateDir, authKey)
	if err != nil {
		return nil, err
	}
	full := n.name()
	if first, _, _ := strings.Cut(full, "."); first != cfg.Name {
		_ = n.close()
		return nil, fmt.Errorf("node %s came up as %s, so %s does not hold its name",
			cfg.Name, full, cfg.StateDir)
	}
	ln, err := n.listenFunnel(protos)
	if err != nil {
		_ = n.close()
		return nil, err
	}
	v := &served{n: n, srv: newServer(h, s.KeepalivePings)}
	go func() {
		if err := v.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("node %s stopped serving: %w", cfg.Name, err)
		}
	}()
	return v, nil
}
