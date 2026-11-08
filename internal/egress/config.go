package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/hostname"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/x402"
)

const letsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// KeyRef names a key file under $CREDENTIALS_DIRECTORY
type KeyRef struct {
	ID         string `toml:"id"`
	Credential string `toml:"credential"`
}

// OldCA is a CA kept after a rotation, trusted by the sandboxes that started under it
type OldCA struct {
	Version    uint32 `toml:"version"`
	Credential string `toml:"credential"`
	CertFile   string `toml:"cert_file"`
}

// Config is bugnet-egress' settings file (DP 10.8) and its two secrets
type Config struct {
	RouterURL         string         `toml:"router_url"`
	ListenAddr        string         `toml:"listen_addr"`
	MetricsListenAddr string         `toml:"metrics_listen_addr"`
	ProxyProtocolFrom []netip.Prefix `toml:"proxy_protocol_from"`
	EgressHost        string         `toml:"egress_host"`
	ACMEEnabled       bool           `toml:"acme_enabled"`
	ACMEDirectory     string         `toml:"acme_directory"`
	ACMEDir           string         `toml:"acme_dir"`
	ACMEEmail         string         `toml:"acme_email"`
	StaticDir         string         `toml:"static_dir"`
	CACredential      string         `toml:"ca_credential"`
	CACertFile        string         `toml:"ca_cert_file"`
	CAVersion         uint32         `toml:"ca_version"`
	OldCAs            []OldCA        `toml:"old_cas"`
	BoxKeys           []KeyRef       `toml:"box_keys"`
	Resolvers         []string       `toml:"resolvers"`
	RefusedHosts      []string       `toml:"refused_hosts"`

	MaxTunnelsPerPlacement      int               `toml:"max_tunnels_per_placement"`
	MaxStreamsPerTunnel         int               `toml:"max_streams_per_tunnel"`
	TunnelIdleTimeout           settings.Duration `toml:"tunnel_idle_timeout"`
	HandshakeTimeout            settings.Duration `toml:"handshake_timeout"`
	TokenFailuresPerMinute      int               `toml:"token_failures_per_minute"`
	FetchSources                []netip.Prefix    `toml:"fetch_sources"`
	CustomHostRequestsPerMinute int               `toml:"custom_host_requests_per_minute"`
	TotalBytesPerSecond         settings.Bytes    `toml:"total_bytes_per_second"`
	ResolveCache                settings.Duration `toml:"resolve_cache"`
	UsageReportInterval         settings.Duration `toml:"usage_report_interval"`

	X402 x402.Settings `toml:"x402"`

	// localrunSettings is empty except in a localrun build
	localrunSettings

	Token      string `toml:"-"` // BUGNET_EGRESS_TOKEN
	FetchToken string `toml:"-"` // BUGNET_EGRESS_FETCH_TOKEN, empty turns the fetcher's entry off
}

func loopback() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
}

// Defaults is every setting at its default, with no egress host, which each deployment sets
func Defaults() Config {
	return Config{
		RouterURL:         "http://127.0.0.1:8080",
		ListenAddr:        "127.0.0.1:9443",
		MetricsListenAddr: "127.0.0.1:9103",
		ProxyProtocolFrom: loopback(),
		ACMEEnabled:       true,
		ACMEDirectory:     letsEncrypt,
		ACMEDir:           "/var/lib/bugnet-egress/acme",
		CACredential:      "egress_ca_key",
		CACertFile:        "/etc/bugnet/egress-ca.pem",
		CAVersion:         1,
		BoxKeys:           []KeyRef{{ID: "k1", Credential: "egress_box_k1"}},
		Resolvers:         []string{"1.1.1.1:53", "8.8.8.8:53"},
		RefusedHosts: []string{"bugnet.sh", "e2b.app", "e2b.dev", "e2b-juliett.dev", "boxd.sh",
			"koyeb.app", "boat.dev", "ascii.dev"},
		MaxTunnelsPerPlacement:      64,
		MaxStreamsPerTunnel:         32,
		TunnelIdleTimeout:           settings.Duration(5 * time.Minute),
		HandshakeTimeout:            settings.Duration(10 * time.Second),
		TokenFailuresPerMinute:      20,
		FetchSources:                loopback(),
		CustomHostRequestsPerMinute: 600,
		TotalBytesPerSecond:         16 << 20,
		ResolveCache:                settings.Duration(30 * time.Second),
		UsageReportInterval:         settings.Duration(5 * time.Second),
		X402:                        x402.Defaults(),
	}
}

// Load reads the settings file at path over the defaults, then the two secrets from getenv
func Load(path string, getenv func(string) (string, bool)) (Config, error) {
	c := Defaults()
	if err := settings.Load(path, &c); err != nil {
		return Config{}, fmt.Errorf("egress: %w", err)
	}
	if err := c.check(); err != nil {
		return Config{}, fmt.Errorf("egress: %s: %w", path, err)
	}
	token, _ := getenv("BUGNET_EGRESS_TOKEN")
	if !validToken(token) {
		return Config{}, errors.New("egress: BUGNET_EGRESS_TOKEN must be at least 32 characters " +
			"with no spaces or control characters")
	}
	c.Token = token
	fetch, _ := getenv("BUGNET_EGRESS_FETCH_TOKEN")
	if fetch != "" && !validToken(fetch) {
		return Config{}, errors.New("egress: BUGNET_EGRESS_FETCH_TOKEN must be empty or at least " +
			"32 characters with no spaces or control characters")
	}
	c.FetchToken = fetch
	return c, nil
}

// validToken says whether v is at least 32 printable characters with no spaces
func validToken(v string) bool {
	bad := func(r rune) bool { return r <= ' ' || r > '~' }
	return len(v) >= 32 && !strings.ContainsFunc(v, bad)
}

func (c *Config) check() error {
	atLeast := func(key string, v, least int) error {
		if v < least {
			return fmt.Errorf("%s must be %d or more", key, least)
		}
		return nil
	}
	checks := []func() error{
		c.checkX402,
		func() error { return checkURL("router_url", c.RouterURL) },
		func() error { return checkAddr("listen_addr", c.ListenAddr) },
		func() error { return checkAddr("metrics_listen_addr", c.MetricsListenAddr) },
		func() error { return checkPrefixes("proxy_protocol_from", c.ProxyProtocolFrom, 1) },
		func() error { return checkPrefixes("fetch_sources", c.FetchSources, 0) },
		func() error {
			if c.EgressHost == "" || !hostname.Valid(c.EgressHost) {
				return errors.New("egress_host must be a lowercase host name such as " +
					"egress.example.com")
			}
			return nil
		},
		c.checkCerts,
		c.checkKeys,
		func() error {
			if len(c.Resolvers) == 0 {
				return errors.New("resolvers needs at least one host and port")
			}
			for _, r := range c.Resolvers {
				if err := checkAddr("resolvers", r); err != nil {
					return err
				}
			}
			for _, h := range c.RefusedHosts {
				if !hostname.Valid(h) {
					return errors.New("refused_hosts holds a name that is not a host name")
				}
			}
			return nil
		},
		func() error { return atLeast("max_tunnels_per_placement", c.MaxTunnelsPerPlacement, 1) },
		func() error { return atLeast("max_streams_per_tunnel", c.MaxStreamsPerTunnel, 1) },
		func() error { return atLeast("token_failures_per_minute", c.TokenFailuresPerMinute, 0) },
		func() error {
			return atLeast("custom_host_requests_per_minute", c.CustomHostRequestsPerMinute, 1)
		},
		func() error {
			for k, d := range map[string]settings.Duration{
				"tunnel_idle_timeout": c.TunnelIdleTimeout, "handshake_timeout": c.HandshakeTimeout,
				"resolve_cache": c.ResolveCache, "usage_report_interval": c.UsageReportInterval,
			} {
				if d <= 0 {
					return fmt.Errorf("%s must be more than 0", k)
				}
			}
			return nil
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkX402 holds the bounds of [x402] and the one that needs a top-level key too
func (c *Config) checkX402() error {
	if err := c.X402.Check(); err != nil {
		return err
	}
	if c.CustomHostRequestsPerMinute >= 1 &&
		c.X402.HostRateFloorPerPlacement > c.CustomHostRequestsPerMinute {
		return fmt.Errorf("x402.host_rate_floor_per_placement (%d) must be at most "+
			"custom_host_requests_per_minute (%d)", c.X402.HostRateFloorPerPlacement,
			c.CustomHostRequestsPerMinute)
	}
	return nil
}

func (c *Config) checkCerts() error {
	if c.CAVersion == 0 {
		return errors.New("ca_version must be 1 or more")
	}
	if c.CACredential == "" || c.CACertFile == "" {
		return errors.New("ca_credential and ca_cert_file are required")
	}
	seen := map[uint32]bool{c.CAVersion: true}
	for _, o := range c.OldCAs {
		if o.Version == 0 || seen[o.Version] || o.Credential == "" || o.CertFile == "" {
			return errors.New("old_cas needs a version, credential and cert_file each, and a " +
				"version of its own")
		}
		seen[o.Version] = true
	}
	if !c.ACMEEnabled {
		return checkDir("static_dir", c.StaticDir)
	}
	if err := checkURL("acme_directory", c.ACMEDirectory); err != nil {
		return err
	}
	return checkDir("acme_dir", c.ACMEDir)
}

func (c *Config) checkKeys() error {
	if len(c.BoxKeys) == 0 {
		return errors.New("box_keys needs at least one key")
	}
	seen := map[string]bool{}
	for _, k := range c.BoxKeys {
		if !validKeyID(k.ID) || k.Credential == "" || seen[k.ID] {
			return errors.New("box_keys needs an id and a credential each, and an id of its own")
		}
		seen[k.ID] = true
	}
	return nil
}

func checkURL(key, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must be an http or https URL with a host", key)
	}
	return nil
}

func checkAddr(key, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil || host == "" || strings.ContainsAny(host, " /") {
		return fmt.Errorf("%s must be a host and port such as 127.0.0.1:9443", key)
	}
	return nil
}

func checkPrefixes(key string, p []netip.Prefix, least int) error {
	if len(p) < least {
		return fmt.Errorf("%s needs at least one prefix, such as 127.0.0.1/32", key)
	}
	return nil
}

func checkDir(key, dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("%s must be an absolute path", key)
	}
	return nil
}

// credential reads the file name holds under $CREDENTIALS_DIRECTORY
func credential(getenv func(string) (string, bool), name string) ([]byte, error) {
	dir, _ := getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return nil, errors.New("egress: CREDENTIALS_DIRECTORY is not set")
	}
	if name != filepath.Base(name) {
		return nil, errors.New("egress: a credential name has no path in it")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("egress: credential %s: %w", name, err)
	}
	return b, nil
}

// LoadSecrets reads the CA and the box keys the config names, apart from the settings file
func (c Config) LoadSecrets(getenv func(string) (string, bool)) (*Minter, *Keys, error) {
	var cas []*CA
	read := func(version uint32, credName, certFile string) error {
		keyPEM, err := credential(getenv, credName)
		if err != nil {
			return err
		}
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		ca, err := LoadCA(version, certPEM, keyPEM)
		if err != nil {
			return err
		}
		cas = append(cas, ca)
		return nil
	}
	if err := read(c.CAVersion, c.CACredential, c.CACertFile); err != nil {
		return nil, nil, err
	}
	for _, o := range c.OldCAs {
		if err := read(o.Version, o.Credential, o.CertFile); err != nil {
			return nil, nil, err
		}
	}
	m, err := NewMinter(time.Now, cas...)
	if err != nil {
		return nil, nil, err
	}
	var keys []BoxKey
	for _, k := range c.BoxKeys {
		raw, err := credential(getenv, k.Credential)
		if err != nil {
			return nil, nil, err
		}
		bk, err := ParseBoxKey(k.ID, raw)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, bk)
	}
	return m, NewKeys(keys...), nil
}
