// Package edge serves bugnet-edge's listeners, host routing, pages and drain, for both roles
package edge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oynozan/bugnet-edges/internal/hostname"
	"github.com/oynozan/bugnet-edges/internal/settings"
)

// Config is bugnet-edge's settings file (DP 8.8) with the ACME switch, and its two secrets
type Config struct {
	RouterURL            string            `toml:"router_url"`
	EdgeID               string            `toml:"edge_id"`
	TLSListenAddr        string            `toml:"tls_listen_addr"`
	RedirectListenAddr   string            `toml:"redirect_listen_addr"`
	MetricsListenAddr    string            `toml:"metrics_listen_addr"`
	ProxyProtocolFrom    []netip.Prefix    `toml:"proxy_protocol_from"`
	Drain                settings.Duration `toml:"drain"`
	MaxConcurrentStreams int               `toml:"max_concurrent_streams"`
	TotalBytesPerSecond  settings.Bytes    `toml:"total_bytes_per_second"`
	Names                Names             `toml:"names"`
	Previews             Previews          `toml:"previews"`
	Transfers            Transfers         `toml:"transfers"`
	Hooks                Hooks             `toml:"hooks"`
	Usage                Usage             `toml:"usage"`
	ACME                 ACME              `toml:"acme"`

	Token          string `toml:"-"` // BUGNET_EDGE_TOKEN
	HookPathSecret string `toml:"-"` // BUGNET_HOOK_PATH_SECRET
}

// Names are the public host names the edge serves
type Names struct {
	PreviewDomain string `toml:"preview_domain"`
	TransferHost  string `toml:"transfer_host"`
	HooksHost     string `toml:"hooks_host"`
}

// Previews holds the preview route's limits and caches
type Previews struct {
	ResolveCache           int               `toml:"resolve_cache"`
	RouteTTL               settings.Duration `toml:"route_ttl"`
	TokenFailuresPerMinute int               `toml:"token_failures_per_minute"`
	QueueWait              settings.Duration `toml:"queue_wait"`
	QueueMax               int               `toml:"queue_max"`
	AbuseContact           string            `toml:"abuse_contact"`
	BoatRequestsPerMinute  int               `toml:"boat_requests_per_minute"`
}

// Transfers holds the transfer route's message size and limits
type Transfers struct {
	Chunk                  settings.Bytes    `toml:"chunk"`
	IdleTimeout            settings.Duration `toml:"idle_timeout"`
	TokenFailuresPerMinute int               `toml:"token_failures_per_minute"`
	MaxConnectionsPerIP    int               `toml:"max_connections_per_ip"`
}

// Hooks holds the hooks route's body cap and rate
type Hooks struct {
	MaxBody           settings.Bytes `toml:"max_body"`
	RequestsPerMinute int            `toml:"requests_per_minute"`
}

// Usage says how often byte counts go to the router
type Usage struct {
	ReportInterval settings.Duration `toml:"report_interval"`
	ReportBytes    settings.Bytes    `toml:"report_bytes"`
}

// ACME says where certificates come from, autocert and the wildcard pair, or one static pair
type ACME struct {
	Enabled     bool   `toml:"enabled"`
	Directory   string `toml:"directory"`
	Email       string `toml:"email"`
	StateDir    string `toml:"state_dir"`
	WildcardDir string `toml:"wildcard_dir"`
	StaticDir   string `toml:"static_dir"`
}

const letsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

func loopback() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
}

// Defaults is every edge setting at its default, with no names, which each deployment sets
func Defaults() Config {
	return Config{
		RouterURL:            "http://127.0.0.1:8080",
		TLSListenAddr:        "127.0.0.1:8443",
		RedirectListenAddr:   ":80",
		MetricsListenAddr:    "127.0.0.1:9101",
		ProxyProtocolFrom:    loopback(),
		Drain:                settings.Duration(5 * time.Minute),
		MaxConcurrentStreams: 128,
		TotalBytesPerSecond:  40 << 20,
		Previews: Previews{
			ResolveCache:           10000,
			RouteTTL:               settings.Duration(time.Minute),
			TokenFailuresPerMinute: 20,
			QueueWait:              settings.Duration(30 * time.Second),
			QueueMax:               256,
			BoatRequestsPerMinute:  5000,
		},
		Transfers: Transfers{
			Chunk:                  256 << 10,
			IdleTimeout:            settings.Duration(time.Minute),
			TokenFailuresPerMinute: 20,
			MaxConnectionsPerIP:    16,
		},
		Hooks: Hooks{MaxBody: 64 << 10, RequestsPerMinute: 60},
		Usage: Usage{ReportInterval: settings.Duration(5 * time.Second), ReportBytes: 8 << 20},
		ACME: ACME{
			Enabled:     true,
			Directory:   letsEncrypt,
			StateDir:    "/var/lib/bugnet-edge",
			WildcardDir: "/var/lib/bugnet-certs/preview",
		},
	}
}

// Load reads the settings file at path over the defaults, then the secrets from getenv
func Load(path string, getenv func(string) (string, bool)) (Config, error) {
	c := Defaults()
	if err := settings.Load(path, &c); err != nil {
		return Config{}, fmt.Errorf("edge: %w", err)
	}
	if err := c.check(); err != nil {
		return Config{}, fmt.Errorf("edge: %s: %w", path, err)
	}
	if c.EdgeID == "" {
		c.EdgeID = defaultEdgeID()
	}
	token, err := callerToken(getenv, "BUGNET_EDGE_TOKEN")
	if err != nil {
		return Config{}, fmt.Errorf("edge: %w", err)
	}
	secret, ok := getenv("BUGNET_HOOK_PATH_SECRET")
	if !ok || secret == "" {
		return Config{}, errors.New("edge: BUGNET_HOOK_PATH_SECRET is required")
	}
	if b, err := base64.RawURLEncoding.DecodeString(secret); err != nil || len(b) != 32 {
		return Config{}, errors.New("edge: BUGNET_HOOK_PATH_SECRET must be 32 bytes in " +
			"base64url without padding")
	}
	c.Token, c.HookPathSecret = token, secret
	return c, nil
}

// edgeID is the form an edge id takes in transfer claims and logs
var edgeID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// defaultEdgeID is host-pid, with anything an edge id cannot hold turned into a hyphen
func defaultEdgeID() string {
	host, _ := os.Hostname()
	host = strings.Map(func(r rune) rune {
		if r < 0x80 && edgeID.MatchString(string(r)) {
			return r
		}
		return '-'
	}, host)
	pid := "-" + strconv.Itoa(os.Getpid())
	if host == "" {
		host = "edge"
	}
	return host[:min(len(host), 64-len(pid))] + pid
}

func (c *Config) check() error {
	n := c.Names
	checks := []func() error{
		func() error { return checkURL("router_url", c.RouterURL) },
		func() error {
			if c.EdgeID != "" && !edgeID.MatchString(c.EdgeID) {
				return errors.New("edge_id must be 1 to 64 letters, digits, dots, " +
					"underscores or hyphens, or empty for host-pid")
			}
			return nil
		},
		func() error { return checkAddr("tls_listen_addr", c.TLSListenAddr) },
		func() error {
			if c.RedirectListenAddr != "" && checkAddr("", c.RedirectListenAddr) != nil {
				return errors.New("redirect_listen_addr must be empty or a host and port " +
					"such as :80")
			}
			return nil
		},
		func() error { return checkAddr("metrics_listen_addr", c.MetricsListenAddr) },
		func() error { return checkPrefixes(c.ProxyProtocolFrom) },
		func() error { return atMost("drain", c.Drain, time.Hour) },
		func() error {
			if c.MaxConcurrentStreams < 1 || c.MaxConcurrentStreams > 10000 {
				return errors.New("max_concurrent_streams must be 1 to 10000")
			}
			return nil
		},
		func() error { return checkHost("names.preview_domain", n.PreviewDomain) },
		func() error { return checkHost("names.transfer_host", n.TransferHost) },
		func() error { return checkHost("names.hooks_host", n.HooksHost) },
		func() error { return c.checkNamesApart() },
		c.Previews.check,
		c.Transfers.check,
		c.Hooks.check,
		func() error { return positive("usage.report_interval", c.Usage.ReportInterval) },
		c.ACME.check,
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkNamesApart keeps the exact names off each other and out of the preview wildcard
func (c *Config) checkNamesApart() error {
	n := c.Names
	for _, h := range []struct{ key, name string }{
		{"names.transfer_host", n.TransferHost}, {"names.hooks_host", n.HooksHost},
	} {
		if h.name == n.PreviewDomain {
			return fmt.Errorf("%s must differ from names.preview_domain", h.key)
		}
		label, ok := strings.CutSuffix(h.name, "."+n.PreviewDomain)
		if ok && !strings.Contains(label, ".") {
			return fmt.Errorf("%s must not be a preview name under names.preview_domain", h.key)
		}
	}
	if n.HooksHost == n.TransferHost {
		return errors.New("names.hooks_host must differ from names.transfer_host")
	}
	return nil
}

func (p Previews) check() error {
	switch {
	case p.ResolveCache < 1:
		return errors.New("previews.resolve_cache must be at least 1")
	case p.TokenFailuresPerMinute < 0:
		return errors.New("previews.token_failures_per_minute must be 0 or more")
	case p.QueueMax < 1:
		return errors.New("previews.queue_max must be at least 1")
	case p.BoatRequestsPerMinute < 0:
		return errors.New("previews.boat_requests_per_minute must be 0 or more")
	}
	if err := positive("previews.route_ttl", p.RouteTTL); err != nil {
		return err
	}
	if err := positive("previews.queue_wait", p.QueueWait); err != nil {
		return err
	}
	return checkContact("previews.abuse_contact", p.AbuseContact)
}

func (t Transfers) check() error {
	switch {
	case t.Chunk < 4<<10 || t.Chunk > 4<<20:
		return errors.New("transfers.chunk must be 4KiB to 4MiB")
	case t.TokenFailuresPerMinute < 0:
		return errors.New("transfers.token_failures_per_minute must be 0 or more")
	case t.MaxConnectionsPerIP < 1:
		return errors.New("transfers.max_connections_per_ip must be at least 1")
	}
	return positive("transfers.idle_timeout", t.IdleTimeout)
}

func (h Hooks) check() error {
	switch {
	case h.MaxBody < 1<<10 || h.MaxBody > 1<<20:
		return errors.New("hooks.max_body must be 1KiB to 1MiB")
	case h.RequestsPerMinute < 0:
		return errors.New("hooks.requests_per_minute must be 0 or more")
	}
	return nil
}

func (a ACME) check() error {
	if !a.Enabled {
		return checkDir("acme.static_dir", a.StaticDir)
	}
	if err := checkURL("acme.directory", a.Directory); err != nil {
		return err
	}
	if err := checkDir("acme.state_dir", a.StateDir); err != nil {
		return err
	}
	if err := checkDir("acme.wildcard_dir", a.WildcardDir); err != nil {
		return err
	}
	if a.StaticDir != "" {
		return checkDir("acme.static_dir", a.StaticDir)
	}
	return nil
}

/* Shared checks */

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
	if err != nil || strings.ContainsAny(host, " /") {
		return fmt.Errorf("%s must be a host and port such as 127.0.0.1:8443", key)
	}
	return nil
}

func checkPrefixes(p []netip.Prefix) error {
	if len(p) == 0 {
		return errors.New("proxy_protocol_from needs at least one prefix, such as 127.0.0.1/32")
	}
	return nil
}

func checkHost(key, name string) error {
	if name == "" {
		return fmt.Errorf("%s is required", key)
	}
	if !hostname.Valid(name) {
		return fmt.Errorf("%s must be a lowercase host name such as host.example.com, with no "+
			"scheme, port or final dot", key)
	}
	return nil
}

func checkDir(key, dir string) error {
	if dir == "" {
		return fmt.Errorf("%s is required", key)
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s must be an absolute path", key)
	}
	return nil
}

// checkContact accepts a bare mail address or an https URL, the two forms a page can link
func checkContact(key, contact string) error {
	if contact == "" {
		return fmt.Errorf("%s is required", key)
	}
	if strings.HasPrefix(contact, "https://") {
		if u, err := url.Parse(contact); err == nil && u.Host != "" {
			return nil
		}
	} else if a, err := mail.ParseAddress(contact); err == nil && a.Address == contact {
		return nil
	}
	return fmt.Errorf("%s must be a mail address or an https URL", key)
}

func positive(key string, d settings.Duration) error {
	if d <= 0 {
		return fmt.Errorf("%s must be more than 0", key)
	}
	return nil
}

func atMost(key string, d settings.Duration, top time.Duration) error {
	if time.Duration(d) > top {
		return fmt.Errorf("%s must be at most %s", key, strings.TrimSuffix(top.String(), "0m0s"))
	}
	return nil
}

// callerToken reads a router caller token, refusing one the router would refuse
func callerToken(getenv func(string) (string, bool), name string) (string, error) {
	v, _ := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if len(v) < 32 || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return "", fmt.Errorf("%s must be at least 32 characters with no spaces or control "+
			"characters", name)
	}
	return v, nil
}

// SecretsConfig is bugnet-edge --role secrets' settings file (DP 8.4) and its token
type SecretsConfig struct {
	RouterURL         string         `toml:"router_url"`
	TLSListenAddr     string         `toml:"tls_listen_addr"`
	MetricsListenAddr string         `toml:"metrics_listen_addr"`
	ProxyProtocolFrom []netip.Prefix `toml:"proxy_protocol_from"`
	Host              string         `toml:"host"`
	PageDir           string         `toml:"page_dir"`
	RequestsPerMinute int            `toml:"requests_per_minute"`
	MaxHeaderBytes    settings.Bytes `toml:"max_header_bytes"`
	ACMEEnabled       bool           `toml:"acme_enabled"`
	ACMEDirectory     string         `toml:"acme_directory"`
	ACMEDir           string         `toml:"acme_dir"`
	ACMEEmail         string         `toml:"acme_email"`
	StaticDir         string         `toml:"static_dir"`

	Token string `toml:"-"` // BUGNET_SECRETS_TOKEN
}

// SecretsDefaults is every secrets route setting at its default, with no host
func SecretsDefaults() SecretsConfig {
	return SecretsConfig{
		RouterURL:         "http://127.0.0.1:8080",
		TLSListenAddr:     "127.0.0.1:8445",
		MetricsListenAddr: "127.0.0.1:9104",
		ProxyProtocolFrom: loopback(),
		PageDir:           "/srv/bugnet/secrets-page",
		RequestsPerMinute: 60,
		MaxHeaderBytes:    1 << 20,
		ACMEEnabled:       true,
		ACMEDirectory:     letsEncrypt,
		ACMEDir:           "/var/lib/bugnet-secrets/acme",
	}
}

// LoadSecrets reads the secrets route's settings file at path over the defaults, then its token
func LoadSecrets(path string, getenv func(string) (string, bool)) (SecretsConfig, error) {
	c := SecretsDefaults()
	if err := settings.Load(path, &c); err != nil {
		return SecretsConfig{}, fmt.Errorf("secrets route: %w", err)
	}
	if err := c.check(); err != nil {
		return SecretsConfig{}, fmt.Errorf("secrets route: %s: %w", path, err)
	}
	token, err := callerToken(getenv, "BUGNET_SECRETS_TOKEN")
	if err != nil {
		return SecretsConfig{}, fmt.Errorf("secrets route: %w", err)
	}
	c.Token = token
	return c, nil
}

func (c *SecretsConfig) check() error {
	checks := []func() error{
		func() error { return checkURL("router_url", c.RouterURL) },
		func() error { return checkAddr("tls_listen_addr", c.TLSListenAddr) },
		func() error { return checkAddr("metrics_listen_addr", c.MetricsListenAddr) },
		func() error { return checkPrefixes(c.ProxyProtocolFrom) },
		func() error { return checkHost("host", c.Host) },
		func() error { return checkDir("page_dir", c.PageDir) },
		func() error {
			if c.RequestsPerMinute < 0 {
				return errors.New("requests_per_minute must be 0 or more")
			}
			return nil
		},
		func() error {
			if c.MaxHeaderBytes < 4<<10 || c.MaxHeaderBytes > 4<<20 {
				return errors.New("max_header_bytes must be 4KiB to 4MiB")
			}
			return nil
		},
		func() error {
			if !c.ACMEEnabled {
				return checkDir("static_dir", c.StaticDir)
			}
			if err := checkURL("acme_directory", c.ACMEDirectory); err != nil {
				return err
			}
			if c.StaticDir != "" {
				if err := checkDir("static_dir", c.StaticDir); err != nil {
					return err
				}
			}
			return checkDir("acme_dir", c.ACMEDir)
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}
