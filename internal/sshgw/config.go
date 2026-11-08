package sshgw

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bugnet-sh/bugnet-edges/internal/metrics"
	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

// Config is bugnet-ssh's settings file (DP 9.8), its token and its host keys
type Config struct {
	RouterURL                  string            `toml:"router_url"`
	GatewayID                  string            `toml:"gateway_id"`
	ListenAddr                 string            `toml:"listen_addr"`
	MetricsListenAddr          string            `toml:"metrics_listen_addr"`
	ProxyProtocolFrom          []netip.Prefix    `toml:"proxy_protocol_from"`
	HostKeyCredentials         []string          `toml:"host_key_credentials"`
	HandshakeTimeout           settings.Duration `toml:"handshake_timeout"`
	MaxSessionsPerConnection   int               `toml:"max_sessions_per_connection"`
	MaxForwardsPerConnection   int               `toml:"max_forwards_per_connection"`
	KeepaliveInterval          settings.Duration `toml:"keepalive_interval"`
	DrainMax                   settings.Duration `toml:"drain_max"`
	AcceptsPerMinutePerIP      int               `toml:"accepts_per_minute_per_ip"`
	AuthFailuresPerMinutePerIP int               `toml:"auth_failures_per_minute_per_ip"`
	UsageReportInterval        settings.Duration `toml:"usage_report_interval"`
	TotalBytesPerSecond        settings.Bytes    `toml:"total_bytes_per_second"`
	// BannerFallback answers a refused lease in the first session instead of an auth banner
	BannerFallback bool `toml:"banner_fallback"`

	Token    string            `toml:"-"` // BUGNET_SSH_TOKEN
	HostKeys []ssh.Signer      `toml:"-"`
	Log      *slog.Logger      `toml:"-"`
	Metrics  *metrics.Registry `toml:"-"`
}

// Defaults is every setting at its default
func Defaults() Config {
	return Config{
		RouterURL:                  "http://127.0.0.1:8080",
		ListenAddr:                 "127.0.0.1:2223",
		MetricsListenAddr:          "127.0.0.1:9102",
		ProxyProtocolFrom:          loopback(),
		HostKeyCredentials:         []string{"ssh_host_ed25519_key"},
		HandshakeTimeout:           settings.Duration(20 * time.Second),
		MaxSessionsPerConnection:   10,
		MaxForwardsPerConnection:   32,
		KeepaliveInterval:          settings.Duration(30 * time.Second),
		DrainMax:                   settings.Duration(2 * time.Hour),
		AcceptsPerMinutePerIP:      60,
		AuthFailuresPerMinutePerIP: 20,
		UsageReportInterval:        settings.Duration(5 * time.Second),
		TotalBytesPerSecond:        16 << 20,
	}
}

func loopback() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
}

// Load reads the settings file at path over the defaults, then the token from getenv
func Load(path string, getenv func(string) (string, bool)) (Config, error) {
	c := Defaults()
	if err := settings.Load(path, &c); err != nil {
		return Config{}, fmt.Errorf("sshgw: %w", err)
	}
	if err := c.check(); err != nil {
		return Config{}, fmt.Errorf("sshgw: %s: %w", path, err)
	}
	if c.GatewayID == "" {
		c.GatewayID = defaultGatewayID()
	}
	v, _ := getenv("BUGNET_SSH_TOKEN")
	if len(v) < 32 || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return Config{}, errors.New("sshgw: BUGNET_SSH_TOKEN must be at least 32 characters " +
			"with no spaces or control characters")
	}
	c.Token = v
	return c, nil
}

var gatewayID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// defaultGatewayID is host-pid, with anything an id cannot hold turned into a hyphen
func defaultGatewayID() string {
	host, _ := os.Hostname()
	host = strings.Map(func(r rune) rune {
		if r < 0x80 && gatewayID.MatchString(string(r)) {
			return r
		}
		return '-'
	}, host)
	pid := "-" + strconv.Itoa(os.Getpid())
	if host == "" {
		host = "ssh"
	}
	return host[:min(len(host), 64-len(pid))] + pid
}

func (c *Config) check() error {
	u, err := url.Parse(c.RouterURL)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("router_url must be an http or https URL with a host")
	}
	if c.GatewayID != "" && !gatewayID.MatchString(c.GatewayID) {
		return errors.New("gateway_id must be 1 to 64 letters, digits, dots, underscores or " +
			"hyphens, or empty for host-pid")
	}
	for k, addr := range map[string]string{
		"listen_addr": c.ListenAddr, "metrics_listen_addr": c.MetricsListenAddr,
	} {
		if err := checkAddr(k, addr); err != nil {
			return err
		}
	}
	if len(c.ProxyProtocolFrom) == 0 {
		return errors.New("proxy_protocol_from needs at least one prefix, such as 127.0.0.1/32")
	}
	if len(c.HostKeyCredentials) == 0 {
		return errors.New("host_key_credentials needs at least one name")
	}
	for _, n := range c.HostKeyCredentials {
		if n == "" || n != filepath.Base(n) || n == "." || n == ".." {
			return errors.New("host_key_credentials holds file names with no directory")
		}
	}
	for k, d := range map[string]settings.Duration{
		"handshake_timeout": c.HandshakeTimeout, "keepalive_interval": c.KeepaliveInterval,
		"usage_report_interval": c.UsageReportInterval, "drain_max": c.DrainMax,
	} {
		if d <= 0 {
			return fmt.Errorf("%s must be more than 0", k)
		}
	}
	if time.Duration(c.DrainMax) > 2*time.Hour {
		return errors.New("drain_max must be at most 2h")
	}
	if c.MaxSessionsPerConnection < 1 || c.MaxSessionsPerConnection > 100 {
		return errors.New("max_sessions_per_connection must be 1 to 100")
	}
	if c.MaxForwardsPerConnection < 1 || c.MaxForwardsPerConnection > 1000 {
		return errors.New("max_forwards_per_connection must be 1 to 1000")
	}
	if c.AcceptsPerMinutePerIP < 0 || c.AuthFailuresPerMinutePerIP < 0 {
		return errors.New("the per-IP limits must be 0 or more, 0 is no limit")
	}
	return nil
}

func checkAddr(key, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil || strings.ContainsAny(host, " /") {
		return fmt.Errorf("%s must be a host and port such as 127.0.0.1:2223", key)
	}
	return nil
}

// LoadHostKeys reads the named private keys from dir, a systemd credentials directory
func LoadHostKeys(dir string, names []string) ([]ssh.Signer, error) {
	if dir == "" {
		return nil, errors.New("sshgw: CREDENTIALS_DIRECTORY is not set")
	}
	var out []ssh.Signer
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, fmt.Errorf("sshgw: host key %s: %w", n, errors.Unwrap(err))
		}
		s, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("sshgw: host key %s is not a private key", n)
		}
		out = append(out, s)
	}
	return out, nil
}
