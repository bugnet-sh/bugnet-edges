// Package certs is bugnet-certs, which renews the preview wildcards by DNS-01 and checks expiries
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/oynozan/bugnet-edges/internal/hostname"
	"github.com/oynozan/bugnet-edges/internal/settings"
)

// Config is bugnet-certs' settings file, /etc/bugnet/certs.toml
type Config struct {
	Directory    string        `toml:"directory"`
	Email        string        `toml:"email"`
	StateDir     string        `toml:"state_dir"`
	DNSProvider  string        `toml:"dns_provider"`
	DNSEnv       []string      `toml:"dns_env"`
	AlertDays    int           `toml:"alert_days"`
	CertMetrics  []string      `toml:"cert_metrics"`
	Certificates []Certificate `toml:"certificates"`
}

// Certificate is one certificate bugnet-certs keeps, its names and the directory it writes
type Certificate struct {
	Names []string `toml:"names"`
	Dir   string   `toml:"dir"`
}

// Defaults is every setting at its default, with no certificate, which each deployment lists
func Defaults() Config {
	return Config{
		Directory:   "https://acme-v02.api.letsencrypt.org/directory",
		StateDir:    "/var/lib/bugnet-certs/acme",
		DNSProvider: "cloudflare",
		DNSEnv:      []string{"CF_DNS_API_TOKEN"},
		AlertDays:   14,
		CertMetrics: []string{"127.0.0.1:9101", "127.0.0.1:9103", "127.0.0.1:9104"},
	}
}

// Load reads the settings file at path over the defaults
func Load(path string) (Config, error) {
	c := Defaults()
	if err := settings.Load(path, &c); err != nil {
		return Config{}, fmt.Errorf("certs: %w", err)
	}
	if err := c.check(); err != nil {
		return Config{}, fmt.Errorf("certs: %s: %w", path, err)
	}
	return c, nil
}

var (
	providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	envName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func (c *Config) check() error {
	if u, err := url.Parse(c.Directory); err != nil || u.Host == "" ||
		u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("directory must be an http or https URL with a host")
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be an absolute path")
	}
	switch {
	case c.DNSProvider == "":
		return errors.New("dns_provider is required")
	case !providerName.MatchString(c.DNSProvider):
		return errors.New("dns_provider must be a lego provider name such as cloudflare")
	case len(c.DNSEnv) == 0:
		return errors.New("dns_env needs at least one variable name, such as CF_DNS_API_TOKEN")
	case c.AlertDays < 1 || c.AlertDays > 60:
		return errors.New("alert_days must be 1 to 60")
	}
	for i, name := range c.DNSEnv {
		if !envName.MatchString(name) {
			return fmt.Errorf("dns_env entry %d must be a variable name", i+1)
		}
	}
	for i, addr := range c.CertMetrics {
		if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
			return fmt.Errorf("cert_metrics entry %d must be a host and port such as "+
				"127.0.0.1:9101", i+1)
		}
	}
	return c.checkCertificates()
}

func (c *Config) checkCertificates() error {
	if len(c.Certificates) == 0 {
		return errors.New("certificates needs at least one [[certificates]] table")
	}
	var dirs []string
	for i, cert := range c.Certificates {
		n := i + 1
		if len(cert.Names) == 0 {
			return fmt.Errorf("certificates entry %d needs a name", n)
		}
		for _, name := range cert.Names {
			if !hostname.Valid(strings.TrimPrefix(name, "*.")) {
				return fmt.Errorf("certificates entry %d has a name that is not a host name "+
					"or *. and a host name", n)
			}
		}
		if !filepath.IsAbs(cert.Dir) {
			return fmt.Errorf("certificates entry %d dir must be an absolute path", n)
		}
		if slices.Contains(dirs, filepath.Clean(cert.Dir)) {
			return fmt.Errorf("certificates entry %d dir is used twice", n)
		}
		dirs = append(dirs, filepath.Clean(cert.Dir))
	}
	return nil
}

// CheckEnv requires every variable the DNS provider reads, naming a missing one, never a value
func CheckEnv(names []string, lookup func(string) (string, bool)) error {
	for _, name := range names {
		if v, ok := lookup(name); !ok || v == "" {
			return fmt.Errorf("certs: dns_env names %s, which is not set in the environment", name)
		}
	}
	return nil
}

// Window is the renewal window a CA suggests through ARI
type Window struct {
	Start time.Time
	End   time.Time
}

// Due reports whether cert should be renewed now, by the ARI window, else at two thirds of its life
func Due(cert *x509.Certificate, ari *Window, now time.Time) bool {
	if cert == nil || !now.Before(cert.NotAfter) {
		return true
	}
	if ari != nil {
		return !now.Before(ari.Start)
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	return !now.Before(cert.NotBefore.Add(life * 2 / 3))
}

// Write replaces fullchain.pem and key.pem in dir by rename, both 0640 in the directory's group
func Write(dir string, chain, key []byte) error {
	if _, err := tls.X509KeyPair(chain, key); err != nil {
		return errors.New("certs: the chain and key do not form a pair")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	gid := -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		gid = int(st.Gid)
	}
	files := []struct {
		name string
		body []byte
		temp string
	}{{name: "key.pem", body: key}, {name: "fullchain.pem", body: chain}}
	defer func() {
		for _, f := range files {
			if f.temp != "" {
				_ = os.Remove(f.temp)
			}
		}
	}()
	for i := range files {
		if files[i].temp, err = temp(dir, files[i].name, files[i].body, gid); err != nil {
			return err
		}
	}
	for i, f := range files {
		if err := os.Rename(f.temp, filepath.Join(dir, f.name)); err != nil {
			return fmt.Errorf("certs: %w", err)
		}
		files[i].temp = ""
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// chown gives f the group gid, leaving its owner
var chown = fileChown

func fileChown(f *os.File, gid int) error {
	return f.Chown(-1, gid)
}

// temp writes body to a new file beside name, so the edge, in dir's group, can read it once renamed
func temp(dir, name string, body []byte, gid int) (string, error) {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return "", fmt.Errorf("certs: %w", err)
	}
	path := f.Name()
	err = f.Chmod(0o640)
	if err == nil {
		err = chown(f, gid)
	}
	if errors.Is(err, syscall.EPERM) {
		err = fmt.Errorf("cannot give it the directory's group, so give the directory the "+
			"setgid bit (mode 2750) or add this user to that group: %w", err)
	}
	if err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("certs: writing %s: %w", name, err)
	}
	return path, nil
}

// readLeaf is the first certificate of dir's fullchain.pem, nil when there is none
func readLeaf(dir string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, errors.New("fullchain.pem holds no certificate")
	}
	return x509.ParseCertificate(p.Bytes)
}

func daysLeft(notAfter, now time.Time) int {
	d := notAfter.Sub(now)
	days := int(d / (24 * time.Hour))
	if d < 0 && d%(24*time.Hour) != 0 {
		days--
	}
	return days
}
