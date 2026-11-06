// Package tlsconf builds one tls.Config that picks the certificate and ALPN list by SNI
package tlsconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"weak"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Name is one exact host name and the ALPN protocols it offers
type Name struct {
	Host string
	ALPN []string
}

// Wildcard serves every one-label name under Suffix from the pair bugnet-certs writes into Dir
type Wildcard struct {
	Suffix string
	Dir    string
	ALPN   []string
}

// ACME issues each exact name by TLS-ALPN-01 and keeps the account and certificates in StateDir
type ACME struct {
	Enabled   bool
	Directory string
	Email     string
	StateDir  string
}

// Options says which names to serve and where their certificates come from
type Options struct {
	Names    []Name    // exact names, each with its ALPN list, issued by autocert when ACME is on
	Wildcard *Wildcard // suffix, the directory bugnet-certs writes, ALPN
	ACME     ACME      // off switches every name, the wildcard too, to the static pair
	Static   string    // a directory with fullchain.pem and key.pem used when ACME is off

	now func() time.Time
}

var errUnknownName = errors.New("tlsconf: no certificate for this server name")

// registry finds what New built from the config it returned, without keeping that config alive
var registry sync.Map

// served is what one config from New serves
type served struct {
	hosts     []string               // exact names in the order given
	exact     map[string]*tls.Config // by exact name
	challenge *tls.Config            // tls-alpn-01 answers, nil when ACME is off
	manager   *autocert.Manager      // nil when ACME is off
	static    *pairFile              // every name's pair when ACME is off

	suffix string // the wildcard suffix with its leading dot, empty without a wildcard
	wild   *tls.Config
	pair   *pairFile // the wildcard's pair
}

// New builds a config that refuses every server name the options do not list
func New(o Options) (*tls.Config, error) {
	if len(o.Names) == 0 && o.Wildcard == nil {
		return nil, errors.New("tlsconf: no names to serve")
	}
	if o.now == nil {
		o.now = time.Now
	}
	s := &served{exact: map[string]*tls.Config{}}
	if err := s.source(o); err != nil {
		return nil, err
	}
	if err := s.names(o.Names); err != nil {
		return nil, err
	}
	if err := s.wildcard(o); err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: s.configFor}
	key := weak.Make(cfg)
	registry.Store(key, s)
	runtime.AddCleanup(cfg, func(k weak.Pointer[tls.Config]) { registry.Delete(k) }, key)
	return cfg, nil
}

// source sets up autocert, or the static pair when ACME is off
func (s *served) source(o Options) error {
	if !o.ACME.Enabled {
		if o.Static == "" {
			return errors.New("tlsconf: ACME is off and no static pair is set")
		}
		p, err := loadPair(o.Static, o.now)
		if err != nil {
			return fmt.Errorf("tlsconf: static pair: %w", err)
		}
		s.static = p
		return nil
	}
	if o.ACME.Directory == "" || o.ACME.StateDir == "" {
		return errors.New("tlsconf: ACME needs a directory URL and a state directory")
	}
	hosts := make([]string, 0, len(o.Names))
	for _, n := range o.Names {
		hosts = append(hosts, normal(n.Host))
	}
	s.manager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(o.ACME.StateDir),
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      o.ACME.Email,
		Client:     &acme.Client{DirectoryURL: o.ACME.Directory},
	}
	s.challenge = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{acme.ALPNProto},
		GetCertificate: s.manager.GetCertificate,
	}
	return nil
}

func (s *served) names(names []Name) error {
	get := s.static.get
	if s.manager != nil {
		get = s.manager.GetCertificate
	}
	for _, n := range names {
		host := normal(n.Host)
		switch {
		case !hostName(host):
			return errors.New("tlsconf: a name is empty or not a host name")
		case len(n.ALPN) == 0:
			return fmt.Errorf("tlsconf: %s offers no ALPN protocol", host)
		case s.exact[host] != nil:
			return fmt.Errorf("tlsconf: %s is listed twice", host)
		}
		s.hosts = append(s.hosts, host)
		s.exact[host] = config(n.ALPN, get)
	}
	return nil
}

func (s *served) wildcard(o Options) error {
	w := o.Wildcard
	if w == nil {
		return nil
	}
	suffix := normal(w.Suffix)
	switch {
	case !hostName(suffix):
		return errors.New("tlsconf: the wildcard suffix is empty or not a host name")
	case len(w.ALPN) == 0:
		return errors.New("tlsconf: the wildcard offers no ALPN protocol")
	}
	s.suffix = "." + suffix
	s.pair = s.static
	if s.manager != nil {
		p, err := loadPair(w.Dir, o.now)
		if err != nil {
			return fmt.Errorf("tlsconf: wildcard pair: %w", err)
		}
		s.pair = p
	}
	s.wild = config(w.ALPN, s.pair.get)
	return nil
}

func config(alpn []string, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     append([]string(nil), alpn...),
		GetCertificate: get,
	}
}

func normal(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// hostName reports whether a normal name has no empty label and nothing a server name never holds
func hostName(name string) bool {
	return !slices.Contains(strings.Split(name, "."), "") &&
		!strings.ContainsFunc(name, func(r rune) bool {
			return r == '*' || r == ':' || r == '/' || unicode.IsSpace(r)
		})
}

func (s *served) configFor(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	name := normal(hello.ServerName)
	if c, ok := s.exact[name]; ok {
		if s.challenge != nil && len(hello.SupportedProtos) == 1 &&
			hello.SupportedProtos[0] == acme.ALPNProto {
			return s.challenge, nil
		}
		return c, nil
	}
	if s.wild != nil {
		label, ok := strings.CutSuffix(name, s.suffix)
		if ok && label != "" && !strings.Contains(label, ".") {
			return s.wild, nil
		}
	}
	return nil, errUnknownName
}

// DaysLeft reports each served name's days to expiry, without names autocert has not issued yet
func DaysLeft(c *tls.Config, now time.Time) map[string]int {
	v, ok := registry.Load(weak.Make(c))
	if !ok {
		return nil
	}
	s := v.(*served)
	out := map[string]int{}
	for _, host := range s.hosts {
		if leaf := s.leaf(host); leaf != nil {
			out[host] = days(leaf.NotAfter.Sub(now))
		}
	}
	if s.pair != nil {
		out["*"+s.suffix] = days(s.pair.current().Leaf.NotAfter.Sub(now))
	}
	return out
}

func days(d time.Duration) int {
	return int(math.Floor(d.Hours() / 24))
}

// leaf is the certificate a visitor to host gets now, nil before autocert first issues it
func (s *served) leaf(host string) *x509.Certificate {
	if s.manager == nil {
		return s.static.current().Leaf
	}
	for _, key := range []string{host, host + "+rsa"} {
		if leaf := cached(s.manager.Cache, key); leaf != nil {
			return leaf
		}
	}
	return nil
}

// cached reads the leaf of autocert's cache entry, a private key followed by the chain
func cached(c autocert.Cache, key string) *x509.Certificate {
	data, err := c.Get(context.Background(), key)
	if err != nil {
		return nil
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			leaf, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return leaf
		}
	}
}
