//go:build localrun

package egress

import (
	"crypto/x509"
	"errors"
	"net/http"
	"os"
)

// Localrun holds the settings only a localrun build reads, for the x402 local run
type Localrun struct {
	// UpstreamAddrs maps a seller name to the host and port dialed for it
	UpstreamAddrs map[string]string `toml:"upstream_addrs"`
	// UpstreamRootsFile is a PEM bundle the sellers' certificates are checked against
	UpstreamRootsFile string `toml:"upstream_roots_file"`
}

type localrunSettings struct {
	Localrun Localrun `toml:"localrun"`
}

// applyLocalrun points the seller dialer at the listed addresses and trusts the test roots
func (s *Server) applyLocalrun() error {
	lr := s.cfg.Localrun
	if len(lr.UpstreamAddrs) == 0 {
		return nil
	}
	s.dialer.upstream = func(host string) (string, bool) {
		to, ok := lr.UpstreamAddrs[host]
		return to, ok
	}
	if lr.UpstreamRootsFile == "" {
		return nil
	}
	t, ok := s.seller.(*http.Transport)
	if !ok {
		return errors.New("the seller transport is not the default one")
	}
	b, err := os.ReadFile(lr.UpstreamRootsFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return errors.New("upstream_roots_file holds no certificate")
	}
	t.TLSClientConfig.RootCAs = pool
	return nil
}
