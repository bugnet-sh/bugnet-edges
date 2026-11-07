package x402

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// day is the gap between two expiry lines
	day = 24 * time.Hour
	// expiryWarn is how long before the client certificate expires the daily line starts
	expiryWarn = 30 * day
	// expiryEvery is how often Run reads the clock for the expiry line
	expiryEvery = time.Hour
	// handshakeTimeout bounds one connection to Payments and its TLS handshake
	handshakeTimeout = 10 * time.Second
)

// creds is one load of the CA and certificate files
type creds struct {
	cert  *tls.Certificate
	roots *x509.CertPool
}

// readKey reads egress's private key from the credential the settings name, never quoting it
func readKey(dir, name string) (crypto.Signer, error) {
	const setting = "x402.payments_client_key_credential"
	if dir == "" {
		return nil, fmt.Errorf("%s needs $CREDENTIALS_DIRECTORY, which is not set", setting)
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("%s names a file under $CREDENTIALS_DIRECTORY that %s", setting,
			problem(err))
	}
	defer clear(raw)
	key, ok := parseKey(raw)
	if !ok {
		return nil, fmt.Errorf("%s names a file with no PKCS #8 or EC private key", setting)
	}
	return key, nil
}

// parseKey reads the first PKCS #8 or EC private key block of raw
func parseKey(raw []byte) (crypto.Signer, bool) {
	for rest := raw; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			return nil, false
		}
		rest = next
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			continue
		}
		clear(block.Bytes)
		if err != nil {
			return nil, false
		}
		s, ok := key.(crypto.Signer)
		return s, ok
	}
}

// readCerts reads every certificate in the file of a setting, naming the setting and never the path
func readCerts(setting, path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("x402.%s names a file that %s", setting, problem(err))
	}
	var certs []*x509.Certificate
	for rest := raw; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x402.%s holds a certificate that does not parse", setting)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("x402.%s holds no PEM certificate", setting)
	}
	return certs, nil
}

// problem says why a file could not be read, without its path
func problem(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "is missing"
	case errors.Is(err, fs.ErrPermission):
		return "egress may not read"
	}
	return "cannot be read"
}

// load reads the CA and certificate files and pairs the certificate with the key from the start
func (s *Signer) load() (creds, error) {
	cas, err := readCerts("payments_ca_file", s.caFile)
	if err != nil {
		return creds{}, err
	}
	chain, err := readCerts("payments_client_cert_file", s.certFile)
	if err != nil {
		return creds{}, err
	}
	pub, ok := s.key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(chain[0].PublicKey) {
		return creds{}, errors.New("x402.payments_client_cert_file is not a certificate for the " +
			"key in x402.payments_client_key_credential")
	}
	roots := x509.NewCertPool()
	for _, c := range cas {
		roots.AddCert(c)
	}
	cert := &tls.Certificate{PrivateKey: s.key, Leaf: chain[0]}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return creds{cert: cert, roots: roots}, nil
}

// Reload re-reads the certificate and CA files and keeps the key from the start
func (s *Signer) Reload() error {
	c, err := s.load()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.creds = c
	s.mu.Unlock()
	// A connection made with the old files ends once idle, so the next call makes a new handshake
	s.transport.CloseIdleConnections()
	return nil
}

// clientCert is the certificate of the last good load, read at each handshake
func (s *Signer) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creds.cert, nil
}

// dialTLS opens a TLS 1.3 connection that checks Payments against the CA of the last good load
func (s *Signer) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.Lock()
	roots := s.creds.roots
	s.mu.Unlock()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: handshakeTimeout},
		Config: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              roots,
			ServerName:           s.serverName,
			GetClientCertificate: s.clientCert,
			NextProtos:           []string{"h2", "http/1.1"},
		},
	}
	return d.DialContext(ctx, network, addr)
}

// checkExpiry logs the expiry line once a day from 30 days before the client certificate expires
func (s *Signer) checkExpiry() {
	now := s.now()
	if !s.lastExpiry.IsZero() && now.Sub(s.lastExpiry) < day {
		return
	}
	s.mu.Lock()
	left := s.creds.cert.Leaf.NotAfter.Sub(now)
	s.mu.Unlock()
	if left > expiryWarn {
		return
	}
	s.lastExpiry = now
	s.log.Error(msgCertExpiry, "file", s.certFile, "days_left", daysLeft(left))
}

// daysLeft is left in whole days, rounded down
func daysLeft(left time.Duration) int {
	days := int(left / day)
	if left < 0 && left%day != 0 {
		days--
	}
	return days
}
