// Package x402test holds a test internal CA and a fake Payments signer for egress's x402 tests
package x402test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// ServerName is the SAN of Payments' server certificate
	ServerName = "bugnet-payments.internal"
	// ClientName is the SAN of egress's client certificate
	ClientName = "bugnet-egress.internal"
)

// The five files of bugnet-dev mtls init --dev, under the names egress and Payments read by default
const (
	CAFile         = "internal-ca.pem"
	ClientCertFile = "egress-x402-client.pem"
	ClientKeyFile  = "egress_x402_client_key"
	ServerCertFile = "x402-server.pem"
	EnvFile        = "payments.env.add"
)

// EnvKey is the variable payments.env.add sets to base64 of the server key PEM
const EnvKey = "BUGNET_X402_TLS_KEY"

// CA is a test internal CA with Payments' server pair and egress's client pair
type CA struct {
	// Cert is the CA certificate and PEM its encoding
	Cert *x509.Certificate
	PEM  []byte
	// Server is Payments' pair, SAN ServerName
	Server tls.Certificate
	// ClientKey is egress's key and ClientPEM its certificate, SAN ClientName
	ClientKey *ecdsa.PrivateKey
	ClientPEM []byte

	// key signs leaves, nil for a CA read back from files
	key *ecdsa.PrivateKey
}

// NewCA makes a CA valid 10 years and both pairs valid 1 year, all ECDSA P-256
func NewCA(t testing.TB) *CA {
	t.Helper()
	key := NewKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "Bugnet test internal CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	c := &CA{Cert: cert, PEM: pemOf("CERTIFICATE", der), key: key}
	year := now.AddDate(1, 0, 0)
	serverKey := NewKey(t)
	c.Server = Pair(t, c.Issue(t, &serverKey.PublicKey, ServerName,
		x509.ExtKeyUsageServerAuth, year), serverKey)
	c.ClientKey = NewKey(t)
	c.ClientPEM = c.Issue(t, &c.ClientKey.PublicKey, ClientName, x509.ExtKeyUsageClientAuth, year)
	return c
}

// NewKey is a fresh ECDSA P-256 key
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// KeyPEM is key as a PKCS #8 PEM block
func KeyPEM(t testing.TB, key crypto.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

// Issue signs a certificate PEM for pub with one DNS name and one extended key use
func (c *CA) Issue(
	t testing.TB, pub crypto.PublicKey, name string, use x509.ExtKeyUsage, notAfter time.Time,
) []byte {
	t.Helper()
	if c.key == nil {
		t.Fatal("x402test: a CA read from files has no key to sign with")
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{use},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("CERTIFICATE", der)
}

// Pool holds the CA certificate
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

// Client is egress's pair for a plain TLS client
func (c *CA) Client(t testing.TB) tls.Certificate {
	t.Helper()
	return Pair(t, c.ClientPEM, c.ClientKey)
}

// Pair joins a certificate PEM and its key
func Pair(t testing.TB, certPEM []byte, key crypto.PrivateKey) tls.Certificate {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, KeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// WriteDev writes the five files of mtls init --dev into dir, keys 0600 and certificates 0644
func (c *CA) WriteDev(t testing.TB, dir string) {
	t.Helper()
	serverPEM := pemOf("CERTIFICATE", c.Server.Certificate[0])
	env := EnvKey + "=" + base64.StdEncoding.EncodeToString(KeyPEM(t, c.Server.PrivateKey)) + "\n"
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{CAFile, c.PEM, 0o644},
		{ClientCertFile, c.ClientPEM, 0o644},
		{ClientKeyFile, KeyPEM(t, c.ClientKey), 0o600},
		{ServerCertFile, serverPEM, 0o644},
		{EnvFile, []byte(env), 0o600},
	} {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
		// The umask never narrows a mode the layout names
		if err := os.Chmod(path, f.mode); err != nil {
			t.Fatal(err)
		}
	}
}

// ReadDev reads the CA certificate and both pairs back from the five files in dir
func ReadDev(t testing.TB, dir string) *CA {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c := &CA{PEM: read(CAFile), ClientPEM: read(ClientCertFile)}
	block, _ := pem.Decode(c.PEM)
	if block == nil {
		t.Fatalf("x402test: %s holds no PEM", CAFile)
	}
	var err error
	if c.Cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	key, ok := parseKey(read(ClientKeyFile)).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("x402test: %s holds no ECDSA key", ClientKeyFile)
	}
	c.ClientKey = key
	line, found := strings.CutPrefix(strings.TrimSuffix(string(read(EnvFile)), "\n"), EnvKey+"=")
	if !found {
		t.Fatalf("x402test: %s does not set %s", EnvFile, EnvKey)
	}
	serverKey, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server, err = tls.X509KeyPair(read(ServerCertFile), serverKey); err != nil {
		t.Fatal(err)
	}
	return c
}

// parseKey reads a PKCS #8 PEM key, nil when there is none
func parseKey(b []byte) crypto.PrivateKey {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	return key
}

func pemOf(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

// serial is a random 128-bit serial number
func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
