package egress

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// leafBackdate and leafLife are DP 10.5's validity window of a minted leaf
	leafBackdate = time.Hour
	leafLife     = 7 * 24 * time.Hour
	// leafRemint re-mints a cached leaf with less than this left
	leafRemint = 24 * time.Hour
	leafCache  = 10_000
	caLife     = 2 * 365 * 24 * time.Hour

	// CAKeyFile is the name ca init gives the CA's private key
	CAKeyFile = "egress-ca.key"
	// CACertFile is the name ca init gives the CA's certificate
	CACertFile = "egress-ca.pem"
)

// CA is one version of the Bugnet CA, with the key that signs leaves
type CA struct {
	Version uint32
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

// LoadCA reads the CA certificate from certPEM and its ECDSA key from keyPEM
func LoadCA(version uint32, certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("egress: the CA certificate file holds no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("egress: CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("egress: the CA certificate is not a CA")
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("egress: the CA key does not belong to the CA certificate")
	}
	return &CA{Version: version, cert: cert, key: key}, nil
}

func parseECKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("egress: the CA key is not PEM")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if k, ok := parsed.(*ecdsa.PrivateKey); err == nil && ok {
		return k, nil
	}
	return nil, errors.New("egress: the CA key is not an ECDSA key")
}

// InitCA writes a new CA, ECDSA P-256 and valid 2 years, into dir without replacing a file
func InitCA(dir string, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := serialNumber()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Bugnet sandbox CA"},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              now.Add(caLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	write := func(name string, mode os.FileMode, b *pem.Block) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if _, err := f.Write(pem.EncodeToMemory(b)); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	if err := write(CAKeyFile, 0o600,
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}
	return write(CACertFile, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// Minter makes the leaf certificates the inner handshakes serve
type Minter struct {
	cas   map[uint32]*CA
	key   *ecdsa.PrivateKey
	now   func() time.Time
	limit int

	mu    sync.Mutex
	lru   *list.List
	byKey map[leafKey]*list.Element
}

type leafKey struct {
	version uint32
	name    string
}

type leafEntry struct {
	key  leafKey
	cert *tls.Certificate
}

// NewMinter signs with the listed CAs, each placement's own version picking one
func NewMinter(now func() time.Time, cas ...*CA) (*Minter, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m := &Minter{
		cas: map[uint32]*CA{}, key: key, now: now, limit: leafCache, lru: list.New(),
		byKey: map[leafKey]*list.Element{},
	}
	for _, ca := range cas {
		m.cas[ca.Version] = ca
	}
	return m, nil
}

// Has says whether the minter holds the CA of version
func (m *Minter) Has(version uint32) bool {
	return m.cas[version] != nil
}

// Leaf returns the cached certificate of name under the CA of version, or mints one
func (m *Minter) Leaf(version uint32, name string) (*tls.Certificate, error) {
	ca := m.cas[version]
	if ca == nil {
		return nil, errors.New("egress: no CA of that version")
	}
	k := leafKey{version, name}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.byKey[k]; ok {
		e := el.Value.(*leafEntry)
		if e.cert.Leaf.NotAfter.Sub(now) >= leafRemint {
			m.lru.MoveToFront(el)
			return e.cert, nil
		}
		m.lru.Remove(el)
		delete(m.byKey, k)
	}
	cert, err := m.mint(ca, name, now)
	if err != nil {
		return nil, err
	}
	m.byKey[k] = m.lru.PushFront(&leafEntry{k, cert})
	for m.lru.Len() > m.limit {
		old := m.lru.Remove(m.lru.Back()).(*leafEntry)
		delete(m.byKey, old.key)
	}
	return cert, nil
}

func (m *Minter) mint(ca *CA, name string, now time.Time) (*tls.Certificate, error) {
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-leafBackdate),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &m.key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: m.key, Leaf: leaf}, nil
}
