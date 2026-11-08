package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAInit(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := InitCA(dir, now); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, st.Mode().Perm(), os.FileMode(0o600))
	certPEM, _ := os.ReadFile(filepath.Join(dir, CACertFile))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	ca, err := LoadCA(1, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := ca.cert.PublicKey.(*ecdsa.PublicKey)
	eq(t, ok && pub.Curve == elliptic.P256(), true)
	eq(t, ca.cert.IsCA, true)
	left := ca.cert.NotAfter.Sub(now)
	eq(t, left > 2*365*24*time.Hour-time.Minute && left <= 2*365*24*time.Hour, true)
	// A second init never replaces the key
	eq(t, InitCA(dir, now) != nil, true)
}

func TestLoadCARefusals(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	_ = InitCA(a, time.Now())
	_ = InitCA(b, time.Now())
	certA, _ := os.ReadFile(filepath.Join(a, CACertFile))
	keyA, _ := os.ReadFile(filepath.Join(a, CAKeyFile))
	keyB, _ := os.ReadFile(filepath.Join(b, CAKeyFile))
	_, err := LoadCA(1, certA, keyB)
	eq(t, err != nil, true)
	_, err = LoadCA(1, []byte("not pem"), keyA)
	eq(t, err != nil, true)
	_, err = LoadCA(1, certA, []byte("not pem"))
	eq(t, err != nil, true)
}

func TestLeafCertificate(t *testing.T) {
	ca := newCA(t, 1)
	now := time.Now()
	m, err := NewMinter(func() time.Time { return now }, ca)
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Leaf(1, "hf.example")
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	eq(t, leaf.DNSNames, []string{"hf.example"})
	eq(t, leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	back := now.Sub(leaf.NotBefore)
	eq(t, back >= 59*time.Minute && back <= 61*time.Minute, true)
	eq(t, leaf.NotAfter.Sub(now) > 7*24*time.Hour-time.Minute, true)
	eq(t, leaf.NotAfter.Sub(now) <= 7*24*time.Hour, true)
	eq(t, leaf.SerialNumber.BitLen() > 100, true)
	opts := x509.VerifyOptions{Roots: ca.pool(), DNSName: "hf.example", CurrentTime: now}
	_, err = leaf.Verify(opts)
	eq(t, err, nil)
	opts.DNSName = "other.example"
	_, err = leaf.Verify(opts)
	eq(t, err != nil, true)

	// One process-wide key, a certificate of its own per name
	d, _ := m.Leaf(1, "other.example")
	eq(t, d.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(leaf.PublicKey), true)
	eq(t, d.Leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0, true)
	// The cached certificate comes back until a day is left
	again, _ := m.Leaf(1, "hf.example")
	eq(t, again == c, true)
	now = now.Add(6*24*time.Hour + 2*time.Hour)
	fresh, _ := m.Leaf(1, "hf.example")
	eq(t, fresh != c, true)
	eq(t, fresh.Leaf.NotAfter.After(c.Leaf.NotAfter), true)
	_, err = m.Leaf(2, "hf.example")
	eq(t, err != nil, true)
}

func TestLeafCacheKeepsTheNewest(t *testing.T) {
	m, err := NewMinter(time.Now, newCA(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, m.limit, 10_000)
	m.limit = 40
	for i := range 90 {
		if _, err := m.Leaf(1, "h"+itoa(i)+".example"); err != nil {
			t.Fatal(err)
		}
	}
	eq(t, m.lru.Len(), 40)
	eq(t, len(m.byKey), 40)
	// The newest stay and the oldest go
	_, newest := m.byKey[leafKey{1, "h89.example"}]
	_, oldest := m.byKey[leafKey{1, "h0.example"}]
	eq(t, newest, true)
	eq(t, oldest, false)
}

func TestOlderCAStaysTrustedForItsSandboxes(t *testing.T) {
	old, current := newCA(t, 1), newCA(t, 2)
	m, _ := NewMinter(time.Now, old, current)
	a, _ := m.Leaf(1, "hf.example")
	b, _ := m.Leaf(2, "hf.example")
	_, errOld := a.Leaf.Verify(x509.VerifyOptions{Roots: old.pool(), DNSName: "hf.example"})
	_, errNew := b.Leaf.Verify(x509.VerifyOptions{Roots: current.pool(), DNSName: "hf.example"})
	eq(t, errOld, nil)
	eq(t, errNew, nil)
	_, cross := a.Leaf.Verify(x509.VerifyOptions{Roots: current.pool(), DNSName: "hf.example"})
	eq(t, cross != nil, true)
}
