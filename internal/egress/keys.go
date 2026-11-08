// Package egress is the secret proxy of DP 10, which swaps placeholders for sealed values
package egress

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Binding is the sealing binding of a placement, equal to the router's dpkeys.Binding
func Binding(placement uuid.UUID) string {
	sum := sha256.Sum256(slices.Concat([]byte("bugnet-secret-binding"), []byte{0}, placement[:]))
	return b32.EncodeToString(sum[:])
}

// BoxKey is one X25519 key the proxy opens sealed boxes with
type BoxKey struct {
	ID      string
	private [32]byte
	public  [32]byte
}

// boxKeyFile is the file box-key new writes for id, named as the credential in box_keys
func boxKeyFile(id string) string {
	return "egress_box_" + id
}

// NewBoxKey writes a fresh key for id into dir at mode 0600 and returns its public half
func NewBoxKey(dir, id string) (public [32]byte, err error) {
	if !validKeyID(id) {
		return public, errors.New("egress: the key id is 1 to 32 letters, digits, - or _")
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return public, err
	}
	line := base64.StdEncoding.EncodeToString(priv[:]) + "\n"
	f, err := os.OpenFile(filepath.Join(dir, boxKeyFile(id)),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return public, err
	}
	if _, err := f.WriteString(line); err != nil {
		_ = f.Close()
		return public, err
	}
	return *pub, f.Close()
}

func validKeyID(id string) bool {
	return id != "" && len(id) <= 32 &&
		strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == ""
}

// ParseBoxKey reads the base64 private key a box-key file holds
func ParseBoxKey(id string, raw []byte) (BoxKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != 32 {
		return BoxKey{}, fmt.Errorf("egress: box key %s is not 32 bytes in base64", id)
	}
	k := BoxKey{ID: id}
	copy(k.private[:], b)
	pub, err := curve25519.X25519(k.private[:], curve25519.Basepoint)
	if err != nil {
		return BoxKey{}, fmt.Errorf("egress: box key %s: %w", id, err)
	}
	copy(k.public[:], pub)
	return k, nil
}

// Public is the key's X25519 public half
func (k BoxKey) Public() [32]byte {
	return k.public
}

// Keys holds the box keys newest first
type Keys struct {
	list []BoxKey
}

// NewKeys lists keys newest first
func NewKeys(keys ...BoxKey) *Keys {
	return &Keys{list: keys}
}

// Open opens a sealed box with the key named keyID
func (k *Keys) Open(keyID string, sealed []byte) ([]byte, error) {
	for _, key := range k.list {
		if key.ID == keyID {
			out, ok := box.OpenAnonymous(nil, sealed, &key.public, &key.private)
			if !ok {
				return nil, errOpen
			}
			return out, nil
		}
	}
	return nil, errOpen
}

var errOpen = errors.New("egress: the sealed box does not open")

// Payload is the JSON a sealed box holds (DP 10.2)
type Payload struct {
	V         int      `json:"v"`
	Binding   string   `json:"binding"`
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	Headers   []string `json:"headers"`
	FetchOnly bool     `json:"fetchOnly"`
	Value     string   `json:"value"`
}

// matches says whether the payload equals the record the router served, the lists as sets
func (p Payload) matches(binding, name string, hosts, headers []string, fetchOnly bool) bool {
	return p.V == 1 && p.Binding == binding && p.Name == name && p.FetchOnly == fetchOnly &&
		slices.Equal(canonical(p.Hosts), canonical(hosts)) &&
		slices.Equal(canonical(p.Headers), canonical(headers))
}

// canonical lower-cases, drops a trailing dot, sorts and removes repeats
func canonical(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, strings.TrimSuffix(strings.ToLower(s), "."))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// openPayload opens box under keyID and decodes its payload
func (k *Keys) openPayload(keyID string, sealed []byte) (Payload, error) {
	plain, err := k.Open(keyID, sealed)
	if err != nil {
		return Payload{}, err
	}
	defer clear(plain)
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Payload{}, errors.New("egress: the sealed payload is not JSON of the known shape")
	}
	return p, nil
}
