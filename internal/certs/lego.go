package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// dnsProvider builds the lego DNS provider by its name, which reads its own variables
func dnsProvider(name string) (challenge.Provider, error) {
	p, err := dns.NewDNSChallengeProviderByName(name)
	if err != nil {
		return nil, fmt.Errorf("certs: dns_provider: %w", err)
	}
	return p, nil
}

// account is the ACME account bugnet-certs keeps, so runs never register a new one
type account struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (a *account) GetEmail() string                        { return a.email }
func (a *account) GetRegistration() *registration.Resource { return a.reg }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// accountDir keeps one account per ACME directory, so staging and production never mix
func accountDir(stateDir, directory string) string {
	host := "directory"
	if u, err := url.Parse(directory); err == nil && u.Host != "" {
		host = strings.NewReplacer(":", "_", "/", "_").Replace(u.Host)
	}
	return filepath.Join(stateDir, host)
}

// loadAccount reads the account key and registration from dir, making a key when there is none
func loadAccount(dir, email string) (*account, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "account.key")
	b, err := os.ReadFile(keyPath)
	var key *ecdsa.PrivateKey
	switch {
	case errors.Is(err, os.ErrNotExist):
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		out := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := writeExclusive(keyPath, out); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		p, _ := pem.Decode(b)
		if p == nil {
			return nil, errors.New("account.key holds no PEM key")
		}
		if key, err = x509.ParseECPrivateKey(p.Bytes); err != nil {
			return nil, fmt.Errorf("account.key: %w", err)
		}
	}
	a := &account{email: email, key: key}
	b, err = os.ReadFile(filepath.Join(dir, "account.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var reg registration.Resource
		if err := json.Unmarshal(b, &reg); err != nil || reg.URI == "" {
			return nil, errors.New("account.json is not a registration")
		}
		a.reg = &reg
	}
	return a, nil
}

func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return errors.Join(err, f.Sync(), f.Close())
}

func saveRegistration(dir string, reg *registration.Resource) error {
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "account.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type legoIssuer struct {
	client   *lego.Client
	newOrder string // the CA's new order URL, which a refused order's problem names
	log      *slog.Logger
}

// NewLego is the Issuer on lego, solving DNS-01 through dns_provider with the account it keeps
func NewLego(cfg Config, log *slog.Logger) (Issuer, error) {
	return newLego(cfg, log, nil)
}

// newLego is NewLego with lego's own HTTP client when hc is nil
func newLego(cfg Config, log *slog.Logger, hc *http.Client) (Issuer, error) {
	provider, err := dnsProvider(cfg.DNSProvider)
	if err != nil {
		return nil, err
	}
	dir := accountDir(cfg.StateDir, cfg.Directory)
	a, err := loadAccount(dir, cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("certs: account: %w", err)
	}
	lc := lego.NewConfig(a)
	lc.CADirURL = cfg.Directory
	lc.UserAgent = "bugnet-certs"
	lc.Certificate.KeyType = certcrypto.EC256
	if hc != nil {
		lc.HTTPClient = hc
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("certs: ACME directory: %w", err)
	}
	if a.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("certs: ACME account: %w", err)
		}
		if err := saveRegistration(dir, reg); err != nil {
			return nil, fmt.Errorf("certs: account: %w", err)
		}
		a.reg = reg
		log.Info("ACME account registered", "directory", cfg.Directory)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	core, err := api.New(lc.HTTPClient, lc.UserAgent, lc.CADirURL, a.reg.URI, a.key)
	if err != nil {
		return nil, fmt.Errorf("certs: ACME directory: %w", err)
	}
	return &legoIssuer{client: client, newOrder: core.GetDirectory().NewOrderURL, log: log}, nil
}

func (l *legoIssuer) Window(cert *x509.Certificate) (*Window, error) {
	info, err := l.client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if errors.Is(err, api.ErrNoARI) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Window{Start: info.SuggestedWindow.Start, End: info.SuggestedWindow.End}, nil
}

func (l *legoIssuer) Obtain(names []string, old *x509.Certificate) ([]byte, []byte, error) {
	obtain := func(replaces string) (*certificate.Resource, error) {
		return l.client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: names, Bundle: true, ReplacesCertID: replaces,
		})
	}
	res, err := obtainReplacing(obtain, old, l.newOrder, l.log.With("names",
		strings.Join(names, ",")))
	if err != nil {
		return nil, nil, err
	}
	return res.Certificate, res.PrivateKey, nil
}

// obtainFunc asks the CA for one certificate, naming by its ARI id the one it replaces
type obtainFunc func(replaces string) (*certificate.Resource, error)

// obtainReplacing orders as old's replacement, then once without when the CA refuses that order
func obtainReplacing(
	obtain obtainFunc, old *x509.Certificate, newOrder string, log *slog.Logger,
) (*certificate.Resource, error) {
	var id string
	if old != nil {
		id, _ = certificate.MakeARICertID(old)
	}
	res, err := obtain(id)
	if err != nil && id != "" && refusedOrder(err, newOrder) {
		log.Warn("the CA refused the order as a replacement, ordering again without it",
			"err", err)
		res, err = obtain("")
	}
	return res, err
}

const acmeProblem = "urn:ietf:params:acme:error:"

// refusedOrder is the CA refusing the new order request, before any validation ran
func refusedOrder(err error, newOrder string) bool {
	var p *acme.ProblemDetails
	if !errors.As(err, &p) || p.URL != newOrder {
		return false
	}
	switch p.Type {
	case acmeProblem + "malformed", acmeProblem + "unauthorized", acme.AlreadyReplacedErr:
		return true
	}
	return p.HTTPStatus == http.StatusConflict
}
