package sshgw

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

// The banners of DP 9.3 step 4 and the line a failed upstream gets
const (
	bannerDenied   = "bugnet: this key is not accepted for this alias, or the sandbox has ended"
	bannerFull     = "bugnet: this sandbox already has 8 SSH connections"
	bannerRetry    = "bugnet: try again in a few seconds"
	upstreamFailed = "bugnet: the sandbox's SSH server is not reachable yet, " +
		"try again in a few seconds"
)

const (
	// keyCacheTTL is how long checkKey remembers the router's answer for an alias and key
	keyCacheTTL              = 10 * time.Second
	keyCacheMax              = 10000
	routerDomain             = "bugnet.router"
	reasonTooManyConnections = "TOO_MANY_CONNECTIONS"
)

// acceptedAlgorithms are the public key algorithms the gateway verifies, never ssh-rsa with SHA-1
var acceptedAlgorithms = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

var (
	errDenied = errors.New("sshgw: the key is not accepted")
	errFull   = errors.New("sshgw: the sandbox has all its connections")
	errRetry  = errors.New("sshgw: the router cannot answer now")
)

// verdict is what a router answer means for the user
type verdict int

const (
	allowed verdict = iota
	denied
	full
	retry
)

func (v verdict) banner() string {
	switch v {
	case denied:
		return bannerDenied
	case full:
		return bannerFull
	}
	return bannerRetry
}

func (v verdict) err() error {
	switch v {
	case denied:
		return errDenied
	case full:
		return errFull
	}
	return errRetry
}

// classify turns a router error into a verdict, every unexpected one reading as try again
func classify(err error) verdict {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound, connect.CodePermissionDenied, connect.CodeFailedPrecondition:
		return denied
	case connect.CodeResourceExhausted:
		if reasonOf(err) == reasonTooManyConnections {
			return full
		}
		return denied
	}
	return retry
}

// reasonOf is the ErrorInfo reason the router put on err, empty when there is none
func reasonOf(err error) string {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return ""
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if info, ok := v.(*errdetails.ErrorInfo); derr == nil && ok &&
			info.GetDomain() == routerDomain {
			return info.GetReason()
		}
	}
	return ""
}

// banner is the error that makes x/crypto/ssh print text before it fails the attempt
func banner(v verdict) error {
	return &ssh.BannerError{Err: v.err(), Message: v.banner() + "\r\n"}
}

/* The key cache */

type keyID struct{ alias, fingerprint string }

type keyAnswer struct {
	grant   *routerv1.AuthorizeSshKeyResponse
	verdict verdict
	until   time.Time
}

// keyCache keeps AuthorizeSshKey answers for keyCacheTTL, so a client's retries ask once
type keyCache struct {
	mu sync.Mutex
	m  map[keyID]keyAnswer
}

func newKeyCache() *keyCache { return &keyCache{m: map[keyID]keyAnswer{}} }

func (k *keyCache) get(id keyID, now time.Time) (keyAnswer, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	a, ok := k.m[id]
	if !ok || !now.Before(a.until) {
		delete(k.m, id)
		return keyAnswer{}, false
	}
	if a.grant != nil && a.grant.GetDeadline() != nil &&
		!now.Before(a.grant.GetDeadline().AsTime()) {
		delete(k.m, id)
		return keyAnswer{}, false
	}
	return a, true
}

func (k *keyCache) put(id keyID, a keyAnswer, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.m) >= keyCacheMax {
		for id, old := range k.m {
			if !now.Before(old.until) {
				delete(k.m, id)
			}
		}
		if len(k.m) >= keyCacheMax {
			clear(k.m)
		}
	}
	a.until = now.Add(keyCacheTTL)
	k.m[id] = a
}

func (k *keyCache) forget(id keyID) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, id)
}

/* Failures per alias */

// aliasFailures counts refused attempts on each alias, so a guessed alias draws few router calls
type aliasFailures struct {
	limit int
	mu    sync.Mutex
	m     map[string]*aliasWindow
}

type aliasWindow struct {
	start time.Time
	n     int
	last  time.Time // the last router call allowed past the limit
}

const aliasWindowLen = time.Minute

func newAliasFailures(perMinute int) *aliasFailures {
	return &aliasFailures{limit: perMinute, m: map[string]*aliasWindow{}}
}

func (a *aliasFailures) window(alias string, now time.Time) *aliasWindow {
	w := a.m[alias]
	if w == nil || now.Sub(w.start) >= aliasWindowLen {
		if len(a.m) >= keyCacheMax {
			clear(a.m)
		}
		w = &aliasWindow{start: now}
		a.m[alias] = w
	}
	return w
}

// fail counts one refused attempt on alias
func (a *aliasFailures) fail(alias string) {
	if a.limit <= 0 {
		return
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.window(alias, now).n++
}

// mayAsk is false for most router calls on an alias past its limit, one a second still goes
func (a *aliasFailures) mayAsk(alias string) bool {
	if a.limit <= 0 {
		return true
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	w := a.window(alias, now)
	if w.n < a.limit {
		return true
	}
	if now.Sub(w.last) < time.Second {
		return false
	}
	w.last = now
	return true
}

/* The callbacks of one connection */

// checkKey is PublicKeyCallback, read-only and also run for key queries
func (c *conn) checkKey(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, banner(denied)
	}
	fp := ssh.FingerprintSHA256(key)
	grant, v := c.g.authorize(c.ctx, meta.User(), key, fp, c.ip)
	if v != allowed {
		return nil, banner(v)
	}
	c.rememberGrant(fp, grant)
	return &ssh.Permissions{Extensions: map[string]string{extFingerprint: fp}}, nil
}

// extFingerprint names the key a Permissions was made for, so acquire sees the verified key
const extFingerprint = "fingerprint"

// authorize asks the router whether alias and key may connect, answering from its cache for 10 s
func (g *Gateway) authorize(
	ctx context.Context, alias string, key ssh.PublicKey, fp string, ip netip.Addr,
) (*routerv1.AuthorizeSshKeyResponse, verdict) {
	id := keyID{alias, fp}
	now := time.Now()
	if a, ok := g.keys.get(id, now); ok {
		return a.grant, a.verdict
	}
	if !g.aliases.mayAsk(alias) {
		return nil, denied
	}
	ctx, cancel := context.WithTimeout(ctx, g.routerTimeout)
	defer cancel()
	res, err := g.router.AuthorizeSshKey(ctx, connect.NewRequest(&routerv1.AuthorizeSshKeyRequest{
		Alias: alias, PublicKey: key.Marshal(), ClientIp: ip.String(),
	}))
	if err != nil {
		v := classify(err)
		if v == denied {
			g.keys.put(id, keyAnswer{verdict: denied}, now)
		}
		return nil, v
	}
	g.keys.put(id, keyAnswer{grant: res.Msg, verdict: allowed}, now)
	return res.Msg, allowed
}

// acquire is VerifiedPublicKeyCallback, the only place a connection lease is taken (S7)
func (c *conn) acquire(
	meta ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, _ string,
) (*ssh.Permissions, error) {
	fp := ssh.FingerprintSHA256(key)
	grant := c.grantFor(fp)
	if grant == nil || perms == nil || perms.Extensions[extFingerprint] != fp {
		return nil, banner(denied)
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.g.routerTimeout)
	defer cancel()
	res, err := c.g.router.AcquireSshConnection(ctx,
		connect.NewRequest(&routerv1.AcquireSshConnectionRequest{
			GrantId: grant.GetGrantId(), GatewayId: c.g.cfg.GatewayID,
		}))
	if err != nil {
		v := classify(err)
		if v == denied {
			c.g.keys.forget(keyID{meta.User(), fp})
		}
		return c.refuse(v)
	}
	c.attach(grant, fp, res.Msg)
	return perms, nil
}

// refuse is a failed lease, an auth banner or with banner_fallback the first session's stderr
func (c *conn) refuse(v verdict) (*ssh.Permissions, error) {
	if c.g.cfg.BannerFallback {
		return &ssh.Permissions{Extensions: map[string]string{extRefuse: v.banner()}}, nil
	}
	return nil, banner(v)
}

// extRefuse carries the text the first session shows when the auth banner fallback is on
const extRefuse = "refuse"

// authLog counts refused attempts per address and alias, never a key query that succeeded
func (c *conn) authLog(meta ssh.ConnMetadata, method string, err error) {
	switch {
	case method != "publickey":
	case err == nil:
		c.g.m.auths.Inc("ok")
	case errors.Is(err, errDenied):
		c.g.m.auths.Inc("denied")
		c.g.guard.Failed(c.ip)
		c.g.aliases.fail(meta.User())
	case errors.Is(err, errFull):
		c.g.m.auths.Inc("full")
	case errors.Is(err, errRetry):
		c.g.m.auths.Inc("retry")
	default:
		c.g.m.auths.Inc("failed")
		c.g.guard.Failed(c.ip)
		c.g.aliases.fail(meta.User())
	}
}
