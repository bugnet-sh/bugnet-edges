// Package routerclient builds the HTTP clients the edge binaries call router-api with
package routerclient

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	errOtherHost = errors.New("routerclient: the router token goes only to the router URL")
	errBaseURL   = errors.New("routerclient: the router URL is not an http or https URL")
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
	// pingAfter sends a ping on a silent shared connection, so a dead router is noticed
	pingAfter   = 30 * time.Second
	pingTimeout = 15 * time.Second
)

// New is the shared client, h2c to an http router so calls share one connection, TLS otherwise
func New(baseURL, token string) *http.Client {
	var p http.Protocols
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		p.SetHTTP1(true)
		p.SetHTTP2(true)
	} else {
		p.SetUnencryptedHTTP2(true)
	}
	t := transport(p)
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: pingAfter, PingTimeout: pingTimeout}
	return client(baseURL, token, t)
}

// PerCall is HTTP/1.1 with DisableKeepAlives, one connection per call
func PerCall(baseURL, token string) *http.Client {
	var p http.Protocols
	p.SetHTTP1(true)
	t := transport(p)
	t.DisableKeepAlives = true
	return client(baseURL, token, t)
}

// transport never goes through an environment proxy, since the router is on a private address
func transport(p http.Protocols) *http.Transport {
	d := &net.Dialer{Timeout: dialTimeout}
	return &http.Transport{
		Protocols:           &p,
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: handshakeTimeout,
	}
}

func client(baseURL, token string, next http.RoundTripper) *http.Client {
	b := &bearer{auth: "Bearer " + token, next: next}
	u, err := url.Parse(baseURL)
	if err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		b.scheme, b.host = u.Scheme, strings.ToLower(u.Host)
	}
	return &http.Client{
		Transport: b,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// bearer sends the token on requests to the router's scheme and host and refuses every other
type bearer struct {
	scheme, host string
	auth         string
	next         http.RoundTripper
}

func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	var err error
	switch {
	case b.host == "":
		err = errBaseURL
	case !strings.EqualFold(r.URL.Scheme, b.scheme) || strings.ToLower(r.URL.Host) != b.host:
		err = errOtherHost
	}
	if err != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", b.auth)
	return b.next.RoundTrip(r)
}
