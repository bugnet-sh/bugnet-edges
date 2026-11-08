package egress

import (
	"crypto/tls"
	"net/http"
	"time"
)

// newSellerTransport reaches x402 sellers over the refusing dialer, checking certificates against
// the public roots for the host asked for. Only RoundTrip is ever called on it, so no redirect
// is followed and no payment header rides one.
func (s *Server) newSellerTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            s.dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: int64(s.cfg.X402.SellerHeaderMax),
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        90 * time.Second,
		DisableCompression:     true,
		ExpectContinueTimeout:  time.Second,
	}
}
