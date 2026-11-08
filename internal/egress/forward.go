package egress

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"
)

type reqKey struct{}

// reqState is what the proxy learned about one request, shared with the response hooks
type reqState struct {
	host    string
	swap    swapped
	status  int
	bytes   int64
	counted bool
}

func stateOf(ctx context.Context) *reqState {
	st, _ := ctx.Value(reqKey{}).(*reqState)
	return st
}

// newTransport reaches public hosts only, verifying certificates against the public roots
func (s *Server) newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           s.dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		ExpectContinueTimeout: time.Second,
	}
}

// newProxy forwards each request to https://<host> on port 443 and never follows a redirect
func (s *Server) newProxy(t http.RoundTripper) http.Handler {
	if t == nil {
		t = s.newTransport()
	}
	return &httputil.ReverseProxy{
		// Rewrite, not Director, so no X-Forwarded-* header is added or passed on
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := stateOf(pr.In.Context()).host
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = host
			pr.Out.Host = host
		},
		Transport:     t,
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			st := stateOf(resp.Request.Context())
			st.status = resp.StatusCode
			scrubHeader(resp.Header, st.swap.scrub)
			scrubHeader(resp.Trailer, st.swap.scrub)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			s.log.Debug("egress: the upstream request failed")
			if st := stateOf(r.Context()); st != nil {
				st.status = http.StatusBadGateway
			}
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
		ErrorLog: s.errorLog(),
	}
}

// itoa is strconv.Itoa for the metric labels
func itoa(n int) string {
	return strconv.Itoa(n)
}
