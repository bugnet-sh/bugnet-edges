package egress

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// innerServer serves the requests that arrive inside the tunnels, HTTP/1.1 and HTTP/2
func (s *Server) innerServer() *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &http.Server{
		Handler:           http.HandlerFunc(s.serveInner),
		Protocols:         &protocols,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: s.cfg.MaxStreamsPerTunnel},
		ReadHeaderTimeout: time.Minute,
		IdleTimeout:       time.Duration(s.cfg.TunnelIdleTimeout),
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          s.errorLog(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if info, ok := s.conns.Load(c); ok {
				return context.WithValue(ctx, infoKey{}, info)
			}
			return ctx
		},
	}
}

type infoKey struct{}

// statusWriter records the status and the bytes of a response, passing hijacks and flushes on
type statusWriter struct {
	http.ResponseWriter
	st *reqState
}

func (w *statusWriter) WriteHeader(code int) {
	if code >= 200 {
		w.st.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.st.status == 0 {
		w.st.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.st.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and Hijack
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// hostOf is the Host of a request without port 443, lower case and without a final dot
func hostOf(h string) string {
	h = strings.TrimSuffix(h, ":443")
	return normalHost(h)
}

// serveInner is the only place values appear (DP 10.5, each request)
func (s *Server) serveInner(w http.ResponseWriter, r *http.Request) {
	info, _ := r.Context().Value(infoKey{}).(*connInfo)
	if info == nil {
		http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}
	p := info.p
	st := &reqState{host: info.sni}
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w, st: st}
	defer func() { s.finish(p, r, st, start) }()

	// Host and SNI must agree, which stops domain fronting
	if hostOf(r.Host) != info.sni {
		answer(sw, http.StatusMisdirectedRequest)
		return
	}
	if r.Method == http.MethodTrace || r.Method == "TRACK" {
		sw.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
		answer(sw, http.StatusMethodNotAllowed)
		return
	}
	for k := range r.Header {
		if strings.HasPrefix(k, "Bugnet-") {
			delete(r.Header, k)
		}
	}
	select {
	case p.flight <- struct{}{}:
		defer func() { <-p.flight }()
	case <-r.Context().Done():
		return
	}

	kind := s.kindOf(p, st.host)
	v := p.view()
	if kind == kindX402 {
		s.serveX402(sw, r, p, st, v.x402)
		return
	}
	st.swap = swapHeaders(r.Header, st.host, v.set)
	if st.swap.missing {
		// A placeholder the cached set lacks may be a secret added a moment ago
		p.refresh(r.Context(), true)
		v = p.view()
		st.swap.merge(swapHeaders(r.Header, st.host, v.set))
	}
	switch kind {
	case kindNone:
		answer(sw, http.StatusMisdirectedRequest)
		return
	case kindCustom:
		// Without a swap a custom host would be a free relay
		if !st.swap.did() {
			answer(sw, http.StatusForbidden)
			return
		}
		if !s.custom.allow(st.host) {
			sw.Header().Set("Retry-After", "60")
			answer(sw, http.StatusTooManyRequests)
			return
		}
	}
	ctx := context.WithValue(r.Context(), reqKey{}, st)
	s.proxy.ServeHTTP(sw, r.WithContext(ctx))
}

func answer(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

// finish counts and logs the request, never a header value, a URL with a query or a body
func (s *Server) finish(p *placement, r *http.Request, st *reqState, start time.Time) {
	kind := "preset"
	switch p.view().hosts[st.host] {
	case kindCustom:
		kind = "custom"
		s.custom.addBytes(st.host, st.bytes)
	case kindX402:
		kind = "x402"
	}
	s.m.requests.Inc(kind, itoa(st.status), boolText(st.swap.did()))
	secret := ""
	if len(st.swap.names) > 0 {
		secret = strings.Join(st.swap.names, ",")
	}
	s.log.Info("egress: request", "placement", p.short, "host", st.host, "method", r.Method,
		"status", st.status, "bytes", st.bytes, "swapped", st.swap.did(), "secret", secret,
		"took", time.Since(start).Round(time.Millisecond).String())
}
