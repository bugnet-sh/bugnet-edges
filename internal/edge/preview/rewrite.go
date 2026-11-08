package preview

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
)

// The gate's names this route reads and sets, the shared wire names of the plan
const (
	gateKeyHeader  = "Bugnet-Gate"
	portHeader     = "Bugnet-Port"
	hostHeader     = "Bugnet-Host"
	clientIPHeader = "Bugnet-Client-Ip"
	markHeader     = "Bugnet-Gate-Response"
	errorHeader    = "Bugnet-Gate-Error"
	cacheHeader    = "Bugnet-Cache-Control"
	serverHeader   = "Bugnet-Server"
	portClosed     = "port_closed"
	gateBusy       = "busy"
	bugnetPrefix   = "bugnet-"
)

// errProvider is an answer that lacks the gate's mark, so the provider made it
var errProvider = errors.New("preview: the provider answered instead of the gate")

// gateError is the gate's own refusal, named by Bugnet-Gate-Error
type gateError struct {
	value string
}

func (e *gateError) Error() string {
	return "preview: the gate answered " + e.value
}

// rewrite is DP 8.2.5, run on each outgoing request
func (h *handler) rewrite(pr *httputil.ProxyRequest) {
	c := callOf(pr.In)
	pr.SetURL(c.rt.base)
	// ReverseProxy cleans a query it cannot parse, and the app must see the visitor's bytes
	pr.Out.URL.RawQuery, _ = stripToken(pr.In.URL.RawQuery)
	hd := pr.Out.Header
	for name := range hd {
		if strings.HasPrefix(strings.ToLower(name), bugnetPrefix) {
			delete(hd, name)
		}
	}
	requestCookies(hd, c.rt)
	for _, v := range c.rt.headers {
		hd.Set(v.GetName(), v.GetValue())
	}
	hd.Set(portHeader, strconv.Itoa(c.rt.port))
	hd.Set(hostHeader, c.host)
	if c.ip.IsValid() {
		hd.Set(clientIPHeader, c.ip.String())
	}
	if pr.Out.Body != nil && pr.Out.Body != http.NoBody {
		pr.Out.Body = &pacedBody{
			Reader: c.lane.Reader(pr.Out.Body, true, c.countIn), Closer: pr.Out.Body,
		}
	}
}

type pacedBody struct {
	io.Reader
	io.Closer
}

// requestCookies drops __Host-bnp and the route's own cookie names, then adds the route's
func requestCookies(hd http.Header, rt *route) {
	var pairs []string
	for _, line := range hd.Values("Cookie") {
		for p := range strings.SplitSeq(line, ";") {
			p = strings.TrimSpace(p)
			n, _, _ := strings.Cut(p, "=")
			n = strings.TrimSpace(n)
			if p == "" || strings.EqualFold(n, cookieName) || rt.cookieNames[n] {
				continue
			}
			pairs = append(pairs, p)
		}
	}
	for _, c := range rt.cookies {
		pairs = append(pairs, c.GetName()+"="+c.GetValue())
	}
	hd.Del("Cookie")
	if len(pairs) > 0 {
		hd.Set("Cookie", strings.Join(pairs, "; "))
	}
}

// modify is DP 8.2.6, run on each answer before the visitor sees it
func (h *handler) modify(res *http.Response) error {
	hd := res.Header
	if hd.Get(markHeader) == "" {
		return errProvider
	}
	if v := hd.Get(errorHeader); v != "" {
		return &gateError{value: v}
	}
	c := callOf(res.Request)
	restore(hd, "Cache-Control", cacheHeader)
	restore(hd, "Server", serverHeader)
	for name := range hd {
		if dropped(strings.ToLower(name)) {
			delete(hd, name)
		}
	}
	responseCookies(hd, c.rt)
	if loc := hd.Get("Location"); loc != "" {
		hd.Set("Location", rewriteLocation(loc, c.rt.base.Hostname(), c.host))
	}
	return nil
}

// restore puts back the app's header the gate moved aside, or none for the gate's -
func restore(hd http.Header, name, moved string) {
	v, ok := hd[moved]
	if !ok {
		return
	}
	hd.Del(name)
	if len(v) > 0 && v[0] != "-" {
		hd[name] = v
	}
}

func dropped(lower string) bool {
	switch lower {
	case "alt-svc", "nel", "report-to", "reporting-endpoints", "strict-transport-security",
		"via":
		return true
	}
	return strings.HasPrefix(lower, "cf-") || strings.HasPrefix(lower, "x-koyeb-") ||
		strings.HasPrefix(lower, bugnetPrefix)
}

// responseCookies drops __Host-bnp and the route's cookies and strips Domain from the rest
func responseCookies(hd http.Header, rt *route) {
	lines := hd.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	hd.Del("Set-Cookie")
	for _, line := range lines {
		parts := strings.Split(line, ";")
		name, _, _ := strings.Cut(parts[0], "=")
		name = strings.TrimSpace(name)
		if len(name) >= len(cookieName) && strings.EqualFold(name[:len(cookieName)], cookieName) ||
			rt.cookieNames[name] {
			continue
		}
		kept := parts[:1]
		for _, a := range parts[1:] {
			k, _, _ := strings.Cut(a, "=")
			if !strings.EqualFold(strings.TrimSpace(k), "domain") {
				kept = append(kept, a)
			}
		}
		hd.Add("Set-Cookie", strings.Join(kept, ";"))
	}
}

// rewriteLocation points a redirect at the provider or a loopback name back at the preview
func rewriteLocation(loc, provider, preview string) string {
	rest, ok := "", false
	for _, scheme := range []string{"http://", "https://", "//"} {
		if len(loc) >= len(scheme) && strings.EqualFold(loc[:len(scheme)], scheme) {
			rest, ok = loc[len(scheme):], true
			break
		}
	}
	if !ok {
		return loc
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if strings.Contains(authority, "@") {
		return loc
	}
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case strings.ToLower(provider), "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return "https://" + preview + tail
	}
	return loc
}
