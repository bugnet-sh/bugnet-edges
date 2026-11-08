package preview

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/bugnet-sh/bugnet-edges/internal/pages"
)

// maxForm bounds the Continue form, which holds only a token and a path
const maxForm = 16 << 10

// warn shows the interstitial for a browser's first page load with the token in the query
func (h *handler) warn(w http.ResponseWriter, r *http.Request, rt *route, tok string) {
	pages.Interstitial(w, pages.Warning{
		Started: rt.started, Ends: rt.expires, Source: rt.source,
		Contact: h.d.AbuseContact, Token: tok, Next: target(r),
	})
}

// cont is POST /__bugnet/continue, which sets the cookie and sends the browser to next
func (h *handler) cont(w http.ResponseWriter, r *http.Request, id, host string) {
	if r.Header.Get("Origin") != "https://"+host {
		pages.Write(w, pages.Forbidden)
		return
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
		pages.Write(w, pages.Forbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		pages.Write(w, pages.BadRequest)
		return
	}
	next, ok := cleanNext(r.PostForm.Get("next"))
	if !ok {
		pages.Write(w, pages.BadRequest)
		return
	}
	tok := r.PostForm.Get("token")
	if _, page, ok := h.lookup(r.Context(), id, tok, clientIP(r)); !ok {
		pages.Write(w, page)
		return
	}
	hd := w.Header()
	hd.Add("Set-Cookie", cookieFor(tok))
	hd.Set("Location", next)
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusSeeOther)
}

// cleanNext rebuilds next as a path and query on this host, refusing what could leave it
func cleanNext(next string) (string, bool) {
	if next == "" {
		return "/", true
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsRune(next, '\\') || strings.ContainsFunc(next, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return "", false
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	rest, _ := stripToken(u.RawQuery)
	out := (&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: rest}).String()
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "", false
	}
	return out, true
}
