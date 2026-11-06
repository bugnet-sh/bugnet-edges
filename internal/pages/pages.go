// Package pages writes the edge's own HTML pages and the transfer route's JSON errors
package pages

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Page is one HTML answer the edge makes itself, never naming the provider
type Page struct {
	status     int
	title      string
	text       string
	retryAfter time.Duration
}

// The pages of DP 8.6, by situation
var (
	NotFound = Page{status: 404, title: "No such preview",
		text: "There is nothing at this address. Check that you copied the whole link."}
	Unauthorized = Page{status: 401, title: "Link not valid",
		text: "This link is incomplete or no longer valid."}
	Ended = Page{status: 410, title: "Sandbox ended",
		text: "This sandbox has ended and everything in it was deleted."}
	BudgetSpent = Page{status: 429, title: "Traffic limit reached",
		text: "This sandbox reached its traffic limit."}
	SlowDown = Page{status: 429, title: "Slow down",
		text:       "Too many requests came from your address. Try again later.",
		retryAfter: time.Minute}
	Busy = Page{status: 503, title: "Busy",
		text: "This preview is busy. Try again in a moment.", retryAfter: 2 * time.Second}
	GateDown = Page{status: 502, title: "Preview stopped",
		text: "The sandbox's preview service stopped. Reload in a minute."}
	RouterDown = Page{status: 503, title: "Try again shortly",
		text: "Try again shortly.", retryAfter: 2 * time.Second}
)

// NothingOnPort is the 502 page for a sandbox port no app listens on yet
func NothingOnPort(port int) Page {
	return Page{status: 502, title: "Nothing on port " + strconv.Itoa(port),
		text: fmt.Sprintf("Nothing is listening on port %d in the sandbox yet. "+
			"Reload once the app has started.", port)}
}

// all lists every page, for tests
func all() []Page {
	return []Page{
		NotFound, Unauthorized, Ended, BudgetSpent, SlowDown, Busy, GateDown, RouterDown,
		NothingOnPort(3000),
	}
}

// RetryAfter is the page answered with a Retry-After of d, rounded up to whole seconds
func (p Page) RetryAfter(d time.Duration) Page {
	p.retryAfter = d
	return p
}

// Status is the page's HTTP status
func (p Page) Status() int {
	return p.status
}

const csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; " +
	"frame-ancestors 'none'"

// Headers sets the headers every edge page carries, the interstitial's
func Headers(h http.Header) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", csp)
}

// Write answers with the page
func Write(w http.ResponseWriter, p Page) {
	render(w, p.status, p.retryAfter, view{Title: p.title, Text: p.text})
}

func render(w http.ResponseWriter, status int, retryAfter time.Duration, v view) {
	var b bytes.Buffer
	if err := layout.Execute(&b, v); err != nil {
		status = http.StatusInternalServerError
		b.Reset()
	}
	h := w.Header()
	Headers(h)
	setRetryAfter(h, retryAfter)
	h.Set("Content-Length", strconv.Itoa(b.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

func setRetryAfter(h http.Header, d time.Duration) {
	if d > 0 {
		h.Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
	}
}

// Landing serves the short page that says what previews are and where to report abuse
func Landing(abuseContact string) http.Handler {
	link := "mailto:" + abuseContact
	if strings.HasPrefix(abuseContact, "https://") {
		link = abuseContact
	}
	v := view{
		Title: "Bugnet previews",
		Text: "Pages under this address are previews of apps that run in temporary Bugnet " +
			"sandboxes. Anonymous users start them, and Bugnet has not checked them. Each " +
			"link works only while its sandbox runs.",
		Contact: abuseContact,
		Link:    link,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Write(w, NotFound)
			return
		}
		render(w, http.StatusOK, 0, v)
	})
}

type view struct {
	Title   string
	Text    string
	Contact string
	Link    string
}

var layout = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
body{margin:0;font:16px/1.5 system-ui,sans-serif;color:#1d1d1f;background:#fafafa}
main{max-width:34rem;margin:15vh auto 0;padding:0 1.25rem}
h1{font-size:1.5rem;margin:0 0 .75rem}
a{color:#0b57d0}
@media (prefers-color-scheme:dark){body{color:#ececec;background:#161616}a{color:#8ab4f8}}
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Text}}</p>
{{- if .Contact}}
<p>To report abuse, write to <a href="{{.Link}}">{{.Contact}}</a>.</p>
{{- end}}
</main>
</body>
</html>
`))
