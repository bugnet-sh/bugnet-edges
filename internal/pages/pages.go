// Package pages writes the edge's own HTML pages and the transfer route's JSON errors
package pages

import (
	"bytes"
	_ "embed"
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

// The pages of DP 8.6 by situation, and 421 for a request on another name's connection
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
	Misdirected = Page{status: 421, title: "Wrong connection",
		text: "This request reached the wrong connection. Reload the page."}
	Revoked = Page{status: 410, title: "Preview turned off",
		text: "This preview was turned off and its links no longer work."}
	Forbidden = Page{status: 403, title: "Refused",
		text: "This request did not come from the preview page itself."}
	BadRequest = Page{status: 400, title: "Bad request",
		text: "This request is not one the preview can follow."}
	TooLarge = Page{status: 431, title: "Request too large",
		text: "The request headers are too large. Clear the cookies of this site and try again."}
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
		Misdirected, NothingOnPort(3000), Revoked, Forbidden, BadRequest, TooLarge,
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
	execute(w, layout, p.status, p.retryAfter, view{Title: p.title, Text: p.text})
}

func execute(
	w http.ResponseWriter, tmpl *template.Template, status int, retryAfter time.Duration, v any,
) {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, v); err != nil {
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
	v := view{
		Title: "Bugnet previews",
		Text: "Pages under this address are previews of apps that run in temporary Bugnet " +
			"sandboxes. Anonymous users start them, and Bugnet has not checked them. Each " +
			"link works only while its sandbox runs.",
		Contact: abuseContact,
		Link:    contactLink(abuseContact),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			Write(w, NotFound)
			return
		}
		execute(w, landingPage, http.StatusOK, 0, v)
	})
}

// contactLink is a mailto link for a mail address and the URL itself for an https one
func contactLink(contact string) string {
	if strings.HasPrefix(contact, "https://") {
		return contact
	}
	return "mailto:" + contact
}

// Warning is what the interstitial shows about one preview and the form that continues to it
type Warning struct {
	Started time.Time
	Ends    time.Time
	Source  string // placements.source_label as stored, empty when unknown
	Contact string // previews.abuse_contact
	Token   string
	Next    string // the clean path and query Continue answers with
}

// WarningText is DP 8.2.4's warning, word for word
const WarningText = "This page is served by code running in a temporary Bugnet sandbox that an " +
	"anonymous user paid for. Bugnet has not checked it. Do not enter passwords, keys or " +
	"payment details unless you started this sandbox yourself."

// sourceMax is how many characters of the source label the interstitial shows
const sourceMax = 120

// Interstitial answers 200 with the warning a browser sees before a preview's first page
func Interstitial(w http.ResponseWriter, warn Warning) {
	source := []rune(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, warn.Source))
	execute(w, warningPage, http.StatusOK, 0, interstitialView{
		Text: WarningText, Started: stamp(warn.Started), Ends: stamp(warn.Ends),
		Source:  string(source[:min(len(source), sourceMax)]),
		Contact: warn.Contact, Link: contactLink(warn.Contact),
		Token: warn.Token, Next: warn.Next,
	})
}

// stamp is a time as the interstitial shows it, in UTC to the minute
func stamp(t time.Time) string {
	if t.IsZero() {
		return "an unknown time"
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

type interstitialView struct {
	Text          string
	Started, Ends string
	Source        string
	Contact, Link string
	Token, Next   string
}

type view struct {
	Title   string
	Text    string
	Contact string
	Link    string
}

var (
	//go:embed landing.html
	landingHTML string
	//go:embed interstitial.html
	interstitialHTML string

	base        = template.Must(template.New("style").Parse(style))
	layout      = template.Must(template.Must(base.Clone()).New("page").Parse(pageHTML))
	landingPage = template.Must(template.Must(base.Clone()).New("landing").Parse(landingHTML))
	warningPage = template.Must(template.Must(base.Clone()).New("interstitial").
			Parse(interstitialHTML))
)

const style = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<style>
body{margin:0;font:16px/1.5 system-ui,sans-serif;color:#1d1d1f;background:#fafafa}
main{max-width:34rem;margin:15vh auto 0;padding:0 1.25rem}
h1{font-size:1.5rem;margin:0 0 .75rem}
a{color:#0b57d0}
code{font:14px/1.4 ui-monospace,monospace;overflow-wrap:anywhere}
button{font:inherit;padding:.5rem 1.25rem;border:1px solid #0b57d0;border-radius:.375rem;
color:#fff;background:#0b57d0;cursor:pointer}
button:focus:not(:focus-visible){outline:none}
@media (prefers-color-scheme:dark){body{color:#ececec;background:#161616}a{color:#8ab4f8}
button{border-color:#8ab4f8;color:#161616;background:#8ab4f8}}
</style>`

const pageHTML = `<!doctype html>
<html lang="en">
<head>
{{template "style"}}
<title>{{.Title}}</title>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Text}}</p>
</main>
</body>
</html>
`
