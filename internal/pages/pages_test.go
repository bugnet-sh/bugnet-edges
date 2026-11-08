package pages

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const wantCSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; " +
	"frame-ancestors 'none'"

func write(p Page) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	Write(w, p)
	return w
}

func writeJSON(c Code) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	WriteJSON(w, c)
	return w
}

func landing(t *testing.T, contact string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	Landing(contact).ServeHTTP(w, httptest.NewRequest("GET", "https://preview.example.test/", nil))
	return w
}

func TestPageStatusesAndTexts(t *testing.T) {
	for _, tc := range []struct {
		page   Page
		status int
		text   string
		retry  string
	}{
		{NotFound, 404, "No such preview", ""},
		{Unauthorized, 401, "This link is incomplete or no longer valid", ""},
		{Ended, 410, "This sandbox has ended and everything in it was deleted", ""},
		{BudgetSpent, 429, "This sandbox reached its traffic limit", ""},
		{SlowDown, 429, "Slow down", "60"},
		{SlowDown.RetryAfter(10 * time.Minute), 429, "Slow down", "600"},
		{Busy, 503, "Busy", "2"},
		{NothingOnPort(5173), 502, "Nothing is listening on port 5173 in the sandbox yet", ""},
		{GateDown, 502, "preview service stopped. Reload in a minute", ""},
		{RouterDown, 503, "Try again shortly", "2"},
		{Misdirected, 421, "reached the wrong connection", ""},
		{Revoked, 410, "This preview was turned off", ""},
		{Forbidden, 403, "did not come from the preview page", ""},
		{BadRequest, 400, "not one the preview can follow", ""},
		{TooLarge, 431, "Clear the cookies of this site", ""},
	} {
		w := write(tc.page)
		eq(t, w.Code, tc.status)
		eq(t, tc.page.Status(), tc.status)
		if !strings.Contains(w.Body.String(), tc.text) {
			t.Fatalf("%d: %q missing from\n%s", tc.status, tc.text, w.Body)
		}
		eq(t, w.Header().Get("Retry-After"), tc.retry)
	}
}

func TestPageHeaders(t *testing.T) {
	for _, w := range []*httptest.ResponseRecorder{
		write(NotFound), write(NothingOnPort(80)), landing(t, "abuse@example.test"),
	} {
		h := w.Header()
		eq(t, h.Get("Content-Type"), "text/html; charset=utf-8")
		eq(t, h.Get("Cache-Control"), "no-store")
		eq(t, h.Get("Referrer-Policy"), "no-referrer")
		eq(t, h.Get("X-Content-Type-Options"), "nosniff")
		eq(t, h.Get("Content-Security-Policy"), wantCSP)
		eq(t, h.Get("Set-Cookie"), "")
	}
	h := http.Header{}
	Headers(h)
	eq(t, h.Get("Content-Security-Policy"), wantCSP)
}

func TestLandingNamesTheAbuseContact(t *testing.T) {
	w := landing(t, "abuse@example.test")
	eq(t, w.Code, 200)
	if !strings.Contains(w.Body.String(), `href="mailto:abuse@example.test"`) {
		t.Fatalf("no mail link in\n%s", w.Body)
	}
	w = landing(t, "https://example.test/abuse?a=1&b=2")
	if !strings.Contains(w.Body.String(), `href="https://example.test/abuse?a=1&amp;b=2"`) {
		t.Fatalf("no web link in\n%s", w.Body)
	}
	w = landing(t, `"><script>x</script>@example.test`)
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatalf("the contact reached the page unescaped\n%s", w.Body)
	}
	r := httptest.NewRequest("POST", "https://preview.example.test/", nil)
	w = httptest.NewRecorder()
	Landing("abuse@example.test").ServeHTTP(w, r)
	eq(t, w.Code, 404)
}

func TestJSONErrors(t *testing.T) {
	for _, tc := range []struct {
		code   Code
		status int
		name   string
		retry  string
	}{
		{TokenUnknown, 404, "token_unknown", ""},
		{TokenUsed, 410, "token_used", ""},
		{TokenExpired, 410, "token_expired", ""},
		{SandboxEnded, 410, "sandbox_ended", ""},
		{TooLong, 408, "too_long", ""},
		{TrafficLimit, 429, "budget_spent", ""},
		{RateLimited, 429, "rate_limited", "60"},
		{RateLimited.RetryAfter(1500 * time.Millisecond), 429, "rate_limited", "2"},
		{InUse, 409, "in_use", ""},
		{SizeMismatch, 400, "size_mismatch", ""},
		{OverCap, 413, "over_cap", ""},
		{FileChanged, 412, "file_changed", ""},
		{Range, 416, "range", ""},
		{ChecksumMismatch, 422, "checksum_mismatch", ""},
		{NoSpace, 507, "no_space", ""},
		{Unavailable, 503, "unavailable", "2"},
		{MethodNotAllowed, 405, "method", ""},
		{ContentRange, 400, "content_range", ""},
		{TooManyTransfers, 429, "too_many_transfers", "10"},
		{HeadersTooLarge, 431, "headers_too_large", ""},
	} {
		w := writeJSON(tc.code)
		eq(t, w.Code, tc.status)
		eq(t, tc.code.Status(), tc.status)
		eq(t, w.Header().Get("Content-Type"), "application/json")
		eq(t, w.Header().Get("Cache-Control"), "no-store")
		eq(t, w.Header().Get("X-Content-Type-Options"), "nosniff")
		eq(t, w.Header().Get("Retry-After"), tc.retry)
		var body map[string]string
		dec := json.NewDecoder(w.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			t.Fatal(err)
		}
		eq(t, body["error"], tc.name)
		eq(t, len(body), 2)
		if body["message"] == "" {
			t.Fatalf("%s has no message", tc.name)
		}
	}
}

func TestPagesNeverNameTheProvider(t *testing.T) {
	var answers []*httptest.ResponseRecorder
	for _, p := range all() {
		answers = append(answers, write(p))
	}
	for _, c := range allCodes() {
		answers = append(answers, writeJSON(c))
	}
	answers = append(answers, landing(t, "abuse@example.test"), warn(Warning{
		Started: time.Now(), Ends: time.Now(), Source: "github.com/acme/app@1a2b3c4",
		Contact: "abuse@example.test", Token: "bnp_x", Next: "/",
	}))
	if len(answers) < 25 {
		t.Fatalf("only %d answers checked", len(answers))
	}
	for _, w := range answers {
		var text strings.Builder
		text.WriteString(w.Body.String())
		for k, v := range w.Header() {
			text.WriteString(k + strings.Join(v, ""))
		}
		lower := strings.ToLower(text.String())
		for _, name := range []string{"e2b", "boxd", "koyeb", "boat"} {
			if strings.Contains(lower, name) {
				t.Fatalf("%q in\n%s", name, text.String())
			}
		}
	}
}

func warn(w Warning) *httptest.ResponseRecorder {
	r := httptest.NewRecorder()
	Interstitial(r, w)
	return r
}

func TestInterstitial(t *testing.T) {
	start := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	w := warn(Warning{
		Started: start, Ends: start.Add(10 * time.Minute),
		Source: "github.com/acme/app@1a2b3c4", Contact: "https://example.test/abuse",
		Token: "bnp_abc", Next: "/app?page=2&q=a%20b",
	})
	eq(t, w.Code, 200)
	eq(t, w.Header().Get("Cache-Control"), "no-store")
	eq(t, w.Header().Get("Referrer-Policy"), "no-referrer")
	eq(t, w.Header().Get("X-Content-Type-Options"), "nosniff")
	eq(t, w.Header().Get("Content-Security-Policy"), wantCSP)
	body := w.Body.String()
	for _, want := range []string{
		WarningText,
		"started 2026-11-08 10:00 UTC and ends 2026-11-08 10:10 UTC",
		"Source: <code>github.com/acme/app@1a2b3c4</code>",
		`<form method="post" action="/__bugnet/continue">`,
		`name="token" value="bnp_abc"`,
		`name="next" value="/app?page=2&amp;q=a%20b"`,
		`<a href="https://example.test/abuse">Report abuse</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("%q missing from\n%s", want, body)
		}
	}
	if strings.Count(WarningText, ".") != 3 || !strings.HasPrefix(WarningText, "This page is "+
		"served by code running in a temporary Bugnet sandbox that an anonymous user paid for.") {
		t.Fatalf("the warning is not DP 8.2.4's: %q", WarningText)
	}
}

func TestInterstitialSourceIsDataCutTo120(t *testing.T) {
	w := warn(Warning{Source: "<script>alert(1)</script>\x00" + strings.Repeat("a", 200),
		Contact: "abuse@example.test"})
	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("the source reached the page as markup\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;"+strings.Repeat("a", 95)+
		"</code>") {
		t.Fatalf("the source is not cut to 120 characters\n%s", body)
	}
	eq(t, strings.Contains(warn(Warning{Contact: "a@example.test"}).Body.String(), "Source:"),
		false)
	eq(t, strings.Contains(body, `href="mailto:abuse@example.test"`), true)
	eq(t, strings.Contains(body, "an unknown time"), true)
}
