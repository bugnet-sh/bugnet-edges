package pages

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Code is one JSON error the transfer route answers instead of a page
type Code struct {
	status     int
	code       string
	message    string
	retryAfter time.Duration
}

// The transfer route's errors of DP 8.6, and the shared situations in the same form
var (
	TokenUnknown = Code{status: 404, code: "token_unknown",
		message: "This transfer link is not known."}
	TokenUsed = Code{status: 410, code: "token_used",
		message: "This transfer link was already used."}
	TokenExpired = Code{status: 410, code: "token_expired",
		message: "This transfer link was not used in time. Ask for a new one."}
	SandboxEnded = Code{status: 410, code: "sandbox_ended",
		message: "This sandbox has ended and everything in it was deleted."}
	TrafficLimit = Code{status: 429, code: "budget_spent",
		message: "This sandbox reached its traffic limit."}
	RateLimited = Code{status: 429, code: "rate_limited",
		message:    "Too many requests came from your address. Try again later.",
		retryAfter: time.Minute}
	InUse = Code{status: 409, code: "in_use",
		message: "This transfer is already running."}
	SizeMismatch = Code{status: 400, code: "size_mismatch",
		message: "The body length differs from the size this link was made for."}
	OverCap = Code{status: 413, code: "over_cap",
		message: "The file is larger than this link allows."}
	FileChanged = Code{status: 412, code: "file_changed",
		message: "The file changed since this link was made."}
	Range = Code{status: 416, code: "range",
		message: "The requested range is outside the file."}
	ChecksumMismatch = Code{status: 422, code: "checksum_mismatch",
		message: "The file's SHA-256 differs from the one given."}
	NoSpace = Code{status: 507, code: "no_space",
		message: "The sandbox's disk is full."}
	Unavailable = Code{status: 503, code: "unavailable",
		message: "Try again shortly.", retryAfter: 2 * time.Second}
)

// allCodes lists every code, for tests
func allCodes() []Code {
	return []Code{
		TokenUnknown, TokenUsed, TokenExpired, SandboxEnded, TrafficLimit, RateLimited, InUse,
		SizeMismatch, OverCap, FileChanged, Range, ChecksumMismatch, NoSpace, Unavailable,
	}
}

// RetryAfter is the error answered with a Retry-After of d, rounded up to whole seconds
func (c Code) RetryAfter(d time.Duration) Code {
	c.retryAfter = d
	return c
}

// Status is the error's HTTP status
func (c Code) Status() int {
	return c.status
}

// WriteJSON answers the error as a JSON object with its code and message
func WriteJSON(w http.ResponseWriter, c Code) {
	body, _ := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{c.code, c.message})
	body = append(body, '\n')
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	setRetryAfter(h, c.retryAfter)
	w.WriteHeader(c.status)
	_, _ = w.Write(body)
}
