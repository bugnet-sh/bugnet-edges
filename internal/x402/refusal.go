package x402

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/oynozan/bugnet-edges/internal/settings"
)

// Code is a refusal code of XS 6.13
type Code string

// The codes of XS 6.13, in its table's order
const (
	CodePathRefused            Code = "path_refused"
	CodePathNotEnabled         Code = "path_not_enabled"
	CodeUnpaidCap              Code = "unpaid_cap"
	CodeUpgradeRefused         Code = "upgrade_refused"
	CodeHostRate               Code = "host_rate"
	CodeBufferBusy             Code = "buffer_busy"
	CodePaymentsUnavailable    Code = "payments_unavailable"
	CodeUpstreamUnreachable    Code = "upstream_unreachable"
	CodeX402Disabled           Code = "x402_disabled"
	CodeAccountClosed          Code = "account_closed"
	CodeServiceNotEnabled      Code = "service_not_enabled"
	CodeRefConflict            Code = "ref_conflict"
	CodeMethodNotEnabled       Code = "method_not_enabled"
	CodePathNotPaid            Code = "path_not_paid"
	CodeBodyTooLarge           Code = "body_too_large"
	CodeBodySlow               Code = "body_slow"
	CodeFirstAnswerSlow        Code = "first_answer_slow"
	CodeNotX402                Code = "not_x402"
	CodeVersionUnsupported     Code = "version_unsupported"
	CodeNetworkUnsupported     Code = "network_unsupported"
	CodeSplitsUnsupported      Code = "splits_unsupported"
	CodeFlowUnsupported        Code = "flow_unsupported"
	CodeATACreationUnsupported Code = "ata_creation_unsupported"
	CodeFeePayerRefused        Code = "fee_payer_refused"
	CodePayeeRefused           Code = "payee_refused"
	CodePayeeChanged           Code = "payee_changed"
	CodePayeeUnreliable        Code = "payee_unreliable"
	CodePaytoBlocked           Code = "payto_blocked"
	CodePriceAboveMax          Code = "price_above_max"
	CodeAllowanceSpent         Code = "allowance_spent"
	CodeRateCap                Code = "rate_cap"
	CodeTooManyOpenPayments    Code = "too_many_open_payments"
	CodePaytoDailyCap          Code = "payto_daily_cap"
	CodeOutflowCap             Code = "outflow_cap"
	CodeOutflowPaused          Code = "outflow_paused"
	CodePaymentRejected        Code = "payment_rejected"
	CodePaidNoAnswer           Code = "paid_no_answer"
)

// The event statuses of XS 8.2
const (
	EventPaid           = "paid"
	EventUncertain      = "uncertain"
	EventPaymentFailed  = "payment_failed"
	EventFree           = "free"
	EventSelfPaid       = "self_paid"
	EventRefusedCap     = "refused_cap"
	EventRefusedPrice   = "refused_price"
	EventRefusedPayee   = "refused_payee"
	EventRefusedNetwork = "refused_network"
	EventRefusedTerms   = "refused_terms"
	EventRefusedRequest = "refused_request"
	EventRefusedHost    = "refused_host"
	EventNotPaid        = "not_paid"
	EventUpstreamError  = "upstream_error"
)

// Refusal is one row of XS 6.13
type Refusal struct {
	Code        Code
	HTTPStatus  int
	EventStatus string
	// BeforeSend says the message starts "Bugnet did not send this request"
	BeforeSend bool
	// OwnLimit says it is one of Bugnet's own limits, which never use up the request cap
	OwnLimit bool
}

// row is a refusal with the message text after its start
type row struct {
	Refusal
	text func(Settings) string
	// whole says the text is the message, for the two codes that sent a payment
	whole bool
}

func fixed(text string) func(Settings) string {
	return func(Settings) string { return text }
}

// refusals is XS 6.13's table in its order
var refusals = []row{
	{Refusal: Refusal{CodePathRefused, 400, EventRefusedRequest, true, false},
		text: fixed("the path has `.`, `..`, `//`, `;`, an encoded character or non-ASCII text " +
			"Bugnet does not forward, or the query has a space, a control byte or non-ASCII text")},
	{Refusal: Refusal{CodePathNotEnabled, 403, EventRefusedRequest, true, false},
		text: fixed("this path is outside the enabled prefixes")},
	{Refusal: Refusal{CodeUnpaidCap, 403, EventRefusedCap, true, false},
		text: fixed("this host's unpaid requests or bytes for this sandbox are used up, so " +
			"Bugnet sends no more requests to it")},
	{Refusal: Refusal{CodeUpgradeRefused, 405, EventRefusedRequest, true, false},
		text: fixed("WebSockets, CONNECT and h2c are not forwarded to x402 hosts")},
	{Refusal: Refusal{CodeHostRate, 429, EventRefusedCap, true, false},
		text: fixed("this host gets too many requests through Bugnet right now")},
	{Refusal: Refusal{CodeBufferBusy, 503, EventNotPaid, true, true},
		text: fixed("Bugnet is busy, try again in 2 s")},
	{Refusal: Refusal{CodePaymentsUnavailable, 503, EventNotPaid, false, true},
		text: fixed("Bugnet's payment service did not answer, try again in 5 s")},
	{Refusal: Refusal{CodeUpstreamUnreachable, 502, EventUpstreamError, true, false},
		text: fixed("Bugnet could not reach the seller")},
	{Refusal: Refusal{CodeX402Disabled, 402, EventNotPaid, false, true},
		text: fixed("paying x402 APIs is switched off right now")},
	{Refusal: Refusal{CodeAccountClosed, 402, EventNotPaid, false, false},
		text: fixed("this sandbox is ending")},
	{Refusal: Refusal{CodeServiceNotEnabled, 402, EventNotPaid, false, false},
		text: fixed("this service is not enabled for this sandbox")},
	{Refusal: Refusal{CodeRefConflict, 402, EventNotPaid, false, false},
		text: fixed("Bugnet could not match this payment to its own records")},
	{Refusal: Refusal{CodeMethodNotEnabled, 402, EventRefusedRequest, false, false},
		text: fixed("only the enabled method is paid on this service")},
	{Refusal: Refusal{CodePathNotPaid, 402, EventRefusedRequest, false, false},
		text: fixed("Bugnet has not reviewed this service, so only the approved path is paid")},
	{Refusal: Refusal{CodeBodyTooLarge, 402, EventRefusedRequest, false, false},
		text: func(s Settings) string {
			return "request bodies over " + size(int64(s.ReplayBodyMax)) + " are not paid"
		}},
	{Refusal: Refusal{CodeBodySlow, 402, EventRefusedRequest, false, false},
		text: func(s Settings) string {
			return "the request body took over " + seconds(s.BodyReadTimeout) + " to arrive"
		}},
	{Refusal: Refusal{CodeFirstAnswerSlow, 402, EventRefusedRequest, false, false},
		text: func(s Settings) string {
			return "the seller took over " + seconds(s.FirstHeaderTimeout) + " to ask for payment"
		}},
	{Refusal: Refusal{CodeNotX402, 402, EventRefusedNetwork, false, false},
		text: fixed("the seller's 402 has no x402 price")},
	{Refusal: Refusal{CodeVersionUnsupported, 402, EventRefusedNetwork, false, false},
		text: fixed("the seller offers only the old x402 version")},
	{Refusal: Refusal{CodeNetworkUnsupported, 402, EventRefusedNetwork, false, false},
		text: fixed("the seller takes no USDC on Solana")},
	{Refusal: Refusal{CodeSplitsUnsupported, 402, EventRefusedTerms, false, false},
		text: fixed("the seller splits the payment between several payees")},
	{Refusal: Refusal{CodeFlowUnsupported, 402, EventRefusedTerms, false, false},
		text: fixed("the seller asks for a payment flow Bugnet does not use")},
	{Refusal: Refusal{CodeATACreationUnsupported, 402, EventRefusedTerms, false, false},
		text: fixed("the seller asks the payer to create an account")},
	{Refusal: Refusal{CodeFeePayerRefused, 402, EventRefusedPayee, false, false},
		text: fixed("the seller names a fee payer Bugnet cannot use")},
	{Refusal: Refusal{CodePayeeRefused, 402, EventRefusedPayee, false, false},
		text: fixed("the seller asks to be paid at an address Bugnet does not pay")},
	{Refusal: Refusal{CodePayeeChanged, 402, EventRefusedPayee, false, false},
		text: fixed("the seller asks to be paid at another address than the one approved")},
	{Refusal: Refusal{CodePayeeUnreliable, 402, EventRefusedPayee, false, false},
		text: fixed("this seller failed too many paid calls in this sandbox")},
	{Refusal: Refusal{CodePaytoBlocked, 402, EventRefusedPayee, false, false},
		text: fixed("Bugnet has blocked this payee")},
	{Refusal: Refusal{CodePriceAboveMax, 402, EventRefusedPrice, false, false},
		text: fixed("the seller asks more than the approved price")},
	{Refusal: Refusal{CodeAllowanceSpent, 402, EventRefusedCap, false, true},
		text: fixed("the sandbox's x402 allowance is spent. The agent can add more with the " +
			"user's approval")},
	{Refusal: Refusal{CodeRateCap, 429, EventRefusedCap, false, true},
		text: fixed("the spending limit a minute is reached, the SDK can retry after the wait")},
	{Refusal: Refusal{CodeTooManyOpenPayments, 429, EventRefusedCap, false, true},
		text: func(s Settings) string {
			n := s.MaxOpenSignedPerPlacement
			if n == 1 {
				return "1 payment is still settling, the SDK can retry after the wait"
			}
			return strconv.Itoa(n) + " payments are still settling, the SDK can retry after " +
				"the wait"
		}},
	{Refusal: Refusal{CodePaytoDailyCap, 402, EventRefusedCap, false, true},
		text: fixed("this payee, or unreviewed payees together, reached Bugnet's daily limit")},
	{Refusal: Refusal{CodeOutflowCap, 402, EventRefusedCap, false, true},
		text: fixed("Bugnet's daily x402 limit is reached until 00:00 UTC")},
	{Refusal: Refusal{CodeOutflowPaused, 402, EventRefusedCap, false, true},
		text: fixed("Bugnet paused x402 payments")},
	{Refusal: Refusal{CodePaymentRejected, 402, EventPaymentFailed, false, false},
		text: fixed("Bugnet sent a payment and the seller refused it (x402 payment_rejected): " +
			"nothing is charged unless it still lands on chain"), whole: true},
	{Refusal: Refusal{CodePaidNoAnswer, 502, EventUncertain, false, false},
		text: fixed("Bugnet sent a payment and the seller did not answer (x402 paid_no_answer): " +
			"nothing is charged unless it lands on chain; a retry resends the same payment"),
		whole: true},
}

var byCode = func() map[Code]row {
	m := make(map[Code]row, len(refusals))
	for _, r := range refusals {
		m[r.Code] = r
	}
	return m
}()

// Lookup finds the row of a code
func Lookup(c Code) (Refusal, bool) {
	r, ok := byCode[c]
	return r.Refusal, ok
}

// Message builds the error message, numbers taken from the live settings
func Message(c Code, s Settings) string {
	r, ok := byCode[c]
	switch {
	case !ok:
		return "Bugnet did not pay this call (x402 " + string(c) + ")."
	case r.whole:
		return r.text(s) + "."
	case r.BeforeSend:
		return "Bugnet did not send this request (x402 " + string(c) + "): " + r.text(s) + "."
	}
	return "Bugnet did not pay this call (x402 " + string(c) + "): " + r.text(s) + "."
}

// size writes bytes in the largest binary unit that divides them
func size(n int64) string {
	for _, u := range []struct {
		name string
		size int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + " " + u.name
		}
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// seconds writes a span in seconds with no trailing zeros
func seconds(d settings.Duration) string {
	return strconv.FormatFloat(time.Duration(d).Seconds(), 'f', -1, 64) + " s"
}

// Facts are the bugnet_x402 object, each pointer nil when unknown
type Facts struct {
	Host                   string
	AskedMicros, MaxMicros *int64
	LeftMicros             *int64
	RetryAfterSeconds      *int
}

// body is XS 6.13's JSON in its field order
type body struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    Code   `json:"code"`
	} `json:"error"`
	X402 struct {
		Host       string `json:"host,omitempty"`
		AskedUSD   string `json:"asked_usd,omitempty"`
		MaxUSD     string `json:"max_usd,omitempty"`
		LeftUSD    string `json:"left_usd,omitempty"`
		RetryAfter *int   `json:"retry_after_s,omitempty"`
	} `json:"bugnet_x402"`
}

// Body is the compact one-line JSON body of XS 6.13
func Body(c Code, f Facts, s Settings) []byte {
	var b body
	b.Error.Message, b.Error.Type, b.Error.Code = Message(c, s), "bugnet_x402", c
	b.X402.Host = f.Host
	b.X402.AskedUSD = usdOf(f.AskedMicros)
	b.X402.MaxUSD = usdOf(f.MaxMicros)
	b.X402.LeftUSD = usdOf(f.LeftMicros)
	b.X402.RetryAfter = f.RetryAfterSeconds
	out, _ := json.Marshal(b)
	return append(out, '\n')
}

func usdOf(micros *int64) string {
	if micros == nil {
		return ""
	}
	return USD(*micros)
}

// RetryAfter is the Retry-After value in seconds, zero when the code sets none
func RetryAfter(c Code, now time.Time) int {
	switch c {
	case CodeRateCap:
		wait := now.Truncate(time.Minute).Add(time.Minute).Sub(now)
		return max(1, int((wait+time.Second-1)/time.Second))
	case CodeTooManyOpenPayments, CodeBufferBusy:
		return 2
	case CodePaymentsUnavailable:
		return 5
	case CodeHostRate:
		return 10
	}
	return 0
}
