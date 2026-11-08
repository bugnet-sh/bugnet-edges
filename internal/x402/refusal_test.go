package x402

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

// table is XS 6.13's rows by code, HTTP status and event status, in its order
var table = []struct {
	code   Code
	status int
	event  string
}{
	{"path_refused", 400, "refused_request"},
	{"path_not_enabled", 403, "refused_request"},
	{"unpaid_cap", 403, "refused_cap"},
	{"upgrade_refused", 405, "refused_request"},
	{"host_rate", 429, "refused_cap"},
	{"buffer_busy", 503, "not_paid"},
	{"payments_unavailable", 503, "not_paid"},
	{"upstream_unreachable", 502, "upstream_error"},
	{"x402_disabled", 402, "not_paid"},
	{"account_closed", 402, "not_paid"},
	{"service_not_enabled", 402, "not_paid"},
	{"ref_conflict", 402, "not_paid"},
	{"method_not_enabled", 402, "refused_request"},
	{"path_not_paid", 402, "refused_request"},
	{"body_too_large", 402, "refused_request"},
	{"body_slow", 402, "refused_request"},
	{"first_answer_slow", 402, "refused_request"},
	{"not_x402", 402, "refused_network"},
	{"version_unsupported", 402, "refused_network"},
	{"network_unsupported", 402, "refused_network"},
	{"splits_unsupported", 402, "refused_terms"},
	{"flow_unsupported", 402, "refused_terms"},
	{"ata_creation_unsupported", 402, "refused_terms"},
	{"fee_payer_refused", 402, "refused_payee"},
	{"payee_refused", 402, "refused_payee"},
	{"payee_changed", 402, "refused_payee"},
	{"payee_unreliable", 402, "refused_payee"},
	{"payto_blocked", 402, "refused_payee"},
	{"price_above_max", 402, "refused_price"},
	{"allowance_spent", 402, "refused_cap"},
	{"rate_cap", 429, "refused_cap"},
	{"too_many_open_payments", 429, "refused_cap"},
	{"payto_daily_cap", 402, "refused_cap"},
	{"outflow_cap", 402, "refused_cap"},
	{"outflow_paused", 402, "refused_cap"},
	{"payment_rejected", 402, "payment_failed"},
	{"paid_no_answer", 502, "uncertain"},
}

var beforeSend = map[Code]bool{
	"path_refused": true, "path_not_enabled": true, "unpaid_cap": true, "upgrade_refused": true,
	"host_rate": true, "buffer_busy": true, "upstream_unreachable": true,
}

// ownLimit is XS 6.8's nine codes, which never use up the unpaid request cap
var ownLimit = map[Code]bool{
	"allowance_spent": true, "rate_cap": true, "too_many_open_payments": true,
	"payto_daily_cap": true, "outflow_cap": true, "outflow_paused": true, "x402_disabled": true,
	"payments_unavailable": true, "buffer_busy": true,
}

func TestRefusalTable(t *testing.T) {
	eq(t, len(table), 37)
	eq(t, len(refusals), len(table))
	for i, row := range table {
		r, ok := Lookup(row.code)
		if !ok {
			t.Fatalf("%s: not found", row.code)
		}
		eq(t, r, Refusal{
			Code:        row.code,
			HTTPStatus:  row.status,
			EventStatus: row.event,
			BeforeSend:  beforeSend[row.code],
			OwnLimit:    ownLimit[row.code],
		})
		eq(t, refusals[i].Code, row.code)
	}
	if _, ok := Lookup("self_hosted"); ok {
		t.Fatal("an unknown code was found")
	}
	eq(t, len(ownLimit), 9)
}

func TestCodeConstants(t *testing.T) {
	consts := []Code{
		CodePathRefused, CodePathNotEnabled, CodeUnpaidCap, CodeUpgradeRefused, CodeHostRate,
		CodeBufferBusy, CodePaymentsUnavailable, CodeUpstreamUnreachable, CodeX402Disabled,
		CodeAccountClosed, CodeServiceNotEnabled, CodeRefConflict, CodeMethodNotEnabled,
		CodePathNotPaid, CodeBodyTooLarge, CodeBodySlow, CodeFirstAnswerSlow, CodeNotX402,
		CodeVersionUnsupported, CodeNetworkUnsupported, CodeSplitsUnsupported,
		CodeFlowUnsupported, CodeATACreationUnsupported, CodeFeePayerRefused, CodePayeeRefused,
		CodePayeeChanged, CodePayeeUnreliable, CodePaytoBlocked, CodePriceAboveMax,
		CodeAllowanceSpent, CodeRateCap, CodeTooManyOpenPayments, CodePaytoDailyCap,
		CodeOutflowCap, CodeOutflowPaused, CodePaymentRejected, CodePaidNoAnswer,
	}
	eq(t, len(consts), len(table))
	for i, c := range consts {
		eq(t, c, table[i].code)
	}
}

func TestEventStatusConstants(t *testing.T) {
	eq(t, []string{
		EventPaid, EventUncertain, EventPaymentFailed, EventFree, EventSelfPaid, EventRefusedCap,
		EventRefusedPrice, EventRefusedPayee, EventRefusedNetwork, EventRefusedTerms,
		EventRefusedRequest, EventRefusedHost, EventNotPaid, EventUpstreamError,
	}, []string{
		"paid", "uncertain", "payment_failed", "free", "self_paid", "refused_cap",
		"refused_price", "refused_payee", "refused_network", "refused_terms", "refused_request",
		"refused_host", "not_paid", "upstream_error",
	})
}

func TestBodyGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/allowance_spent.json")
	if err != nil {
		t.Fatal(err)
	}
	got := Body(CodeAllowanceSpent, Facts{
		Host:        "agent402.tools",
		AskedMicros: ptr[int64](10000),
		MaxMicros:   ptr[int64](10000),
		LeftMicros:  ptr[int64](0),
	}, Defaults())
	if !bytes.Equal(got, want) {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestBodyFactsInOrderAndNilLeftOut(t *testing.T) {
	s := Defaults()
	got := Body(CodeRateCap, Facts{
		Host: "api.example.com", MaxMicros: ptr[int64](500000), RetryAfterSeconds: ptr(43),
	}, s)
	want := `{"error":{"message":"` + Message(CodeRateCap, s) +
		`","type":"bugnet_x402","code":"rate_cap"},` +
		`"bugnet_x402":{"host":"api.example.com","max_usd":"0.50","retry_after_s":43}}` + "\n"
	eq(t, string(got), want)

	got = Body(CodePaymentsUnavailable, Facts{
		Host: "api.example.com", AskedMicros: ptr[int64](1500), MaxMicros: ptr[int64](10000),
		LeftMicros: ptr[int64](990000), RetryAfterSeconds: ptr(5),
	}, s)
	var decoded struct {
		Error struct {
			Message, Type, Code string
		} `json:"error"`
		X402 json.RawMessage `json:"bugnet_x402"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	eq(t, decoded.Error.Type, "bugnet_x402")
	eq(t, decoded.Error.Code, "payments_unavailable")
	eq(t, string(decoded.X402), `{"host":"api.example.com","asked_usd":"0.0015",`+
		`"max_usd":"0.01","left_usd":"0.99","retry_after_s":5}`)

	got = Body(CodePathRefused, Facts{}, s)
	if !strings.HasSuffix(string(got), `"bugnet_x402":{}}`+"\n") {
		t.Fatalf("an empty fact set is not an empty object: %s", got)
	}
	if bytes.Count(got, []byte("\n")) != 1 {
		t.Fatalf("not one line: %q", got)
	}
}

func TestMessageStarts(t *testing.T) {
	s := Defaults()
	for _, row := range table {
		m := Message(row.code, s)
		var start string
		switch {
		case row.code == CodePaymentRejected || row.code == CodePaidNoAnswer:
			start = "Bugnet sent a payment"
			if !strings.Contains(m, "(x402 "+string(row.code)+"): ") {
				t.Errorf("%s: %q does not name its code", row.code, m)
			}
		case beforeSend[row.code]:
			start = "Bugnet did not send this request (x402 " + string(row.code) + "): "
		default:
			start = "Bugnet did not pay this call (x402 " + string(row.code) + "): "
		}
		if !strings.HasPrefix(m, start) {
			t.Errorf("%s: %q does not start %q", row.code, m, start)
		}
		if !strings.HasSuffix(m, ".") || strings.HasSuffix(m, "..") {
			t.Errorf("%s: %q does not end with one period", row.code, m)
		}
	}
	eq(t, Message(CodePaymentRejected, s), "Bugnet sent a payment and the seller refused it "+
		"(x402 payment_rejected): nothing is charged unless it still lands on chain.")
	eq(t, Message(CodePaidNoAnswer, s), "Bugnet sent a payment and the seller did not answer "+
		"(x402 paid_no_answer): nothing is charged unless it lands on chain; a retry resends "+
		"the same payment.")
	eq(t, Message(CodeUnpaidCap, s), "Bugnet did not send this request (x402 unpaid_cap): "+
		"this host's unpaid requests or bytes for this sandbox are used up, so Bugnet sends "+
		"no more requests to it.")
	eq(t, Message(CodeOutflowCap, s), "Bugnet did not pay this call (x402 outflow_cap): "+
		"Bugnet's daily x402 limit is reached until 00:00 UTC.")
}

func TestMessageDefaultNumbers(t *testing.T) {
	s := Defaults()
	for c, want := range map[Code]string{
		CodeBodyTooLarge:        "request bodies over 1 MiB are not paid.",
		CodeBodySlow:            "the request body took over 10 s to arrive.",
		CodeFirstAnswerSlow:     "the seller took over 30 s to ask for payment.",
		CodeTooManyOpenPayments: "8 payments are still settling, the SDK can retry after the wait.",
		CodeBufferBusy:          "Bugnet is busy, try again in 2 s.",
		CodePaymentsUnavailable: "Bugnet's payment service did not answer, try again in 5 s.",
	} {
		if m := Message(c, s); !strings.HasSuffix(m, "): "+want) {
			t.Errorf("%s: %q does not end %q", c, m, want)
		}
	}
}

func TestMessageNumbersFromSettings(t *testing.T) {
	s := Defaults()
	s.ReplayBodyMax = 2 << 20
	s.FirstHeaderTimeout = settings.Duration(45 * time.Second)
	s.BodyReadTimeout = settings.Duration(5 * time.Second)
	s.MaxOpenSignedPerPlacement = 4
	s.PaymentsTimeout = settings.Duration(9 * time.Second)
	for c, want := range map[Code]string{
		CodeBodyTooLarge:        "request bodies over 2 MiB are not paid",
		CodeFirstAnswerSlow:     "the seller took over 45 s to ask for payment",
		CodeBodySlow:            "the request body took over 5 s to arrive",
		CodeTooManyOpenPayments: "4 payments are still settling",
		CodeBufferBusy:          "try again in 2 s",
		CodePaymentsUnavailable: "try again in 5 s",
	} {
		if m := Message(c, s); !strings.Contains(m, want) {
			t.Errorf("%s: %q does not hold %q", c, m, want)
		}
	}

	s.ReplayBodyMax = 1536 << 10
	s.BodyReadTimeout = settings.Duration(1500 * time.Millisecond)
	s.FirstHeaderTimeout = settings.Duration(2 * time.Minute)
	s.MaxOpenSignedPerPlacement = 1
	for c, want := range map[Code]string{
		CodeBodyTooLarge:        "request bodies over 1536 KiB are not paid",
		CodeBodySlow:            "the request body took over 1.5 s to arrive",
		CodeFirstAnswerSlow:     "the seller took over 120 s to ask for payment",
		CodeTooManyOpenPayments: "1 payment is still settling",
	} {
		if m := Message(c, s); !strings.Contains(m, want) {
			t.Errorf("%s: %q does not hold %q", c, m, want)
		}
	}
	s.ReplayBodyMax = 1000
	if m := Message(CodeBodyTooLarge, s); !strings.Contains(m, "over 1000 bytes") {
		t.Errorf("%q does not hold over 1000 bytes", m)
	}
	s.ReplayBodyMax = 1 << 30
	if m := Message(CodeBodyTooLarge, s); !strings.Contains(m, "over 1 GiB") {
		t.Errorf("%q does not hold over 1 GiB", m)
	}
}

func TestMessageUnknownCode(t *testing.T) {
	eq(t, Message("made_up", Defaults()), "Bugnet did not pay this call (x402 made_up).")
}

func TestRetryAfter(t *testing.T) {
	at := func(sec, nsec int) time.Time {
		return time.Date(2026, 11, 7, 12, 0, sec, nsec, time.UTC)
	}
	eq(t, RetryAfter(CodeRateCap, at(17, 0)), 43)
	eq(t, RetryAfter(CodeRateCap, at(59, 500_000_000)), 1)
	eq(t, RetryAfter(CodeRateCap, at(17, 300_000_000)), 43)
	eq(t, RetryAfter(CodeRateCap, at(0, 0)), 60)
	eq(t, RetryAfter(CodeRateCap, at(17, 0).In(time.FixedZone("lmt", 3600+17))), 43)
	for c, want := range map[Code]int{
		CodeTooManyOpenPayments: 2,
		CodeBufferBusy:          2,
		CodePaymentsUnavailable: 5,
		CodeHostRate:            10,
		CodeAllowanceSpent:      0,
		CodeUnpaidCap:           0,
		CodePaidNoAnswer:        0,
		"made_up":               0,
	} {
		eq(t, RetryAfter(c, at(17, 0)), want)
	}
}
