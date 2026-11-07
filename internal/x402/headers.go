package x402

import (
	"net/http"
	"net/textproto"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// The answer headers egress adds on an x402 host
const (
	HeaderStatus  = "Bugnet-X402-Status"
	HeaderPaidUSD = "Bugnet-X402-Paid-Usd"
	HeaderLeftUSD = "Bugnet-X402-Left-Usd"
	HeaderError   = "Bugnet-X402-Error"
)

// The values of Bugnet-X402-Status, XS 6.12
const (
	StatusPaid      = "paid"
	StatusUncertain = "uncertain"
	StatusRejected  = "rejected"
)

// PaymentScrubbed stands in for the payment value wherever a seller echoes it in a header
const PaymentScrubbed = "[bugnet-payment]"

// hopByHop are the lower-case names XS 6.6 strips besides those Connection lists
var hopByHop = []string{
	"connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate",
	"te", "trailer", "transfer-encoding", "upgrade",
}

// StripHopByHop deletes hop-by-hop headers, keeping TE trailers on a send
func StripHopByHop(h http.Header, send bool) {
	trailers := send && httpguts.HeaderValuesContainsToken(values(h, "te"), "trailers")
	drop := make(map[string]bool, len(hopByHop))
	for _, name := range hopByHop {
		drop[name] = true
	}
	for _, v := range values(h, "connection") {
		for _, f := range strings.Split(v, ",") {
			if f = textproto.TrimString(f); f != "" {
				drop[strings.ToLower(f)] = true
			}
		}
	}
	for k := range h {
		if drop[strings.ToLower(k)] {
			delete(h, k)
		}
	}
	if trailers {
		h.Set("Te", "trailers")
	}
}

// values gathers a header's values under every spelling of its name
func values(h http.Header, lower string) []string {
	var vs []string
	for k, v := range h {
		if strings.ToLower(k) == lower {
			vs = append(vs, v...)
		}
	}
	return vs
}

// StripBugnet deletes every Bugnet- header an upstream sent
func StripBugnet(h http.Header) {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "bugnet-") {
			delete(h, k)
		}
	}
}

// ScrubValue replaces each exact occurrence of value in every header value
func ScrubValue(h http.Header, value string) {
	if value == "" {
		return
	}
	for _, vs := range h {
		for i, v := range vs {
			vs[i] = strings.ReplaceAll(v, value, PaymentScrubbed)
		}
	}
}

// PaidHeaders sets Bugnet-X402-Status, Bugnet-X402-Paid-Usd and Bugnet-X402-Left-Usd
func PaidHeaders(h http.Header, status string, paidMicros int64, leftMicros *int64) {
	h.Set(HeaderStatus, status)
	h.Del(HeaderPaidUSD)
	if status == StatusPaid || status == StatusUncertain {
		h.Set(HeaderPaidUSD, USD(paidMicros))
	}
	h.Del(HeaderLeftUSD)
	if leftMicros != nil {
		h.Set(HeaderLeftUSD, USD(*leftMicros))
	}
}
