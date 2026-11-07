package x402

import (
	"net/http"
	"testing"
)

func TestHeaderNames(t *testing.T) {
	eq(t, []string{HeaderStatus, HeaderPaidUSD, HeaderLeftUSD, HeaderError}, []string{
		"Bugnet-X402-Status", "Bugnet-X402-Paid-Usd", "Bugnet-X402-Left-Usd", "Bugnet-X402-Error",
	})
	for _, name := range []string{HeaderStatus, HeaderPaidUSD, HeaderLeftUSD, HeaderError} {
		eq(t, http.CanonicalHeaderKey(name), name)
	}
	eq(t, []string{StatusPaid, StatusUncertain, StatusRejected},
		[]string{"paid", "uncertain", "rejected"})
	eq(t, PaymentScrubbed, "[bugnet-payment]")
}

func TestStripHopByHop(t *testing.T) {
	h := http.Header{
		"Connection":          {"close, X-Foo", " x-bar ,,"},
		"X-Foo":               {"1"},
		"X-Bar":               {"2"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Connection":    {"keep-alive"},
		"Proxy-Authorization": {"Basic eDp5"},
		"Proxy-Authenticate":  {"Basic"},
		"Trailer":             {"X-Sum"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"Te":                  {"trailers"},
		"Content-Type":        {"application/json"},
		"Authorization":       {"Bearer sk-real"},
	}
	StripHopByHop(h, true)
	eq(t, h, http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer sk-real"},
		"Te":            {"trailers"},
	})

	h = http.Header{"Te": {"trailers"}, "X-Keep": {"1"}}
	StripHopByHop(h, false)
	eq(t, h, http.Header{"X-Keep": {"1"}})

	for _, te := range [][]string{{"gzip"}, {"gzip;q=0.5"}, {"deflate", "chunked"}} {
		h = http.Header{"Te": te}
		StripHopByHop(h, true)
		eq(t, h, http.Header{})
	}

	h = http.Header{"Te": {"gzip, Trailers"}}
	StripHopByHop(h, true)
	eq(t, h, http.Header{"Te": {"trailers"}})

	h = http.Header{"Connection": {"Te"}, "Te": {"trailers"}}
	StripHopByHop(h, true)
	eq(t, h, http.Header{"Te": {"trailers"}})

	h = http.Header{"connection": {"x-a"}, "X-A": {"1"}, "keep-alive": {"1"}, "X-B": {"2"}}
	StripHopByHop(h, false)
	eq(t, h, http.Header{"X-B": {"2"}})
}

func TestStripBugnet(t *testing.T) {
	h := http.Header{
		"bugnet-x402-status": {"paid"},
		"Bugnet-Foo":         {"1"},
		"BUGNET-X402-ERROR":  {"x"},
		"Bugnet-":            {"x"},
		"X-Bugnet":           {"kept"},
		"Bugnet":             {"kept"},
		"Content-Type":       {"text/plain"},
	}
	StripBugnet(h)
	eq(t, h, http.Header{
		"X-Bugnet":     {"kept"},
		"Bugnet":       {"kept"},
		"Content-Type": {"text/plain"},
	})
}

func TestScrubValue(t *testing.T) {
	payload := "eyJ4NDAyVmVyc2lvbiI6Mn0="
	h := http.Header{
		"X-Echo":       {payload},
		"X-Echo-Twice": {"a " + payload + " b " + payload},
		"X-Many":       {"clean", "pre" + payload},
		"X-Near":       {"eyJ4NDAyVmVyc2lvbiI6Mn0"},
		"Content-Type": {"text/plain"},
	}
	ScrubValue(h, payload)
	eq(t, h, http.Header{
		"X-Echo":       {"[bugnet-payment]"},
		"X-Echo-Twice": {"a [bugnet-payment] b [bugnet-payment]"},
		"X-Many":       {"clean", "pre[bugnet-payment]"},
		"X-Near":       {"eyJ4NDAyVmVyc2lvbiI6Mn0"},
		"Content-Type": {"text/plain"},
	})

	h = http.Header{"X-A": {"abc"}}
	ScrubValue(h, "")
	eq(t, h, http.Header{"X-A": {"abc"}})
}

func TestPaidHeaders(t *testing.T) {
	h := http.Header{"Content-Type": {"application/json"}}
	PaidHeaders(h, StatusPaid, 10000, ptr[int64](990000))
	eq(t, h, http.Header{
		"Content-Type":         {"application/json"},
		"Bugnet-X402-Status":   {"paid"},
		"Bugnet-X402-Paid-Usd": {"0.01"},
		"Bugnet-X402-Left-Usd": {"0.99"},
	})

	h = http.Header{}
	PaidHeaders(h, StatusUncertain, 1500, nil)
	eq(t, h, http.Header{
		"Bugnet-X402-Status":   {"uncertain"},
		"Bugnet-X402-Paid-Usd": {"0.0015"},
	})

	h = http.Header{}
	PaidHeaders(h, StatusRejected, 10000, ptr[int64](1000000))
	eq(t, h, http.Header{
		"Bugnet-X402-Status":   {"rejected"},
		"Bugnet-X402-Left-Usd": {"1.00"},
	})

	h = http.Header{"Bugnet-X402-Left-Usd": {"5.00"}, "Bugnet-X402-Paid-Usd": {"5.00"}}
	PaidHeaders(h, StatusRejected, 10000, nil)
	eq(t, h, http.Header{"Bugnet-X402-Status": {"rejected"}})
}
