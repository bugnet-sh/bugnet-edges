package metrics

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMetricsTextFormat(t *testing.T) {
	r := New()
	c := r.Counter("egress_tunnel_sources_total", "Tunnel sources by verdict", "verdict")
	c.Inc("pass")
	c.Add(2, "pass")
	c.Inc("mismatch")
	g := r.Gauge("edge_open_websockets", "Open WebSockets")
	g.Set(3)
	g.Add(-0.5)
	r.GaugeFunc("edge_cert_days_left", "Days until each served certificate expires",
		[]string{"name"}, func(emit func(float64, ...string)) {
			emit(80, "transfer.example.test")
			emit(13, "*.preview.example.test")
		})
	e := r.Counter("edge_escapes_total", "Help with \\ and\nnewline", "path", "kind")
	e.Inc(`a"b\c`+"\nd", "x")
	r.Counter("edge_unlabelled_total", "Never counted")
	r.Counter("edge_labelled_total", "Never counted", "route")
	odd := r.Gauge("edge_odd", "Values without a fixed point", "v")
	odd.Set(math.Inf(1), "inf")
	odd.Set(math.Inf(-1), "neg")
	odd.Set(math.NaN(), "nan")
	odd.Set(1e21, "big")

	var b strings.Builder
	n, err := r.WriteTo(&b)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, b.String(), `# HELP edge_cert_days_left Days until each served certificate expires
# TYPE edge_cert_days_left gauge
edge_cert_days_left{name="*.preview.example.test"} 13
edge_cert_days_left{name="transfer.example.test"} 80
# HELP edge_escapes_total Help with \\ and\nnewline
# TYPE edge_escapes_total counter
edge_escapes_total{path="a\"b\\c\nd",kind="x"} 1
# HELP edge_labelled_total Never counted
# TYPE edge_labelled_total counter
# HELP edge_odd Values without a fixed point
# TYPE edge_odd gauge
edge_odd{v="big"} 1e+21
edge_odd{v="inf"} +Inf
edge_odd{v="nan"} NaN
edge_odd{v="neg"} -Inf
# HELP edge_open_websockets Open WebSockets
# TYPE edge_open_websockets gauge
edge_open_websockets 2.5
# HELP edge_unlabelled_total Never counted
# TYPE edge_unlabelled_total counter
edge_unlabelled_total 0
# HELP egress_tunnel_sources_total Tunnel sources by verdict
# TYPE egress_tunnel_sources_total counter
egress_tunnel_sources_total{verdict="mismatch"} 1
egress_tunnel_sources_total{verdict="pass"} 3
`)
	eq(t, n, int64(b.Len()))
}

func TestMetricsHandler(t *testing.T) {
	r := New()
	r.Counter("edge_requests_total", "Requests").Inc()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	eq(t, w.Code, http.StatusOK)
	eq(t, w.Header().Get("Content-Type"), "text/plain; version=0.0.4; charset=utf-8")
	body, _ := io.ReadAll(w.Body)
	eq(t, strings.HasSuffix(string(body), "edge_requests_total 1\n"), true)
}

func TestMetricsRefuseMisuse(t *testing.T) {
	r := New()
	c := r.Counter("edge_a_total", "A", "route")
	for name, f := range map[string]func(){
		"bad name":        func() { r.Counter("edge-a", "A") },
		"empty name":      func() { r.Gauge("", "A") },
		"bad label":       func() { r.Counter("edge_b_total", "B", "1route") },
		"reserved label":  func() { r.Counter("edge_c_total", "C", "__name") },
		"repeated label":  func() { r.Counter("edge_d_total", "D", "a", "a") },
		"twice":           func() { r.Gauge("edge_a_total", "A") },
		"too few values":  func() { c.Inc() },
		"too many values": func() { c.Inc("a", "b") },
		"func values": func() {
			r.GaugeFunc("edge_e", "E", []string{"x"}, func(emit func(float64, ...string)) {
				emit(1)
			})
			_, _ = r.WriteTo(io.Discard)
		},
	} {
		if !panics(f) {
			t.Errorf("%s did not panic", name)
		}
	}
}

func panics(f func()) (did bool) {
	defer func() { did = recover() != nil }()
	f()
	return false
}

func TestMetricsConcurrentUse(t *testing.T) {
	r := New()
	c := r.Counter("edge_bytes_total", "Bytes", "way")
	g := r.Gauge("edge_open", "Open")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 1000 {
				c.Add(2, []string{"in", "out"}[i%2])
				g.Add(1)
				_, _ = r.WriteTo(io.Discard)
			}
		})
	}
	wg.Wait()
	var b strings.Builder
	_, _ = r.WriteTo(&b)
	for _, line := range []string{
		`edge_bytes_total{way="in"} 8000`, `edge_bytes_total{way="out"} 8000`, "edge_open 8000",
	} {
		eq(t, strings.Contains(b.String(), line+"\n"), true)
	}
}
