package x402

import (
	"net/http"
	"slices"
	"testing"
)

// svc is a service on api.example.com with the given id, method and prefix
func svc(id, method, prefix string) Service {
	return Service{ID: id, Host: "api.example.com", Prefix: prefix, Method: method}
}

// matchBothOrders runs Match on services and on their reverse, failing when the two differ
func matchBothOrders(t *testing.T, services []Service, path, method string) (Service, bool) {
	t.Helper()
	got, ok := Match(services, path, method)
	reversed := slices.Clone(services)
	slices.Reverse(reversed)
	back, backOK := Match(reversed, path, method)
	if back != got || backOK != ok {
		t.Fatalf("order changes the match: %+v %v, then %+v %v", got, ok, back, backOK)
	}
	return got, ok
}

func TestMatchLongestPrefix(t *testing.T) {
	services := []Service{svc("xs_a", "GET", "/v1/"), svc("xs_b", "GET", "/v1/auto/")}
	got, ok := matchBothOrders(t, services, "/v1/auto/x", "GET")
	eq(t, ok, true)
	eq(t, got.Prefix, "/v1/auto/")

	got, ok = matchBothOrders(t, services, "/v1/other", "GET")
	eq(t, ok, true)
	eq(t, got.Prefix, "/v1/")
}

func TestMatchMethodFirst(t *testing.T) {
	services := []Service{svc("xs_a", "POST", "/v1/"), svc("xs_b", "GET", "/v1/auto/")}
	got, ok := matchBothOrders(t, services, "/v1/auto/x", "POST")
	eq(t, ok, true)
	eq(t, got.ID, "xs_a")

	got, ok = matchBothOrders(t, services, "/v1/auto/x", "GET")
	eq(t, ok, true)
	eq(t, got.ID, "xs_b")

	got, ok = matchBothOrders(t, services, "/v1/auto/x", "PUT")
	eq(t, ok, true)
	eq(t, got.ID, "xs_b")
}

func TestMatchTieLowerID(t *testing.T) {
	services := []Service{
		svc("xs_bbbbbbbbbbbbbbbb", "GET", "/v1/"),
		svc("xs_aaaaaaaaaaaaaaaa", "POST", "/v1/"),
	}
	got, ok := matchBothOrders(t, services, "/v1/x", "PUT")
	eq(t, ok, true)
	eq(t, got.ID, "xs_aaaaaaaaaaaaaaaa")

	got, _ = matchBothOrders(t, services, "/v1/x", "GET")
	eq(t, got.ID, "xs_bbbbbbbbbbbbbbbb")
}

func TestMatchSlashRule(t *testing.T) {
	services := []Service{svc("xs_a", "GET", "/search/")}
	for path, want := range map[string]bool{
		"/search":    true,
		"/search/":   true,
		"/search/x":  true,
		"/searchx":   false,
		"/searc":     false,
		"/":          false,
		"/other/x":   false,
		"/x/search/": false,
	} {
		_, ok := Match(services, path, "GET")
		if ok != want {
			t.Errorf("%s gives %v, want %v", path, ok, want)
		}
	}
	if _, ok := Match(nil, "/search", "GET"); ok {
		t.Error("no service matched")
	}
}

func TestMatchSkipsMalformedPrefix(t *testing.T) {
	for _, prefix := range []string{"", "/", "search/", "/search", "//"} {
		if got, ok := Match([]Service{svc("xs_a", "GET", prefix)}, "/search/x", "GET"); ok {
			t.Errorf("prefix %q matched as %+v", prefix, got)
		}
	}
}

func TestPayability(t *testing.T) {
	indexed := Service{ID: "xs_a", Prefix: "/v1/auto/", Method: "POST"}
	listed := Service{ID: "xs_b", Prefix: "/search/", Method: "GET", PaidPath: "/search"}
	sig := http.Header{}
	sig.Set("PAYMENT-SIGNATURE", "eyJ4IjoxfQ==")
	lower := http.Header{"x-payment": {"eyJ4IjoxfQ=="}}
	canonical := http.Header{}
	canonical.Set("x-payment", "eyJ4IjoxfQ==")
	for _, c := range []struct {
		name   string
		s      Service
		path   string
		method string
		h      http.Header
		want   Pay
	}{
		{"indexed any path", indexed, "/v1/auto/chat/completions", "POST", http.Header{}, Payable},
		{"listed paid path", listed, "/search", "GET", nil, Payable},
		{"payment signature", indexed, "/v1/auto/x", "POST", sig, SelfPaid},
		{"x-payment lower case", indexed, "/v1/auto/x", "POST", lower, SelfPaid},
		{"x-payment canonical", indexed, "/v1/auto/x", "POST", canonical, SelfPaid},
		{"self paid before method", indexed, "/v1/auto/x", "GET", sig, SelfPaid},
		{"other method", indexed, "/v1/auto/x", "GET", nil, MethodNotEnabled},
		{"method before path", listed, "/search/x", "POST", nil, MethodNotEnabled},
		{"other path", listed, "/search/x", "GET", nil, PathNotPaid},
		{"trailing slash", listed, "/search/", "GET", nil, PathNotPaid},
	} {
		if got := Payability(c.s, c.path, c.method, c.h); got != c.want {
			t.Errorf("%s gives %d, want %d", c.name, got, c.want)
		}
	}
}

func TestIsUpgrade(t *testing.T) {
	for _, c := range []struct {
		name   string
		method string
		h      http.Header
		want   bool
	}{
		{"websocket", "GET", http.Header{"Upgrade": {"websocket"}}, true},
		{"empty upgrade", "GET", http.Header{"Upgrade": {""}}, true},
		{"connection list", "GET", http.Header{"Connection": {"keep-alive, Upgrade"}}, true},
		{"connection lower", "GET", http.Header{"connection": {"upgrade"}}, true},
		{"connect", "CONNECT", http.Header{}, true},
		{"connect lower", "connect", http.Header{}, true},
		{"extended connect", "CONNECT", http.Header{":protocol": {"websocket"}}, true},
		{"protocol alone", "GET", http.Header{":protocol": {"websocket"}}, true},
		{"h2c", "GET", http.Header{"Http2-Settings": {"AAMAAABkAAQAAP__"}}, true},
		{"plain get", "GET", http.Header{"Accept": {"*/*"}}, false},
		{"keep-alive", "POST", http.Header{"Connection": {"keep-alive"}}, false},
		{"upgrades token", "GET", http.Header{"Connection": {"upgrades"}}, false},
	} {
		r, err := http.NewRequest("GET", "https://api.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Method, r.Header = c.method, c.h
		if got := IsUpgrade(r); got != c.want {
			t.Errorf("%s gives %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDropDummyKey(t *testing.T) {
	for _, v := range []string{"Bearer x402", "bearer x402", "BEARER x402", "BeArEr x402"} {
		h := http.Header{"Authorization": {v}, "Accept": {"*/*"}}
		eq(t, DropDummyKey(h), true)
		eq(t, h, http.Header{"Accept": {"*/*"}})
	}

	h := http.Header{"authorization": {"Bearer x402"}}
	eq(t, DropDummyKey(h), true)
	eq(t, h, http.Header{})

	for _, v := range []string{
		"Bearer X402", "Bearer  x402", "Bearer x4021", "Basic x402", "Bearer sk-live",
		" Bearer x402", "Bearer x402 ", "Bearer\tx402", "Bearerx402", "x402", "",
	} {
		h := http.Header{"Authorization": {v}}
		eq(t, DropDummyKey(h), false)
		eq(t, h, http.Header{"Authorization": {v}})
	}

	two := http.Header{"Authorization": {"Bearer x402", "Bearer sk-live"}}
	eq(t, DropDummyKey(two), false)
	eq(t, two, http.Header{"Authorization": {"Bearer x402", "Bearer sk-live"}})

	none := http.Header{"Accept": {"*/*"}}
	eq(t, DropDummyKey(none), false)
	eq(t, none, http.Header{"Accept": {"*/*"}})
}
