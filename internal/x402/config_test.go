package x402

import (
	"testing"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

func block() *routerv1.X402Config {
	return &routerv1.X402Config{
		Enabled: true, AccountId: "order-1",
		Services: []*routerv1.X402Service{
			{ServiceId: "b", Host: "Api.Example", Prefix: "/v1/", Method: "POST",
				MaxPriceMicros: 5, PayTo: "pay", PaidPath: "/v1/x"},
			{ServiceId: "a", Host: "api.example", Prefix: "/v1/auto/", Method: "GET"},
			{ServiceId: "c", Host: "other.example", Prefix: "/", Method: "GET"},
		},
		UnpaidRequestsPerHost: 300, UnpaidBytesPerHost: 50 << 20,
		UnpaidUsed: map[string]*routerv1.X402Unpaid{"api.example": {Requests: 3, Bytes: 9}},
	}
}

func TestConfigFrom(t *testing.T) {
	c := ConfigFrom(block())
	eq(t, c.Enabled, true)
	eq(t, c.AccountID, "order-1")
	eq(t, c.Caps, Caps{Requests: 300, Bytes: 50 << 20})
	eq(t, c.Used, map[string]Unpaid{"api.example": {Requests: 3, Bytes: 9}})
	eq(t, c.Services[0], Service{ID: "b", Host: "api.example", Prefix: "/v1/", Method: "POST",
		MaxPriceMicros: 5, PayTo: "pay", PaidPath: "/v1/x"})
}

func TestConfigFromNothing(t *testing.T) {
	c := ConfigFrom(nil)
	eq(t, c.Enabled, false)
	eq(t, len(c.Services), 0)
	eq(t, c.Hosts(), []string(nil))
	eq(t, c.Listed("a"), false)
}

func TestConfigHostsOnHostListed(t *testing.T) {
	c := ConfigFrom(block())
	eq(t, c.Hosts(), []string{"api.example", "other.example"})
	ids := []string{}
	for _, s := range c.OnHost("api.example") {
		ids = append(ids, s.ID)
	}
	eq(t, ids, []string{"b", "a"})
	eq(t, len(c.OnHost("nope.example")), 0)
	eq(t, c.Listed("c"), true)
	eq(t, c.Listed("z"), false)
}
