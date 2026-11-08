package x402

import (
	"slices"
	"strings"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

// Config is one placement's x402 block, XS 6.5
type Config struct {
	Enabled   bool
	AccountID string
	Services  []Service
	Caps      Caps
	Used      map[string]Unpaid
}

// ConfigFrom reads the block ResolveTunnel answered, a missing block being an empty Config
func ConfigFrom(c *routerv1.X402Config) Config {
	out := Config{
		Enabled:   c.GetEnabled(),
		AccountID: c.GetAccountId(),
		Caps: Caps{
			Requests: c.GetUnpaidRequestsPerHost(), Bytes: c.GetUnpaidBytesPerHost(),
		},
		Used: make(map[string]Unpaid, len(c.GetUnpaidUsed())),
	}
	for _, s := range c.GetServices() {
		out.Services = append(out.Services, Service{
			ID: s.GetServiceId(), Host: strings.ToLower(s.GetHost()), Prefix: s.GetPrefix(),
			Method: s.GetMethod(), MaxPriceMicros: s.GetMaxPriceMicros(), PayTo: s.GetPayTo(),
			PaidPath: s.GetPaidPath(),
		})
	}
	for h, u := range c.GetUnpaidUsed() {
		out.Used[strings.ToLower(h)] = Unpaid{Requests: u.GetRequests(), Bytes: u.GetBytes()}
	}
	return out
}

// Hosts lists the hosts of the services once each, sorted
func (c Config) Hosts() []string {
	var hosts []string
	for _, s := range c.Services {
		hosts = append(hosts, s.Host)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// OnHost lists the services of one host
func (c Config) OnHost(host string) []Service {
	var out []Service
	for _, s := range c.Services {
		if s.Host == host {
			out = append(out, s)
		}
	}
	return out
}

// Listed says whether a service is still in the block
func (c Config) Listed(serviceID string) bool {
	return slices.ContainsFunc(c.Services, func(s Service) bool { return s.ID == serviceID })
}
