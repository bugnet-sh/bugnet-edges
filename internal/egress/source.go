package egress

import (
	"net/netip"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

// SourceCheck is one ResolveTunnel answer's source_check, parsed once
type SourceCheck struct {
	Mode     routerv1.SourceCheckMode
	Prefixes []netip.Prefix
}

// ParseSourceCheck drops a prefix that does not parse, so a bad one can only narrow the check
func ParseSourceCheck(m *routerv1.TunnelSourceCheck) SourceCheck {
	c := SourceCheck{Mode: m.GetMode()}
	for _, s := range m.GetAllowedPrefixes() {
		if p, err := netip.ParsePrefix(s); err == nil {
			c.Prefixes = append(c.Prefixes, p.Masked())
		}
	}
	return c
}

// Verdict is what the check says about one tunnel
type Verdict int

// The verdicts of Judge
const (
	// Unchecked is a tunnel with no check, as the mode is unspecified
	Unchecked Verdict = iota
	Admitted
	// Unmatched is a source outside the prefixes in report mode, served, logged and counted
	Unmatched
	// Refused is a source outside the prefixes in enforce mode, answered with 403
	Refused
)

// String is the verdict's label in egress_tunnel_sources_total
func (v Verdict) String() string {
	return [...]string{"unchecked", "admitted", "unmatched", "refused"}[v]
}

// Judge decides for src. An invalid src falls in no prefix
func (c SourceCheck) Judge(src netip.Addr) Verdict {
	if c.Mode != routerv1.SourceCheckMode_SOURCE_CHECK_MODE_REPORT &&
		c.Mode != routerv1.SourceCheckMode_SOURCE_CHECK_MODE_ENFORCE {
		return Unchecked
	}
	if src.IsValid() {
		src = src.Unmap()
		for _, p := range c.Prefixes {
			if p.Contains(src) {
				return Admitted
			}
		}
	}
	if c.Mode == routerv1.SourceCheckMode_SOURCE_CHECK_MODE_ENFORCE {
		return Refused
	}
	return Unmatched
}

// same says whether d holds the mode and the prefixes c holds
func (c SourceCheck) same(d SourceCheck) bool {
	if c.Mode != d.Mode || len(c.Prefixes) != len(d.Prefixes) {
		return false
	}
	for i := range c.Prefixes {
		if c.Prefixes[i] != d.Prefixes[i] {
			return false
		}
	}
	return true
}
