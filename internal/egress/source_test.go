package egress

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
)

const (
	ownIP     = "2001:db8::5"
	foreignIP = "198.51.100.1"
)

func enforce(prefixes ...string) *routerv1.TunnelSourceCheck {
	return &routerv1.TunnelSourceCheck{
		Mode: routerv1.SourceCheckMode_SOURCE_CHECK_MODE_ENFORCE, AllowedPrefixes: prefixes}
}

func report(prefixes ...string) *routerv1.TunnelSourceCheck {
	return &routerv1.TunnelSourceCheck{
		Mode: routerv1.SourceCheckMode_SOURCE_CHECK_MODE_REPORT, AllowedPrefixes: prefixes}
}

// checked is a placement whose answers carry check
func checked(t *testing.T, h *harness, check *routerv1.TunnelSourceCheck) *fakePlacement {
	t.Helper()
	p, _ := hfPlacement(t, h)
	h.router.setCheck(p, check)
	return p
}

func metricLine(verdict string) string {
	return `egress_tunnel_sources_total{verdict="` + verdict + `"} `
}

func TestJudge(t *testing.T) {
	c := ParseSourceCheck(enforce("2001:db8::5/128", "not-a-prefix"))
	eq(t, len(c.Prefixes), 1) // a bad prefix is dropped, never widening the check
	eq(t, c.Judge(netip.MustParseAddr("2001:db8::5")), Admitted)
	eq(t, c.Judge(netip.MustParseAddr("2001:db8::6")), Refused)
	eq(t, c.Judge(netip.Addr{}), Refused)
	eq(t, ParseSourceCheck(report("2001:db8::5/128")).Judge(netip.MustParseAddr(foreignIP)),
		Unmatched)
	eq(t, ParseSourceCheck(nil).Judge(netip.MustParseAddr(foreignIP)), Unchecked)
	m := ParseSourceCheck(enforce("203.0.113.10/32"))
	eq(t, m.Judge(netip.MustParseAddr("::ffff:203.0.113.10")), Admitted)
	eq(t, ParseSourceCheck(enforce("203.0.113.10/24")).Prefixes[0].String(), "203.0.113.0/24")
	eq(t, []string{Unchecked.String(), Admitted.String(), Unmatched.String(), Refused.String()},
		[]string{"unchecked", "admitted", "unmatched", "refused"})
}

func TestTunnelSendsTheSourceToTheRouter(t *testing.T) {
	h := start(t)
	p := checked(t, h, enforce(ownIP+"/128"))
	c, _, err := h.tunnel(p.token, ownIP)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	h.router.mu.Lock()
	got := append([]string(nil), h.router.sources...)
	h.router.mu.Unlock()
	eq(t, got, []string{ownIP})
	eq(t, h.router.sourceResolves(), 1)
	eq(t, strings.Contains(h.log.String(), ownIP), false)
}

func TestEnforceForcesOneResolveThen403(t *testing.T) {
	h := start(t)
	p := checked(t, h, enforce(ownIP+"/128"))
	_, resp, err := h.tunnel(p.token, foreignIP)
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, 403)
	b := make([]byte, 8)
	n, _ := resp.Body.Read(b)
	eq(t, n, 0)
	// The resolve that made the placement, then the forced one
	eq(t, h.router.sourceResolves(), 2)
	_, resp, _ = h.tunnel(p.token, foreignIP)
	eq(t, resp.StatusCode, 403)
	eq(t, h.router.sourceResolves(), 2)
	logs := h.log.String()
	eq(t, strings.Contains(logs, "tunnel_source_refused"), true)
	eq(t, strings.Contains(logs, foreignIP), true)
}

func TestForcedResolveWaitsForSourceRecheck(t *testing.T) {
	h := start(t, func(c *Config, _ *Deps) { c.SourceRecheck = 50_000_000 })
	p := checked(t, h, enforce(ownIP+"/128"))
	_, _, _ = h.tunnel(p.token, foreignIP)
	eq(t, h.router.sourceResolves(), 2)
	time.Sleep(80 * time.Millisecond)
	_, _, _ = h.tunnel(p.token, foreignIP)
	eq(t, h.router.sourceResolves(), 3)
}

func TestForcedResolveThatMovesThePrefixServes(t *testing.T) {
	h := start(t)
	p := checked(t, h, enforce("2001:db8::1/128"))
	c, _, err := h.tunnel(p.token, "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	// The sandbox's address moved, and the router follows it when asked with the new source
	h.router.mu.Lock()
	h.router.onSource = func(p *fakePlacement, src string) {
		p.resp.SourceCheck = enforce(src + "/128")
	}
	h.router.mu.Unlock()
	c, _, err = h.tunnel(p.token, "2001:db8::9")
	if err != nil {
		t.Fatalf("the moved prefix was refused: %v", err)
	}
	_ = c.Close()
	eq(t, h.router.sourceResolves(), 2)
}

func TestReportServesLogsAndCounts(t *testing.T) {
	h := start(t)
	p := checked(t, h, report(ownIP+"/128"))
	c, _, err := h.tunnel(p.token, foreignIP)
	if err != nil {
		t.Fatalf("report mode refused a tunnel: %v", err)
	}
	_ = c.Close()
	eq(t, strings.Contains(h.log.String(), "tunnel_source_unmatched"), true)
	eq(t, strings.Contains(scrape(t, h), metricLine("unmatched")+"1"), true)
	c, _, err = h.tunnel(p.token, ownIP)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	eq(t, strings.Contains(scrape(t, h), metricLine("admitted")+"1"), true)
}

func TestEnforceWithNoPrefixesIs403(t *testing.T) {
	h := start(t)
	p := checked(t, h, enforce())
	_, resp, err := h.tunnel(p.token, ownIP)
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, 403)
}

func TestUncheckedTunnelsAreCounted(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	c, _, err := h.tunnel(p.token, foreignIP)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	eq(t, strings.Contains(scrape(t, h), metricLine("unchecked")+"1"), true)
	// No forced resolve for a tunnel nothing judges
	eq(t, h.router.sourceResolves(), 1)
}

func TestForeignTunnelsNeverTakeASlot(t *testing.T) {
	h := start(t, func(c *Config, _ *Deps) { c.TokenFailuresPerMinute = 0 })
	p := checked(t, h, enforce(ownIP+"/128"))
	for range 65 {
		_, resp, err := h.tunnel(p.token, foreignIP)
		eq(t, err != nil, true)
		eq(t, resp.StatusCode, 403)
	}
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for i := range 64 {
		c, _, err := h.tunnel(p.token, ownIP)
		if err != nil {
			t.Fatalf("tunnel %d of the sandbox itself: %v", i+1, err)
		}
		open = append(open, c)
	}
}

func TestRefusedSourceCountsAsAFailure(t *testing.T) {
	h := start(t, func(c *Config, _ *Deps) { c.TokenFailuresPerMinute = 3 })
	p := checked(t, h, enforce(ownIP+"/128"))
	for range 3 {
		_, resp, _ := h.tunnel(p.token, foreignIP)
		eq(t, resp.StatusCode, 403)
	}
	_, resp, err := h.tunnel(newToken(), foreignIP)
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, 429)
}

func TestChangedPrefixClosesOnlyInEnforce(t *testing.T) {
	for _, mode := range []string{"enforce", "report"} {
		t.Run(mode, func(t *testing.T) {
			h := start(t)
			check := enforce
			if mode == "report" {
				check = report
			}
			p := checked(t, h, check(ownIP+"/128"))
			c, _, err := h.tunnel(p.token, ownIP)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			h.router.setCheck(p, check("2001:db8::99/128"))
			h.server.secretsChanged(p.id.String())
			closed := func() bool {
				_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				_, err := c.Read(make([]byte, 1))
				ne, ok := err.(net.Error)
				return err != nil && (!ok || !ne.Timeout())
			}
			if mode == "enforce" {
				within(t, "the tunnel to close", closed)
				return
			}
			time.Sleep(300 * time.Millisecond)
			eq(t, closed(), false)
		})
	}
}

func TestFetcherTunnelNeverJudged(t *testing.T) {
	token := strings.Repeat("f", 40)
	h := start(t, func(c *Config, _ *Deps) { c.FetchToken = token })
	p, _ := h.placement(t, secretSpec{name: "PRIVATE", value: "repo_secret",
		hosts: []string{"github.com"}, fetch: true})
	h.router.setCheck(p, enforce(ownIP+"/128"))
	hdr := http.Header{"Bugnet-Placement": {p.id.String()}}
	c, _, err := h.tunnelWith("bnf_"+token, "127.0.0.1", hdr)
	if err != nil {
		t.Fatalf("the fetcher's tunnel was judged: %v", err)
	}
	_ = c.Close()
	eq(t, h.router.sourceResolves(), 0)
}

func scrape(t *testing.T, h *harness) string {
	t.Helper()
	resp, err := http.Get("http://" + h.metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
