package egress

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	routerv1 "github.com/bugnet-sh/bugnet-proto/gen/go/bugnet/router/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

func TestBindingRefusesMovedOrWidenedBox(t *testing.T) {
	h := start(t)
	other := newBoxKey(t, "other")
	_ = other
	p, phs := h.placement(t,
		// A box sealed for another placement, moved into this one's row
		secretSpec{name: "MOVED", value: "moved", hosts: []string{"a.example"},
			binding: Binding(newUUID())},
		// Hosts widened in the record after sealing
		secretSpec{name: "WIDE", value: "wide", hosts: []string{"b.example"},
			recordHosts: []string{"b.example", "evil.example"}},
		// Hosts sealed in another order match the record as sets
		secretSpec{name: "SET", value: "set", hosts: []string{"d.example", "c.example"},
			recordHosts: []string{"c.example", "d.example"}})
	c := h.client(p.token)
	try := func(host, ph string) string {
		t.Helper()
		resp := get(t, c, "https://"+host+"/", map[string]string{"Authorization": "Bearer " + ph})
		eq(t, resp.StatusCode, 200)
		return h.lastSeen().Header.Get("Authorization")
	}
	eq(t, try("a.example", phs[0]), "Bearer "+phs[0])
	eq(t, try("b.example", phs[1]), "Bearer "+phs[1])
	eq(t, try("evil.example", phs[1]), "Bearer "+phs[1])
	eq(t, try("c.example", phs[2]), "Bearer set")
	eq(t, try("d.example", phs[2]), "Bearer set")
	eq(t, strings.Contains(h.log.String(), "MOVED"), true)
}

func TestLostSecretsChangedStopsWithin60s(t *testing.T) {
	h := start(t, func(_ *Config, d *Deps) {
		d.CheckEvery = 100 * time.Millisecond
		d.RefreshEvery = 10 * time.Millisecond
	})
	p, ph := hfPlacement(t, h)
	c := h.client(p.token)
	resp := get(t, c, "https://hf.example/", map[string]string{"Authorization": "Bearer " + ph})
	eq(t, resp.StatusCode, 200)
	eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
	// The secret is deleted and its version moved, but no SecretsChanged is ever written
	h.router.mu.Lock()
	p.resp.Secrets, p.resp.SecretsVersion = nil, 2
	h.router.mu.Unlock()
	within(t, "the deleted secret to stop swapping", func() bool {
		req, _ := http.NewRequest(http.MethodGet, "https://hf.example/", nil)
		req.Header.Set("Authorization", "Bearer "+ph)
		r, err := c.Do(req)
		if err != nil {
			// The host left the set with its last secret, so the handshake fails
			return true
		}
		_ = r.Body.Close()
		// The host left the set, so the open connection gets a 421, or the swap itself stopped
		return r.StatusCode == http.StatusMisdirectedRequest ||
			h.lastSeen().Header.Get("Authorization") == "Bearer "+ph
	})
}

func TestSecretsChangedPicksUpANewSecret(t *testing.T) {
	h := start(t, func(_ *Config, d *Deps) { d.RefreshEvery = time.Hour })
	p, _ := hfPlacement(t, h)
	c := h.client(p.token)
	get(t, c, "https://hf.example/", nil)
	es, ph := h.secret(t, p.id, secretSpec{name: "NEW", value: "new_secret",
		hosts: []string{"hf.example"}})
	h.router.mu.Lock()
	p.resp.Secrets = append(p.resp.Secrets, es)
	p.resp.SecretsVersion = 2
	h.router.mu.Unlock()
	h.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_SecretsChanged{
		SecretsChanged: &routerv1.SecretsChanged{PlacementId: p.id.String()}}}
	within(t, "the new secret to swap", func() bool {
		get(t, c, "https://hf.example/", map[string]string{"Authorization": "Bearer " + ph})
		return h.lastSeen().Header.Get("Authorization") == "Bearer new_secret"
	})
}

func TestAMissingPlaceholderResolvesAtMostOnceEvery2Seconds(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	c := h.client(p.token)
	get(t, c, "https://hf.example/", nil)
	before := h.router.resolveCount()
	for range 5 {
		get(t, c, "https://hf.example/",
			map[string]string{"Authorization": "Bearer " + newPlaceholder()})
	}
	// The view is younger than 2 s, so no resolve happens at all
	eq(t, h.router.resolveCount(), before)
}

func TestAMissingPlaceholderResolvesOnceWhenTheViewIsOld(t *testing.T) {
	h := start(t, func(_ *Config, d *Deps) { d.RefreshEvery = 300 * time.Millisecond })
	p, _ := hfPlacement(t, h)
	c := h.client(p.token)
	get(t, c, "https://hf.example/", nil)
	time.Sleep(350 * time.Millisecond)
	before := h.router.resolveCount()
	for range 5 {
		get(t, c, "https://hf.example/",
			map[string]string{"Authorization": "Bearer " + newPlaceholder()})
	}
	eq(t, h.router.resolveCount(), before+1)
}

func TestSecretsAreSwappedAgainAfterARefreshKeepsThem(t *testing.T) {
	h := start(t, func(_ *Config, d *Deps) { d.RefreshEvery = time.Millisecond })
	p, ph := hfPlacement(t, h)
	c := h.client(p.token)
	for range 5 {
		h.server.secretsChanged(p.id.String())
		resp := get(t, c, "https://hf.example/", map[string]string{"Authorization": "Bearer " + ph})
		eq(t, resp.StatusCode, 200)
		eq(t, h.lastSeen().Header.Get("Authorization"), "Bearer hf_secret")
	}
}

func TestPlacementEndedClosesTunnelsAndZeroesValues(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	tc, err := h.inner(p.token, "hf.example")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	ended := make(chan string, 1)
	h.server.placesMu.Lock()
	place := h.server.places[p.id.String()+kindSuffix(false)]
	h.server.placesMu.Unlock()
	var held *secret
	for _, x := range place.view().set.byHash {
		held = x
	}
	h.server.endedListeners = append(h.server.endedListeners, func(id string) { ended <- id })
	h.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_PlacementEnded{
		PlacementEnded: &routerv1.PlacementEnded{PlacementId: p.id.String(),
			Reason: routerv1.EndReason_END_REASON_STOPPED}}}
	select {
	case id := <-ended:
		eq(t, id, p.id.String())
	case <-time.After(shortWait):
		t.Fatal("the placement did not end")
	}
	_, ok := held.read()
	eq(t, ok, false)
	_ = tc.SetReadDeadline(time.Now().Add(shortWait))
	_, err = tc.Read(make([]byte, 1))
	eq(t, err != nil, true)
	// New tunnels for it are refused once the router says it ended
	h.router.mu.Lock()
	p.notReady = true
	h.router.mu.Unlock()
	within(t, "new tunnels to be refused", func() bool {
		_, resp, err := h.tunnel(p.token, "203.0.113.9")
		return err != nil && resp.StatusCode == http.StatusUnauthorized
	})
}

func TestSpentBudgetClosesTunnelsAndRefusesNewOnes(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	tc, err := h.inner(p.token, "hf.example")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	h.router.mu.Lock()
	p.spent = true
	h.router.mu.Unlock()
	h.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
		BudgetSpent: &routerv1.BudgetSpent{PlacementId: p.id.String(),
			Kind: routerv1.BudgetKind_BUDGET_KIND_EGRESS}}}
	_ = tc.SetReadDeadline(time.Now().Add(shortWait))
	_, err = tc.Read(make([]byte, 1))
	eq(t, err != nil, true)
	within(t, "new tunnels to get 429", func() bool {
		_, resp, err := h.tunnel(p.token, "203.0.113.9")
		return err != nil && resp.StatusCode == http.StatusTooManyRequests
	})
}

func TestEdgeBudgetEventsDoNotEndEgress(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	c := h.client(p.token)
	get(t, c, "https://hf.example/", nil)
	h.router.events <- &routerv1.EdgeEvent{Event: &routerv1.EdgeEvent_BudgetSpent{
		BudgetSpent: &routerv1.BudgetSpent{PlacementId: p.id.String(),
			Kind: routerv1.BudgetKind_BUDGET_KIND_EDGE}}}
	time.Sleep(200 * time.Millisecond)
	resp := get(t, c, "https://hf.example/", nil)
	eq(t, resp.StatusCode, 200)
}

func TestDeadlinePassedEndsTunnels(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	h.router.mu.Lock()
	p.resp.Deadline = timestamppb.New(time.Now().Add(300 * time.Millisecond))
	h.router.mu.Unlock()
	tc, err := h.inner(p.token, "hf.example")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	h.router.mu.Lock()
	p.notReady = true
	h.router.mu.Unlock()
	_ = tc.SetReadDeadline(time.Now().Add(shortWait))
	_, err = tc.Read(make([]byte, 1))
	eq(t, err != nil, true)
}

func TestRouterDownFailsNewTunnelsButNotOpenOnes(t *testing.T) {
	h := start(t, func(c *Config, d *Deps) {
		c.ResolveCache = settings.Duration(150 * time.Millisecond)
		d.RefreshEvery = time.Millisecond
	})
	p, _ := hfPlacement(t, h)
	c := h.client(p.token)
	get(t, c, "https://hf.example/", nil)
	h.router.mu.Lock()
	h.router.down = connect.NewError(connect.CodeUnavailable, nil)
	h.router.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	// The token's cache entry expired, so the secret hosts fail closed
	_, resp, err := h.tunnel(p.token, "203.0.113.9")
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, http.StatusServiceUnavailable)
	// A tunnel that is already open keeps serving, from the view it holds
	r := getStream(t, c, "https://hf.example/", nil)
	eq(t, r.StatusCode, 200)
}

func TestLogsAndMetricsHoldNoSecrets(t *testing.T) {
	h := start(t)
	p, ph := hfPlacement(t, h)
	c := h.client(p.token)
	resp := get(t, c, "https://hf.example/q?token=secret-in-query",
		map[string]string{"Authorization": "Bearer " + ph, "Cookie": "sid=cookie-value"})
	eq(t, resp.StatusCode, 200)
	_, _, _ = h.tunnel(newToken(), "203.0.113.9")
	logs := h.log.String()
	for _, secret := range []string{"hf_secret", ph, p.token, "secret-in-query", "cookie-value",
		p.id.String()} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
	eq(t, strings.Contains(logs, "HF_TOKEN"), true)
	eq(t, strings.Contains(logs, "hf.example"), true)
}

func TestUsageIsReportedToTheRouter(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	resp := get(t, h.client(p.token), "https://hf.example/mid", nil)
	_, _ = readAll(resp)
	within(t, "usage to reach the router", func() bool {
		h.router.mu.Lock()
		defer h.router.mu.Unlock()
		return h.router.usageBytes > 3<<19
	})
}

func TestACAVersionTheProxyLacksIsRefused(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	h.router.mu.Lock()
	p.resp.CaVersion = 9
	h.router.mu.Unlock()
	_, resp, err := h.tunnel(p.token, "203.0.113.9")
	eq(t, err != nil, true)
	eq(t, resp.StatusCode, http.StatusServiceUnavailable)
}

func TestRefusedSNIReachesTheCallback(t *testing.T) {
	got := make(chan [2]string, 4)
	h := start(t, func(_ *Config, d *Deps) {
		d.RefusedSNI = func(placement, sni string) { got <- [2]string{placement, sni} }
	})
	p, _ := hfPlacement(t, h)
	_, err := h.inner(p.token, "unknown.example")
	eq(t, err != nil, true)
	select {
	case v := <-got:
		eq(t, v, [2]string{p.id.String(), "unknown.example"})
	case <-time.After(shortWait):
		t.Fatal("the callback did not run")
	}
}

func TestListenersSeeEndsAndVersions(t *testing.T) {
	h := start(t)
	p, _ := hfPlacement(t, h)
	get(t, h.client(p.token), "https://hf.example/", nil)
	versions := make(chan uint64, 1)
	h.server.versionListeners = append(h.server.versionListeners,
		func(_ string, v uint64) { versions <- v })
	h.server.tr.Leases.CheckNow()
	h.router.mu.Lock()
	p.resp.SecretsVersion = 7
	h.router.mu.Unlock()
	h.server.tr.Leases.CheckNow()
	select {
	case v := <-versions:
		eq(t, v, uint64(7))
	case <-time.After(shortWait):
		t.Fatal("the version listener did not run")
	}
}
