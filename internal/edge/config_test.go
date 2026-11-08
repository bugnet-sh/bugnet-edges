package edge

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-edges/internal/settings"
)

const (
	edgeToken  = "edge-token-0123456789abcdefghijklmnop"
	hookSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	secToken   = "secrets-token-0123456789abcdefghijklmn"
)

func env(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func edgeEnv() func(string) (string, bool) {
	return env(map[string]string{
		"BUGNET_EDGE_TOKEN": edgeToken, "BUGNET_HOOK_PATH_SECRET": hookSecret,
	})
}

// writeFile puts doc in a new settings file and returns its path
func writeFile(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimal = `
[names]
preview_domain = "preview.example.test"
transfer_host = "transfer.example.test"
hooks_host = "hooks.example.test"

[previews]
abuse_contact = "abuse@example.test"
`

func TestExampleEdgeLoadsAtTheDefaults(t *testing.T) {
	cfg, err := Load("../../example/edge.toml", edgeEnv())
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	want.Names = Names{
		PreviewDomain: "preview.bugnet.sh", TransferHost: "transfer.bugnet.sh",
		HooksHost: "hooks.bugnet.sh",
	}
	want.Previews.AbuseContact = "abuse@bugnet.org"
	want.EdgeID = cfg.EdgeID
	want.Token, want.HookPathSecret = edgeToken, hookSecret
	eq(t, cfg, want)
}

func TestEdgeDefaults(t *testing.T) {
	cfg, err := Load(writeFile(t, minimal), edgeEnv())
	if err != nil {
		t.Fatal(err)
	}
	eq(t, cfg.RouterURL, "http://127.0.0.1:8080")
	eq(t, cfg.TLSListenAddr, "127.0.0.1:8443")
	eq(t, cfg.RedirectListenAddr, ":80")
	eq(t, cfg.MetricsListenAddr, "127.0.0.1:9101")
	eq(t, cfg.ProxyProtocolFrom, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"),
	})
	eq(t, time.Duration(cfg.Drain), 5*time.Minute)
	eq(t, cfg.MaxConcurrentStreams, 128)
	eq(t, cfg.TotalBytesPerSecond, settings.Bytes(40<<20))
	eq(t, cfg.Previews, Previews{
		ResolveCache: 10000, RouteTTL: settings.Duration(time.Minute),
		TokenFailuresPerMinute: 20, QueueWait: settings.Duration(30 * time.Second),
		QueueMax: 256, AbuseContact: "abuse@example.test", BoatRequestsPerMinute: 5000,
	})
	eq(t, cfg.Transfers, Transfers{
		Chunk: 256 << 10, IdleTimeout: settings.Duration(time.Minute),
		TokenFailuresPerMinute: 20, MaxConnectionsPerIP: 16,
	})
	eq(t, cfg.Hooks, Hooks{MaxBody: 64 << 10, RequestsPerMinute: 60})
	eq(t, cfg.Usage, Usage{
		ReportInterval: settings.Duration(5 * time.Second), ReportBytes: 8 << 20,
	})
	eq(t, cfg.ACME, ACME{
		Enabled: true, Directory: "https://acme-v02.api.letsencrypt.org/directory",
		StateDir: "/var/lib/bugnet-edge", WildcardDir: "/var/lib/bugnet-certs/preview",
	})
}

func TestEdgeIDIsHostAndPIDWhenEmpty(t *testing.T) {
	cfg, err := Load(writeFile(t, minimal), edgeEnv())
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if !strings.HasSuffix(cfg.EdgeID, "-"+strconv.Itoa(os.Getpid())) || host == "" {
		t.Fatalf("edge id %q", cfg.EdgeID)
	}
	eq(t, edgeID.MatchString(cfg.EdgeID), true)
	cfg, err = Load(writeFile(t, "edge_id = \"edge-a1\"\n"+minimal), edgeEnv())
	if err != nil {
		t.Fatal(err)
	}
	eq(t, cfg.EdgeID, "edge-a1")
}

func TestEdgeSettingsRefused(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{"", "names.preview_domain is required"},
		{strings.Replace(minimal, `abuse_contact = "abuse@example.test"`, "", 1),
			"previews.abuse_contact is required"},
		{strings.Replace(minimal, `"hooks.example.test"`, `"Hooks.example.test"`, 1),
			"names.hooks_host must be a lowercase host name"},
		{strings.Replace(minimal, `"transfer.example.test"`, `"x.preview.example.test"`, 1),
			"names.transfer_host must not be a preview"},
		{strings.Replace(minimal, `"hooks.example.test"`, `"transfer.example.test"`, 1),
			"names.hooks_host must differ"},
		{strings.Replace(minimal, `"transfer.example.test"`, `"preview.example.test"`, 1),
			"names.transfer_host must differ"},
		{strings.Replace(minimal, `"abuse@example.test"`, `"http://example.test/abuse"`, 1),
			"previews.abuse_contact must be a mail address or an https URL"},
		{strings.Replace(minimal, `"abuse@example.test"`, `"abuse at example"`, 1),
			"previews.abuse_contact must be a mail address or an https URL"},
		{"router_url = \"127.0.0.1:8080\"\n" + minimal, "router_url must be an http or https URL"},
		{"edge_id = \"a b\"\n" + minimal, "edge_id must be 1 to 64 letters"},
		{"tls_listen_addr = \"\"\n" + minimal, "tls_listen_addr must be a host and port"},
		{"metrics_listen_addr = \"9101\"\n" + minimal, "metrics_listen_addr must be a host"},
		{"redirect_listen_addr = \"80\"\n" + minimal, "redirect_listen_addr must be empty or"},
		{"proxy_protocol_from = []\n" + minimal, "proxy_protocol_from needs at least one"},
		{"drain = \"2h\"\n" + minimal, "drain must be at most 1h"},
		{"max_concurrent_streams = 0\n" + minimal, "max_concurrent_streams must be 1 to"},
		{minimal + "resolve_cache = 0\n", "previews.resolve_cache must be at least 1"},
		{minimal + "route_ttl = \"0s\"\n", "previews.route_ttl must be more than 0"},
		{minimal + "queue_wait = \"0s\"\n", "previews.queue_wait must be more than 0"},
		{minimal + "queue_max = 0\n", "previews.queue_max must be at least 1"},
		{minimal + "token_failures_per_minute = -1\n", "previews.token_failures_per_minute"},
		{minimal + "boat_requests_per_minute = -1\n", "previews.boat_requests_per_minute"},
		{minimal + "[transfers]\nchunk = \"1KiB\"\n", "transfers.chunk must be 4KiB to 4MiB"},
		{minimal + "[transfers]\nidle_timeout = \"0s\"\n", "transfers.idle_timeout must be"},
		{minimal + "[transfers]\nmax_connections_per_ip = 0\n",
			"transfers.max_connections_per_ip must be at least 1"},
		{minimal + "[hooks]\nmax_body = 0\n", "hooks.max_body must be 1KiB to 1MiB"},
		{minimal + "[hooks]\nrequests_per_minute = -1\n", "hooks.requests_per_minute"},
		{minimal + "[usage]\nreport_interval = \"0s\"\n", "usage.report_interval must be"},
		{minimal + "[acme]\ndirectory = \"\"\n", "acme.directory must be an http or https URL"},
		{minimal + "[acme]\nstate_dir = \"\"\n", "acme.state_dir is required"},
		{minimal + "[acme]\nwildcard_dir = \"\"\n", "acme.wildcard_dir is required"},
		{minimal + "[acme]\nenabled = false\n", "acme.static_dir is required"},
		{minimal + "[acme]\nstatic_dir = \"x\"\n", "acme.static_dir must be an absolute path"},
	} {
		_, err := Load(writeFile(t, tc.doc), edgeEnv())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.doc, err, tc.want)
		}
	}
	_, err := Load(writeFile(t, minimal+"[acme]\nenabled = false\nstatic_dir = \"/x\"\n"),
		edgeEnv())
	eq(t, err, nil)
	_, err = Load(writeFile(t, "redirect_listen_addr = \"\"\n"+minimal), edgeEnv())
	eq(t, err, nil)
}

func TestEdgeSecretsComeFromTheEnvironment(t *testing.T) {
	path := writeFile(t, minimal)
	for _, tc := range []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"BUGNET_HOOK_PATH_SECRET": hookSecret}, "BUGNET_EDGE_TOKEN is required"},
		{map[string]string{"BUGNET_EDGE_TOKEN": "short", "BUGNET_HOOK_PATH_SECRET": hookSecret},
			"BUGNET_EDGE_TOKEN must be at least 32"},
		{map[string]string{
			"BUGNET_EDGE_TOKEN": edgeToken + " x", "BUGNET_HOOK_PATH_SECRET": hookSecret,
		}, "BUGNET_EDGE_TOKEN must be at least 32"},
		{map[string]string{"BUGNET_EDGE_TOKEN": edgeToken}, "BUGNET_HOOK_PATH_SECRET is required"},
		{map[string]string{"BUGNET_EDGE_TOKEN": edgeToken, "BUGNET_HOOK_PATH_SECRET": "c2hvcnQ"},
			"BUGNET_HOOK_PATH_SECRET must be 32 bytes in base64url"},
		{map[string]string{
			"BUGNET_EDGE_TOKEN": edgeToken, "BUGNET_HOOK_PATH_SECRET": hookSecret + "=",
		}, "BUGNET_HOOK_PATH_SECRET must be 32 bytes in base64url"},
	} {
		_, err := Load(path, env(tc.vars))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("got %v, want %q", err, tc.want)
		}
		for _, v := range tc.vars {
			if strings.Contains(err.Error(), v) {
				t.Fatalf("%q quotes a secret", err)
			}
		}
	}
}

func TestExampleSecretsRouteLoadsAtTheDefaults(t *testing.T) {
	cfg, err := LoadSecrets("../../example/secrets-route.toml",
		env(map[string]string{"BUGNET_SECRETS_TOKEN": secToken}))
	if err != nil {
		t.Fatal(err)
	}
	want := SecretsDefaults()
	want.Host = "secrets.bugnet.sh"
	want.Token = secToken
	eq(t, cfg, want)
	eq(t, cfg.MaxHeaderBytes, settings.Bytes(1<<20))
	eq(t, cfg.TLSListenAddr, "127.0.0.1:8445")
	eq(t, cfg.MetricsListenAddr, "127.0.0.1:9104")
	eq(t, cfg.ACMEDir, "/var/lib/bugnet-secrets/acme")
}

func TestSecretsRouteSettingsRefused(t *testing.T) {
	good := env(map[string]string{"BUGNET_SECRETS_TOKEN": secToken})
	for _, tc := range []struct{ doc, want string }{
		{"", "host is required"},
		{"host = \"Secrets.example.test\"\n", "host must be a lowercase host name"},
		{"host = \"s.example.test\"\nmax_header_bytes = \"1KiB\"\n",
			"max_header_bytes must be 4KiB to 4MiB"},
		{"host = \"s.example.test\"\npage_dir = \"x\"\n", "page_dir must be an absolute path"},
		{"host = \"s.example.test\"\nrequests_per_minute = -1\n", "requests_per_minute"},
		{"host = \"s.example.test\"\nacme_dir = \"\"\n", "acme_dir is required"},
		{"host = \"s.example.test\"\nacme_enabled = false\n", "static_dir is required"},
		{"host = \"s.example.test\"\nproxy_protocol_from = []\n", "proxy_protocol_from needs"},
	} {
		_, err := LoadSecrets(writeFile(t, tc.doc), good)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.doc, err, tc.want)
		}
	}
	_, err := LoadSecrets(writeFile(t, "host = \"s.example.test\"\n"), env(nil))
	if err == nil || !strings.Contains(err.Error(), "BUGNET_SECRETS_TOKEN is required") {
		t.Fatalf("got %v", err)
	}
	_, err = LoadSecrets(writeFile(t, "host = \"s.example.test\"\nbogus = 1\n"), good)
	if err == nil || !strings.Contains(err.Error(), "bogus is not a setting") {
		t.Fatalf("got %v", err)
	}
}

const sessToken = "sessions-token-0123456789abcdefghijk"

func TestExampleSessionsLoadsAtTheDefaults(t *testing.T) {
	cfg, err := LoadSessions("../../example/sessions.toml",
		env(map[string]string{"BUGNET_SESSIONS_TOKEN": sessToken}))
	if err != nil {
		t.Fatal(err)
	}
	want := SessionsDefaults()
	want.Host = "sessions.bugnet.sh"
	want.Token = sessToken
	eq(t, cfg, want)
	eq(t, cfg.TLSListenAddr, "127.0.0.1:8448")
	eq(t, cfg.MetricsListenAddr, "127.0.0.1:9105")
	eq(t, cfg.MaxHeaderBytes, settings.Bytes(1<<20))
	eq(t, cfg.ACMEDir, "/var/lib/bugnet-sessions/acme")
	eq(t, cfg.PageDir, "/srv/bugnet/session-page")
	eq(t, [6]int{cfg.RequestsPerMinute, cfg.KeyFailuresPerMinute, cfg.IDFailuresPerMinute,
		cfg.LivePerRecord, cfg.LivePerIP, cfg.LiveMax}, [6]int{60, 20, 20, 8, 4, 256})
}

func TestSessionsSettingsRefused(t *testing.T) {
	good := env(map[string]string{"BUGNET_SESSIONS_TOKEN": sessToken})
	const host = "host = \"s.example.test\"\n"
	for _, tc := range []struct{ doc, want string }{
		{"", "host is required"},
		{"host = \"Sessions.example.test\"\n", "host must be a lowercase host name"},
		{host + "max_header_bytes = \"32KiB\"\n", "max_header_bytes must be 64KiB to 4MiB"},
		{host + "page_dir = \"x\"\n", "page_dir must be an absolute path"},
		{host + "requests_per_minute = -1\n", "requests_per_minute must be 0 or more"},
		{host + "key_failures_per_minute = -1\n", "key_failures_per_minute"},
		{host + "id_failures_per_minute = -1\n", "id_failures_per_minute"},
		{host + "live_per_record = -1\n", "live_per_record"},
		{host + "live_per_ip = -1\n", "live_per_ip"},
		{host + "live_max = -1\n", "live_max"},
		{host + "acme_dir = \"\"\n", "acme_dir is required"},
		{host + "acme_enabled = false\n", "static_dir is required"},
		{host + "proxy_protocol_from = []\n", "proxy_protocol_from needs"},
		{host + "tls_listen_addr = \"8448\"\n", "tls_listen_addr must be a host and port"},
	} {
		_, err := LoadSessions(writeFile(t, tc.doc), good)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.doc, err, tc.want)
		}
	}
	_, err := LoadSessions(writeFile(t, host), env(nil))
	if err == nil || !strings.Contains(err.Error(), "BUGNET_SESSIONS_TOKEN is required") {
		t.Fatalf("got %v", err)
	}
	// The secrets route's token is another caller's
	_, err = LoadSessions(writeFile(t, host),
		env(map[string]string{"BUGNET_SECRETS_TOKEN": secToken}))
	if err == nil || !strings.Contains(err.Error(), "BUGNET_SESSIONS_TOKEN is required") {
		t.Fatalf("got %v", err)
	}
}
