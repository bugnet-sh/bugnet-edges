package x402

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oynozan/bugnet-edges/internal/settings"
)

// file is egress's settings file as far as its [x402] table
type file struct {
	X402 Settings `toml:"x402"`
}

// load decodes doc as a settings file over the defaults
func load(t *testing.T, doc string) (Settings, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	f := file{X402: Defaults()}
	err := settings.Load(path, &f)
	return f.X402, err
}

func TestSettingsDefaults(t *testing.T) {
	eq(t, Defaults(), Settings{
		PaymentsURL:                 "https://127.0.0.1:8449",
		PaymentsServerName:          "bugnet-payments.internal",
		PaymentsCAFile:              "/etc/bugnet/internal-ca.pem",
		PaymentsClientCertFile:      "/etc/bugnet/egress-x402-client.pem",
		PaymentsClientKeyCredential: "egress_x402_client_key",
		PaymentsTimeout:             settings.Duration(3 * time.Second),
		PaidHeaderTimeout:           settings.Duration(150 * time.Second),
		FirstHeaderTimeout:          settings.Duration(30 * time.Second),
		BodyReadTimeout:             settings.Duration(10 * time.Second),
		CleanReportWait:             settings.Duration(time.Second),
		ReplayBodyMax:               1 << 20,
		BufferBudget:                256 << 20,
		BufferPerPlacement:          4 << 20,
		SellerHeaderMax:             64 << 10,
		PaymentRequiredMax:          32 << 10,
		MaxOpenSignedPerPlacement:   8,
		MaxResendsPerPayment:        3,
		ReportQueue:                 10000,
		EventFlushInterval:          settings.Duration(2 * time.Second),
		HostRateFloorPerPlacement:   20,
	})
	if err := Defaults().Check(); err != nil {
		t.Fatalf("the defaults fail their own check: %v", err)
	}
}

// specTable is XS 6.16's egress [x402] table as written there
const specTable = `
[x402]
payments_url = "https://127.0.0.1:8449"
payments_server_name = "bugnet-payments.internal"
payments_ca_file = "/etc/bugnet/internal-ca.pem"
payments_client_cert_file = "/etc/bugnet/egress-x402-client.pem"
payments_client_key_credential = "egress_x402_client_key"   # name under $CREDENTIALS_DIRECTORY
payments_timeout = "3s"
paid_header_timeout = "150s"
first_header_timeout = "30s"
body_read_timeout = "10s"
clean_report_wait = "1s"
replay_body_max = "1MiB"
buffer_budget = "256MiB"
buffer_per_placement = "4MiB"
seller_header_max = "64KiB"
payment_required_max = "32KiB"
max_open_signed_per_placement = 8
max_resends_per_payment = 3
host_rate_floor_per_placement = 20   # a minute per placement and host, never refused host_rate
report_queue = 10000
event_flush_interval = "2s"
`

func TestSettingsSpecTableIsTheDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress.toml")
	if err := os.WriteFile(path, []byte(specTable), 0o600); err != nil {
		t.Fatal(err)
	}
	var f file
	if err := settings.Load(path, &f); err != nil {
		t.Fatal(err)
	}
	eq(t, f.X402, Defaults())
}

func TestSettingsLoadOverDefaults(t *testing.T) {
	s, err := load(t, "[x402]\nreplay_body_max = \"2MiB\"\nmax_open_signed_per_placement = 4\n")
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	want.ReplayBodyMax, want.MaxOpenSignedPerPlacement = 2<<20, 4
	eq(t, s, want)
}

func TestSettingsUnknownKeyFails(t *testing.T) {
	for doc, want := range map[string]string{
		"[x402]\nreplay_body_maximum = \"1MiB\"\n": "x402.replay_body_maximum is not a setting",
		"[x402]\nself_hosted_sellers = []\n":       "x402.self_hosted_sellers is not a setting",
		"[x402]\nhost_rate_counts = \"unpaid\"\n":  "x402.host_rate_counts is not a setting",
		"[x402]\nReplay_Body_Max = \"1MiB\"\n":     "did you mean x402.replay_body_max",
		"[x402]\nenabled = true\n":                 "x402.enabled is not a setting",
	} {
		_, err := load(t, doc)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error with %q", doc, err, want)
		}
	}
}

func TestSettingsBounds(t *testing.T) {
	type change func(s *Settings)
	refused := []struct {
		name   string
		change change
		keys   []string
		secret string // a value the error must never quote
	}{
		{"http url", func(s *Settings) { s.PaymentsURL = "http://127.0.0.1:8449" },
			[]string{"x402.payments_url"}, "127.0.0.1:8449"},
		{"empty url", func(s *Settings) { s.PaymentsURL = "" }, []string{"x402.payments_url"}, ""},
		{"url without host", func(s *Settings) { s.PaymentsURL = "https://:8449" },
			[]string{"x402.payments_url"}, ""},
		{"url not a url", func(s *Settings) { s.PaymentsURL = "https://pay ments\x7f" },
			[]string{"x402.payments_url"}, "pay ments"},
		{"url with a password", func(s *Settings) {
			s.PaymentsURL = "https://egress:hunter2@127.0.0.1:8449/?x#y"
		}, []string{"x402.payments_url"}, "hunter2"},
		{"url with a user", func(s *Settings) {
			s.PaymentsURL = "https://egress-user@127.0.0.1:8449"
		}, []string{"x402.payments_url"}, "egress-user"},
		{"url with an empty user", func(s *Settings) { s.PaymentsURL = "https://@127.0.0.1:8449" },
			[]string{"x402.payments_url"}, ""},
		{"url with a query", func(s *Settings) {
			s.PaymentsURL = "https://127.0.0.1:8449/?token=t0k3n"
		}, []string{"x402.payments_url"}, "t0k3n"},
		{"url with an empty query", func(s *Settings) {
			s.PaymentsURL = "https://127.0.0.1:8449/?"
		}, []string{"x402.payments_url"}, ""},
		{"url with a fragment", func(s *Settings) {
			s.PaymentsURL = "https://127.0.0.1:8449/#fr4gment"
		}, []string{"x402.payments_url"}, "fr4gment"},
		{"url with an empty fragment", func(s *Settings) {
			s.PaymentsURL = "https://127.0.0.1:8449/#"
		}, []string{"x402.payments_url"}, ""},
		{"empty server name", func(s *Settings) { s.PaymentsServerName = "" },
			[]string{"x402.payments_server_name"}, ""},
		{"server name with a port", func(s *Settings) {
			s.PaymentsServerName = "pay.internal:8449"
		}, []string{"x402.payments_server_name"}, "pay.internal"},
		{"server name upper case", func(s *Settings) { s.PaymentsServerName = "Pay.Internal" },
			[]string{"x402.payments_server_name"}, "Pay.Internal"},
		{"empty ca file", func(s *Settings) { s.PaymentsCAFile = "" },
			[]string{"x402.payments_ca_file"}, ""},
		{"relative ca file", func(s *Settings) { s.PaymentsCAFile = "internal-ca.pem" },
			[]string{"x402.payments_ca_file"}, "internal-ca.pem"},
		{"relative cert file", func(s *Settings) { s.PaymentsClientCertFile = "client.pem" },
			[]string{"x402.payments_client_cert_file"}, "client.pem"},
		{"empty credential", func(s *Settings) { s.PaymentsClientKeyCredential = "" },
			[]string{"x402.payments_client_key_credential"}, ""},
		{"credential with a slash", func(s *Settings) { s.PaymentsClientKeyCredential = "a/key" },
			[]string{"x402.payments_client_key_credential"}, "a/key"},
		{"credential dot dot", func(s *Settings) { s.PaymentsClientKeyCredential = ".." },
			[]string{"x402.payments_client_key_credential"}, ""},
		{"credential with a space", func(s *Settings) { s.PaymentsClientKeyCredential = "a key" },
			[]string{"x402.payments_client_key_credential"}, "a key"},
		{"credential of 256 characters", func(s *Settings) {
			s.PaymentsClientKeyCredential = strings.Repeat("k", 256)
		}, []string{"x402.payments_client_key_credential"}, strings.Repeat("k", 256)},
		{"payments_timeout 0", func(s *Settings) { s.PaymentsTimeout = 0 },
			[]string{"x402.payments_timeout"}, ""},
		{"paid_header_timeout 0", func(s *Settings) { s.PaidHeaderTimeout = 0 },
			[]string{"x402.paid_header_timeout"}, ""},
		{"first_header_timeout 0", func(s *Settings) { s.FirstHeaderTimeout = 0 },
			[]string{"x402.first_header_timeout"}, ""},
		{"body_read_timeout 0", func(s *Settings) { s.BodyReadTimeout = 0 },
			[]string{"x402.body_read_timeout"}, ""},
		{"clean_report_wait 0", func(s *Settings) { s.CleanReportWait = 0 },
			[]string{"x402.clean_report_wait"}, ""},
		{"event_flush_interval 0", func(s *Settings) { s.EventFlushInterval = 0 },
			[]string{"x402.event_flush_interval"}, ""},
		{"event_flush_interval 3s", func(s *Settings) {
			s.EventFlushInterval = settings.Duration(3 * time.Second)
		}, []string{"x402.event_flush_interval"}, ""},
		{"replay_body_max 0", func(s *Settings) { s.ReplayBodyMax = 0 },
			[]string{"x402.replay_body_max"}, ""},
		{"buffer_budget 0", func(s *Settings) { s.BufferBudget = 0 },
			[]string{"x402.buffer_budget"}, ""},
		{"buffer_per_placement 0", func(s *Settings) { s.BufferPerPlacement = 0 },
			[]string{"x402.buffer_per_placement"}, ""},
		{"seller_header_max 0", func(s *Settings) { s.SellerHeaderMax = 0 },
			[]string{"x402.seller_header_max"}, ""},
		{"payment_required_max 0", func(s *Settings) { s.PaymentRequiredMax = 0 },
			[]string{"x402.payment_required_max"}, ""},
		{"max_open_signed_per_placement 0", func(s *Settings) { s.MaxOpenSignedPerPlacement = 0 },
			[]string{"x402.max_open_signed_per_placement"}, ""},
		{"max_resends_per_payment -1", func(s *Settings) { s.MaxResendsPerPayment = -1 },
			[]string{"x402.max_resends_per_payment"}, ""},
		{"report_queue 0", func(s *Settings) { s.ReportQueue = 0 },
			[]string{"x402.report_queue"}, ""},
		{"host_rate_floor_per_placement 0", func(s *Settings) { s.HostRateFloorPerPlacement = 0 },
			[]string{"x402.host_rate_floor_per_placement"}, ""},
		{"replay over per placement", func(s *Settings) {
			s.ReplayBodyMax, s.BufferPerPlacement = 5<<20, 4<<20
		}, []string{"x402.replay_body_max", "x402.buffer_per_placement"}, ""},
		{"per placement over budget", func(s *Settings) {
			s.BufferPerPlacement, s.BufferBudget = 512<<20, 256<<20
		}, []string{"x402.buffer_per_placement", "x402.buffer_budget"}, ""},
	}
	for _, c := range refused {
		s := Defaults()
		c.change(&s)
		err := s.Check()
		if err == nil {
			t.Errorf("%s: passed, want refused", c.name)
			continue
		}
		for _, k := range c.keys {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("%s: %q does not name %s", c.name, err, k)
			}
		}
		if c.secret != "" && strings.Contains(err.Error(), c.secret) {
			t.Errorf("%s: %q quotes the value", c.name, err)
		}
	}

	passed := []struct {
		name   string
		change change
	}{
		{"event_flush_interval 2s", func(s *Settings) {
			s.EventFlushInterval = settings.Duration(2 * time.Second)
		}},
		{"replay equals per placement", func(s *Settings) {
			s.ReplayBodyMax = s.BufferPerPlacement
		}},
		{"per placement equals budget", func(s *Settings) {
			s.BufferPerPlacement = s.BufferBudget
		}},
		{"floor of 1", func(s *Settings) { s.HostRateFloorPerPlacement = 1 }},
		{"url with a host name", func(s *Settings) { s.PaymentsURL = "https://payments.internal" }},
		{"url with a final slash", func(s *Settings) { s.PaymentsURL = "https://127.0.0.1:8449/" }},
		{"credential with dots", func(s *Settings) {
			s.PaymentsClientKeyCredential = "x402.key-1"
		}},
		{"credential of 255 characters", func(s *Settings) {
			s.PaymentsClientKeyCredential = strings.Repeat("k", 255)
		}},
	}
	for _, c := range passed {
		s := Defaults()
		c.change(&s)
		if err := s.Check(); err != nil {
			t.Errorf("%s: %v, want it to pass", c.name, err)
		}
	}
}

func TestSettingsBoundsThroughLoad(t *testing.T) {
	for doc, want := range map[string]string{
		"[x402]\nevent_flush_interval = \"3s\"\n":     "x402.event_flush_interval",
		"[x402]\nhost_rate_floor_per_placement = 0\n": "x402.host_rate_floor_per_placement",
	} {
		s, err := load(t, doc)
		if err != nil {
			t.Fatalf("%q: %v", doc, err)
		}
		err = s.Check()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error naming %s", doc, err, want)
		}
	}
}
