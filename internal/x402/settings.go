// Package x402 holds egress's x402 host kind, its settings, refusals, dollar text and header rules
package x402

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"time"

	"github.com/oynozan/bugnet-edges/internal/hostname"
	"github.com/oynozan/bugnet-edges/internal/settings"
)

// Settings is egress's [x402] table, XS 6.16
type Settings struct {
	PaymentsURL                 string            `toml:"payments_url"`
	PaymentsServerName          string            `toml:"payments_server_name"`
	PaymentsCAFile              string            `toml:"payments_ca_file"`
	PaymentsClientCertFile      string            `toml:"payments_client_cert_file"`
	PaymentsClientKeyCredential string            `toml:"payments_client_key_credential"`
	PaymentsTimeout             settings.Duration `toml:"payments_timeout"`
	PaidHeaderTimeout           settings.Duration `toml:"paid_header_timeout"`
	FirstHeaderTimeout          settings.Duration `toml:"first_header_timeout"`
	BodyReadTimeout             settings.Duration `toml:"body_read_timeout"`
	CleanReportWait             settings.Duration `toml:"clean_report_wait"`
	ReplayBodyMax               settings.Bytes    `toml:"replay_body_max"`
	BufferBudget                settings.Bytes    `toml:"buffer_budget"`
	BufferPerPlacement          settings.Bytes    `toml:"buffer_per_placement"`
	SellerHeaderMax             settings.Bytes    `toml:"seller_header_max"`
	PaymentRequiredMax          settings.Bytes    `toml:"payment_required_max"`
	MaxOpenSignedPerPlacement   int               `toml:"max_open_signed_per_placement"`
	MaxResendsPerPayment        int               `toml:"max_resends_per_payment"`
	ReportQueue                 int               `toml:"report_queue"`
	EventFlushInterval          settings.Duration `toml:"event_flush_interval"`
	HostRateFloorPerPlacement   int               `toml:"host_rate_floor_per_placement"`
}

// Defaults are XS 6.16's values
func Defaults() Settings {
	return Settings{
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
	}
}

// maxFlush is the longest event flush, since the 5.6 hint checks again after 2.5 s
const maxFlush = 2 * time.Second

// credential is a file name under $CREDENTIALS_DIRECTORY that cannot leave it
var credential = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,254}$`)

// Check holds XS 6.16's bounds
func (s Settings) Check() error {
	checks := []func() error{
		s.checkPayments,
		func() error {
			for _, d := range []struct {
				key string
				v   settings.Duration
			}{
				{"payments_timeout", s.PaymentsTimeout},
				{"paid_header_timeout", s.PaidHeaderTimeout},
				{"first_header_timeout", s.FirstHeaderTimeout},
				{"body_read_timeout", s.BodyReadTimeout},
				{"clean_report_wait", s.CleanReportWait},
				{"event_flush_interval", s.EventFlushInterval},
			} {
				if d.v <= 0 {
					return fmt.Errorf("x402.%s must be more than 0", d.key)
				}
			}
			if time.Duration(s.EventFlushInterval) > maxFlush {
				return errors.New("x402.event_flush_interval must be at most 2s")
			}
			return nil
		},
		func() error {
			for _, b := range []struct {
				key string
				v   settings.Bytes
			}{
				{"replay_body_max", s.ReplayBodyMax},
				{"buffer_budget", s.BufferBudget},
				{"buffer_per_placement", s.BufferPerPlacement},
				{"seller_header_max", s.SellerHeaderMax},
				{"payment_required_max", s.PaymentRequiredMax},
			} {
				if b.v <= 0 {
					return fmt.Errorf("x402.%s must be more than 0", b.key)
				}
			}
			switch {
			case s.ReplayBodyMax > s.BufferPerPlacement:
				return errors.New("x402.replay_body_max must be at most x402.buffer_per_placement")
			case s.BufferPerPlacement > s.BufferBudget:
				return errors.New("x402.buffer_per_placement must be at most x402.buffer_budget")
			}
			return nil
		},
		func() error {
			for _, n := range []struct {
				key string
				v   int
			}{
				{"max_open_signed_per_placement", s.MaxOpenSignedPerPlacement},
				{"max_resends_per_payment", s.MaxResendsPerPayment},
				{"report_queue", s.ReportQueue},
				{"host_rate_floor_per_placement", s.HostRateFloorPerPlacement},
			} {
				if n.v < 1 {
					return fmt.Errorf("x402.%s must be at least 1", n.key)
				}
			}
			return nil
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkPayments holds the keys that say where Payments is and how egress proves itself to it
func (s Settings) checkPayments() error {
	u, err := url.Parse(s.PaymentsURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("x402.payments_url must be an https URL with a host")
	}
	if !hostname.Valid(s.PaymentsServerName) {
		return errors.New("x402.payments_server_name must be a lowercase host name with no " +
			"scheme, port or final dot")
	}
	for _, f := range []struct{ key, path string }{
		{"payments_ca_file", s.PaymentsCAFile},
		{"payments_client_cert_file", s.PaymentsClientCertFile},
	} {
		if f.path == "" {
			return fmt.Errorf("x402.%s is required", f.key)
		}
		if !filepath.IsAbs(f.path) {
			return fmt.Errorf("x402.%s must be an absolute path", f.key)
		}
	}
	if !credential.MatchString(s.PaymentsClientKeyCredential) {
		return errors.New("x402.payments_client_key_credential must be a credential name of " +
			"letters, digits, dots, underscores or hyphens, not starting with a dot")
	}
	return nil
}
