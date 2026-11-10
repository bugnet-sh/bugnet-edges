package telemetry

import (
	"cmp"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
)

// Table is the [telemetry] table of an edge binary's settings file, DP 20.7.2
type Table struct {
	Traces        bool              `toml:"traces"`
	OTLPEndpoint  string            `toml:"otlp_endpoint"`
	SampleRatio   float64           `toml:"sample_ratio"`
	Environment   string            `toml:"environment"`
	ExportTimeout settings.Duration `toml:"export_timeout"`
	BatchTimeout  settings.Duration `toml:"batch_timeout"`
	BatchSize     int               `toml:"batch_size"`
	QueueSize     int               `toml:"queue_size"`
}

// DefaultTable is the table at its defaults, traces off
func DefaultTable() Table {
	return Table{
		SampleRatio: 1, Environment: "main", ExportTimeout: settings.Duration(10 * time.Second),
		BatchTimeout: settings.Duration(5 * time.Second), BatchSize: 512, QueueSize: 2048,
	}
}

const maxQueue = 1_000_000

var environmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Check refuses a table outside its bounds, naming the key
func (t Table) Check() error {
	if err := checkEndpoint(t.OTLPEndpoint, t.Traces); err != nil {
		return err
	}
	switch {
	case !(t.SampleRatio >= 0 && t.SampleRatio <= 1):
		return errors.New("telemetry.sample_ratio must be 0 to 1")
	case !environmentName.MatchString(cmp.Or(t.Environment, "main")):
		return errors.New("telemetry.environment must be 1 to 32 characters of a to z, 0 to 9, " +
			"_ and -")
	case !inRange(time.Duration(t.ExportTimeout)):
		return errors.New("telemetry.export_timeout must be a Go duration of 100ms to 1m")
	case !inRange(time.Duration(t.BatchTimeout)):
		return errors.New("telemetry.batch_timeout must be a Go duration of 100ms to 1m")
	case t.QueueSize < 1 || t.QueueSize > maxQueue:
		return errors.New("telemetry.queue_size must be 1 to 1000000")
	case t.BatchSize < 1 || t.BatchSize > t.QueueSize:
		return errors.New("telemetry.batch_size must be 1 to telemetry.queue_size")
	}
	return nil
}

func inRange(d time.Duration) bool { return d >= 100*time.Millisecond && d <= time.Minute }

// Settings is the table as New takes it
func (t Table) Settings() Settings {
	return Settings{
		Traces: t.Traces, OTLPEndpoint: t.OTLPEndpoint, SampleRatio: t.SampleRatio,
		Environment: cmp.Or(t.Environment, "main"), ExportTimeout: time.Duration(t.ExportTimeout),
		BatchTimeout: time.Duration(t.BatchTimeout), BatchSize: t.BatchSize,
		QueueSize: t.QueueSize,
	}
}

// FromTable builds the telemetry of one binary from its table and the environment's
// BUGNET_OTLP_AUTHORIZATION
func FromTable(
	t Table, p Process, getenv func(string) (string, bool), log *slog.Logger,
) (*Telemetry, error) {
	auth, _ := getenv("BUGNET_OTLP_AUTHORIZATION")
	return New(t.Settings(), p, auth, log)
}
