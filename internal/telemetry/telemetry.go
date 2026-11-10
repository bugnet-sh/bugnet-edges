// Package telemetry builds the edges' OpenTelemetry spans, which join the router's order trace
// (DP 20.5)
package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
)

// ShutdownTimeout bounds the flush every binary runs after its other shutdown steps
const ShutdownTimeout = 5 * time.Second

// Settings is the [telemetry] table
type Settings struct {
	Traces        bool
	OTLPEndpoint  string
	SampleRatio   float64
	Environment   string
	ExportTimeout time.Duration
	BatchTimeout  time.Duration
	BatchSize     int
	QueueSize     int
}

// Process names the binary on every span it exports
type Process struct {
	Service    string // bugnet-edge, bugnet-secrets, bugnet-ssh or bugnet-egress
	InstanceID string // edge_id, gateway_id or the egress reporter id
	Version    string // from debug.ReadBuildInfo when empty
}

// Telemetry is one process's tracing, a no-op when traces are off
type Telemetry struct {
	on       bool
	provider *sdktrace.TracerProvider
	ratio    float64
	log      *slog.Logger
	filter   *filterExporter
}

// Off returns a Telemetry that builds no spans and sends no headers
func Off() *Telemetry { return &Telemetry{log: slog.Default()} }

// New builds the exporter and tracer provider, authorization being BUGNET_OTLP_AUTHORIZATION
func New(s Settings, p Process, authorization string, log *slog.Logger) (*Telemetry, error) {
	if !s.Traces {
		return Off(), nil
	}
	if log == nil {
		log = slog.Default()
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	version := p.Version
	if version == "" {
		version = buildVersion()
	}
	if !attr.ResourceAllowed(p.Service, version, p.InstanceID, s.Environment) {
		return nil, errors.New("telemetry: the process name, version or instance id is not allowed")
	}
	res := resource.NewSchemaless(attr.Resource(p.Service, version, p.InstanceID, s.Environment)...)
	exp, err := otlptracehttp.New(context.Background(), exporterOptions(s, authorization)...)
	if err != nil {
		return nil, fmt.Errorf("telemetry: %w", err)
	}
	t := &Telemetry{on: true, ratio: s.SampleRatio, log: log}
	t.filter = newFilterExporter(exp, res, log)
	t.provider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(s.SampleRatio))),
		sdktrace.WithRawSpanLimits(spanLimits),
		sdktrace.WithBatcher(t.filter,
			sdktrace.WithMaxQueueSize(s.QueueSize),
			sdktrace.WithMaxExportBatchSize(s.BatchSize),
			sdktrace.WithBatchTimeout(s.BatchTimeout),
			sdktrace.WithExportTimeout(s.ExportTimeout)),
	)
	watchEnvironment(log)
	setErrorHandler(log)
	return t, nil
}

// spanLimits are DP 20.6.4's, no events and four links
var spanLimits = sdktrace.SpanLimits{
	AttributeValueLengthLimit:   256,
	AttributeCountLimit:         32,
	EventCountLimit:             0,
	LinkCountLimit:              4,
	AttributePerEventCountLimit: 0,
	AttributePerLinkCountLimit:  4,
}

// validate refuses settings the table's own check would have refused, for callers that skip it
func (s Settings) validate() error {
	switch {
	case !(s.SampleRatio >= 0 && s.SampleRatio <= 1):
		return errors.New("telemetry: sample_ratio must be 0 to 1")
	case s.QueueSize < 1 || s.BatchSize < 1 || s.BatchSize > s.QueueSize:
		return errors.New("telemetry: batch_size must be 1 to queue_size")
	case s.ExportTimeout <= 0 || s.BatchTimeout <= 0:
		return errors.New("telemetry: export_timeout and batch_timeout must be positive")
	}
	return checkEndpoint(s.OTLPEndpoint, true)
}

// checkEndpoint checks the OTLP URL, https or http to a loopback host, needed while traces are on
func checkEndpoint(raw string, on bool) error {
	if raw == "" {
		if on {
			return errors.New("telemetry.otlp_endpoint is required while telemetry.traces is true")
		}
		return nil
	}
	const want = "telemetry.otlp_endpoint must be an https URL with no user, or http to a " +
		"loopback host"
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return errors.New(want)
	}
	if u.Scheme == "https" || u.Scheme == "http" && loopbackHost(u.Hostname()) {
		return nil
	}
	return errors.New(want)
}

func loopbackHost(h string) bool {
	return h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1"
}

// exporterOptions passes every exporter option explicitly, so no OTEL_ variable applies
func exporterOptions(s Settings, authorization string) []otlptracehttp.Option {
	headers := map[string]string{}
	if authorization != "" {
		headers["Authorization"] = authorization
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(s.OTLPEndpoint),
		otlptracehttp.WithHeaders(headers),
		otlptracehttp.WithTimeout(s.ExportTimeout),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
			Enabled: true, InitialInterval: time.Second, MaxInterval: 5 * time.Second,
			MaxElapsedTime: s.ExportTimeout,
		}),
	}
	if strings.HasPrefix(s.OTLPEndpoint, "https://") {
		// The system roots, whatever OTEL_EXPORTER_OTLP_CERTIFICATE says
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}))
	}
	return opts
}

// buildVersion is 12 hex characters of vcs.revision, with +dirty when modified
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			rev = kv.Value
		case "vcs.modified":
			dirty = kv.Value == "true"
		}
	}
	if len(rev) < 12 {
		return "unknown"
	}
	if dirty {
		return rev[:12] + "+dirty"
	}
	return rev[:12]
}

var envOnce sync.Once

// watchEnvironment logs the names of OTEL_ variables once, since none of them applies
func watchEnvironment(log *slog.Logger) {
	envOnce.Do(func() {
		var names []string
		for _, kv := range os.Environ() {
			if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "OTEL_") {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			log.Warn("OTEL_ variables are ignored, settings live in the telemetry table",
				"names", names)
		}
	})
}

var (
	errMu   sync.Mutex
	errLog  *slog.Logger
	errLast time.Time
	errN    int
	errOnce sync.Once
	reHTTP  = regexp.MustCompile(`\b([1-5][0-9]{2})\b`)
)

// setErrorHandler logs export errors at most once a minute, with a count and the HTTP status
func setErrorHandler(log *slog.Logger) {
	errMu.Lock()
	errLog = log
	errMu.Unlock()
	errOnce.Do(func() {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
			errMu.Lock()
			defer errMu.Unlock()
			errN++
			if time.Since(errLast) < time.Minute {
				return
			}
			errLast = time.Now()
			args := []any{"count", errN}
			if m := reHTTP.FindString(err.Error()); m != "" {
				args = append(args, "status", m)
			}
			errN = 0
			errLog.Warn("trace export failed", args...)
		}))
	})
}

// Enabled reports whether spans are exported
func (t *Telemetry) Enabled() bool { return t != nil && t.on }

// Tracer returns the tracer of one package, scoped by its import path
func (t *Telemetry) Tracer(pkg string) trace.Tracer {
	if !t.Enabled() {
		return noop.NewTracerProvider().Tracer(pkg)
	}
	return t.provider.Tracer(pkg)
}

// Flush exports every finished span now, within ctx
func (t *Telemetry) Flush(ctx context.Context) error {
	if !t.Enabled() {
		return nil
	}
	return t.provider.ForceFlush(ctx)
}

// Shutdown flushes the queue within ctx and stops the exporter
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if !t.Enabled() {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// Close flushes the queue within ShutdownTimeout, for a binary's last shutdown step
func (t *Telemetry) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	_ = t.Shutdown(ctx)
}

// Child starts a span only under a valid span context, else returns ctx and a no-op span
func Child(ctx context.Context, tr trace.Tracer, name string, attrs ...attr.KeyValue) (
	context.Context, trace.Span) {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx, trace.SpanFromContext(context.Background())
	}
	return tr.Start(ctx, name, trace.WithAttributes(attrs...))
}

// Fail marks span failed with a stable reason, never an error's text
func Fail(span trace.Span, reason string) {
	span.SetAttributes(attr.Reason(reason))
	span.SetStatus(codes.Error, strings.ToUpper(reason))
}
