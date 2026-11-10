package telemetry_test

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/bugnet-sh/bugnet-edges/internal/settings"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/attr"
	"github.com/bugnet-sh/bugnet-edges/internal/telemetry/telemetrytest"
)

func tableSettings(endpoint string, ratio float64) telemetry.Settings {
	return telemetry.Settings{
		Traces: true, OTLPEndpoint: endpoint, SampleRatio: ratio, Environment: "test",
		ExportTimeout: 5 * time.Second, BatchTimeout: time.Minute, BatchSize: 512,
		QueueSize: 2048,
	}
}

func TestFilterDropsForbidden(t *testing.T) {
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	_, span := tel.Tracer("test").Start(t.Context(), "Bad Name With Spaces")
	span.SetAttributes(
		attribute.String("bugnet.handle_hash", "9a5bf94fe52b"),
		attribute.String("url.full", "https://x/?a"),
		attribute.String("bugnet.reason", "bnx_secret"),
		attribute.String("bugnet.state", "Ready State"),
		attribute.Int("bugnet.attempt", -1),
		attribute.String("bugnet.provider", "boat"),
	)
	span.AddEvent("exception", trace.WithAttributes(attribute.String("exception.message", "x")))
	span.RecordError(os.ErrNotExist)
	span.SetStatus(codes.Error, strings.Repeat("e", 200))
	span.End()
	got := tel.Flushed(t)
	eq(t, len(got), 1)
	s := got[0]
	keys := make([]string, 0, len(s.Attrs))
	for k := range s.Attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	eq(t, keys, []string{"bugnet.handle_hash", "bugnet.provider"})
	eq(t, s.Events, 0)
	eq(t, s.StatusText, "")
	eq(t, s.Name, "unnamed")
}

func TestAttributeImportOnlyInAttr(t *testing.T) {
	root := filepath.Join("..", "..")
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if im.Path.Value == `"go.opentelemetry.io/otel/attribute"` &&
				!strings.HasSuffix(filepath.ToSlash(path), "internal/telemetry/attr/attr.go") {
				bad = append(bad, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, bad, []string(nil))
}

func TestOTELEnvIgnored(t *testing.T) {
	bait := telemetrytest.NewReceiver(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", bait.URL())
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", bait.URL())
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-evil=1")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=evil,leak=x")
	t.Setenv("OTEL_SERVICE_NAME", "evil")
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	_, span := tel.Tracer("test").Start(t.Context(), "one")
	span.SetAttributes(attr.Provider("boat"), attr.Size("small"), attr.Count(1))
	span.End()
	got := tel.Flushed(t)
	eq(t, len(got), 1)
	eq(t, len(got[0].Attrs), 3)
	eq[any](t, got[0].Resource["service.name"], "bugnet-edge")
	_, leaked := got[0].Resource["leak"]
	eq(t, leaked, false)
	eq(t, bait.Requests, 0)
	for _, h := range tel.Recv.Headers {
		eq(t, h.Get("X-Evil"), "")
		eq(t, h.Get("Content-Encoding"), "gzip")
	}
}

func TestResourceAttributes(t *testing.T) {
	tel := telemetrytest.New(t, "bugnet-ssh", 1)
	_, span := tel.Tracer("test").Start(t.Context(), "one")
	span.End()
	res := tel.Flushed(t)[0].Resource
	eq[any](t, res["service.name"], "bugnet-ssh")
	eq[any](t, res["service.instance.id"], "edge-1")
	eq[any](t, res["deployment.environment.name"], "test")
	v, _ := res["service.version"].(string)
	if v != "unknown" && len(v) < 12 {
		t.Fatalf("version %q", v)
	}
}

func TestAuthorizationHeader(t *testing.T) {
	r := telemetrytest.NewReceiver(t)
	tel, err := telemetry.New(tableSettings(r.URL(), 1),
		telemetry.Process{Service: "bugnet-edge", InstanceID: "e1"}, "Basic dGVzdDp0ZXN0",
		slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, span := tel.Tracer("test").Start(t.Context(), "one")
	span.End()
	if err := tel.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	eq(t, len(r.Headers), 1)
	eq(t, r.Headers[0].Get("Authorization"), "Basic dGVzdDp0ZXN0")
	// An empty authorization sends no header
	r2 := telemetrytest.New(t, "bugnet-edge", 1)
	_, span = r2.Tracer("test").Start(t.Context(), "one")
	span.End()
	r2.Flushed(t)
	eq(t, r2.Recv.Headers[0].Get("Authorization"), "")
}

func TestFromTableReadsTheAuthorizationVariable(t *testing.T) {
	r := telemetrytest.NewReceiver(t)
	tab := telemetry.DefaultTable()
	tab.Traces, tab.OTLPEndpoint = true, r.URL()
	env := func(k string) (string, bool) {
		return map[string]string{"BUGNET_OTLP_AUTHORIZATION": "Basic eDp5"}[k], true
	}
	tel, err := telemetry.FromTable(tab, telemetry.Process{Service: "bugnet-egress",
		InstanceID: "egress"}, env, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, span := tel.Tracer("test").Start(t.Context(), "one")
	span.End()
	tel.Close()
	eq(t, r.Headers[0].Get("Authorization"), "Basic eDp5")
}

func TestOffBuildsNothing(t *testing.T) {
	r := telemetrytest.NewReceiver(t)
	s := tableSettings(r.URL(), 1)
	s.Traces = false
	tel, err := telemetry.New(s, telemetry.Process{Service: "bugnet-edge", InstanceID: "e1"},
		"", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	eq(t, tel.Enabled(), false)
	ctx, span := tel.Tracer("x").Start(t.Context(), "never")
	span.End()
	eq(t, trace.SpanContextFromContext(ctx).IsValid(), false)
	ctx, sess := tel.Session(t.Context(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"edge.transfer", time.Now())
	sess.End()
	eq(t, trace.SpanContextFromContext(ctx).IsValid(), false)
	eq(t, tel.Shutdown(t.Context()), nil)
	eq(t, r.Requests, 0)
	// A nil Telemetry is off too
	var none *telemetry.Telemetry
	eq(t, none.Enabled(), false)
}

func TestSettingsValidation(t *testing.T) {
	for name, s := range map[string]telemetry.Settings{
		"http to a public host": tableSettings("http://traces.example.com/v1/traces", 1),
		"ratio 1.5":             tableSettings("http://127.0.0.1:4318/v1/traces", 1.5),
		"no endpoint":           tableSettings("", 1),
		"credentials":           tableSettings("https://u:p@traces.example.com/v1/traces", 1),
	} {
		if _, err := telemetry.New(s, telemetry.Process{Service: "bugnet-edge",
			InstanceID: "e1"}, "", slog.Default()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTableCheck(t *testing.T) {
	good := func(change func(*telemetry.Table)) telemetry.Table {
		tab := telemetry.DefaultTable()
		change(&tab)
		return tab
	}
	eq(t, telemetry.DefaultTable().Check(), nil)
	eq(t, good(func(x *telemetry.Table) {
		x.Traces, x.OTLPEndpoint = true, "http://localhost:4318/v1/traces"
	}).Check(), nil)
	for key, tab := range map[string]telemetry.Table{
		"telemetry.otlp_endpoint": good(func(x *telemetry.Table) { x.Traces = true }),
		"telemetry.sample_ratio":  good(func(x *telemetry.Table) { x.SampleRatio = 1.5 }),
		"telemetry.environment":   good(func(x *telemetry.Table) { x.Environment = "Not OK" }),
		"telemetry.export_timeout": good(func(x *telemetry.Table) {
			x.ExportTimeout = settings.Duration(time.Millisecond)
		}),
		"telemetry.queue_size": good(func(x *telemetry.Table) { x.QueueSize = 0 }),
		"telemetry.batch_size": good(func(x *telemetry.Table) { x.BatchSize = 4096 }),
		"telemetry.otlp_endpoint ": good(func(x *telemetry.Table) {
			x.OTLPEndpoint = "http://traces.example.com/v1/traces"
		}),
	} {
		err := tab.Check()
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(key)) {
			t.Errorf("%s: got %v", key, err)
		}
	}
}

func TestShutdownFlushes(t *testing.T) {
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	for range 3 {
		_, span := tel.Tracer("test").Start(t.Context(), "one")
		span.End()
	}
	// The batch timeout is a minute, so only Shutdown can have sent these
	eq(t, len(tel.Recv.Spans()), 0)
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	eq(t, len(tel.Recv.Spans()), 3)
}

func TestLogHandlerAddsTraceID(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(telemetry.LogHandler(slog.NewJSONHandler(&buf, nil)))
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	ctx, span := tel.Tracer("test").Start(t.Context(), "one")
	defer span.End()
	log.WarnContext(ctx, "under a span")
	line := buf.String()
	if !strings.Contains(line, `"trace_id":"`+span.SpanContext().TraceID().String()+`"`) ||
		!strings.Contains(line, `"span_id":"`+span.SpanContext().SpanID().String()+`"`) {
		t.Fatalf("no ids in %s", line)
	}
	buf.Reset()
	log.Warn("no span")
	eq(t, strings.Contains(buf.String(), "trace_id"), false)
}

func TestChildOnlyMakesNoRoots(t *testing.T) {
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	tr := tel.Tracer("test")
	ctx, span := telemetry.Child(t.Context(), tr, "ssh.upstream")
	span.End()
	eq(t, trace.SpanContextFromContext(ctx).IsValid(), false)
	eq(t, len(tel.Flushed(t)), 0)
	pctx, parent := tr.Start(t.Context(), "parent")
	_, child := telemetry.Child(pctx, tr, "ssh.upstream")
	child.End()
	parent.End()
	eq(t, len(tel.Flushed(t)), 2)
}

func TestFailNamesAReasonNotText(t *testing.T) {
	tel := telemetrytest.New(t, "bugnet-edge", 1)
	_, span := tel.Tracer("test").Start(t.Context(), "one")
	telemetry.Fail(span, "upstream_failed")
	span.End()
	s := tel.Flushed(t)[0]
	eq[any](t, s.Attrs["bugnet.reason"], "upstream_failed")
	eq(t, s.StatusText, "UPSTREAM_FAILED")
}
