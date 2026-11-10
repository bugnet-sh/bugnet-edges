// Package telemetrytest is an OTLP receiver and a Telemetry wired to it, for tests only
package telemetrytest

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/bugnet-sh/bugnet-edges/internal/telemetry"
)

// Link is one span link as exported
type Link struct {
	TraceID, SpanID string
	Attrs           map[string]any
}

// Span is one exported span, decoded
type Span struct {
	Name, TraceID, SpanID, ParentID string
	Kind                            tracepb.Span_SpanKind
	Start, End                      time.Time
	Attrs                           map[string]any
	Resource                        map[string]any
	Links                           []Link
	Events                          int
	StatusCode                      tracepb.Status_StatusCode
	StatusText                      string
	TraceState                      string
	Flags                           uint32
}

// Receiver collects the spans POSTed to its URL, as an OTLP/HTTP backend does
type Receiver struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []Span
	// Headers holds the request headers of every export, for authorization checks
	Headers []http.Header
	// Requests counts export requests
	Requests int
}

// NewReceiver starts a receiver on 127.0.0.1 with a random port, closed when t ends
func NewReceiver(t testing.TB) *Receiver {
	t.Helper()
	r := &Receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// URL is the traces endpoint of the receiver
func (r *Receiver) URL() string { return r.srv.URL + "/v1/traces" }

func (r *Receiver) serve(w http.ResponseWriter, req *http.Request) {
	var body io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(req.Body)
		if err != nil {
			http.Error(w, "gzip", http.StatusBadRequest)
			return
		}
		body = zr
	}
	raw, _ := io.ReadAll(body)
	var msg collector.ExportTraceServiceRequest
	if err := proto.Unmarshal(raw, &msg); err != nil {
		http.Error(w, "proto", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.Requests++
	r.Headers = append(r.Headers, req.Header.Clone())
	for _, rs := range msg.GetResourceSpans() {
		res := attrMap(rs.GetResource().GetAttributes())
		for _, ss := range rs.GetScopeSpans() {
			for _, s := range ss.GetSpans() {
				r.got = append(r.got, decode(s, res))
			}
		}
	}
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-protobuf")
	out, _ := proto.Marshal(&collector.ExportTraceServiceResponse{})
	_, _ = w.Write(out)
}

func decode(s *tracepb.Span, res map[string]any) Span {
	out := Span{
		Name: s.GetName(), TraceID: hex.EncodeToString(s.GetTraceId()),
		SpanID: hex.EncodeToString(s.GetSpanId()), Kind: s.GetKind(),
		Start: time.Unix(0, int64(s.GetStartTimeUnixNano())),
		End:   time.Unix(0, int64(s.GetEndTimeUnixNano())),
		Attrs: attrMap(s.GetAttributes()), Resource: res, Events: len(s.GetEvents()),
		StatusCode: s.GetStatus().GetCode(), StatusText: s.GetStatus().GetMessage(),
		Flags: s.GetFlags(), TraceState: s.GetTraceState(),
	}
	if len(s.GetParentSpanId()) > 0 {
		out.ParentID = hex.EncodeToString(s.GetParentSpanId())
	}
	for _, l := range s.GetLinks() {
		out.Links = append(out.Links, Link{
			TraceID: hex.EncodeToString(l.GetTraceId()), SpanID: hex.EncodeToString(l.GetSpanId()),
			Attrs: attrMap(l.GetAttributes()),
		})
	}
	return out
}

func attrMap(kvs []*commonpb.KeyValue) map[string]any {
	out := map[string]any{}
	for _, kv := range kvs {
		switch v := kv.GetValue().GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.GetKey()] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			out[kv.GetKey()] = v.IntValue
		case *commonpb.AnyValue_BoolValue:
			out[kv.GetKey()] = v.BoolValue
		default:
			out[kv.GetKey()] = nil
		}
	}
	return out
}

// Spans returns what the receiver holds
func (r *Receiver) Spans() []Span {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Span(nil), r.got...)
}

// Reset forgets the spans and requests received so far
func (r *Receiver) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got, r.Headers, r.Requests = nil, nil, 0
}

// Telemetry is a Telemetry exporting to a Receiver
type Telemetry struct {
	*telemetry.Telemetry
	Recv *Receiver
}

// New builds a Telemetry for process service at ratio, exporting to a fresh receiver
func New(t testing.TB, service string, ratio float64) *Telemetry {
	t.Helper()
	r := NewReceiver(t)
	tel, err := telemetry.New(telemetry.Settings{
		Traces: true, OTLPEndpoint: r.URL(), SampleRatio: ratio, Environment: "test",
		ExportTimeout: 5 * time.Second, BatchTimeout: time.Minute, BatchSize: 512,
		QueueSize: 2048,
	}, telemetry.Process{Service: service, InstanceID: "edge-1"}, "", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	return &Telemetry{Telemetry: tel, Recv: r}
}

// Flushed exports every finished span and returns what the receiver now holds
func (x *Telemetry) Flushed(t testing.TB) []Span {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := x.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	return x.Recv.Spans()
}

// Scan reports the label of each needle that any exported span holds, searching its raw form and
// its base64, hex and URL-escaped ones through names, attributes, links, status and resource
func Scan(spans []Span, needles map[string]string) []string {
	var found []string
	for label, needle := range needles {
		if needle == "" {
			continue
		}
		forms := []string{
			needle, url.QueryEscape(needle), url.PathEscape(needle),
			hex.EncodeToString([]byte(needle)),
			base64.StdEncoding.EncodeToString([]byte(needle)),
			base64.RawURLEncoding.EncodeToString([]byte(needle)),
		}
		for _, s := range spans {
			blob := spanText(s)
			holds := func(f string) bool { return strings.Contains(blob, f) }
			if slices.ContainsFunc(forms, holds) {
				found = append(found, label)
				break
			}
		}
	}
	slices.Sort(found)
	return found
}

func spanText(s Span) string {
	var b strings.Builder
	b.WriteString(s.Name + "\n" + s.StatusText + "\n" + s.TraceState + "\n")
	for _, m := range []map[string]any{s.Attrs, s.Resource} {
		for k, v := range m {
			fmt.Fprintf(&b, "%s=%v\n", k, v)
		}
	}
	for _, l := range s.Links {
		for k, v := range l.Attrs {
			fmt.Fprintf(&b, "%s=%v\n", k, v)
		}
	}
	return b.String()
}

// orderLabel is the derivation label of DP 20.2.1, pinned here and in the router and the gateway
const orderLabel = "bugnet-order-trace-v1|"

// OrderIDs derives the order trace id and root span id of a handle, as the router does
func OrderIDs(handle string) (traceID, spanID string) {
	inner := sha256.Sum256([]byte(handle))
	d := sha256.Sum256(append([]byte(orderLabel), inner[:]...))
	return hex.EncodeToString(d[0:16]), hex.EncodeToString(d[16:24])
}

// Traceparent formats a sampled version 00 traceparent
func Traceparent(traceID, spanID string) string {
	return "00-" + traceID + "-" + spanID + "-01"
}

// Named returns the spans with name
func Named(spans []Span, name string) []Span {
	var out []Span
	for _, s := range spans {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

// Only returns the one span with name, and fails the test when there is not exactly one
func Only(t testing.TB, spans []Span, name string) Span {
	t.Helper()
	got := Named(spans, name)
	if len(got) != 1 {
		t.Fatalf("got %d spans named %s, want 1", len(got), name)
	}
	return got[0]
}
