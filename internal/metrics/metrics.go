// Package metrics keeps counters and gauges and writes them in the Prometheus text format
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Registry holds every metric one binary serves on its metrics listener
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

// New returns an empty registry
func New() *Registry {
	return &Registry{families: map[string]*family{}}
}

// family is one metric name with its series by label values
type family struct {
	name, help, kind string
	labels           []string
	read             func(emit func(float64, ...string)) // set for a gauge read at scrape time

	mu     sync.RWMutex
	series map[string]*series
}

type series struct {
	values []string
	bits   atomic.Uint64 // a counter's count, or a gauge's float64 bits
}

// Counter is a count that only grows, one series per set of label values
type Counter struct{ f *family }

// Gauge is a value that goes up and down, one series per set of label values
type Gauge struct{ f *family }

// Counter registers a counter, panicking on a bad or repeated name
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{r.add(name, help, "counter", labels, nil)}
}

// Gauge registers a gauge, panicking on a bad or repeated name
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	return &Gauge{r.add(name, help, "gauge", labels, nil)}
}

// GaugeFunc registers a gauge whose series read emits at each scrape, one call per series
func (r *Registry) GaugeFunc(
	name, help string, labels []string, read func(emit func(v float64, values ...string)),
) {
	r.add(name, help, "gauge", labels, read)
}

func (r *Registry) add(
	name, help, kind string, labels []string, read func(func(float64, ...string)),
) *family {
	if !metricName.MatchString(name) {
		panic(fmt.Sprintf("metrics: %q is not a metric name", name))
	}
	for i, l := range labels {
		reserved := strings.HasPrefix(l, "__")
		if !labelName.MatchString(l) || reserved || slices.Contains(labels[:i], l) {
			panic(fmt.Sprintf("metrics: %q is not a label name for %s", l, name))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.families[name] != nil {
		panic(fmt.Sprintf("metrics: %s is registered twice", name))
	}
	f := &family{
		name: name, help: help, kind: kind, labels: slices.Clone(labels), read: read,
		series: map[string]*series{},
	}
	if len(labels) == 0 && read == nil {
		f.get(nil)
	}
	r.families[name] = f
	return f
}

// get finds or makes the series for one set of label values
func (f *family) get(values []string) *series {
	if len(values) != len(f.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, not %d",
			f.name, len(f.labels), len(values)))
	}
	key := strings.Join(values, "\xff")
	f.mu.RLock()
	s := f.series[key]
	f.mu.RUnlock()
	if s != nil {
		return s
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s = f.series[key]; s == nil {
		s = &series{values: slices.Clone(values)}
		f.series[key] = s
	}
	return s
}

// Add counts n for the series with these label values
func (c *Counter) Add(n uint64, values ...string) {
	c.f.get(values).bits.Add(n)
}

// Inc counts one for the series with these label values
func (c *Counter) Inc(values ...string) {
	c.Add(1, values...)
}

// Set sets the series with these label values to v
func (g *Gauge) Set(v float64, values ...string) {
	g.f.get(values).bits.Store(math.Float64bits(v))
}

// Add adds d, which may be negative, to the series with these label values
func (g *Gauge) Add(d float64, values ...string) {
	b := &g.f.get(values).bits
	for {
		old := b.Load()
		if b.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// WriteTo writes every metric in the Prometheus text format, names and series in sorted order
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	families := make([]*family, 0, len(r.families))
	for _, f := range r.families {
		families = append(families, f)
	}
	r.mu.Unlock()
	slices.SortFunc(families, func(a, b *family) int { return strings.Compare(a.name, b.name) })
	var b strings.Builder
	for _, f := range families {
		f.write(&b)
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// row is one series as written
type row struct {
	values []string
	value  string
}

func (f *family) rows() []row {
	var rows []row
	if f.read != nil {
		f.read(func(v float64, values ...string) {
			if len(values) != len(f.labels) {
				panic(fmt.Sprintf("metrics: %s takes %d label values, not %d",
					f.name, len(f.labels), len(values)))
			}
			rows = append(rows, row{slices.Clone(values), number(v)})
		})
	} else {
		f.mu.RLock()
		for _, s := range f.series {
			v := s.bits.Load()
			text := strconv.FormatUint(v, 10)
			if f.kind == "gauge" {
				text = number(math.Float64frombits(v))
			}
			rows = append(rows, row{s.values, text})
		}
		f.mu.RUnlock()
	}
	slices.SortFunc(rows, func(a, b row) int { return slices.Compare(a.values, b.values) })
	return rows
}

func (f *family) write(b *strings.Builder) {
	help := strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(f.help)
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", f.name, help, f.name, f.kind)
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	for _, r := range f.rows() {
		b.WriteString(f.name)
		if len(r.values) > 0 {
			b.WriteByte('{')
			for i, v := range r.values {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(b, `%s="%s"`, f.labels[i], quote.Replace(v))
			}
			b.WriteByte('}')
		}
		b.WriteString(" " + r.value + "\n")
	}
}

// number writes a float as Prometheus reads it, +Inf, -Inf and NaN included
func number(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// ServeHTTP answers a scrape with every metric
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = r.WriteTo(w)
}
