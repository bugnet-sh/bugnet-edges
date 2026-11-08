package sessionsroute

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	headersFile = "headers.txt"
	indexFile   = "index.html"
	assetsDir   = "assets"
	// maxBundle bounds what one bundle may hold in memory, the page being well under 1 MiB
	maxBundle = 16 << 20
)

// assetName is a hashed file name under /assets/, as the session page's build writes it
var assetName = regexp.MustCompile(`^([A-Za-z0-9-]+)\.([a-z0-9]+)$`)

// assetTypes are the only files /assets/ serves, the woff2 fonts as font/woff2 (SP 7.2)
var assetTypes = map[string]string{
	"js":    "text/javascript; charset=utf-8",
	"css":   "text/css; charset=utf-8",
	"svg":   "image/svg+xml",
	"woff2": "font/woff2",
}

// Bundle is the session page's static build, read once at start from page_dir
type Bundle struct {
	headers [][2]string
	index   file
	assets  map[string]file
}

// file is one served file, with its gzip form when that is smaller
type file struct {
	body, gz []byte
	typ      string
}

// LoadBundle reads index.html, headers.txt and assets/ from dir, the bundle's build output
func LoadBundle(dir string) (*Bundle, error) {
	b := &Bundle{assets: map[string]file{}}
	text, err := os.ReadFile(filepath.Join(dir, headersFile))
	if err != nil {
		return nil, fmt.Errorf("sessions route: the page bundle: %w", err)
	}
	if b.headers, err = parseHeaders(string(text)); err != nil {
		return nil, fmt.Errorf("sessions route: %s: %w", headersFile, err)
	}
	total := 0
	read := func(path, typ string) (file, error) {
		body, err := os.ReadFile(path)
		if err != nil {
			return file{}, fmt.Errorf("sessions route: the page bundle: %w", err)
		}
		if total += len(body); total > maxBundle {
			return file{}, errors.New("sessions route: the page bundle is over 16 MiB")
		}
		return newFile(body, typ), nil
	}
	if b.index, err = read(filepath.Join(dir, indexFile), "text/html; charset=utf-8"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, assetsDir))
	if err != nil {
		return nil, fmt.Errorf("sessions route: the page bundle: %w", err)
	}
	for _, e := range entries {
		m := assetName.FindStringSubmatch(e.Name())
		typ, ok := "", false
		if m != nil {
			typ, ok = assetTypes[m[2]]
		}
		if !ok || !e.Type().IsRegular() {
			continue
		}
		f, err := read(filepath.Join(dir, assetsDir, e.Name()), typ)
		if err != nil {
			return nil, err
		}
		b.assets[e.Name()] = f
	}
	return b, nil
}

// required are the headers.txt lines every answer must carry, the record holding sandbox output
var required = map[string]string{
	"Cache-Control":          "no-store",
	"Referrer-Policy":        "no-referrer",
	"X-Content-Type-Options": "nosniff",
}

// parseHeaders reads one header a line and refuses a bundle that leaves out or sets the wrong ones
func parseHeaders(text string) ([][2]string, error) {
	var out [][2]string
	seen := map[string]string{}
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("the line %q is not a header", line)
		}
		key := http.CanonicalHeaderKey(name)
		switch key {
		case "Set-Cookie", "Content-Type", "Content-Length", "Content-Encoding":
			return nil, fmt.Errorf("%s is the role's to set", name)
		}
		seen[key] = value
		out = append(out, [2]string{name, value})
	}
	if seen["Content-Security-Policy"] == "" {
		return nil, errors.New("no Content-Security-Policy")
	}
	for name, want := range required {
		if got, ok := seen[name]; !ok || !strings.EqualFold(got, want) {
			return nil, fmt.Errorf("%s must be %s", name, want)
		}
	}
	return out, nil
}

// newFile keeps a gzip form of text types, the fonts being compressed already
func newFile(body []byte, typ string) file {
	f := file{body: body, typ: typ}
	if typ == "font/woff2" {
		return f
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(body)
	_ = zw.Close()
	if buf.Len() < len(body) {
		f.gz = buf.Bytes()
	}
	return f
}

// setHeaders puts the bundle's headers on h, the CSP among them, replacing any set before
func (b *Bundle) setHeaders(h http.Header) {
	for _, kv := range b.headers {
		h.Set(kv[0], kv[1])
	}
}
