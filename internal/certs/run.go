package certs

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Issuer gets certificates from the CA
type Issuer interface {
	// Window is the CA's suggested renewal window for cert, nil when the CA offers none
	Window(cert *x509.Certificate) (*Window, error)
	// Obtain issues one certificate for names, replacing old when old is set
	Obtain(names []string, old *x509.Certificate) (chain, key []byte, err error)
}

const (
	metricsTries   = 3
	metricsTimeout = 5 * time.Second
)

// retryWait is the pause between tries of one metrics address
var retryWait = 2 * time.Second

// Run renews each due certificate and checks every name's days left, true when nothing is wrong
func Run(ctx context.Context, cfg Config, iss Issuer, log *slog.Logger, now time.Time) bool {
	ok := true
	for _, c := range cfg.Certificates {
		if !renew(c, iss, log, now) {
			ok = false
		}
	}
	for _, c := range cfg.Certificates {
		names := strings.Join(c.Names, ",")
		leaf, err := readPair(c.Dir)
		switch {
		case errors.Is(err, errKey):
			log.Error("certificate key missing or not its pair", "names", names)
			ok = false
		case err != nil:
			log.Error("certificate unreadable", "names", names, "err", err)
			ok = false
		case leaf == nil:
			log.Error("certificate missing", "names", names)
			ok = false
		case daysLeft(leaf.NotAfter, now) < cfg.AlertDays:
			log.Error("certificate expires soon", "names", names,
				"days_left", daysLeft(leaf.NotAfter, now))
			ok = false
		}
	}
	for _, addr := range cfg.CertMetrics {
		if !checkServed(ctx, addr, cfg.AlertDays, log) {
			ok = false
		}
	}
	return ok
}

// renew obtains c again when it is missing, due or without its key, and writes it into its dir
func renew(c Certificate, iss Issuer, log *slog.Logger, now time.Time) bool {
	names := strings.Join(c.Names, ",")
	leaf, err := readPair(c.Dir)
	keyless := errors.Is(err, errKey)
	switch {
	case keyless:
		// The chain still names what the new pair replaces, so ARI can exempt it from limits
		log.Warn("key.pem is missing or is not the chain's key, obtaining a new pair",
			"names", names)
	case err != nil:
		log.Warn("the current certificate is unreadable, obtaining a new one", "names", names,
			"err", err)
	}
	var win *Window
	if leaf != nil && !keyless && iss != nil {
		if win, err = iss.Window(leaf); err != nil {
			log.Warn("no renewal window from the CA, renewing at two thirds", "names", names,
				"err", err)
			win = nil
		}
	}
	if !keyless && !Due(leaf, win, now) {
		log.Info("certificate not due", "names", names, "not_after", leaf.NotAfter)
		return true
	}
	if iss == nil {
		log.Error("certificate due with no ACME client", "names", names)
		return false
	}
	chain, key, err := iss.Obtain(c.Names, leaf)
	if err == nil {
		err = Write(c.Dir, chain, key)
	}
	if err != nil {
		log.Error("certificate renewal failed", "names", names, "err", err)
		return false
	}
	log.Info("certificate renewed", "names", names)
	return true
}

// checkServed reads one service's certificate metrics and logs each name that needs a person
func checkServed(ctx context.Context, addr string, alertDays int, log *slog.Logger) bool {
	days, issued, err := readMetrics(ctx, addr)
	if err != nil {
		log.Error("cannot read certificate metrics", "from", addr, "err", err)
		return false
	}
	ok := true
	for name, d := range days {
		if d < alertDays {
			log.Error("certificate expires soon", "from", addr, "name", name, "days_left", d)
			ok = false
		}
	}
	for name, done := range issued {
		if !done {
			log.Error("certificate never issued", "from", addr, "name", name)
			ok = false
		}
	}
	return ok
}

func readMetrics(ctx context.Context, addr string) (map[string]int, map[string]bool, error) {
	var err error
	for try := range metricsTries {
		if try > 0 {
			select {
			case <-time.After(retryWait):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		var days map[string]int
		var issued map[string]bool
		if days, issued, err = scrape(ctx, addr); err == nil {
			return days, issued, nil
		}
	}
	return nil, nil, err
}

func scrape(ctx context.Context, addr string) (map[string]int, map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, metricsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/metrics", nil)
	if err != nil {
		return nil, nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d", res.StatusCode)
	}
	return parseMetrics(io.LimitReader(res.Body, 4<<20))
}

// parseMetrics reads edge_cert_days_left and edge_cert_issued from the Prometheus text format
func parseMetrics(r io.Reader) (map[string]int, map[string]bool, error) {
	days, issued := map[string]int{}, map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		metric, rest, ok := strings.Cut(line, "{")
		if !ok || metric != "edge_cert_days_left" && metric != "edge_cert_issued" {
			continue
		}
		name, value, err := nameAndValue(rest)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", metric, err)
		}
		if metric == "edge_cert_days_left" {
			days[name] = int(math.Floor(value))
		} else {
			issued[name] = value == 1
		}
	}
	return days, issued, sc.Err()
}

var errLine = errors.New("a series line is not name=\"...\"} value")

// nameAndValue reads `name="..."} value`, the one label the certificate metrics carry
func nameAndValue(s string) (string, float64, error) {
	rest, ok := strings.CutPrefix(s, `name="`)
	if !ok {
		return "", 0, errLine
	}
	var name strings.Builder
	for i := 0; i < len(rest); i++ {
		switch c := rest[i]; {
		case c == '\\' && i+1 < len(rest):
			i++
			if rest[i] == 'n' {
				name.WriteByte('\n')
			} else {
				name.WriteByte(rest[i])
			}
		case c == '"':
			after, ok := strings.CutPrefix(rest[i+1:], "} ")
			if !ok {
				return "", 0, errLine
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(after), 64)
			if err != nil {
				return "", 0, errLine
			}
			return name.String(), v, nil
		default:
			name.WriteByte(c)
		}
	}
	return "", 0, errLine
}
