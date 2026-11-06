// Package certmetric exports each served certificate's days left and whether each name was issued
package certmetric

import (
	"crypto/tls"
	"log/slog"
	"sync"
	"time"

	"github.com/oynozan/bugnet-edges/internal/metrics"
	"github.com/oynozan/bugnet-edges/internal/tlsconf"
)

// Export registers edge_cert_days_left and edge_cert_issued for c and asks for each exact name once
func Export(r *metrics.Registry, c *tls.Config, log *slog.Logger) <-chan struct{} {
	var failed sync.Map
	r.GaugeFunc("edge_cert_days_left", "Whole days until each served certificate expires",
		[]string{"name"}, func(emit func(float64, ...string)) {
			for name, days := range tlsconf.DaysLeft(c, time.Now()) {
				emit(float64(days), name)
			}
		})
	r.GaugeFunc("edge_cert_issued",
		"1 once a name has a certificate, 0 once its request at start failed",
		[]string{"name"}, func(emit func(float64, ...string)) {
			left := tlsconf.DaysLeft(c, time.Now())
			exact, wildcard := tlsconf.Hosts(c)
			for _, name := range append(exact, wildcard) {
				if _, ok := left[name]; ok {
					emit(1, name)
				} else if _, ok := failed.Load(name); ok {
					emit(0, name)
				}
			}
		})
	exact, _ := tlsconf.Hosts(c)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, name := range exact {
		wg.Go(func() {
			// A name autocert never issued is absent from DaysLeft, so its failure must show here
			if err := tlsconf.Issue(c, name); err != nil {
				failed.Store(name, true)
				log.Error("certificate not issued at start", "name", name, "err", err)
			}
		})
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}
