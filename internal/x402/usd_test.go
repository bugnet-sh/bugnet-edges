package x402

import (
	"math"
	"testing"
)

func TestUSD(t *testing.T) {
	for micros, want := range map[int64]string{
		0:             "0.00",
		1:             "0.000001",
		1000:          "0.001",
		1500:          "0.0015",
		10000:         "0.01",
		500000:        "0.50",
		990000:        "0.99",
		1000000:       "1.00",
		1234567:       "1.234567",
		12000000:      "12.00",
		-1500:         "-0.0015",
		math.MaxInt64: "9223372036854.775807",
		math.MinInt64: "-9223372036854.775808",
	} {
		eq(t, USD(micros), want)
	}
}
