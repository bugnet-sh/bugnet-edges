package x402

import (
	"strconv"
	"strings"
)

// USD writes micros as dollars, at least two decimals and no trailing zeros past them
func USD(micros int64) string {
	sign := ""
	m := uint64(micros)
	if micros < 0 {
		sign, m = "-", -m
	}
	frac := strconv.FormatUint(m%1_000_000+1_000_000, 10)[1:]
	frac = strings.TrimRight(frac, "0")
	if len(frac) < 2 {
		frac += strings.Repeat("0", 2-len(frac))
	}
	return sign + strconv.FormatUint(m/1_000_000, 10) + "." + frac
}
