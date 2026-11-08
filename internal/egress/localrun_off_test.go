//go:build !localrun

package egress

import (
	"strings"
	"testing"
)

func TestLocalrunSeamsAbsentInNormalBuilds(t *testing.T) {
	body := `egress_host = "egress.example.com"` + "\n[localrun]\nupstream_roots_file = \"x\"\n"
	_, err := Load(write(t, body), env(goodEnv))
	if err == nil || !strings.Contains(err.Error(), "localrun") {
		t.Fatalf("a [localrun] table was not refused as unknown: %v", err)
	}
}
