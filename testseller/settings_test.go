package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodToml = `
pay_to = "ApP993TBkpkUVFtYibkjmKGr1EsipdJwfxyFQg26wrxg"
pay_to_token_account = "ApP993TBkpkUVFtYibkjmKGr1EsipdJwfxyFQg26wrxg"
fee_payer = "ApP993TBkpkUVFtYibkjmKGr1EsipdJwfxyFQg26wrxg"
bugnet_fee_payer = "ApP993TBkpkUVFtYibkjmKGr1EsipdJwfxyFQg26wrxg"
rpc_url = "https://api.mainnet-beta.solana.com"

[[node]]
name = "x402-seller-a"

[[node]]
name = "x402-seller-b"
state_dir = "/var/b"
`

func load(t *testing.T, body string) (settings, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seller.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadSettings(path, "/home/me")
}

func TestLoadSettingsDefaults(t *testing.T) {
	s, err := load(t, goodToml)
	if err != nil {
		t.Fatal(err)
	}
	if s.Nodes[0].StateDir != "/home/me/.local/share/bugnet/tsnet/x402-seller-a" ||
		s.Nodes[1].StateDir != "/var/b" {
		t.Fatalf("state dirs %+v", s.Nodes)
	}
	if s.EnvFile != "/home/me/.config/bugnet/testseller.env" ||
		s.TailscaleEnvFile != "/home/me/.config/bugnet/tailscale.env" ||
		s.FacilitatorAddr != "127.0.0.1:8402" || s.KeepalivePings {
		t.Fatalf("defaults %+v", s)
	}
}

func TestLoadSettingsRefuses(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "bogus = 1\n" + goodToml,
		"no node":          strings.Split(goodToml, "[[node]]")[0],
		"key in the url":   strings.Replace(goodToml, "solana.com", "solana.com/?api-key=x", 1),
		"public facil":     "facilitator_addr = \"0.0.0.0:8402\"\n" + goodToml,
		"bad address":      strings.Replace(goodToml, "ApP993", "0P993", 1),
		"duplicate node":   goodToml + "\n[[node]]\nname = \"x402-seller-a\"\n",
		"keepalive string": "keepalive_pings = \"yes\"\n" + goodToml,
	}
	for name, body := range cases {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
