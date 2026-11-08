package egress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

var goodEnv = map[string]string{
	"BUGNET_EGRESS_TOKEN":       strings.Repeat("t", 40),
	"BUGNET_EGRESS_FETCH_TOKEN": strings.Repeat("f", 40),
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "egress.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExampleSettingsAreTheDefaults(t *testing.T) {
	c, err := Load("../../example/egress.toml", env(goodEnv))
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	want.EgressHost = "egress.bugnet.sh"
	want.Token = goodEnv["BUGNET_EGRESS_TOKEN"]
	want.FetchToken = goodEnv["BUGNET_EGRESS_FETCH_TOKEN"]
	eq(t, c, want)
}

func TestLoadRefusals(t *testing.T) {
	good := `egress_host = "egress.example.com"` + "\n"
	for name, tc := range map[string]struct {
		body string
		env  map[string]string
	}{
		"no host":     {"", goodEnv},
		"an IP host":  {`egress_host = "203.0.113.5"`, goodEnv},
		"unknown key": {good + "nope = 1", goodEnv},
		"no token":    {good, map[string]string{}},
		"short token": {good, map[string]string{"BUGNET_EGRESS_TOKEN": "short"}},
		"short fetch": {good, map[string]string{
			"BUGNET_EGRESS_TOKEN":       goodEnv["BUGNET_EGRESS_TOKEN"],
			"BUGNET_EGRESS_FETCH_TOKEN": "short"}},
		"no box keys": {good + "box_keys = []", goodEnv},
		"repeated key id": {good + `box_keys = [{id="a", credential="x"}, ` +
			`{id="a", credential="y"}]`, goodEnv},
		"acme off no dir": {good + "acme_enabled = false", goodEnv},
		"zero streams":    {good + "max_streams_per_tunnel = 0", goodEnv},
		"bad old ca": {good + `old_cas = [{version = 1, credential = "c", ` +
			`cert_file = "/x"}]`, goodEnv},
		"relative acme": {good + `acme_dir = "relative"`, goodEnv},
	} {
		if _, err := Load(write(t, tc.body), env(tc.env)); err == nil {
			t.Errorf("%s: the settings loaded", name)
		}
	}
	// The fetcher's token is optional
	if _, err := Load(write(t, good), env(map[string]string{
		"BUGNET_EGRESS_TOKEN": goodEnv["BUGNET_EGRESS_TOKEN"]})); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsErrorsNeverQuoteTheTokens(t *testing.T) {
	_, err := Load(write(t, `egress_host = "egress.example.com"`), env(map[string]string{
		"BUGNET_EGRESS_TOKEN": "tok en"}))
	eq(t, err != nil && !strings.Contains(err.Error(), "tok en"), true)
}

func TestLoadSecretsReadsCredentials(t *testing.T) {
	ca := t.TempDir()
	if err := InitCA(ca, timeNow()); err != nil {
		t.Fatal(err)
	}
	creds := t.TempDir()
	keyPEM, _ := os.ReadFile(filepath.Join(ca, CAKeyFile))
	_ = os.WriteFile(filepath.Join(creds, "egress_ca_key"), keyPEM, 0o600)
	if _, err := NewBoxKey(creds, "k1"); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.CACertFile = filepath.Join(ca, CACertFile)
	e := env(map[string]string{"CREDENTIALS_DIRECTORY": creds})
	m, keys, err := c.LoadSecrets(e)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, m.Has(1), true)
	eq(t, len(keys.list), 1)
	_, _, err = c.LoadSecrets(env(nil))
	eq(t, err != nil, true)
	c.BoxKeys = []KeyRef{{ID: "k1", Credential: "../escape"}}
	_, _, err = c.LoadSecrets(e)
	eq(t, err != nil, true)
}

func timeNow() time.Time { return time.Now() }
