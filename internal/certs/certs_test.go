package certs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCertsDue(t *testing.T) {
	c := certValid(t, day0, 90*24*time.Hour)
	eq(t, Due(c, nil, day0.Add(59*24*time.Hour)), false)
	eq(t, Due(c, nil, day0.Add(61*24*time.Hour)), true)
	eq(t, Due(c, &Window{Start: day0.Add(30 * 24 * time.Hour)}, day0.Add(31*24*time.Hour)), true)
	eq(t, Due(c, &Window{Start: day0.Add(70 * 24 * time.Hour)}, day0.Add(65*24*time.Hour)), false)
	eq(t, Due(c, &Window{Start: day0.Add(99 * 24 * time.Hour)}, day0.Add(91*24*time.Hour)), true)
	eq(t, Due(nil, nil, day0), true)
}

func TestCertsWriteByRename(t *testing.T) {
	dir := t.TempDir()
	oldChain, oldKey := pemPair(t, day0, day0.AddDate(0, 0, 90), "*.preview.example.test")
	if err := Write(dir, oldChain, oldKey); err != nil {
		t.Fatal(err)
	}
	before := map[string]os.FileInfo{}
	for _, name := range []string{"fullchain.pem", "key.pem"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = fi
	}
	chain, key := pemPair(t, day0, day0.AddDate(0, 0, 90), "*.preview.example.test")
	if err := Write(dir, chain, key); err != nil {
		t.Fatal(err)
	}
	dirInfo, _ := os.Stat(dir)
	for name, want := range map[string][]byte{"fullchain.pem": chain, "key.pem": key} {
		p := filepath.Join(dir, name)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, bytes.Equal(got, want), true)
		fi, _ := os.Stat(p)
		eq(t, fi.Mode().Perm(), os.FileMode(0o640))
		eq(t, os.SameFile(fi, before[name]), false)
		eq(t, fi.Sys().(*syscall.Stat_t).Gid, dirInfo.Sys().(*syscall.Stat_t).Gid)
	}
	entries, _ := os.ReadDir(dir)
	eq(t, len(entries), 2)

	// A chain and key that do not match replace neither file
	_, otherKey := pemPair(t, day0, day0.AddDate(0, 0, 90), "*.preview.example.test")
	if err := Write(dir, oldChain, otherKey); err == nil {
		t.Fatal("a mismatched pair was written")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	eq(t, bytes.Equal(got, chain), true)
	got, _ = os.ReadFile(filepath.Join(dir, "key.pem"))
	eq(t, bytes.Equal(got, key), true)
	entries, _ = os.ReadDir(dir)
	eq(t, len(entries), 2)
}

func TestCertsWriteNamesTheSetgidBitWhenTheGroupIsRefused(t *testing.T) {
	dir := t.TempDir()
	oldChain, oldKey := pemPair(t, day0, day0.AddDate(0, 0, 90), wildcard)
	if err := Write(dir, oldChain, oldKey); err != nil {
		t.Fatal(err)
	}
	chown = func(f *os.File, _ int) error {
		return &os.PathError{Op: "fchown", Path: f.Name(), Err: syscall.EPERM}
	}
	t.Cleanup(func() { chown = fileChown })
	chain, key := pemPair(t, day0, day0.AddDate(0, 0, 90), wildcard)
	err := Write(dir, chain, key)
	if err == nil || !strings.Contains(err.Error(), "setgid") ||
		!errors.Is(err, syscall.EPERM) {
		t.Fatalf("got %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	eq(t, bytes.Equal(got, oldChain), true)
	entries, _ := os.ReadDir(dir)
	eq(t, len(entries), 2)
}

func TestExampleCertsLoadsAtTheDefaults(t *testing.T) {
	cfg, err := Load("../../example/certs.toml")
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults()
	want.Certificates = []Certificate{{
		Names: []string{"*.preview.bugnet.sh"}, Dir: "/var/lib/bugnet-certs/preview",
	}}
	eq(t, cfg, want)
	eq(t, cfg.DNSProvider, "cloudflare")
	eq(t, cfg.DNSEnv, []string{"CF_DNS_API_TOKEN"})
	eq(t, cfg.AlertDays, 14)
	eq(t, cfg.CertMetrics, []string{"127.0.0.1:9101", "127.0.0.1:9103", "127.0.0.1:9104"})
}

func TestCertsSettingsRefused(t *testing.T) {
	const cert = "\n[[certificates]]\nnames = [\"*.preview.example.test\"]\ndir = \"/x\"\n"
	for _, tc := range []struct{ doc, want string }{
		{"", "certificates needs at least one"},
		{"directory = \"x\"\n" + cert, "directory must be an http or https URL"},
		{"state_dir = \"x\"\n" + cert, "state_dir must be an absolute path"},
		{"dns_provider = \"\"\n" + cert, "dns_provider is required"},
		{"dns_provider = \"Cloud Flare\"\n" + cert, "dns_provider must be a lego provider name"},
		{"dns_env = []\n" + cert, "dns_env needs at least one"},
		{"dns_env = [\"cf token\"]\n" + cert, "dns_env entry 1 must be a variable name"},
		{"alert_days = 0\n" + cert, "alert_days must be 1 to 60"},
		{"cert_metrics = [\"9101\"]\n" + cert, "cert_metrics entry 1 must be a host and port"},
		{"\n[[certificates]]\nnames = []\ndir = \"/x\"\n", "certificates entry 1 needs a name"},
		{"\n[[certificates]]\nnames = [\"*.*.example.test\"]\ndir = \"/x\"\n",
			"certificates entry 1 has a name that is not a host name"},
		{"\n[[certificates]]\nnames = [\"a.example.test\"]\ndir = \"x\"\n",
			"certificates entry 1 dir must be an absolute path"},
		{cert + cert, "certificates entry 2 dir is used twice"},
		{"bogus = 1\n" + cert, "bogus is not a setting"},
	} {
		_, err := Load(writeFile(t, tc.doc))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want %q", tc.doc, err, tc.want)
		}
	}
	cfg, err := Load(writeFile(t, "cert_metrics = []\n"+cert))
	eq(t, err, nil)
	eq(t, len(cfg.CertMetrics), 0)
}

func TestCertsDNSProviderIsASetting(t *testing.T) {
	err := CheckEnv([]string{"CF_DNS_API_TOKEN", "OTHER_VAR"}, func(name string) (string, bool) {
		return "secret-value", name == "OTHER_VAR"
	})
	if err == nil || !strings.Contains(err.Error(), "CF_DNS_API_TOKEN") ||
		strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("got %v", err)
	}
	err = CheckEnv([]string{"CF_DNS_API_TOKEN"}, func(string) (string, bool) { return "", true })
	if err == nil || !strings.Contains(err.Error(), "CF_DNS_API_TOKEN") {
		t.Fatalf("an empty variable passed: %v", err)
	}
	eq(t, CheckEnv([]string{"A"}, func(string) (string, bool) { return "v", true }), nil)

	t.Setenv("CF_DNS_API_TOKEN", "")
	t.Setenv("CF_API_EMAIL", "")
	t.Setenv("CF_API_KEY", "")
	if _, err := dnsProvider("cloudflare"); err == nil {
		t.Fatal("cloudflare built without a token")
	}
	t.Setenv("CF_DNS_API_TOKEN", "fake-token-for-a-test")
	if _, err := dnsProvider("cloudflare"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXEC_PATH", "/bin/true")
	if _, err := dnsProvider("exec"); err != nil {
		t.Fatal(err)
	}
	if _, err := dnsProvider("no-such-provider"); err == nil {
		t.Fatal("an unknown provider name was accepted")
	}
}
