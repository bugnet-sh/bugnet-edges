package settings

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type Common struct {
	EdgeID string `toml:"edge_id"`
}

type sample struct {
	Common
	RouterURL string         `toml:"router_url"`
	Drain     Duration       `toml:"drain"`
	Total     Bytes          `toml:"total_bytes_per_second"`
	Streams   int            `toml:"max_concurrent_streams"`
	Small     int8           `toml:"small"`
	Count     uint32         `toml:"count"`
	Debug     bool           `toml:"debug"`
	From      []netip.Prefix `toml:"proxy_protocol_from"`
	Skipped   string         `toml:"-"`
	Names     struct {
		Preview string `toml:"preview_domain"`
	} `toml:"names"`
	Hooks *struct {
		MaxBody Bytes `toml:"max_body"`
	} `toml:"hooks"`
	Limits map[string]int `toml:"limits"`
	Routes []struct {
		Host string `toml:"host"`
		Port int    `toml:"port"`
	} `toml:"routes"`
	Inline struct {
		A int `toml:"a"`
	} `toml:"inline"`
}

// write puts doc in a new settings file and returns its path
func write(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.toml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// loadErr loads doc and returns the error with the file's path cut off
func loadErr(t *testing.T, doc string) string {
	t.Helper()
	path := write(t, doc)
	var s sample
	err := Load(path, &s)
	if err == nil {
		t.Fatalf("%q loaded", doc)
	}
	msg, ok := strings.CutPrefix(err.Error(), "settings: "+path+": ")
	if !ok {
		t.Fatalf("%q does not name the file", err)
	}
	return msg
}

func TestSettingsDecodes(t *testing.T) {
	path := write(t, `
router_url = "http://127.0.0.1:8080"
edge_id = "e1"
drain = "5m"
total_bytes_per_second = "40MiB"
max_concurrent_streams = 128
small = -8
count = 7
debug = true
proxy_protocol_from = ["127.0.0.1/32", "::1/128"]
limits.a = 1
limits.b = 2
inline = { a = 3 }

[names]
preview_domain = "preview.example.test"

[hooks]
max_body = "64KiB"

[[routes]]
host = "a"
port = 1

[[routes]]
host = "b"
`)
	var s sample
	if err := Load(path, &s); err != nil {
		t.Fatal(err)
	}
	eq(t, s.RouterURL, "http://127.0.0.1:8080")
	eq(t, s.EdgeID, "e1")
	eq(t, time.Duration(s.Drain), 5*time.Minute)
	eq(t, s.Total, Bytes(40<<20))
	eq(t, s.Streams, 128)
	eq(t, s.Small, int8(-8))
	eq(t, s.Count, uint32(7))
	eq(t, s.Debug, true)
	eq(t, s.From, []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"),
	})
	eq(t, s.Names.Preview, "preview.example.test")
	eq(t, s.Hooks.MaxBody, Bytes(64<<10))
	eq(t, s.Limits, map[string]int{"a": 1, "b": 2})
	eq(t, len(s.Routes), 2)
	eq(t, s.Routes[1].Host, "b")
	eq(t, s.Inline.A, 3)
}

func TestSettingsUnknownKeyFails(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{
			"drain = \"5m\"\n\ntypo = 1\n",
			"line 3: typo is not a setting",
		},
		{
			"[names]\npreview_domian = \"x\"\n",
			"line 2: names.preview_domian is not a setting",
		},
		{
			"Drain = \"5m\"\n",
			"line 1: Drain is not a setting, did you mean drain",
		},
		{
			"\n[nope]\na = 1\n",
			"line 2: nope is not a setting",
		},
		{
			"drain.x = \"1\"\n",
			"line 1: drain.x is not a setting",
		},
		{
			"inline = { a = 1, b = 2 }\n",
			"line 1: inline.b is not a setting",
		},
		{
			"[[routes]]\nhost = \"a\"\nweight = 1\n",
			"line 3: routes.weight is not a setting",
		},
		{
			"routes = [{ host = \"a\" }, { hots = 1 }]\n",
			"line 1: routes.hots is not a setting",
		},
		{
			"Skipped = \"x\"\n",
			"line 1: Skipped is not a setting",
		},
		{
			"edge_id = \"a\"\nCommon = 1\n",
			"line 2: Common is not a setting",
		},
		{
			"limits.a = 1\n[limits.b]\n",
			"line 2: limits.b takes a whole number",
		},
		{
			"[hooks.max_body]\n",
			"line 1: hooks.max_body takes a size such as 64KiB or 2GiB",
		},
		{
			"[[names]]\n",
			"line 1: names takes a table",
		},
	} {
		if got := loadErr(t, tc.doc); got != tc.want {
			t.Errorf("%q gave %q, want %q", tc.doc, got, tc.want)
		}
	}
}

func TestSettingsErrorsNameKeyAndLine(t *testing.T) {
	for _, tc := range []struct{ doc, want string }{
		{
			"debug = true\nmax_concurrent_streams = \"many\"\n",
			"line 2: max_concurrent_streams takes a whole number",
		},
		{
			"drain = 5\n",
			"line 1: drain takes a duration such as 30s or 5m",
		},
		{
			"drain = \"-1s\"\n",
			"line 1: drain takes a duration such as 30s or 5m",
		},
		{
			"total_bytes_per_second = \"2GB\"\n",
			"line 1: total_bytes_per_second takes a size such as 64KiB or 2GiB",
		},
		{
			"[hooks]\nmax_body = \"64 KiB\"\n",
			"line 2: hooks.max_body takes a size such as 64KiB or 2GiB",
		},
		{
			"proxy_protocol_from = [\n  \"127.0.0.1/32\",\n  \"localhost\",\n]\n",
			"line 3: proxy_protocol_from takes an array, " +
				"each item an address prefix such as 127.0.0.1/32",
		},
		{
			"small = 300\n",
			"line 1: small takes a whole number from -128 to 127",
		},
		{
			"count = -1\n",
			"line 1: count takes a whole number from 0 to 4294967295",
		},
		{
			"debug = \"yes\"\n",
			"line 1: debug takes true or false",
		},
		{
			"names = 3\n",
			"line 1: names takes a table",
		},
		{
			"drain = \"1m\"\ndrain = \"2m\"\n",
			"line 2: drain is set twice",
		},
		{
			"[names]\n[hooks]\n[names]\n",
			"line 3: names is set twice",
		},
		{
			"[[routes]]\nport = 1\n[[routes]]\nport = 2\nport = 3\n",
			"line 5: routes.port is set twice",
		},
		{
			"inline = { a = 1, a = 2 }\n",
			"line 1: inline.a is set twice",
		},
		{
			"limits.a = 1\n[limits]\nb = 2\n",
			"line 2: limits is set twice",
		},
		{
			"inline = { a = 1 }\ninline.a = 2\n",
			"line 2: inline is set twice",
		},
		{
			"routes = []\n[[routes]]\n",
			"line 2: routes is set twice",
		},
	} {
		got := loadErr(t, tc.doc)
		if got != tc.want {
			t.Errorf("%q gave %q, want %q", tc.doc, got, tc.want)
		}
		for _, v := range []string{"many", "2GB", "localhost", "yes", "300"} {
			if strings.Contains(got, v) {
				t.Errorf("%q quotes its value in %q", tc.doc, got)
			}
		}
	}
}

func TestSettingsSyntaxErrorNamesOnlyTheLine(t *testing.T) {
	eq(t, loadErr(t, "drain = \"5m\"\nrouter_url = \"http://a\n"), "line 2: not valid TOML")
	eq(t, loadErr(t, "drain = \"5m\"\nsk-live-abc123def456 \n"), "line 2: not valid TOML")
}

func TestSettingsMissingFileAndTarget(t *testing.T) {
	var s sample
	err := Load(filepath.Join(t.TempDir(), "none.toml"), &s)
	eq(t, err != nil && strings.HasPrefix(err.Error(), "settings: "), true)
	path := write(t, "drain = \"5m\"\n")
	eq(t, Load(path, s) != nil, true)
	eq(t, Load(path, (*sample)(nil)) != nil, true)
	n := 3
	eq(t, Load(path, &n) != nil, true)
}

func TestBytesForms(t *testing.T) {
	sizes := map[string]Bytes{
		"0": 0, "1": 1, "8388608": 8 << 20, "64KiB": 64 << 10, "8MiB": 8 << 20, "2GiB": 2 << 30,
		"1024GiB": 1 << 40, "1048576MiB": 1 << 40, "0MiB": 0,
	}
	for raw, want := range sizes {
		var b Bytes
		if err := b.UnmarshalText([]byte(raw)); err != nil || b != want {
			t.Errorf("%q gave %d, %v, want %d", raw, b, err, want)
		}
	}
	for _, raw := range []string{
		"", "KiB", "-1", "-1KiB", "8 KiB", "8kib", "8GB", "8TiB", "1e3", "0x10", "1.5GiB",
		"1025GiB", "1099511627777", "+1MiB", "1_024",
	} {
		var b Bytes
		if err := b.UnmarshalText([]byte(raw)); err == nil {
			t.Errorf("%q gave %d, want it refused", raw, b)
		} else if strings.Contains(err.Error(), raw) && raw != "" {
			t.Errorf("%q is quoted in %q", raw, err)
		}
	}
}

func TestDurationForms(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"0": 0, "0s": 0, "10s": 10 * time.Second, "5m": 5 * time.Minute, "1h30m": 90 * time.Minute,
		"250ms": 250 * time.Millisecond,
	} {
		var d Duration
		if err := d.UnmarshalText([]byte(raw)); err != nil || time.Duration(d) != want {
			t.Errorf("%q gave %v, %v, want %v", raw, time.Duration(d), err, want)
		}
	}
	for _, raw := range []string{"", "5", "-1s", "5 m", "five minutes", "1d"} {
		var d Duration
		if err := d.UnmarshalText([]byte(raw)); err == nil {
			t.Errorf("%q gave %v, want it refused", raw, time.Duration(d))
		}
	}
}
