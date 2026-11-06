// Package settings reads each edge binary's TOML settings file strictly
package settings

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Load decodes the TOML file at path into a struct pointer, refusing keys no field names exactly
func Load(path string, into any) error {
	v := reflect.ValueOf(into)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return errors.New("settings: Load needs a pointer to a struct")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	root := v.Elem().Type()
	keys, err := check(raw, root)
	if err != nil {
		return fmt.Errorf("settings: %s: %w", path, err)
	}
	dec := toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("settings: %s: %w", path, explain(err, keys, root))
	}
	return nil
}

// explain names the key and line of a decode error and what the key takes, never its value
func explain(err error, keys []key, root reflect.Type) error {
	var de *toml.DecodeError
	if !errors.As(err, &de) {
		return errors.New("a value does not fit its setting")
	}
	row, col := de.Position()
	var at *key
	for i := range keys {
		k := &keys[i]
		if k.line < row || k.line == row && k.column <= col {
			at = k
		}
	}
	if at == nil {
		return fmt.Errorf("line %d: a value does not fit its setting", row)
	}
	t, _ := fieldType(root, at.path)
	return fmt.Errorf("line %d: %s takes %s", row, at.name, describe(t))
}

var (
	errBytes    = errors.New("settings: not a byte size")
	errDuration = errors.New("settings: not a duration of 0 or more")
)

// Bytes is a byte size from 0 to 1 TiB, a whole number with an optional unit, such as "2GiB"
type Bytes int64

// maxBytes is the largest size Bytes takes, so sums of sizes never overflow
const maxBytes = 1 << 40

var units = []struct {
	suffix string
	size   int64
}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}}

// UnmarshalText reads bytes, KiB, MiB or GiB, such as 65536, 64KiB or 2GiB
func (b *Bytes) UnmarshalText(text []byte) error {
	digits, unit := string(text), int64(1)
	for _, u := range units {
		if d, ok := strings.CutSuffix(digits, u.suffix); ok {
			digits, unit = d, u.size
			break
		}
	}
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return errBytes
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n > maxBytes/unit {
		return errBytes
	}
	*b = Bytes(n * unit)
	return nil
}

// Duration is a span of 0 or more in Go's form, such as "30s", "5m" or "1h30m"
type Duration time.Duration

// UnmarshalText reads a span with time.ParseDuration and refuses a negative one
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil || v < 0 {
		return errDuration
	}
	*d = Duration(v)
	return nil
}
