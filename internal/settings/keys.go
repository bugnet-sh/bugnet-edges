package settings

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

// key is one key or table header a document writes
type key struct {
	name   string
	path   []string
	line   int
	column int
}

// checker walks a document's keys against the target struct as the parser reads them
type checker struct {
	p      unstable.Parser
	root   reflect.Type
	keys   []key
	seen   map[string]int // what the document defined at each id so far
	arrays map[string]int // elements of each array of tables so far, by id
}

// check refuses unknown or miscased keys, keys set twice and misplaced tables, and lists the keys
func check(raw []byte, root reflect.Type) ([]key, error) {
	c := &checker{root: root, seen: map[string]int{}, arrays: map[string]int{}}
	c.p.Reset(raw)
	scope := ""
	var table []string
	for c.p.NextExpression() {
		e := c.p.Expression()
		var err error
		switch e.Kind {
		case unstable.Table, unstable.ArrayTable:
			table, scope, err = c.header(e)
		case unstable.KeyValue:
			err = c.keyValue(table, scope, e)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := c.p.Error(); err != nil {
		return nil, c.syntax(err)
	}
	return c.keys, nil
}

// What a document defined at an id, the kinds a second definition may not meet
const (
	definedValue = iota + 1
	definedTable
	definedDotted // a table dotted keys define, which other dotted keys may add to
	definedArray
)

// position reads a dotted key and where it starts
func (c *checker) position(it unstable.Iterator) (parts []string, line, column int) {
	for it.Next() {
		n := it.Node()
		if len(parts) == 0 {
			start := c.p.Shape(n.Raw).Start
			line, column = start.Line, start.Column
		}
		parts = append(parts, string(n.Data))
	}
	return parts, line, column
}

// id names a path in the document, each array of tables by its latest element
func (c *checker) id(path []string) string {
	id := ""
	for _, part := range path {
		id += "." + strconv.Quote(part)
		if n, ok := c.arrays[id]; ok {
			id += "#" + strconv.Itoa(n)
		}
	}
	return id
}

func (c *checker) header(e *unstable.Node) (path []string, scope string, err error) {
	path, line, column := c.position(e.Key())
	k, t, err := c.add(path, line, column)
	if err != nil {
		return nil, "", err
	}
	array := e.Kind == unstable.ArrayTable
	if !holds(t, array) {
		return nil, "", fmt.Errorf("line %d: %s takes %s", line, k.name, describe(t))
	}
	if !array {
		scope = c.id(path)
		return path, scope, c.define(scope, definedTable, k.line, k.name)
	}
	base := c.id(path[:len(path)-1]) + "." + strconv.Quote(path[len(path)-1])
	if kind, ok := c.seen[base]; ok && kind != definedArray {
		return nil, "", twice(line, k.name)
	}
	c.seen[base] = definedArray
	c.arrays[base]++
	return path, base + "#" + strconv.Itoa(c.arrays[base]), nil
}

func (c *checker) keyValue(table []string, scope string, kv *unstable.Node) error {
	parts, line, column := c.position(kv.Key())
	path := slices.Concat(table, parts)
	k, t, err := c.add(path, line, column)
	if err != nil {
		return err
	}
	id := scope
	for i, part := range parts {
		id += "." + strconv.Quote(part)
		if i == len(parts)-1 {
			break
		}
		if kind, ok := c.seen[id]; ok && kind != definedDotted {
			return twice(line, strings.Join(path[:len(table)+i+1], "."))
		}
		c.seen[id] = definedDotted
	}
	if err := c.define(id, definedValue, line, k.name); err != nil {
		return err
	}
	v := kv.Value()
	if v.Kind == unstable.Integer && !fits(t, v.Data) {
		return fmt.Errorf("line %d: %s takes %s", line, k.name, describe(t))
	}
	return c.inner(path, id, v)
}

// inner checks the keys of inline tables in a value, those inside arrays included
func (c *checker) inner(path []string, id string, v *unstable.Node) error {
	it := v.Children()
	switch v.Kind {
	case unstable.InlineTable:
		for it.Next() {
			if err := c.keyValue(path, id, it.Node()); err != nil {
				return err
			}
		}
	case unstable.Array:
		for i := 0; it.Next(); i++ {
			if err := c.inner(path, id+"#"+strconv.Itoa(i), it.Node()); err != nil {
				return err
			}
		}
	}
	return nil
}

// add finds the type a key names, or says it is not a setting
func (c *checker) add(path []string, line, column int) (key, reflect.Type, error) {
	k := key{name: strings.Join(path, "."), path: path, line: line, column: column}
	t, near := fieldTypeNear(c.root, path)
	if t == nil {
		msg := fmt.Sprintf("line %d: %s is not a setting", line, k.name)
		if near != "" {
			msg += ", did you mean " + near
		}
		return k, nil, errors.New(msg)
	}
	c.keys = append(c.keys, k)
	return k, t, nil
}

// define records what an id holds, refusing an id the document already defined
func (c *checker) define(id string, kind, line int, name string) error {
	if _, ok := c.seen[id]; ok {
		return twice(line, name)
	}
	c.seen[id] = kind
	return nil
}

func twice(line int, name string) error {
	return fmt.Errorf("line %d: %s is set twice", line, name)
}

// syntax names the line TOML breaks on and nothing else, since its text may be a pasted secret
func (c *checker) syntax(err error) error {
	data := c.p.Data()
	line := bytes.Count(data, []byte{'\n'}) + 1
	var pe *unstable.ParserError
	if errors.As(err, &pe) && len(pe.Highlight) > 0 {
		line = c.p.Shape(c.p.Range(pe.Highlight)).Start.Line
	}
	return fmt.Errorf("line %d: not valid TOML", line)
}

/* Types */

var textType = reflect.TypeFor[encoding.TextUnmarshaler]()

// text reports whether a value of t is read from its text, so t has no keys below it
func text(t reflect.Type) bool {
	return t.Implements(textType) || reflect.PointerTo(t).Implements(textType)
}

// element unwraps pointers, slices and arrays to the type their keys belong to
func element(t reflect.Type) reflect.Type {
	for !text(t) {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			t = t.Elem()
		default:
			return t
		}
	}
	return t
}

// fieldType is the type a key path names below root, nil when it names none
func fieldType(root reflect.Type, path []string) (reflect.Type, bool) {
	t, _ := fieldTypeNear(root, path)
	return t, t != nil
}

// fieldTypeNear is fieldType, and on a miss the path with the part spelled as its field is
func fieldTypeNear(root reflect.Type, path []string) (reflect.Type, string) {
	t := root
	for i, part := range path {
		t = element(t)
		switch {
		case text(t):
			return nil, ""
		case t.Kind() == reflect.Struct:
			f, near := field(t, part)
			if f == nil {
				if near != "" {
					near = strings.Join(slices.Concat(path[:i], []string{near}), ".")
				}
				return nil, near
			}
			t = f
		case t.Kind() == reflect.Map && t.Key().Kind() == reflect.String:
			t = t.Elem()
		case t.Kind() == reflect.Interface:
			return t, ""
		default:
			return nil, ""
		}
	}
	return t, ""
}

// field is the type of t's field named exactly name, else the tag that differs only in case
func field(t reflect.Type, name string) (reflect.Type, string) {
	near := ""
	for i := range t.NumField() {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if tag == "-" {
			continue
		}
		if tag == "" && f.Anonymous && f.Type.Kind() == reflect.Struct {
			if ft, n := field(f.Type, name); ft != nil || n != "" {
				return ft, n
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		if tag == name {
			return f.Type, ""
		}
		if strings.EqualFold(tag, name) {
			near = tag
		}
	}
	return nil, near
}

// holds reports whether a [table] header, or an [[array]] header, may set t
func holds(t reflect.Type, array bool) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if array {
		if text(t) || t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return t.Kind() == reflect.Interface
		}
		t = t.Elem()
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
	}
	if text(t) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Map, reflect.Interface:
		return true
	}
	return false
}

// fits reports whether an integer literal fits t, true when t is not an integer type
func fits(t reflect.Type, literal []byte) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if text(t) {
		return true
	}
	s := string(literal)
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, err := strconv.ParseInt(s, 0, t.Bits())
		return err == nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_, err := strconv.ParseUint(s, 0, t.Bits())
		return err == nil
	}
	return true
}

// describe says in words what a setting of type t takes
func describe(t reflect.Type) string {
	if t == nil {
		return "another kind of value"
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t {
	case reflect.TypeFor[Bytes]():
		return "a size such as 64KiB or 2GiB"
	case reflect.TypeFor[Duration]():
		return "a duration such as 30s or 5m"
	case reflect.TypeFor[netip.Prefix]():
		return "an address prefix such as 127.0.0.1/32"
	case reflect.TypeFor[netip.Addr]():
		return "an address such as 127.0.0.1"
	case reflect.TypeFor[netip.AddrPort]():
		return "an address and port such as 127.0.0.1:8443"
	}
	if text(t) {
		return "a quoted value"
	}
	switch t.Kind() {
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if b := t.Bits(); b < 64 {
			return fmt.Sprintf("a whole number from %d to %d", -int64(1)<<(b-1), int64(1)<<(b-1)-1)
		}
		return "a whole number"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if b := t.Bits(); b < 64 {
			return fmt.Sprintf("a whole number from 0 to %d", uint64(1)<<b-1)
		}
		return "a whole number, 0 or more"
	case reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.Struct, reflect.Map:
		return "a table"
	case reflect.Slice, reflect.Array:
		return "an array, each item " + describe(t.Elem())
	}
	return "another kind of value"
}
