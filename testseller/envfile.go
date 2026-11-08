package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// secretFile reads the value of key from the env-format file at path, never quoting any value
func secretFile(path, key string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s: cannot be read (%s)", path, reason(err))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: is not a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("%s: mode must be 0600", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: cannot be read (%s)", path, reason(err))
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	value := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || strings.TrimSpace(name) != key {
			continue
		}
		value = unquote(strings.TrimSpace(v))
	}
	if sc.Err() != nil {
		return "", fmt.Errorf("%s: cannot be read", path)
	}
	if value == "" {
		return "", fmt.Errorf("%s: holds no %s", path, key)
	}
	return value, nil
}

// unquote drops one pair of matching quotes around v
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// reason names why a file could not be opened, without the path the error repeats
func reason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	}
	return "unreadable"
}
