package x402

import (
	"reflect"
	"testing"
)

// eq fails the test when got and want differ
func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// ptr is a pointer to a copy of v
func ptr[T any](v T) *T {
	return &v
}
