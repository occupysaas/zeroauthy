package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// ts returns a fixed-precision UTC timestamp so values round-trip through
// databases that store milliseconds.
func ts(offset time.Duration) time.Time {
	return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(offset)
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustErrIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}

func mustEqual(t *testing.T, got, want any) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}
