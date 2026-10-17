package seed

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestCheckedInSeeds loads and applies the seed files the test harnesses use
// (tests/*/seed.yaml), so a schema change cannot break them unnoticed.
func TestCheckedInSeeds(t *testing.T) {
	paths, err := filepath.Glob("../../tests/*/seed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no tests/*/seed.yaml found")
	}
	for _, p := range paths {
		t.Run(filepath.Base(filepath.Dir(p)), func(t *testing.T) {
			f, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := Apply(context.Background(), memory.New(), f, fixedNow, testWrapper(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
