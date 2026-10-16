package customdb

import (
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func TestProbeMissingNode(t *testing.T) {
	r, err := NewNodeRunner(config.CustomDB{Node: filepath.Join(t.TempDir(), "no-node")}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Probe(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Probe = %v, want ErrUnavailable", err)
	}
}

func TestProbeNode(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	if err := r.Probe(); err != nil {
		t.Fatalf("Probe = %v", err)
	}
}
