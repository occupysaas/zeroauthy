package customdb

import (
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// requireNode skips the test when no usable Node.js (22.13 or later) is on
// PATH, or fails it when ZA_REQUIRE_NODE=1 (as CI sets).
func requireNode(t *testing.T) {
	t.Helper()
	reason := ""
	if p, err := exec.LookPath("node"); err != nil {
		reason = "node not found on PATH"
	} else if out, err := exec.Command(p, "--version").Output(); err != nil {
		reason = "node --version failed: " + err.Error()
	} else if err := checkNodeVersion(strings.TrimSpace(string(out))); err != nil {
		reason = err.Error()
	}
	if reason == "" {
		return
	}
	if os.Getenv("ZA_REQUIRE_NODE") == "1" {
		t.Fatalf("ZA_REQUIRE_NODE=1 but %s", reason)
	}
	t.Skip(reason)
}

// newRunner builds a NodeRunner closed at test cleanup. Zero fields of cfg
// get their defaults from NewNodeRunner.
func newRunner(t *testing.T, cfg config.CustomDB) *NodeRunner {
	t.Helper()
	return newRunnerLog(t, cfg, slog.New(slog.DiscardHandler))
}

func newRunnerLog(t *testing.T, cfg config.CustomDB, log *slog.Logger) *NodeRunner {
	t.Helper()
	requireNode(t)
	r, err := NewNodeRunner(cfg, log)
	if err != nil {
		t.Fatalf("NewNodeRunner: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
