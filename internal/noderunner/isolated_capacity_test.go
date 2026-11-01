package noderunner

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A globally saturated isolated pool must queue without starting any child.
// Occupy the production capacity permits directly to avoid spawning64 Node
// processes merely to exercise this admission branch.
func TestIsolatedCallGlobalCapacity(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("ZA_REQUIRE_NODE") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	version, err := exec.Command(node, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckNodeVersion(strings.TrimSpace(string(version))); err != nil {
		if os.Getenv("ZA_REQUIRE_NODE") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	starts := 0
	p, err := New(Config{Node: node, Script: []byte(`process.stdin.resume()`), OnStart: func(string) any { starts++; return nil }}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for range cap(p.isolationCapacity) {
		p.isolationCapacity <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	_, err = p.CallWith(ctx, "bounded", map[string]any{}, CallOptions{Isolated: true, Budget: time.Second})
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if starts != 0 || len(p.live) != 0 || len(p.isolated) != 0 {
		t.Fatalf("saturated pool spawned/leaked: starts=%d live=%d tenants=%d", starts, len(p.live), len(p.isolated))
	}
}
