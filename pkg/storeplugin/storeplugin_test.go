package storeplugin_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/pkg/store"
	"github.com/zeroauthy/zeroauthy/pkg/storeplugin"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var pluginBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "zeroauthy-plugin")
	if err != nil {
		panic(err)
	}
	pluginBin = filepath.Join(dir, "zeroauthy-store-memory")
	out, err := exec.Command("go", "build", "-o", pluginBin, "github.com/zeroauthy/zeroauthy/cmd/zeroauthy-store-memory").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Spec §12: storetest runs against the sample gRPC plugin, one plugin
// process per fresh store.
func TestConformanceThroughPluginProcess(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := storeplugin.Open(context.Background(), pluginBin)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := storeplugin.Open(ctx, "/nonexistent/plugin"); err == nil {
		t.Fatal("missing binary opened")
	}
	if _, err := storeplugin.Open(ctx, "relative/plugin"); err == nil {
		t.Fatal("relative path accepted")
	}
	// A program that never handshakes fails within the start timeout.
	// exec: a forked sleep would hold the plugin's pipes and make Kill wait.
	sleeper := filepath.Join(t.TempDir(), "sleeper.sh")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := storeplugin.Open(ctx, sleeper)
	if err == nil {
		t.Fatal("non-plugin opened")
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("took %v; want the start timeout", time.Since(start))
	}
}

// A plugin that prints junk instead of the handshake fails Open, and the
// error does not echo the plugin's arguments (which may be secrets).
func TestOpenGarbageHandshakeOmitsArgs(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.sh")
	if err := os.WriteFile(junk, []byte("#!/bin/sh\necho not-a-handshake\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := storeplugin.Open(context.Background(), junk, "--password=hunter2-secret")
	if err == nil {
		t.Fatal("non-plugin opened")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks args: %v", err)
	}
}

// Open honours ctx while waiting for the plugin to start.
func TestOpenHonoursContext(t *testing.T) {
	sleeper := filepath.Join(t.TempDir(), "sleeper.sh")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := storeplugin.Open(ctx, sleeper)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Open took %v after ctx expiry", d)
	}
	if out, _ := exec.Command("pgrep", "-f", sleeper).Output(); len(out) > 0 {
		t.Fatalf("plugin process left behind: %s", out)
	}
}

// A real crash: SIGKILL the plugin while the connection is live.
func TestPluginSIGKILL(t *testing.T) {
	ctx := context.Background()
	s, err := storeplugin.Open(ctx, pluginBin)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(storeplugin.PidForTest(s), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Ping(cctx); err == nil {
		t.Fatal("Ping succeeded after SIGKILL")
	}
	if cctx.Err() != nil {
		t.Fatal("Ping hung until the deadline")
	}
}

// Once the plugin is stopped (via the client side), calls fail promptly.
func TestPluginStopped(t *testing.T) {
	ctx := context.Background()
	s, err := storeplugin.Open(ctx, pluginBin)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	storeplugin.KillForTest(s)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Ping(cctx); err == nil {
		t.Fatal("Ping succeeded after the plugin died")
	}
	if cctx.Err() != nil {
		t.Fatal("Ping hung until the deadline")
	}
}
