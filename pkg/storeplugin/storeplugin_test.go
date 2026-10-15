package storeplugin_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Open errors must not echo the plugin's arguments, which may be secrets.
func TestOpenErrorOmitsArgs(t *testing.T) {
	sleeper := filepath.Join(t.TempDir(), "exits.sh")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := storeplugin.Open(context.Background(), sleeper, "--password=hunter2-secret")
	if err == nil {
		t.Fatal("non-plugin opened")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks args: %v", err)
	}
}

// When the plugin dies, calls fail promptly and Ping reports it.
func TestPluginCrash(t *testing.T) {
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
