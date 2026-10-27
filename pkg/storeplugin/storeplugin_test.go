package storeplugin_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	if bin := os.Getenv("ZA_TEST_HELPER_HOST"); bin != "" {
		helperHost(bin)
		return
	}
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

// helperHost is the body of the re-executed test binary that plays a host:
// it opens the plugin, prints the plugin pid, starts a transaction and waits
// to be killed.
func helperHost(bin string) {
	s, err := storeplugin.Open(context.Background(), bin)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(2)
	}
	_ = s.WithTx(context.Background(), func(store.Store) error {
		fmt.Println("pid", storeplugin.PidForTest(s))
		time.Sleep(time.Minute)
		return nil
	})
	os.Exit(3)
}

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// go-plugin does not notice a dead host; Serve does: a SIGKILLed host with a
// transaction open must not leave the plugin running.
func TestPluginExitsWhenHostIsKilled(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "ZA_TEST_HELPER_HOST="+pluginBin)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("helper output: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(line, "pid %d", &pid); err != nil {
		t.Fatalf("helper said %q", line)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	if !pidAlive(pid) {
		t.Fatal("plugin not running before the host was killed")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	deadline := time.Now().Add(6 * time.Second)
	for pidAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatal("plugin still running 6s after its host was killed")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The plugin does not see zeroauthy's own variables, but keeps the rest.
func TestPluginEnvironmentIsScrubbed(t *testing.T) {
	t.Setenv("ZEROAUTHY_SECURITY__MASTER_KEY", "top-secret")
	t.Setenv("ZEROAUTHY_STORAGE__DSN", "postgres://u:pw@h/db")
	t.Setenv("ZA_TEST_MARKER", "kept")
	dump := filepath.Join(t.TempDir(), "env.txt")
	wrapper := writeScript(t, "wrap.sh", "env > "+dump+"\nexec "+pluginBin+"\n")
	s, err := storeplugin.Open(context.Background(), wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	// The handshake cookie is itself ZEROAUTHY_STORE_PLUGIN; it is the one
	// allowed variable and proves go-plugin's own variables arrive.
	env := strings.ReplaceAll(string(b), storeplugin.Handshake.MagicCookieKey+"=", "COOKIE=")
	if !strings.Contains(env, "COOKIE="+storeplugin.Handshake.MagicCookieValue) {
		t.Fatalf("magic cookie missing:\n%s", env)
	}
	if strings.Contains(env, "ZEROAUTHY_") || strings.Contains(env, "top-secret") {
		t.Fatalf("plugin inherited zeroauthy variables:\n%s", env)
	}
	if !strings.Contains(env, "ZA_TEST_MARKER=kept") {
		t.Fatalf("ordinary variable not passed:\n%s", env)
	}
	// Open succeeded, so go-plugin's own handshake variables arrived too.
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Each arg reaches the plugin's argv, in order.
func TestPluginArgsReachArgvInOrder(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "argv.txt")
	wrapper := writeScript(t, "wrap.sh", "for a in \"$@\"; do echo \"$a\" >> "+dump+"; done\nexec "+pluginBin+"\n")
	s, err := storeplugin.Open(context.Background(), wrapper, "--first", "two words", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "--first\ntwo words\n\n"; got != want {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}
