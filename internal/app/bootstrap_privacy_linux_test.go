//go:build linux

package app

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// A subprocess limits only its own filesystem writes. This exercises actual
// CreateTemp/write/cleanup without adding production fault-injection controls.
func TestBootstrapAdminEmailArtifactWriteFailure(t *testing.T) {
	if os.Getenv("ZEROAUTHY_TEST_BOOTSTRAP_FILE_LIMIT") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestBootstrapAdminEmailArtifactWriteFailure$")
		cmd.Env = append(os.Environ(), "ZEROAUTHY_TEST_BOOTSTRAP_FILE_LIMIT=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("limited-write subprocess: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	var output strings.Builder
	a, err := New(context.Background(), &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}}, slog.New(slog.NewJSONHandler(&output, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapOperator(context.Background(), a.store, "root@example.test", a.log); err == nil || err.Error() != "app: could not save private operator setup file" {
		t.Fatalf("bootstrap write failure did not return a safe error: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "zeroauthy-operator-setup-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("failed setup write left an artifact: %v, %v", files, err)
	}
	if strings.Contains(output.String(), "ticket=") || strings.Contains(output.String(), "setup_url") || strings.Contains(output.String(), "setup_file") {
		t.Fatal("failed setup write logged a credential or delivery announcement")
	}
}
