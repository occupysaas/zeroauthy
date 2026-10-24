package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func TestBreachFileStartup(t *testing.T) {
	for _, valid := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "corpus")
		body := "corrupt\n"
		if valid {
			body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"
		}
		os.WriteFile(path, []byte(body), 0600)
		cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Security: config.Security{BreachedPasswords: config.BreachedPasswords{Mode: "file", File: path}}}
		a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if a != nil {
			a.Close()
		}
		if (err == nil) != valid {
			t.Fatal("corpus validation", valid, err)
		}
	}
}
