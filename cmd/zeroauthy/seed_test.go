package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSeedCommand(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n  - name: globex\n"), 0o600)
	_ = os.WriteFile(cfgPath, []byte("server:\n  system_host: system.localhost\nstorage:\n  dsn: memory://\n"), 0o600)

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 tenant(s)") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSeedCommandNeedsFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "zeroauthy.yaml")
	_ = os.WriteFile(cfgPath, []byte("server:\n  system_host: system.localhost\nstorage:\n  dsn: memory://\n"), 0o600)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"seed", "--config", cfgPath})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "no seed file") {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscardsData(t *testing.T) {
	for dsn, want := range map[string]bool{
		"memory://": true,
		"plugin:///opt/plugins/zeroauthy-store-memory":       true,
		"plugin:///opt/plugins/zeroauthy-store-memory?arg=x": true,
		"plugin:///opt/plugins/my-store":                     false,
		"sqlite:///tmp/z.db":                                 false,
	} {
		if got := discardsData(dsn); got != want {
			t.Errorf("discardsData(%q) = %v, want %v", dsn, got, want)
		}
	}
}

func TestSeedCommandConfiguredEventStreamLimit(t *testing.T) {
	for _, tc := range []struct {
		limit, count int
		conflict     bool
	}{{2, 3, true}, {20, 11, false}} {
		t.Run(fmt.Sprint(tc.limit), func(t *testing.T) {
			dir := t.TempDir()
			seedPath := filepath.Join(dir, "seed.yaml")
			cfgPath := filepath.Join(dir, "config.yaml")
			var body strings.Builder
			body.WriteString("tenants:\n- name: acme\n  event_streams:\n")
			for i := 0; i < tc.count; i++ {
				fmt.Fprintf(&body, "  - name: Stream %d\n    subscriptions: [{event_type: user.created}]\n    destination: {type: eventbridge, configuration: {aws_account_id: '123456789012', aws_region: us-east-1}}\n", i)
			}
			if err := os.WriteFile(seedPath, []byte(body.String()), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("server: {system_host: system.localhost}\nstorage: {dsn: 'memory://'}\nevents: {max_streams: %d}\n", tc.limit)), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := newRootCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"seed", "--config", cfgPath, "--file", seedPath})
			err := cmd.Execute()
			if tc.conflict && !errors.Is(err, store.ErrConflict) {
				t.Fatalf("quota bypass: %v", err)
			}
			if !tc.conflict && err != nil {
				t.Fatalf("configured higher quota rejected: %v", err)
			}
		})
	}
}
