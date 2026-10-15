package storage

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestOpenNeverLeaksPassword: no error from Open, for a malformed or an
// unreachable DSN of any scheme, may contain the DSN's password.
func TestOpenNeverLeaksPassword(t *testing.T) {
	const pw = "s3cr3tPW"
	dir := t.TempDir()
	for _, dsn := range []string{
		// Malformed: url.Parse fails or there is no scheme.
		"postgres://u:" + pw + "@host:badport/db",
		"postgresql://u:" + pw + "@host:badport/db",
		"mysql://u:" + pw + "@host:badport/db",
		"sqlite://u:" + pw + "@host:badport/db",
		"u:" + pw + "@host/db",
		"://u:" + pw + "@host/db",
		"oracle://u:" + pw + "@host/db",
		"postgres://u:" + pw + "@127.0.0.1:1/db?%zz",
		// Parsed as a URL but rejected by the driver's own parser.
		"postgres://u:" + pw + "@127.0.0.1:1/db?sslmode=bogus",
		"postgres://u:" + pw + "@127.0.0.1:1/db?connect_timeout=notanumber",
		"mysql://u:" + pw + "@127.0.0.1:1/db?timeout=notaduration",
		"mysql://u:" + pw + "@127.0.0.1:1/db?tls=bogus",
		"sqlite://" + dir + "/missing/dir/z.db?x=" + pw,
		// Well formed but unreachable.
		"postgres://u:" + pw + "@127.0.0.1:1/db?sslmode=disable&connect_timeout=2",
		"postgresql://u:" + pw + "@127.0.0.1:1/db?sslmode=disable&connect_timeout=2",
		"mysql://u:" + pw + "@127.0.0.1:1/db?timeout=2s",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		st, err := Open(ctx, dsn)
		cancel()
		if err == nil {
			_ = st.Close()
			t.Errorf("Open(%q) succeeded, want an error", strings.ReplaceAll(dsn, pw, "***"))
			continue
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("Open(%q) error leaks the password: %v", strings.ReplaceAll(dsn, pw, "***"), err)
		}
	}
}
