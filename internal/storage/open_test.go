package storage

import (
	"context"
	"strings"
	"testing"
)

func TestOpen(t *testing.T) {
	st, err := Open(context.Background(), "memory://")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	for dsn, want := range map[string]string{
		"postgres://localhost/db": `driver "postgres" is not available`,
		"nonsense":                "scheme",
		"":                        "scheme",
	} {
		if _, err := Open(context.Background(), dsn); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Open(%q) err = %v, want it to contain %q", dsn, err, want)
		}
	}
}
