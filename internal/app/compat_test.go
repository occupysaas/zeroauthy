package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

func TestCompatStartupWarnings(t *testing.T) {
	names := []string{
		"ZEROAUTHY_COMPAT__NONCOMPLIANT_IGNORE_CLAIMS_PARAMETER",
		"ZEROAUTHY_COMPAT__NONCOMPLIANT_OPTIONAL_REDIRECT_URI",
		"ZEROAUTHY_COMPAT__NONCOMPLIANT_LOGOUT_TOKEN_TYP_JWT",
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "enabled"}[enabled], func(t *testing.T) {
			environ := []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__SYSTEM_HOST=system.example.test"}
			if enabled {
				for _, name := range names {
					environ = append(environ, name+"=1")
				}
			}
			cfg, err := config.Load("", environ)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			a, err := New(t.Context(), cfg, slog.New(slog.NewJSONHandler(&output, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			want := 0
			if enabled {
				want = 1
			}
			for _, name := range names {
				if n := strings.Count(output.String(), name); n != want {
					t.Errorf("%s: warning count %d, want %d", name, n, want)
				}
			}
		})
	}
}
