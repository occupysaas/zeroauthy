package compat

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name, raw      string
		enabled, valid bool
	}{
		{"unset", "", false, true}, {"one", "1", true, true}, {"true", "true", true, true},
		{"zero", "0", false, true}, {"false", "false", false, true},
		{"typo", "ture", false, false}, {"case", "TRUE", false, false},
		{"whitespace", " true ", false, false}, {"arbitrary", "private-value", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{IgnoreClaimsParameterEnv, OptionalRedirectURIEnv, LogoutTokenTypJWTEnv} {
				getenv := func(key string) string {
					if key == name {
						return tc.raw
					}
					return ""
				}
				got := FromEnv(getenv)
				want := Switches{}
				switch name {
				case IgnoreClaimsParameterEnv:
					want.IgnoreClaimsParameter = tc.enabled
				case OptionalRedirectURIEnv:
					want.OptionalRedirectURI = tc.enabled
				case LogoutTokenTypJWTEnv:
					want.LogoutTokenTypJWT = tc.enabled
				}
				if got != want {
					t.Errorf("%s: got %+v, want %+v", name, got, want)
				}
				if err := ValidateEnv(getenv); (err == nil) != tc.valid {
					t.Errorf("%s: validation error %v, valid=%v", name, err, tc.valid)
				}
			}
		})
	}
}

func TestWarn(t *testing.T) {
	for _, switches := range []Switches{{}, {IgnoreClaimsParameter: true}, {OptionalRedirectURI: true}, {LogoutTokenTypJWT: true}, {true, true, true}} {
		var buf bytes.Buffer
		switches.Warn(slog.New(slog.NewJSONHandler(&buf, nil)))
		found := map[string]int{}
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal(err)
			}
			if record["level"] != "WARN" {
				t.Fatalf("not warning: %v", record)
			}
			name, ok := record["switch"].(string)
			if !ok {
				t.Fatalf("missing switch name: %v", record)
			}
			found[name]++
		}
		for name, on := range map[string]bool{IgnoreClaimsParameterEnv: switches.IgnoreClaimsParameter, OptionalRedirectURIEnv: switches.OptionalRedirectURI, LogoutTokenTypJWTEnv: switches.LogoutTokenTypJWT} {
			want := 0
			if on {
				want = 1
			}
			if found[name] != want {
				t.Errorf("%s: warnings=%d, want %d", name, found[name], want)
			}
			delete(found, name)
		}
		if len(found) > 0 {
			t.Errorf("unexpected warnings: %v", found)
		}
	}
}
