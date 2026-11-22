// Package compat holds explicit opt-ins to protocol behavior that differs from
// the OpenID specifications. Defaults remain suitable for conformance testing.
package compat

import (
	"fmt"
	"log/slog"
)

const (
	IgnoreClaimsParameterEnv = "ZEROAUTHY_COMPAT__NONCOMPLIANT_IGNORE_CLAIMS_PARAMETER"
	OptionalRedirectURIEnv   = "ZEROAUTHY_COMPAT__NONCOMPLIANT_OPTIONAL_REDIRECT_URI"
	LogoutTokenTypJWTEnv     = "ZEROAUTHY_COMPAT__NONCOMPLIANT_LOGOUT_TOKEN_TYP_JWT"
)

type Switches struct {
	IgnoreClaimsParameter bool
	OptionalRedirectURI   bool
	LogoutTokenTypJWT     bool
}

// FromEnv reads only canonical true values. Call ValidateEnv before using the
// result at startup so a misspelling cannot silently change server behavior.
func FromEnv(getenv func(string) string) Switches {
	enabled := func(name string) bool { v := getenv(name); return v == "1" || v == "true" }
	return Switches{enabled(IgnoreClaimsParameterEnv), enabled(OptionalRedirectURIEnv), enabled(LogoutTokenTypJWTEnv)}
}

func ValidateEnv(getenv func(string) string) error {
	for _, name := range []string{IgnoreClaimsParameterEnv, OptionalRedirectURIEnv, LogoutTokenTypJWTEnv} {
		switch getenv(name) {
		case "", "0", "false", "1", "true":
		default:
			return fmt.Errorf("config: %s must be empty, 0, false, 1 or true", name)
		}
	}
	return nil
}

// Warn names each enabled switch without including environment values.
func (s Switches) Warn(log *slog.Logger) {
	for _, entry := range []struct {
		name    string
		enabled bool
	}{
		{IgnoreClaimsParameterEnv, s.IgnoreClaimsParameter},
		{OptionalRedirectURIEnv, s.OptionalRedirectURI},
		{LogoutTokenTypJWTEnv, s.LogoutTokenTypJWT},
	} {
		if entry.enabled {
			log.Warn("non-compliant compatibility behavior enabled", "switch", entry.name)
		}
	}
}
