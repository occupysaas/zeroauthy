package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Apple endpoints are fixed; provider fixture overrides never enter options.
const (
	AppleIssuer           = "https://appleid.apple.com"
	AppleAuthorizationURL = AppleIssuer + "/auth/authorize"
	AppleTokenURL         = AppleIssuer + "/auth/token"
	AppleJWKSURL          = AppleIssuer + "/auth/keys"
	AppleDiscoveryURL     = AppleIssuer + "/.well-known/openid-configuration"
)

var appleIdentifier = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// SecretOption is the write-only credential field for a strategy. Apple uses
// app_secret on the wire and the shared sealed ClientSecret slot internally.
func SecretOption(strategy string) string {
	if strategy == Apple {
		return "app_secret"
	}
	return "client_secret"
}

// ConnectionSecret reads a supplied credential without putting it in Settings.
// A named null, empty or non-string credential is rejected by Parse.
func ConnectionSecret(strategy string, options map[string]any) (string, bool) {
	v, named := options[SecretOption(strategy)]
	s, _ := v.(string)
	return s, named
}

// ParseAppleSigningKey accepts only Apple's unencrypted PKCS#8 PEM P-256 key.
// Parse errors are deliberately independent of the supplied signing material.
func ParseAppleSigningKey(secret string) (*ecdsa.PrivateKey, error) {
	invalid := func() (*ecdsa.PrivateKey, error) {
		return nil, fmt.Errorf("options.app_secret must be a PKCS#8 PEM EC P-256 private key")
	}
	if len(secret) > maxSecretBytes || !strings.HasPrefix(strings.TrimSpace(secret), "-----BEGIN PRIVATE KEY-----") {
		return invalid()
	}
	block, rest := pem.Decode([]byte(secret))
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return invalid()
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return invalid()
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return invalid()
	}
	return key, nil
}

func validateAppleSecret(o map[string]any, sealed bool, out *Settings) []error {
	if _, named := o["client_secret"]; named {
		return []error{fmt.Errorf("options.client_secret is not supported for apple; use app_secret")}
	}
	secret, named := ConnectionSecret(Apple, o)
	if !named {
		if !sealed {
			return []error{fmt.Errorf("options.app_secret is required")}
		}
		return nil
	}
	if _, err := ParseAppleSigningKey(secret); err != nil {
		return []error{err}
	}
	out.HasPlainSecret = true
	return nil
}

func parseApple(o map[string]any, out *Settings) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	for _, field := range []struct {
		key  string
		dest *string
	}{{"team_id", &out.AppleTeamID}, {"kid", &out.AppleKID}} {
		value, ok := o[field.key].(string)
		if !ok || !appleIdentifier.MatchString(value) {
			fail("options.%s must be exactly 10 uppercase alphanumerics", field.key)
		} else {
			*field.dest = value
		}
	}
	scopes := []string{}
	for _, k := range []string{"name", "email"} {
		value, named := o[k]
		flag, ok := value.(bool)
		if named && !ok {
			fail("options.%s must be a boolean", k)
		}
		if !named || flag {
			scopes = append(scopes, k)
		}
	}
	if value, named := o["scope"]; named {
		scope, ok := value.(string)
		if !ok {
			fail("options.scope must be a space-delimited string")
		} else if got := scopeList(scope, "options.scope", fail); !sameSet(got, scopes) {
			fail("options.scope must match the name and email flags (%s)", strings.Join(scopes, " "))
		}
	}
	if value, named := o["freeform_scopes"]; named {
		values, ok := value.([]any)
		if !ok {
			fail("options.freeform_scopes must be an array of strings")
		} else {
			for _, value := range values {
				scope, ok := value.(string)
				if !ok || (scope != "name" && scope != "email") || !slices.Contains(scopes, scope) {
					fail("options.freeform_scopes must contain only scopes enabled by the name and email flags")
				}
			}
		}
	}
	out.Scopes = scopes
	out.AuthorizationURL, out.TokenURL, out.DiscoveryURL = AppleAuthorizationURL, AppleTokenURL, AppleDiscoveryURL
	return errs
}
