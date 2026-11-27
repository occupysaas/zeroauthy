package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/dcr"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Validation is the OpenAPI's validation result.
type Validation struct {
	Valid      bool     `json:"valid"`
	Violations []string `json:"violations"`
	Warnings   []string `json:"warnings"`
}

// Credential is a public key from the document's jwks or jwks_uri.
type Credential struct {
	KID, Alg, Thumbprint string
	DER                  []byte
}

// Mapped is the client the document describes.
type Mapped struct {
	ExternalClientID        string
	Name                    string
	AppType                 string
	Callbacks               []string
	LogoURI                 string
	Description             string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	JWKSURI                 string
	Credentials             []Credential
}

const maxNameLength = 255

// Evaluate validates d (D-0090) and maps it to client fields. Keys behind
// jwks_uri are fetched with f. The mapping is meaningful only when the
// validation is valid.
func (f *Fetcher) Evaluate(ctx context.Context, d *Document) (Mapped, Validation) {
	v := Validation{Violations: []string{}, Warnings: []string{}}
	violate := func(format string, args ...any) { v.Violations = append(v.Violations, fmt.Sprintf(format, args...)) }
	warn := func(format string, args ...any) { v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...)) }
	m := Mapped{ExternalClientID: d.URL}
	str := func(name string) (string, bool) {
		raw, ok := d.Members[name]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			violate("%s must be a string", name)
			return "", false
		}
		return s, true
	}

	// Identity binding: the document names its own URL exactly.
	if id, ok := str("client_id"); !ok || id != d.URL {
		violate("client_id must equal the document URL exactly")
	}
	for _, secret := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := d.Members[secret]; ok {
			violate("%s is not allowed: Client ID Metadata Document clients use no shared secrets", secret)
		}
	}

	if name, ok := str("client_name"); ok {
		if name == "" || len([]rune(name)) > maxNameLength {
			violate("client_name must be 1 to %d characters", maxNameLength)
		}
		m.Name = name
	} else if _, present := d.Members["client_name"]; !present {
		if u, err := url.Parse(d.URL); err == nil {
			m.Name = u.Hostname()
		}
		warn("client_name is absent; the URL's host is used")
	}
	if logo, ok := str("logo_uri"); ok {
		m.LogoURI = logo
		warn("logo_uri is mapped but not stored: applications have no logo")
	}
	if desc, ok := str("description"); ok {
		m.Description = desc
	}

	if raw, ok := d.Members["redirect_uris"]; !ok {
		violate("redirect_uris is required")
	} else if json.Unmarshal(raw, &m.Callbacks) != nil {
		violate("redirect_uris must be a list of strings")
		m.Callbacks = nil
	} else if len(m.Callbacks) == 0 || len(m.Callbacks) > 20 {
		violate("redirect_uris must have 1 to 20 URIs")
	} else {
		for _, cb := range m.Callbacks {
			if err := dcr.CheckRedirectURI(cb); err != nil {
				violate("redirect_uris: %v", err)
			}
		}
	}

	if raw, ok := d.Members["response_types"]; ok {
		var types []string
		if json.Unmarshal(raw, &types) != nil || slices.ContainsFunc(types, func(t string) bool { return t != "code" }) {
			violate("response_types supports only code")
		}
	}
	m.GrantTypes = slices.Clone(dcr.AllowedGrants)
	if raw, ok := d.Members["grant_types"]; ok {
		var asked []string
		if json.Unmarshal(raw, &asked) != nil {
			violate("grant_types must be a list of strings")
		} else {
			m.GrantTypes = nil
			for _, g := range dcr.AllowedGrants {
				if slices.Contains(asked, g) {
					m.GrantTypes = append(m.GrantTypes, g)
				}
			}
			for _, g := range asked {
				if !slices.Contains(dcr.AllowedGrants, g) {
					warn("grant type %q is not available and is dropped", g)
				}
			}
			if len(m.GrantTypes) == 0 {
				m.GrantTypes = []string{"authorization_code"}
			}
		}
	}

	m.TokenEndpointAuthMethod = store.AuthMethodNone
	if method, ok := str("token_endpoint_auth_method"); ok {
		if method != store.AuthMethodNone && method != store.AuthMethodPrivateKeyJWT {
			violate("token_endpoint_auth_method must be none or private_key_jwt")
		}
		m.TokenEndpointAuthMethod = method
	}
	m.AppType = string(store.AppTypeSPA)
	if m.TokenEndpointAuthMethod == store.AuthMethodPrivateKeyJWT {
		m.AppType = string(store.AppTypeRegularWeb)
	}

	_, hasJWKS := d.Members["jwks"]
	jwksURI, hasJWKSURI := str("jwks_uri")
	switch {
	case hasJWKS && hasJWKSURI:
		violate("jwks and jwks_uri must not both be present")
	case hasJWKS:
		keys, err := parseJWKS(d.Members["jwks"])
		if err != nil {
			violate("jwks: %v", err)
		}
		m.Credentials = credentials(keys, violate)
	case hasJWKSURI:
		m.JWKSURI = jwksURI
		if err := f.policy.CheckEndpoint(jwksURI); err != nil {
			violate("jwks_uri must be a public https URL")
			break
		}
		keys, err := f.FetchJWKS(ctx, jwksURI)
		if err != nil {
			violate("jwks_uri: %v", err)
			break
		}
		m.Credentials = credentials(keys, violate)
	}
	if m.TokenEndpointAuthMethod == store.AuthMethodPrivateKeyJWT && len(m.Credentials) == 0 {
		violate("private_key_jwt needs keys in jwks or jwks_uri")
	}
	v.Valid = len(v.Violations) == 0
	return m, v
}

func credentials(keys []json.RawMessage, violate func(string, ...any)) []Credential {
	var out []Credential
	for i, raw := range keys {
		p, alg, err := clientcred.ParseJWK(raw, "")
		if err != nil {
			violate("jwks key %d: %v", i, err)
			continue
		}
		out = append(out, Credential{KID: p.KID, Alg: alg, Thumbprint: p.Thumbprint, DER: p.DER})
	}
	return out
}
