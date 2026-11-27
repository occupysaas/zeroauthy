// Package dcr is open Dynamic Client Registration at /oidc/register (Plan
// 41b, RFC 7591, D-0090): request validation, the client it creates and the
// handler.
package dcr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Limits (D-0090).
const (
	maxRedirectURIs = 20
	maxNameLength   = 255
	maxURILength    = 2048
	// DefaultName is the client_name of a registration without one (R41-3).
	DefaultName = "My App"
)

// AllowedGrants are the only grant types a DCR client gets (Auth0: DCR
// clients support authorization_code and refresh_token).
var AllowedGrants = []string{"authorization_code", "refresh_token"}

// Error is an RFC 7591 §3.2.2 error.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func metadataError(format string, args ...any) *Error {
	return &Error{Code: "invalid_client_metadata", Description: fmt.Sprintf(format, args...)}
}

func redirectError(format string, args ...any) *Error {
	return &Error{Code: "invalid_redirect_uri", Description: fmt.Sprintf(format, args...)}
}

// Request is a validated registration.
type Request struct {
	Name         string
	RedirectURIs []string
	// AuthMethod is store.AuthMethodNone or store.AuthMethodClientSecretPost.
	AuthMethod string
	// GrantTypes are the requested grant types filtered to AllowedGrants.
	GrantTypes []string
}

// Parse validates an RFC 7591 registration body. Unknown members, and the
// metadata zeroauthy does not keep (logo_uri, client_uri, policy_uri,
// tos_uri, contacts, ...), are accepted and ignored (R41-4).
func Parse(body []byte) (Request, *Error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&raw); err != nil || raw == nil || dec.More() {
		return Request{}, metadataError("the body must be a JSON object")
	}
	req := Request{Name: DefaultName, AuthMethod: store.AuthMethodClientSecretPost}
	if v, ok := raw["client_name"]; ok {
		if json.Unmarshal(v, &req.Name) != nil || req.Name == "" || len([]rune(req.Name)) > maxNameLength {
			return Request{}, metadataError("client_name must be a string of 1 to %d characters", maxNameLength)
		}
	}
	v, ok := raw["redirect_uris"]
	if !ok || string(bytes.TrimSpace(v)) == "null" {
		return Request{}, redirectError("redirect_uris is required")
	}
	if json.Unmarshal(v, &req.RedirectURIs) != nil {
		return Request{}, metadataError("redirect_uris must be a list of strings")
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		return Request{}, redirectError("redirect_uris must have 1 to %d URIs", maxRedirectURIs)
	}
	for _, u := range req.RedirectURIs {
		if err := CheckRedirectURI(u); err != nil {
			return Request{}, redirectError("%v", err)
		}
	}
	if v, ok := raw["token_endpoint_auth_method"]; ok {
		if json.Unmarshal(v, &req.AuthMethod) != nil || (req.AuthMethod != store.AuthMethodNone && req.AuthMethod != store.AuthMethodClientSecretPost) {
			return Request{}, metadataError("token_endpoint_auth_method must be none or client_secret_post")
		}
	}
	if v, ok := raw["response_types"]; ok {
		var types []string
		if json.Unmarshal(v, &types) != nil || slices.ContainsFunc(types, func(t string) bool { return t != "code" }) {
			return Request{}, metadataError("response_types supports only code")
		}
	}
	req.GrantTypes = slices.Clone(AllowedGrants)
	if v, ok := raw["grant_types"]; ok && string(bytes.TrimSpace(v)) != "null" {
		var asked []string
		if json.Unmarshal(v, &asked) != nil {
			return Request{}, metadataError("grant_types must be a list of strings")
		}
		req.GrantTypes = filterGrants(asked)
	}
	return req, nil
}

// filterGrants keeps the requested grants a DCR client may have, in
// AllowedGrants order; with none left the client still gets
// authorization_code, the flow every registration is for.
func filterGrants(asked []string) []string {
	var out []string
	for _, g := range AllowedGrants {
		if slices.Contains(asked, g) {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return []string{"authorization_code"}
	}
	return out
}

// deniedSchemes can run script or reach local files; they are never
// callbacks.
var deniedSchemes = []string{"javascript", "data", "file", "vbscript", "blob", "about", "ftp", "ws", "wss"}

// CheckRedirectURI reports why raw cannot be a callback of a dynamically
// registered client: it must be absolute and at most 2048 characters,
// without a fragment, credentials or wildcard; https with a host, http only
// on a loopback host, or a private-use scheme (RFC 8252 §7.1).
func CheckRedirectURI(raw string) error {
	if raw == "" || len(raw) > maxURILength {
		return fmt.Errorf("redirect URI must be 1 to %d characters", maxURILength)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Scheme == "":
		return fmt.Errorf("%q is not an absolute URI", raw)
	case strings.Contains(raw, "#"):
		return fmt.Errorf("%q must not contain a fragment", raw)
	case u.User != nil:
		return fmt.Errorf("%q must not contain credentials", raw)
	case strings.Contains(u.Host, "*"):
		return fmt.Errorf("%q must not contain a wildcard", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
		if u.Hostname() == "" {
			return fmt.Errorf("%q has no host", raw)
		}
	case scheme == "http":
		if !loopback(u.Hostname()) {
			return fmt.Errorf("%q must use https unless the host is loopback", raw)
		}
	case slices.Contains(deniedSchemes, scheme):
		return fmt.Errorf("%q uses a scheme that cannot be a callback", raw)
	}
	return nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CallbackOrigins are the origins of the http and https redirect URIs, in
// order and without duplicates: a dynamically registered client's
// allowed_origins (LR41b-10), as Auth0 allows an application's callback
// URLs for CORS by default.
func CallbackOrigins(uris []string) []string {
	var out []string
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if !slices.Contains(out, origin) {
			out = append(out, origin)
		}
	}
	return out
}
