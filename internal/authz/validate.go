package authz

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	responseModes = []string{"query", "fragment", "form_post", "web_message"}
	knownPrompts  = []string{"none", "login", "consent", "select_account"}
	// RFC 7636 §4.2: S256 challenges are 43 base64url characters.
	s256Challenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// validate checks an authorization request in the order of spec §6.2.
// Errors with redirectable=false must be shown on an error page: the
// client or redirect URI cannot be trusted.
func validate(ctx context.Context, st store.Store, t *store.Tenant, req *Request) (*store.Client, *Error, bool) {
	if req.ClientID == "" {
		return nil, errInvalidRequest("client_id is required"), false
	}
	client, err := st.Clients().Get(ctx, t.ID, req.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errInvalidRequest("unknown client"), false
	}
	if err != nil {
		return nil, errServer(), false
	}
	if req.RedirectURI == "" {
		return client, errInvalidRequest("redirect_uri is required"), false
	}
	if !callbackAllowed(client.Callbacks, req.RedirectURI) {
		return client, errInvalidRequest("redirect_uri is not registered for this application"), false
	}

	if req.ResponseMode == "" {
		req.ResponseMode = "query"
	}
	if !slices.Contains(responseModes, req.ResponseMode) {
		req.ResponseMode = "query"
		return client, errInvalidRequest("unsupported response_mode"), true
	}
	if req.ResponseMode == "web_message" && !slices.Contains(client.WebOrigins, originOf(req.RedirectURI)) {
		return client, errInvalidRequest("web_message requires the redirect_uri origin to be an allowed web origin"), false
	}

	switch req.ResponseType {
	case "":
		return client, errInvalidRequest("response_type is required"), true
	case "code":
	default:
		return client, errUnsupportedResponseType("only response_type=code is supported"), true
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return client, errUnauthorizedClient("the application may not use the authorization code grant"), true
	}
	if req.Organization != "" || req.Invitation != "" {
		return client, errInvalidRequest("organizations are not supported yet"), true
	}

	switch {
	case req.CodeChallenge != "" && req.CodeChallengeMethod != "S256":
		return client, errInvalidRequest("code_challenge_method must be S256"), true
	case req.CodeChallenge != "" && !s256Challenge.MatchString(req.CodeChallenge):
		return client, errInvalidRequest("code_challenge is malformed"), true
	case req.CodeChallenge == "" && req.CodeChallengeMethod != "":
		return client, errInvalidRequest("code_challenge is required with code_challenge_method"), true
	case req.CodeChallenge == "" && client.TokenEndpointAuthMethod == store.AuthMethodNone:
		return client, errInvalidRequest("public applications must use PKCE (code_challenge)"), true
	}

	if req.MaxAge != "" {
		if n, err := strconv.Atoi(req.MaxAge); err != nil || n < 0 {
			return client, errInvalidRequest("max_age must be a non-negative integer"), true
		}
	}
	prompts := req.Prompts()
	for _, p := range prompts {
		if !slices.Contains(knownPrompts, p) {
			return client, errInvalidRequest("unsupported prompt value " + strconv.Quote(p)), true
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) > 1 {
		return client, errInvalidRequest("prompt=none cannot be combined with other values"), true
	}

	if req.Audience == "" {
		req.Audience = t.DefaultAudience
	}
	if req.Audience != "" {
		if _, err := st.ResourceServers().GetByIdentifier(ctx, t.ID, req.Audience); errors.Is(err, store.ErrNotFound) {
			return client, errAccessDenied("unknown audience"), true
		} else if err != nil {
			return client, errServer(), true
		}
	}

	if req.Connection != "" {
		conn, err := st.Connections().GetByName(ctx, t.ID, req.Connection)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !slices.Contains(conn.EnabledClients, client.ClientID)) {
			return client, errInvalidRequest("connection is not enabled for this application"), true
		} else if err != nil {
			return client, errServer(), true
		}
	}
	return client, nil, true
}

// dnsLabel matches one RFC 1123 DNS label.
var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// callbackAllowed reports whether uri exactly matches a registered
// callback, or matches a callback of the form https://*.domain/path where
// "*" stands for exactly one DNS label. Only a callback whose authority
// begins with "*." is a wildcard pattern.
func callbackAllowed(callbacks []string, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Fragment != "" || strings.Contains(uri, "#") || u.User != nil || u.Host == "" {
		return false
	}
	for _, cb := range callbacks {
		if cb == uri {
			return true
		}
		if !strings.HasPrefix(cb, "https://*.") {
			continue
		}
		pattern, err := url.Parse("https://wildcard." + strings.TrimPrefix(cb, "https://*."))
		if err != nil || !strings.HasPrefix(pattern.Host, "wildcard.") {
			continue
		}
		suffix := strings.TrimPrefix(pattern.Host, "wildcard")
		label, ok := strings.CutSuffix(u.Host, suffix)
		if !ok || !dnsLabel.MatchString(label) {
			continue
		}
		if u.Scheme == "https" && u.EscapedPath() == pattern.EscapedPath() && u.RawQuery == pattern.RawQuery {
			return true
		}
	}
	return false
}

// originOf returns scheme://host[:port] of an absolute URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
