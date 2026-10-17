// Package access decides whether an application may get tokens for an API
// and whether the user must consent or confirm first. Decide is pure:
// callers load the records it needs. Auth0 sources and the observed values
// are listed in D-0025, D-0026 and D-0027.
package access

import (
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Flow int

const (
	Interactive       Flow = iota // /authorize
	Password                      // password and password-realm grants
	Refresh                       // refresh_token grant
	ClientCredentials             // client_credentials grant
	Device                        // device authorization request (RFC 8628)
)

type Input struct {
	Flow   Flow
	Client *store.Client
	// API is the audience's resource server; nil when there is no audience.
	API *store.ResourceServer
	// ClientGrant is the client's grant for API with SubjectType(Flow), or nil.
	ClientGrant *store.ClientGrant
	// UserGrant is the user's consent for Client and the audience, or nil.
	UserGrant   *store.UserGrant
	Scopes      []string // requested (Interactive, Password) or held (Refresh)
	Prompts     []string
	RedirectURI string
	// TenantSkipConfirmation is the tenant's
	// skip_non_verifiable_callback_uri_confirmation_prompt.
	TenantSkipConfirmation bool
	// ScreenShown means the user already saw a login, signup or consent
	// screen in this transaction, so no confirmation is needed (D-0027).
	ScreenShown bool
}

type Decision struct {
	Scopes       []string // to issue; nil for ClientCredentials (the grant decides)
	Consent      bool     // show the consent screen
	Confirmation bool     // show the confirmation screen
	Err          *Error
}

type Error struct{ Code, Description string }

var oidcScopes = []string{"openid", "profile", "email"}

// SubjectType is the client grant subject type a flow needs.
func SubjectType(f Flow) string {
	if f == ClientCredentials {
		return store.SubjectTypeClient
	}
	return store.SubjectTypeUser
}

// Strict reports whether c is a third-party client in strict mode. An
// unknown mode counts as strict (fail closed).
func Strict(c *store.Client) bool {
	return !c.IsFirstParty && c.ThirdPartySecurityMode != store.SecurityModePermissive
}

func Decide(in Input) Decision {
	if !in.Client.IsFirstParty && in.Flow == Password {
		return fail("unauthorized_client", "the password grant is not available to third-party applications")
	}
	if e := checkPolicy(in); e != nil {
		return Decision{Err: e}
	}
	if in.Flow == ClientCredentials {
		return Decision{}
	}
	d := Decision{Scopes: issuedScopes(in)}
	if in.Flow != Interactive && in.Flow != Device {
		return d
	}
	d.Consent = needsConsent(in, d.Scopes)
	d.Confirmation = !d.Consent && !in.ScreenShown && NonVerifiable(in.RedirectURI) && !skipConfirmation(in)
	if slices.Contains(in.Prompts, "none") {
		switch {
		case d.Consent:
			return fail(codeConsentRequired, "the user must consent to this application")
		case d.Confirmation:
			return fail(codeConfirmationRequired, "the user must confirm this login")
		}
	}
	return d
}

func fail(code, desc string) Decision { return Decision{Err: &Error{Code: code, Description: desc}} }

func checkPolicy(in Input) *Error {
	code := codeTokenDenied
	switch in.Flow {
	case Interactive, Device:
		code = codeAuthorizeDenied
	case ClientCredentials:
		code = "access_denied"
	}
	if in.API == nil {
		if Strict(in.Client) && in.Flow != ClientCredentials {
			return &Error{codeStrictNoAudience, "this application must request an API audience"}
		}
		return nil
	}
	policy := in.API.SubjectTypeAuthorization.User
	if in.Flow == ClientCredentials {
		policy = in.API.SubjectTypeAuthorization.Client
		if policy == "" {
			policy = store.PolicyRequireClientGrant
		}
	} else if policy == "" {
		policy = store.PolicyAllowAll
	}
	switch policy {
	case store.PolicyDenyAll:
		return &Error{code, "the API does not allow this application to access it"}
	case store.PolicyAllowAll:
		if in.Flow == ClientCredentials {
			// Auth0 offers only require_client_grant and deny_all for
			// clients; a stored allow_all fails closed.
			if in.ClientGrant == nil {
				return &Error{code, "client is not authorized for this audience"}
			}
			return nil
		}
		if in.ClientGrant == nil && !in.Client.IsFirstParty && (Strict(in.Client) || !permissiveFollowsPolicy) {
			return &Error{code, "the application is not authorized to access this API"}
		}
		return nil
	default: // require_client_grant and unknown values (fail closed)
		if in.ClientGrant == nil {
			if in.Flow == ClientCredentials {
				return &Error{code, "client is not authorized for this audience"}
			}
			return &Error{code, "the application is not authorized to access this API"}
		}
		return nil
	}
}

// issuedScopes keeps requested OIDC scopes (not for strict clients),
// offline_access, and scopes the API defines that the client grant, when
// there is one, allows. Order follows the request; duplicates are dropped.
func issuedScopes(in Input) []string {
	strict := Strict(in.Client)
	var out []string
	for _, s := range in.Scopes {
		if slices.Contains(out, s) {
			continue
		}
		switch {
		case slices.Contains(oidcScopes, s):
			if strict {
				continue
			}
		case s == "offline_access":
		default:
			if in.API == nil || !slices.ContainsFunc(in.API.Scopes, func(d store.Scope) bool { return d.Value == s }) {
				continue
			}
			if in.ClientGrant != nil && !slices.Contains(in.ClientGrant.Scopes, s) {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

func needsConsent(in Input, scopes []string) bool {
	if in.Client.IsFirstParty {
		if in.API == nil {
			return false
		}
		if in.API.SkipConsentForVerifiableFirstPartyClients &&
			!(firstPartyNonVerifiableConsent && NonVerifiable(in.RedirectURI)) {
			return false
		}
	} else if in.API == nil && !consentWithoutAudience {
		return false
	}
	if slices.Contains(in.Prompts, "consent") || in.UserGrant == nil {
		return true
	}
	for _, s := range scopes {
		if !slices.Contains(in.UserGrant.Scopes, s) {
			return true
		}
	}
	return false
}

func skipConfirmation(in Input) bool {
	if p := in.Client.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		return *p
	}
	return in.TenantSkipConfirmation
}

// NonVerifiable reports whether the authorization server cannot verify
// which application receives redirectURI: custom schemes and loopback hosts.
func NonVerifiable(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return true
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ConnectionUsable reports whether c may log users in through conn:
// third-party clients use domain connections, first-party clients the
// connections enabled for them.
func ConnectionUsable(c *store.Client, conn *store.Connection) bool {
	if !c.IsFirstParty {
		return conn.IsDomainConnection
	}
	return slices.Contains(conn.EnabledClients, c.ClientID)
}

// ShowErrorPage reports whether c's /authorize errors must be shown on an
// error page instead of redirected: under open_redirect_protection every
// error is (observed, D-0027).
func ShowErrorPage(c *store.Client) bool {
	if c.IsFirstParty {
		return c.RedirectionPolicy == store.RedirectionPolicyOpenRedirectProtection
	}
	// Third-party clients fail closed: only an explicit allow_always redirects.
	return c.RedirectionPolicy != store.RedirectionPolicyAllowAlways
}

// GrantScopes is the scope list a user grant holds after the user accepts
// accepted on top of existing.
func GrantScopes(existing, accepted []string) []string {
	if !mergeGrantScopes {
		return slices.Clone(accepted)
	}
	out := slices.Clone(existing)
	for _, s := range accepted {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
