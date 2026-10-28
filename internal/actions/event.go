package actions

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// Protocol values of event.transaction.protocol (frozen in Task 1).
const (
	ProtocolOIDCBasicProfile  = "oidc-basic-profile"
	ProtocolDeviceCode        = "oauth2-device-code"
	ProtocolPassword          = "oauth2-password"
	ProtocolResourceOwner     = "oauth2-resource-owner"
	ProtocolRefreshToken      = "oauth2-refresh-token"
	ProtocolClientCredentials = "oauth2-client-credentials"
)

// RequestInfo is event.request: the HTTP request that triggered the flow.
// geoip and asn are omitted (D-0053).
type RequestInfo struct {
	IP, Hostname, Method, UserAgent, Language string
	// Origin is the resolved public origin, set by the HTTP handler.
	Origin      string
	Query, Body map[string]any
}

// TransactionInfo carries the authorization transaction fields. Signup
// uses its Protocol and RequestedScopes; post-login preserves the existing
// PostLoginInput.Protocol and RequestedScopes fields.
type TransactionInfo struct {
	ID, RedirectURI, State, Locale                                                string
	Protocol, ResponseMode, ResponseType, UILocales, Prompt, LoginHint, ACRValues string
	RequestedScopes                                                               []string
}

// RegistrationInput describes a prospective or newly created signup profile.
// Transaction is nil for dbconnections/signup; CustomDomain is supplied only
// when the request used a custom domain.
type RegistrationInput struct {
	Tenant       tenant.Resolved
	Client       *store.Client
	User         *store.User
	Connection   *store.Connection
	Request      RequestInfo
	Transaction  *TransactionInfo
	CustomDomain string
}

// PostChangePasswordInput snapshots the profile after a password change.
type PostChangePasswordInput struct {
	Tenant     tenant.Resolved
	User       *store.User
	Connection *store.Connection
	Request    RequestInfo
}

// ResetChallengeInput carries a valid, unspent reset ticket and its profile.
type ResetChallengeInput struct {
	Tenant      tenant.Resolved
	Client      *store.Client
	User        *store.User
	Connection  *store.Connection
	Ticket      *store.PasswordResetTicket
	Request     RequestInfo
	CanRedirect bool
}

// EmailMessage is the rendered message handed to a custom email Action.
type EmailMessage struct{ From, To, Subject, HTML, Text, Locale, Type string }

// EmailInput snapshots a custom provider hand-off. Tenant is its ID;
// TenantInfo supplies the tenant profile, loaded by the caller.
type EmailInput struct {
	Tenant     string
	TenantInfo *store.Tenant
	User       *store.User
	Client     *store.Client
	Connection *store.Connection
	Message    EmailMessage
	Request    RequestInfo
}

// PostLoginInput is everything a post-login flow sees.
type PostLoginInput struct {
	Tenant          tenant.Resolved
	Client          *store.Client
	User            *store.User
	Connection      *store.Connection
	Session         *store.LoginSession
	Request         RequestInfo
	Transaction     TransactionInfo
	Protocol        string
	RequestedScopes []string
	TargetScopes    []string
	ResourceServer  *store.ResourceServer
	// CanRedirect is api.redirect.canRedirect(): an interactive browser
	// flow that is not prompt=none.
	CanRedirect bool
	// Prepare, when set, completes the input (for example loads the user
	// or connection) once the engine knows Actions are bound, so a tenant
	// without post-login Actions pays only the bindings read.
	Prepare func(ctx context.Context, in *PostLoginInput) error `json:"-"`
	// Continuation carries caller-owned flow parameters, sealed during suspension.
	Continuation map[string]string
}

// CredentialsInput is everything a credentials-exchange flow sees.
type CredentialsInput struct {
	Tenant          tenant.Resolved
	Client          *store.Client
	ResourceServer  *store.ResourceServer
	Request         RequestInfo
	RequestedScopes []string
	// TargetScopes are the scopes the client grant allows for this request;
	// event.accessToken.scope starts as them.
	TargetScopes []string
}

func rfc3339(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

func obj(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return maps.Clone(m)
}

// credentialParams are request body parameters that are credentials and
// never reach an Action's event.request.body. It is a deny-list, not an
// allowlist: Auth0 passes the request body, and Actions read non-secret
// custom parameters from it. Every token grant's credentials must be
// listed; oauth's TestActionsBodyStripsEveryGrant enforces that.
var credentialParams = []string{"password", "client_secret", "client_assertion", "code_verifier", "refresh_token", "device_code"}

// StripCredentials is body without its credentials (the authorization code
// grant's code is one too), as event.request.body carries it.
func StripCredentials(body map[string]any) map[string]any { return requestBody(body) }

// requestBody is r's body without its credentials; the authorization
// code grant's code is one too.
func requestBody(body map[string]any) map[string]any {
	out := obj(body)
	for _, k := range credentialParams {
		delete(out, k)
	}
	if gt, _ := out["grant_type"].(string); gt == "authorization_code" {
		delete(out, "code")
	}
	return out
}

func requestEvent(r RequestInfo, host string, query bool) map[string]any {
	hostname := r.Hostname
	if hostname == "" {
		hostname = host
	}
	out := map[string]any{"ip": r.IP, "hostname": hostname, "method": r.Method, "user_agent": r.UserAgent,
		"language": r.Language, "body": requestBody(r.Body)}
	if query {
		out["query"] = obj(r.Query)
	}
	return out
}

func clientEvent(c *store.Client) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{"client_id": c.ClientID, "name": c.Name, "metadata": map[string]any{}}
}

func tenantEvent(t tenant.Resolved) map[string]any {
	id := ""
	if t.Tenant != nil {
		id = t.Tenant.ID
	}
	return map[string]any{"id": id}
}

func resourceServerEvent(rs *store.ResourceServer) map[string]any {
	if rs == nil {
		return nil
	}
	return map[string]any{"identifier": rs.Identifier}
}

// userEvent is event.user after the flow's uncommitted metadata changes
// (D-0053: later Actions see earlier Actions' setAppMetadata/setUserMetadata).
func userEvent(u *store.User, eff *Effects) map[string]any {
	if u == nil {
		return nil
	}
	view := *u
	userrules.ApplyPatch(&view, metadataPatch(eff))
	ids := make([]any, 0, len(u.Identities))
	for _, id := range u.Identities {
		ids = append(ids, map[string]any{"connection": id.Connection, "provider": id.Provider, "user_id": id.UserID,
			"isSocial": !nonSocial[id.Provider]})
	}
	out := map[string]any{
		"user_id": u.UserID, "email": u.Email, "email_verified": u.EmailVerified, "name": u.Name,
		"nickname": u.Nickname, "picture": u.Picture, "given_name": u.GivenName, "family_name": u.FamilyName,
		"app_metadata": obj(view.AppMetadata), "user_metadata": obj(view.UserMetadata), "identities": ids,
		"created_at": rfc3339(u.CreatedAt), "updated_at": rfc3339(u.UpdatedAt),
	}
	if u.Username != "" {
		out["username"] = u.Username
	}
	if u.PhoneNumber != "" {
		out["phone_number"], out["phone_verified"] = u.PhoneNumber, u.PhoneVerified
	}
	if u.LastLogin != nil {
		out["last_login"] = rfc3339(*u.LastLogin)
	}
	return out
}

// nonSocial are the identity providers Auth0 reports with isSocial false:
// databases, passwordless and enterprise connections.
var nonSocial = map[string]bool{"": true, "auth0": true, "email": true, "sms": true, "samlp": true, "oidc": true,
	"waad": true, "ad": true, "adfs": true, "okta": true, "pingfederate": true, "google-apps": true, "office365": true}

// metadataPatch is the flow's accumulated metadata as a PATCH /users patch.
func metadataPatch(eff *Effects) *userrules.Patch {
	p := &userrules.Patch{}
	if eff != nil && len(eff.AppMetadata) > 0 {
		p.AppMetadata = userrules.Metadata{Set: true, Value: maps.Clone(eff.AppMetadata)}
	}
	if eff != nil && len(eff.UserMetadata) > 0 {
		p.UserMetadata = userrules.Metadata{Set: true, Value: maps.Clone(eff.UserMetadata)}
	}
	return p
}

func sessionEvent(s *store.LoginSession) map[string]any {
	if s == nil {
		return nil
	}
	return map[string]any{"id": s.ID, "created_at": rfc3339(s.CreatedAt), "updated_at": rfc3339(s.UpdatedAt),
		"authenticated_at": rfc3339(s.AuthenticatedAt), "last_interacted_at": rfc3339(s.LastInteractedAt),
		"expires_at": rfc3339(s.ExpiresAt), "idle_expires_at": rfc3339(s.IdleExpiresAt)}
}

// postLoginEvent builds event for the next Action from the input, the roles
// snapshot and the effects accumulated so far.
func postLoginEvent(in *PostLoginInput, roleNames []string, a *accum) map[string]any {
	ev := map[string]any{
		"user":          userEvent(in.User, &a.eff),
		"client":        clientEvent(in.Client),
		"request":       requestEvent(in.Request, in.Tenant.Host, true),
		"tenant":        tenantEvent(in.Tenant),
		"authorization": map[string]any{"roles": strs(roleNames)},
		"transaction": map[string]any{
			"id": in.Transaction.ID, "protocol": in.Protocol, "redirect_uri": in.Transaction.RedirectURI,
			"state": in.Transaction.State, "locale": in.Transaction.Locale,
			"requested_scopes": strs(in.RequestedScopes), "target_scopes": strs(a.target),
			"metadata": obj(a.eff.TxnMetadata),
		},
	}
	if in.Connection != nil {
		ev["connection"] = map[string]any{"id": in.Connection.ID, "name": in.Connection.Name, "strategy": in.Connection.Strategy, "metadata": map[string]any{}}
	}
	if in.User != nil {
		ev["stats"] = map[string]any{"logins_count": in.User.LoginsCount}
	}
	if rs := resourceServerEvent(in.ResourceServer); rs != nil {
		ev["resource_server"] = rs
	}
	if s := sessionEvent(in.Session); s != nil {
		ev["session"] = s
	}
	return ev
}

// credentialsEvent builds the credentials-exchange event.
func credentialsEvent(in *CredentialsInput, a *accum) map[string]any {
	ev := map[string]any{
		"client":  clientEvent(in.Client),
		"request": requestEvent(in.Request, in.Tenant.Host, false),
		"tenant":  tenantEvent(in.Tenant),
		"transaction": map[string]any{
			"requested_scopes": strs(in.RequestedScopes), "target_scopes": strs(a.target),
		},
		"accessToken": map[string]any{"scope": strs(in.TargetScopes), "customClaims": map[string]any{}},
	}
	if rs := resourceServerEvent(in.ResourceServer); rs != nil {
		ev["resource_server"] = rs
	}
	return ev
}

func connectionEvent(c *store.Connection) map[string]any {
	return map[string]any{"id": c.ID, "name": c.Name, "strategy": c.Strategy, "metadata": map[string]any{}}
}

func signupTransaction(t *TransactionInfo) map[string]any {
	return map[string]any{"locale": t.Locale, "protocol": t.Protocol, "redirect_uri": t.RedirectURI,
		"requested_scopes": strs(t.RequestedScopes), "response_mode": t.ResponseMode, "response_type": t.ResponseType,
		"state": t.State, "ui_locales": t.UILocales, "prompt": t.Prompt, "login_hint": t.LoginHint, "acr_values": t.ACRValues}
}

// signupRequest removes password-like fields recursively while retaining
// arbitrary custom body parameters. Existing grant credential stripping also
// applies within nested objects and arrays; the caller's body is untouched.
func signupRequest(r RequestInfo, host string, query bool) map[string]any {
	ev := requestEvent(r, host, query)
	// Normalize JSON-shaped typed maps/slices too; otherwise a nested
	// map[string]string could bypass the generic-map recursion.
	var body map[string]any
	raw, err := json.Marshal(r.Body)
	if err == nil {
		_ = json.Unmarshal(raw, &body)
	}
	ev["body"] = scrubBody(body)
	return ev
}

func scrubBody(body map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range requestBody(body) {
		normalized := strings.Map(func(r rune) rune {
			if r == '_' || r == '-' || r == ' ' {
				return -1
			}
			return r
		}, strings.ToLower(key))
		if strings.Contains(normalized, "password") || strings.Contains(normalized, "passwd") || strings.Contains(normalized, "pwd") {
			continue
		}
		out[key] = scrubValue(value)
	}
	return out
}

func scrubValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return scrubBody(x)
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = scrubValue(v)
		}
		return out
	default:
		return v
	}
}

func registrationEvent(in *RegistrationInput, a *accum) map[string]any {
	ev := map[string]any{"client": clientEvent(in.Client), "tenant": tenantEvent(in.Tenant), "request": signupRequest(in.Request, in.Tenant.Host, false)}
	if in.Connection != nil {
		ev["connection"] = connectionEvent(in.Connection)
	}
	if in.Transaction != nil {
		ev["transaction"] = signupTransaction(in.Transaction)
	}
	if in.CustomDomain != "" {
		ev["custom_domain"] = map[string]any{"domain": in.CustomDomain, "domain_metadata": map[string]any{}}
	}
	if in.User != nil {
		profile := userEvent(in.User, &a.eff)
		user := map[string]any{}
		for _, key := range []string{"email", "username", "name", "given_name", "family_name", "nickname", "picture", "phone_number", "user_metadata", "app_metadata"} {
			if value, ok := profile[key]; ok {
				user[key] = value
			}
		}
		ev["user"] = user
	}
	return ev
}

func postRegistrationEvent(in *RegistrationInput, a *accum) map[string]any {
	ev := map[string]any{"user": userEvent(in.User, &a.eff), "tenant": tenantEvent(in.Tenant), "request": signupRequest(in.Request, in.Tenant.Host, false)}
	if in.Connection != nil {
		ev["connection"] = connectionEvent(in.Connection)
	}
	if in.Transaction != nil {
		ev["transaction"] = signupTransaction(in.Transaction)
	}
	return ev
}

func postChangePasswordEvent(in *PostChangePasswordInput) map[string]any {
	ev := map[string]any{"tenant": tenantEvent(in.Tenant), "request": signupRequest(in.Request, in.Tenant.Host, false)}
	if in.Connection != nil {
		ev["connection"] = connectionEvent(in.Connection)
	}
	if u := in.User; u != nil {
		user := map[string]any{"user_id": u.UserID, "email": u.Email, "email_verified": u.EmailVerified, "username": u.Username, "phone_number": u.PhoneNumber, "phone_verified": u.PhoneVerified}
		if u.LastPasswordReset != nil {
			user["last_password_reset"] = rfc3339(*u.LastPasswordReset)
		}
		ev["user"] = user
	}
	return ev
}

func resetChallengeEvent(in *ResetChallengeInput, a *accum) map[string]any {
	locale := ""
	if in.Ticket != nil {
		locale = in.Ticket.Lang
	}
	ev := map[string]any{"user": userEvent(in.User, &a.eff), "tenant": tenantEvent(in.Tenant), "request": signupRequest(in.Request, in.Tenant.Host, true), "transaction": map[string]any{"locale": locale, "correlation_id": ""}}
	if in.Client != nil {
		ev["client"] = clientEvent(in.Client)
	}
	if in.Connection != nil {
		ev["connection"] = connectionEvent(in.Connection)
	}
	return ev
}

func emailEvent(in *EmailInput, a *accum) map[string]any {
	host := ""
	ten := map[string]any{"id": in.Tenant, "friendly_name": "", "support_email": "", "support_url": ""}
	if t := in.TenantInfo; t != nil {
		host = t.CanonicalHost
		ten["friendly_name"] = t.FriendlyName
		ten["support_email"] = t.SupportEmail
		ten["support_url"] = t.SupportURL
	}
	m := in.Message
	ev := map[string]any{"user": userEvent(in.User, &a.eff), "client": clientEvent(in.Client), "tenant": ten, "request": signupRequest(in.Request, host, false), "notification": map[string]any{"from": m.From, "to": m.To, "subject": m.Subject, "html": m.HTML, "text": m.Text, "locale": m.Locale, "message_type": m.Type}}
	if in.Connection != nil {
		ev["connection"] = connectionEvent(in.Connection)
	}
	return ev
}
