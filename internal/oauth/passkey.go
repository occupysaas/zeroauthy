package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// nativePasskeyState is sealed server metadata, separate from the service's
// ceremony binding. It contains no raw auth_session or credential response.
type nativePasskeyState struct {
	Binding           passkey.Binding
	User              *store.User
	IP                string
	Profile, Metadata string
}

const nativeStatePrefix = "native-passkey:"
const passkeyGrantDescription = "Passkey authentication failed."

func passkeyNotFound() *Error { return &Error{Status: 404, Code: "not_found"} }

func (h *Handlers) nativeSetup(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*store.Connection, rpid.Result, *store.Organization, *Error) {
	if h.Passkeys == nil {
		return nil, rpid.Result{}, nil, passkeyNotFound()
	}
	// Capability first: without webauthn.v1 every host answers 404, the
	// canonical host included.
	if cap, ok := h.Store.(store.WebAuthnSupporter); ok {
		if err := cap.CheckWebAuthnSupport(ctx); errors.Is(err, store.ErrWebAuthnUnavailable) {
			return nil, rpid.Result{}, nil, passkeyNotFound()
		} else if err != nil {
			return nil, rpid.Result{}, nil, serverError()
		}
		if !cap.WebAuthnSupported() {
			return nil, rpid.Result{}, nil, passkeyNotFound()
		}
	}
	switch h.Store.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return nil, rpid.Result{}, nil, passkeyNotFound()
	}
	policy := h.Passkeys.RPID
	policy.Store = h.Store
	rp, err := policy.For(ctx, res)
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		return nil, rp, nil, passkeyNotFound()
	}
	if err != nil {
		return nil, rp, nil, serverError()
	}
	if rp.Kind == rpid.KindCanonical || !rp.Valid {
		return nil, rp, nil, invalidRequest("Passkeys require a usable custom domain")
	}
	cfg, err := h.Store.HostedLogins().Get(ctx, res.Tenant.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, rp, nil, passkeyNotFound()
	}
	if err != nil {
		return nil, rp, nil, serverError()
	}
	conns, _, err := h.Store.Connections().List(ctx, res.Tenant.ID, store.ConnectionFilter{}, store.Page{})
	if err != nil {
		return nil, rp, nil, serverError()
	}
	effective := false
	var enabled []*store.Connection
	var conn *store.Connection
	for _, v := range conns {
		p, _ := connrules.Passkeys(v, cfg.Prompts)
		if p.Effective {
			effective = true
		}
		if v.Strategy != store.StrategyDatabase || !slices.Contains(v.EnabledClients, c.ClientID) {
			continue
		}
		if form.Get("realm") != "" && v.Name == form.Get("realm") {
			conn = v
		}
		if form.Get("realm") == "" && v.Name == res.Tenant.DefaultDirectory {
			conn = v
		}
		if p.Effective {
			enabled = append(enabled, v)
		}
	}
	if !effective {
		return nil, rp, nil, passkeyNotFound()
	}
	if conn == nil && form.Get("realm") == "" && len(enabled) == 1 {
		conn = enabled[0]
	}
	if conn == nil {
		return nil, rp, nil, invalidRequest("A database realm enabled for this client is required")
	}
	p, _ := connrules.Passkeys(conn, cfg.Prompts)
	if !p.Effective {
		return nil, rp, nil, invalidRequest("Passkeys are unavailable for this realm")
	}
	org, oerr := h.machineOrganization(ctx, res, form)
	if oerr != nil {
		return nil, rp, nil, oerr
	}
	if org == nil && c.OrganizationUsage == store.OrgUsageRequire {
		return nil, rp, nil, invalidRequest("organization is required")
	}
	if org != nil {
		if c.OrganizationUsage != store.OrgUsageAllow && c.OrganizationUsage != store.OrgUsageRequire {
			return nil, rp, nil, invalidRequest("organization is not allowed")
		}
		if err := orglogin.CheckMemberClient(ctx, h.Store, res.Tenant.ID, org.ID, c.ClientID); err != nil {
			return nil, rp, nil, accessDenied("organization access is unavailable")
		}
		link, err := h.Store.Organizations().GetConnection(ctx, res.Tenant.ID, org.ID, conn.ID)
		if err != nil || link.IsEnabledSet && !link.IsEnabled {
			return nil, rp, nil, invalidRequest("The realm is not enabled for this organization")
		}
	}
	return conn, rp, org, nil
}
func nativeBinding(conn *store.Connection, rp rpid.Result, c *store.Client, org *store.Organization) passkey.Binding {
	b := passkey.Binding{Purpose: passkey.PasskeyLogin, RPID: rp.RPID, Origins: passkey.NativeOrigins(rp, c), ClientID: c.ClientID, Realm: conn.Name}
	if org != nil {
		b.Organization = org.ID
	}
	return b
}

func (h *Handlers) PasskeyRegister(w http.ResponseWriter, r *http.Request) {
	h.nativePasskey(w, r, true)
}
func (h *Handlers) PasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	h.nativePasskey(w, r, false)
}
func (h *Handlers) nativePasskey(w http.ResponseWriter, r *http.Request, register bool) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	*r = *r.WithContext(logs.WithEvent(logs.WithRecorder(r.Context(), h.Recorder), logs.FromRequest(r)))
	purpose := "challenge"
	if register {
		purpose = "register"
	}
	var client *store.Client
	fail := func(e *Error) {
		h.nativeEvent(r.Context(), res, client, "passkey_challenge_failed", purpose, "request", nil, "")
		if e.Status == 404 {
			httpx.WriteJSON(w, 404, map[string]string{"error": "not_found"})
		} else {
			writeError(w, e)
		}
	}
	form, oerr := parseTokenRequest(w, r, "user_profile", "user_metadata")
	if oerr != nil {
		fail(oerr)
		return
	}
	client, oerr = h.authenticateClient(r.Context(), r, form, res.Tenant.ID)
	if oerr != nil {
		fail(oerr)
		return
	}
	if !client.IsFirstParty || !slices.Contains(client.GrantTypes, clientrules.GrantPasskey) {
		fail(invalidRequest("The client cannot use passkeys"))
		return
	}
	ctx := withRequestInfo(withClientIP(r.Context(), h.endUserIP(r, client)), r, h.endUserIP(r, client), form)
	conn, rp, org, oerr := h.nativeSetup(ctx, res, client, form)
	if oerr != nil {
		fail(oerr)
		return
	}
	b := nativeBinding(conn, rp, client, org)
	state := nativePasskeyState{IP: clientIPFrom(ctx)}
	if register {
		u, oerr := h.nativeProfile(ctx, res, conn, form)
		if oerr != nil {
			fail(oerr)
			return
		}
		attempt := protection.Attempt{Tenant: res.Tenant, Connection: conn, Identifier: u.Email, IP: state.IP, Flow: "signup"}
		svc := h.protectionService()
		dec, err := svc.Begin(ctx, attempt)
		if err != nil {
			fail(serverError())
			return
		}
		if !dec.Allowed {
			fail(tooManyRequests())
			return
		}
		required, err := svc.RequireChallenge(ctx, attempt)
		outcome := "failure"
		if err != nil || required {
			outcome = "refund"
		}
		if e := svc.Finish(ctx, dec.Receipt, outcome); e != nil {
			fail(serverError())
			return
		}
		if err != nil {
			fail(serverError())
			return
		}
		if required {
			fail(&Error{Status: 401, Code: "requires_verification", Description: "Complete verification using interactive web login."})
			return
		}
		// This documented existence answer follows the store-backed registration budget.
		for _, identifier := range []struct {
			value string
			phone bool
		}{{u.Email, false}, {u.Username, false}, {u.PhoneNumber, true}} {
			v := identifier.value
			if v == "" {
				continue
			}
			var err error
			exists := false
			if identifier.phone {
				var matches []store.User
				matches, err = h.Store.Phone().FindUsersByPhone(ctx, res.Tenant.ID, conn.Name, v)
				exists = len(matches) > 0
			} else {
				_, err = h.Store.Users().FindByLogin(ctx, res.Tenant.ID, conn.Name, v)
				exists = err == nil
			}
			if exists {
				if e := svc.RecordFailure(ctx, attempt, secrets.RandomString(32)); e != nil {
					fail(serverError())
					return
				}
				fail(invalidRequest("The user already exists"))
				return
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				fail(serverError())
				return
			}
		}
		b.Purpose = passkey.PasskeyRegister
		b.UserID = u.UserID
		state.User = u
		state.Profile = form.Get("user_profile")
		state.Metadata = form.Get("user_metadata")
	}
	state.Binding = b
	i, err := h.Passkeys.Issue(ctx, res.Tenant.ID, b, webauthnrules.Limits.NativeTimeout)
	if err != nil {
		fail(serverError())
		return
	}
	plain, err := json.Marshal(state)
	if err != nil {
		fail(serverError())
		return
	}
	sealed, err := keys.SealBound(h.Wrapper, "native-passkey/v1", []string{res.Tenant.ID, i.ID}, plain)
	if err != nil {
		_ = h.Store.MFA().ConsumeChallenge(ctx, res.Tenant.ID, i.ID, h.now())
		fail(serverError())
		return
	}
	if err = h.Store.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: res.Tenant.ID, ID: nativeStatePrefix + i.ID, Kind: "webauthn", Binding: sealed, ExpiresAt: i.ExpiresAt}); err != nil {
		_ = h.Store.MFA().ConsumeChallenge(ctx, res.Tenant.ID, i.ID, h.now())
		fail(serverError())
		return
	}
	var options []byte
	if register {
		o, e := h.Passkeys.CreationOptions(ctx, res.Tenant.ID, state.User, passkey.UserDisplay{}, rp.RPID, passkey.Signup, i.Challenge, i.UserHandle, webauthnrules.Limits.NativeTimeout)
		err = e
		if err == nil {
			options, err = o.JSON()
		}
	} else {
		options, err = json.Marshal(map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(i.Challenge), "timeout": 60000, "rpId": rp.RPID, "userVerification": "preferred"})
	}
	if err != nil {
		fail(serverError())
		return
	}
	h.nativeEvent(ctx, res, client, "passkey_challenge_started", purpose, "", conn, "")
	noStore(w)
	httpx.WriteJSON(w, 200, map[string]any{"auth_session": i.Session, "authn_params_public_key": json.RawMessage(options)})
}
func (h *Handlers) nativeProfile(ctx context.Context, res tenant.Resolved, conn *store.Connection, form url.Values) (*store.User, *Error) {
	if conn.DisableSignup {
		return nil, invalidRequest("Signup is unavailable")
	}
	for _, name := range []string{"email", "phone_number"} {
		signup, _ := store.IdentifierAttribute(conn, name)["signup"].(map[string]any)
		verification, _ := signup["verification"].(map[string]any)
		active, _ := verification["active"].(bool)
		if active || name == "phone_number" && store.PhoneIdentifierActive(conn) && store.PhoneSignupVerification(conn) {
			return nil, invalidRequest("Signup requires interactive verification")
		}
	}
	var profile map[string]string
	if json.Unmarshal([]byte(form.Get("user_profile")), &profile) != nil || profile == nil {
		return nil, invalidRequest("user_profile must be an object")
	}
	bounds := map[string]int{"email": 320, "phone_number": 32, "username": 128, "name": 300, "given_name": 150, "family_name": 150, "nickname": 300, "picture": 2000}
	for k, v := range profile {
		max, ok := bounds[k]
		if !ok || utf8.RuneCountInString(v) > max || v == "" {
			return nil, invalidRequest("Invalid user_profile")
		}
	}
	metadata := map[string]any{}
	if raw := form.Get("user_metadata"); raw != "" {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) != nil || m == nil || len(m) > 10 {
			return nil, invalidRequest("user_metadata must contain at most ten string fields")
		}
		for k, v := range m {
			text, ok := v.(string)
			if !ok {
				return nil, invalidRequest("user_metadata must contain at most ten string fields")
			}
			metadata[k] = text
		}
	}
	in := identity.SignupInput{Email: profile["email"], Username: profile["username"], PhoneNumber: profile["phone_number"], Name: profile["name"], GivenName: profile["given_name"], FamilyName: profile["family_name"], Nickname: profile["nickname"], Picture: profile["picture"], UserMetadata: metadata}
	email, username, err := identity.CheckSignupProfile(conn, in)
	if err != nil {
		return nil, invalidRequest("Invalid signup profile")
	}
	// The legacy helper clears optional usernames. Flexible identifier policy
	// independently enables them, so validate and retain the normalized value.
	if store.IdentifierActive(conn, "username") && in.Username != "" {
		username = identity.NormalizeLogin(in.Username)
		if err := identity.CheckUsername(conn, username); err != nil {
			return nil, invalidRequest("Invalid signup profile")
		}
	}
	// Enforce every explicit flexible signup identifier, including email/username.
	for _, name := range []string{"email", "username", "phone_number"} {
		signup, _ := store.IdentifierAttribute(conn, name)["signup"].(map[string]any)
		status, _ := signup["status"].(string)
		if status == "required" && profile[name] == "" || status == "not_allowed" && profile[name] != "" {
			return nil, invalidRequest("Invalid signup identifiers")
		}
		if profile[name] != "" && !store.IdentifierActive(conn, name) {
			return nil, invalidRequest("Invalid signup identifiers")
		}
	}
	number := in.PhoneNumber
	if number != "" {
		number, err = phone.NormalizeE164(number, "")
		if err != nil {
			return nil, invalidRequest("Invalid phone number")
		}
	}
	id := secrets.RandomString(24)
	return &store.User{TenantID: res.Tenant.ID, UserID: "auth0|" + id, Email: email, Username: username, PhoneNumber: number, Name: in.Name, GivenName: in.GivenName, FamilyName: in.FamilyName, Nickname: in.Nickname, Picture: in.Picture, UserMetadata: metadata, Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: conn.Name, UserID: id}}, CreatedAt: h.now(), UpdatedAt: h.now()}, nil
}
func (h *Handlers) nativeEvent(ctx context.Context, res tenant.Resolved, c *store.Client, code, purpose, reason string, conn *store.Connection, uid string) {
	e := logs.Event{TenantID: res.Tenant.ID, Type: code, Hostname: res.Host, IP: clientIPFrom(ctx), UserAgent: requestInfoFrom(ctx).UserAgent, UserID: uid}
	if c != nil {
		e.ClientID = c.ClientID
		e.ClientName = c.Name
	}
	if conn != nil {
		e.Connection = conn.Name
		e.ConnectionID = conn.ID
		e.Strategy = conn.Strategy
		e.StrategyType = logs.StrategyType(conn.Strategy)
	}
	switch code {
	case "passkey_challenge_started", "passkey_challenge_failed":
		e.Details = map[string]any{"purpose": purpose}
		if reason != "" {
			e.Details["error"] = map[string]any{"message": reason}
		}
	case "ss":
		e.Details = map[string]any{"authentication_methods": []string{"passkey"}}
	case "s":
		e.Details = map[string]any{"prompts": []any{map[string]any{"name": "login-id", "performed_amr": []string{"phr"}}}}
	}
	logs.RecordEvent(ctx, h.Recorder, e)
}

// Unknown or mismatched sessions still spend the IP failure budget. Selecting
// an enabled database connection here carries no credential/identity authority.
func (h *Handlers) nativeFailureBudget(ctx context.Context, res tenant.Resolved, c *store.Client, conn *store.Connection) *Error {
	if conn == nil {
		conns, _, err := h.Store.Connections().List(ctx, res.Tenant.ID, store.ConnectionFilter{}, store.Page{})
		if err != nil {
			return serverError()
		}
		for _, v := range conns {
			if v.Strategy == store.StrategyDatabase && slices.Contains(v.EnabledClients, c.ClientID) {
				conn = v
				break
			}
		}
	}
	if conn == nil {
		return nil
	}
	svc := h.protectionService()
	a := protection.Attempt{Tenant: res.Tenant, Connection: conn, IP: clientIPFrom(ctx), Flow: "passkey-login-failure"}
	dec, err := svc.Begin(ctx, a)
	if err != nil {
		return serverError()
	}
	if !dec.Allowed {
		return tooManyRequests()
	}
	if err := svc.Finish(ctx, dec.Receipt, "failure"); err != nil {
		return serverError()
	}
	if err := svc.RecordFailure(ctx, a, secrets.RandomString(32)); err != nil {
		return serverError()
	}
	return nil
}
