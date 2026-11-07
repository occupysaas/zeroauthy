package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/signupactions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

// firstFactorTokens preserves the initial factor and organization through a
// sealed MFA continuation and the normal user-token/refresh issuance path.
type firstFactorTokens struct {
	Passkey      bool
	Organization *store.Organization
	ConnectionID string
}

func (h *Handlers) passkeyGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	if !c.IsFirstParty {
		return nil, unauthorizedClient("The client cannot use passkeys")
	}
	if form.Get("auth_session") == "" || form.Get("authn_response") == "" {
		return nil, invalidRequest("auth_session and authn_response are required")
	}
	ctx = logscrub.WithCredentials(ctx, form.Get("auth_session"), form.Get("authn_response"))
	logs.AddCredentials(ctx, form.Get("auth_session"), form.Get("authn_response"))
	purpose := "challenge"
	reason := "challenge"
	var conn *store.Connection
	uid := ""
	defer func() {
		if failure != nil && failure.Code != "mfa_required" {
			if purpose == "challenge" && failure.Code == "invalid_grant" && failure.Description == passkeyGrantDescription {
				if e := h.nativeFailureBudget(ctx, res, c, conn); e != nil {
					failure = e
				}
			}
			h.nativeEvent(ctx, res, c, "passkey_challenge_failed", purpose, reason, conn, uid)
		}
	}()
	invalid := func() (*authapi.TokenResponse, *Error) { return nil, invalidGrant(passkeyGrantDescription) }
	if h.Passkeys == nil {
		return invalid()
	}
	hash := secrets.HashToken(form.Get("auth_session"))
	tid := res.Tenant.ID
	// Consume the server metadata before parsing the authenticator response or
	// resolving submitted context. A second Take consumes the ceremony even when
	// setup fails, so changing a realm/client/domain cannot retain the challenge.
	row, err := h.Store.MFA().GetChallenge(ctx, tid, nativeStatePrefix+hash, h.now())
	if err != nil {
		_, _ = h.Passkeys.Take(ctx, tid, hash, passkey.Binding{})
		return invalid()
	}
	if err = h.Store.MFA().ConsumeChallenge(ctx, tid, nativeStatePrefix+hash, h.now()); err != nil {
		return invalid()
	}
	takenDone := false
	defer func() {
		if !takenDone {
			_, _ = h.Passkeys.Take(ctx, tid, hash, passkey.Binding{})
		}
	}()
	plain, err := keys.OpenBound(h.Wrapper, "native-passkey/v1", []string{tid, hash}, row.Binding)
	if err != nil {
		return invalid()
	}
	var state nativePasskeyState
	if json.Unmarshal(plain, &state) != nil {
		return invalid()
	}
	if state.Binding.Purpose == passkey.PasskeyRegister {
		purpose = "register"
	}
	conn, rp, org, oerr := h.nativeSetup(ctx, res, c, form)
	if oerr != nil {
		return invalid()
	}
	want := nativeBinding(conn, rp, c, org)
	want.Purpose = state.Binding.Purpose
	want.UserID = state.Binding.UserID
	taken, err := h.Passkeys.Take(ctx, tid, hash, want)
	takenDone = true
	if err != nil {
		return invalid()
	}
	var user *store.User
	if want.Purpose == passkey.PasskeyRegister {
		if state.User == nil || state.User.UserID != want.UserID {
			return invalid()
		}
		// Validate the proof before allowing registration Actions to execute. The
		// service repeats verification inside the atomic user/credential transaction.
		credential, e := webauthn.ParseCredentialJSON([]byte(form.Get("authn_response")))
		if e == nil {
			_, e = webauthn.VerifyRegistration(credential, webauthn.Expect{Challenge: taken.Challenge, RPID: want.RPID, Origins: want.Origins})
		}
		if e != nil {
			reason = boundedPasskeyReason(e)
			return invalid()
		}
		profile := url.Values{"user_profile": {state.Profile}, "user_metadata": {state.Metadata}}
		if _, e := h.nativeProfile(ctx, res, conn, profile); e != nil {
			return invalid()
		}
		svc := h.protectionService()
		attempt := protection.Attempt{Tenant: res.Tenant, Connection: conn, IP: clientIPFrom(ctx), Identifier: state.User.Email, Flow: "signup", RegistrationAdmitted: state.IP == clientIPFrom(ctx)}
		dec, e := svc.Begin(ctx, attempt)
		if e != nil {
			return nil, serverError()
		}
		if !dec.Allowed {
			return nil, tooManyRequests()
		}
		bot, e := svc.RequireChallenge(ctx, attempt)
		outcome := "failure"
		if e != nil || bot {
			outcome = "refund"
		}
		if e2 := svc.Finish(ctx, dec.Receipt, outcome); e2 != nil {
			return nil, serverError()
		}
		if e != nil {
			return nil, serverError()
		}
		if bot {
			reason = "policy"
			return nil, &Error{Status: 401, Code: "requires_verification", Description: "Complete verification using interactive web login."}
		}
		in := actions.RegistrationInput{Tenant: res, Client: c, Connection: conn, Request: requestInfoFrom(ctx), Transaction: &actions.TransactionInfo{Protocol: actions.ProtocolWebAuthn, RequestedScopes: strings.Fields(form.Get("scope"))}}
		in = signupactions.WithOrganization(in, org)
		callbacks := signupactions.Callbacks(h.Store, h.Actions, in)
		callbacks.Commit = func(ctx context.Context, tx store.Store, u *store.User) error {
			return nativeMembership(ctx, tx, tid, u.UserID, conn.ID, c.ClientID, org)
		}
		if h.Database == nil {
			return nil, serverError()
		}
		err = h.Database.CreateWithCredential(ctx, conn, callbacks, state.User, func(ctx context.Context, tx store.Store, u *store.User) error {
			current, e := tx.Connections().Get(ctx, tid, conn.ID)
			if e != nil {
				return e
			}
			boundH := *h
			boundH.Store = tx
			if _, e := boundH.nativeProfile(ctx, res, current, profile); e != nil {
				return passkey.ErrCeremony
			}
			bound := *h.Passkeys
			bound.Store = tx
			var e2 error
			user, _, e2 = bound.Signup(ctx, tid, u, []byte(form.Get("authn_response")), taken, requestInfoFrom(ctx).UserAgent)
			return e2
		})
		if err != nil {
			reason = boundedPasskeyReason(err)
			var denied *identity.ErrSignupDenied
			var failed *identity.ErrSignupActionFailed
			switch {
			case errors.As(err, &denied):
				return nil, accessDenied(denied.Description)
			case errors.As(err, &failed):
				return nil, serverError()
			case errors.Is(err, passkey.ErrCeremony), errors.Is(err, identity.ErrUserExists), errors.Is(err, identity.ErrSignupDisabled):
				return invalid()
			default:
				return nil, serverError()
			}
		}
		uid = user.UserID
		h.nativeEvent(ctx, res, c, "ss", "register", "", conn, uid)
	} else if want.Purpose == passkey.PasskeyLogin {
		result, e := h.Passkeys.Login(ctx, tid, []byte(form.Get("authn_response")), taken.Challenge, taken.Binding)
		if errors.Is(e, identity.ErrUserBlocked) {
			reason = "blocked"
			return nil, invalidGrant("user is blocked")
		}
		if e != nil {
			reason = boundedPasskeyReason(e)
			return invalid()
		}
		user = result.User
		uid = user.UserID
		var meta struct {
			IdentityUserID string `json:"identity_user_id"`
		}
		if json.Unmarshal(result.Method.PublicData, &meta) != nil {
			return invalid()
		}
		identifier := ""
		for i := range user.Identities {
			id := &user.Identities[i]
			if id.Provider == store.StrategyDatabase && id.Connection == conn.Name && id.UserID == meta.IdentityUserID {
				identifier = protection.IdentityIdentifier(user, id)
				break
			}
		}
		if identifier == "" {
			return invalid()
		}
		svc := h.protectionService()
		attempt := protection.Attempt{Tenant: res.Tenant, Connection: conn, Identifier: identifier, IP: clientIPFrom(ctx), Flow: "login"}
		dec, e := svc.Begin(ctx, attempt)
		if e != nil {
			return nil, serverError()
		}
		if !dec.Allowed {
			reason = "blocked"
			return nil, tooManyRequests()
		}
		bot, e := svc.RequireChallenge(ctx, attempt)
		if e2 := svc.Finish(ctx, dec.Receipt, "success"); e2 != nil {
			return nil, serverError()
		}
		if e != nil {
			return nil, serverError()
		}
		if bot {
			reason = "policy"
			return nil, &Error{Status: 401, Code: "requires_verification", Description: "Complete verification using interactive web login."}
		}
		if err := orglogin.WithMembershipEvents(ctx, h.Store, func(ctx context.Context, tx store.Store) error {
			return nativeMembership(ctx, tx, tid, user.UserID, conn.ID, c.ClientID, org)
		}); err != nil {
			reason = "organization"
			return invalid()
		}
	} else {
		return invalid()
	}
	now := h.now().UTC()
	ctx = logs.WithEvent(ctx, logs.Event{UserID: user.UserID, UserName: user.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: "database"})
	if org != nil {
		ctx = logs.WithEvent(ctx, logs.Event{OrganizationID: org.ID, OrganizationName: org.Name})
	}
	if err := h.Store.Users().RecordLogin(ctx, tid, user.UserID, now, httpx.CanonicalIP(clientIPFrom(ctx))); err != nil {
		h.log().WarnContext(ctx, "record passkey login", "err", err)
	}
	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tid, aud)
	if oerr != nil {
		return nil, oerr
	}
	requested := strings.Fields(form.Get("scope"))
	d, oerr := h.decide(ctx, tid, access.Password, c, rs, userScopes(requested, rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	orgID := ""
	if org != nil {
		orgID = org.ID
	}
	eff, oerr := h.postLogin(ctx, res, c, loginFlow{organizationID: orgID, user: user, connection: conn, rs: rs, protocol: actions.ProtocolWebAuthn, requested: requested, target: requested, session: &store.LoginSession{AuthMethods: []store.AuthMethod{{Name: "passkey", At: now}}}})
	if oerr != nil {
		return nil, oerr
	}
	before := d.Scopes
	if eff != nil && eff.Target != nil {
		d, oerr = h.decide(ctx, tid, access.Password, c, rs, userScopes(eff.Target.Scopes, rs, offlineAllowed(c, rs)))
		if oerr != nil {
			return nil, oerr
		}
	}
	ceiling := actions.CeilingOf(d.Scopes, before)
	flow := firstFactorTokens{Passkey: true, Organization: org, ConnectionID: conn.ID}
	if required := h.passwordMFA(ctx, res, c, user, conn, aud, d.Scopes, ceiling, eff, now, flow); required != nil {
		return nil, required
	}
	resp, write, oerr := h.preparePasswordTokens(ctx, res, c, user, rs, lifetime, aud, d.Scopes, ceiling, eff, now, time.Time{}, flow)
	if oerr != nil {
		return nil, oerr
	}
	version := user.Version
	err = h.mintCheckedTx(ctx, tid, user.UserID, &version, func(tx store.Store) error {
		return checkTokenOrganization(ctx, tx, tid, user.UserID, orgID, conn.ID, c.ClientID)
	}, write)
	if errors.Is(err, errUserBlocked) {
		return nil, invalidGrant("user is blocked")
	}
	if err != nil {
		return invalid()
	}
	h.nativeEvent(ctx, res, c, "s", purpose, "", conn, user.UserID)
	return resp, nil
}
func boundedPasskeyReason(err error) string {
	if code := webauthn.Reason(err); code != "" {
		return code
	}
	return "challenge"
}
func nativeMembership(ctx context.Context, tx store.Store, tid, uid, connectionID, clientID string, org *store.Organization) error {
	c, err := tx.Clients().Get(ctx, tid, clientID)
	if err != nil {
		return err
	}
	if org == nil {
		if c.OrganizationUsage == store.OrgUsageRequire {
			return errOrganizationGrant
		}
		return nil
	}
	if c.OrganizationUsage != store.OrgUsageAllow && c.OrganizationUsage != store.OrgUsageRequire {
		return errOrganizationGrant
	}
	if err := orglogin.CheckMemberClient(ctx, tx, tid, org.ID, clientID); err != nil {
		return err
	}
	if err := orglogin.EnsureMembership(ctx, tx, orglogin.Context{Org: org}, uid, connectionID); err != nil {
		return err
	}
	return checkTokenOrganization(ctx, tx, tid, uid, org.ID, connectionID, clientID)
}
