package myaccount

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// passkeySession is a started passkey registration.
type passkeySession struct {
	Challenge      string          `json:"challenge"`
	Binding        passkey.Binding `json:"binding"`
	IdentityUserID string          `json:"identity_user_id"`
}

// webAuthnSession is a started WebAuthn security-key enrollment.
type webAuthnSession struct {
	Factor      string          `json:"factor"`
	ChallengeID string          `json:"challenge_id"`
	Binding     passkey.Binding `json:"binding"`
}

// webAuthnNames name new WebAuthn methods (the verify request has no name).
var webAuthnNames = map[string]string{"webauthn-roaming": "Security key", "webauthn-platform": "This device"}

var errInvalidAttestation = badRequest("invalid_authn_response", "The authenticator response could not be verified.", ValidationError{Detail: "invalid", Field: "authn_response", Source: "body"})

var errPasskeyLimit = conflict("enrollment_limit_reached", "The user has reached the passkey limit.")

// databaseIdentity selects the database identity a passkey or password
// enrollment is for: identity_user_id and connection when given, else the
// user's own identity.
func (h *Handlers) databaseIdentity(ctx context.Context, u *store.User, connName, identityUserID string) (*store.Identity, *store.Connection, *Problem) {
	var chosen *store.Identity
	for i := range u.Identities {
		id := &u.Identities[i]
		if id.Provider != store.StrategyDatabase || identityUserID != "" && id.UserID != identityUserID || connName != "" && id.Connection != connName {
			continue
		}
		if chosen == nil || !id.Linked() && chosen.Linked() {
			chosen = id
		}
	}
	if chosen == nil {
		return nil, nil, badRequest("invalid_identity", "The user has no such database identity.", ValidationError{Detail: "no such identity", Field: "identity_user_id", Source: "body"})
	}
	conn, err := h.Store.Connections().GetByName(ctx, u.TenantID, chosen.Connection)
	if err != nil {
		return nil, nil, badRequest("invalid_identity", "The identity's connection does not exist.", ValidationError{Detail: "no such connection", Field: "connection", Source: "body"})
	}
	return chosen, conn, nil
}

// origins are the RP origin and the caller's web origins under the RP ID.
func (h *Handlers) origins(ctx context.Context, c *Caller, rp rpid.Result) ([]string, error) {
	client, err := h.Store.Clients().Get(ctx, c.TenantID, c.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return []string{rp.Origin}, nil
	}
	if err != nil {
		return nil, err
	}
	return passkey.NativeOrigins(rp, client), nil
}

func (h *Handlers) startPasskey(w http.ResponseWriter, r *http.Request, c *Caller, b createBody) {
	ctx := r.Context()
	if h.Passkeys == nil {
		writeProblem(w, r, errFactorDisabled)
		return
	}
	id, conn, p := h.databaseIdentity(ctx, c.User, b.Connection, b.IdentityUserID)
	if p != nil {
		writeProblem(w, r, p)
		return
	}
	res, _ := tenant.FromContext(ctx)
	_, rp, ok, err := h.Passkeys.Effective(ctx, c.TenantID, res, conn)
	if err != nil && !errors.Is(err, passkey.ErrCeremony) {
		h.fail(w, r, "check passkeys", err)
		return
	}
	if !ok || !slices.Contains(conn.EnabledClients, c.ClientID) {
		writeProblem(w, r, errFactorDisabled)
		return
	}
	origins, err := h.origins(ctx, c, rp)
	if err != nil {
		h.fail(w, r, "load the application", err)
		return
	}
	bind := passkey.Binding{Purpose: passkey.PasskeyProgressiveRegister, RPID: rp.RPID, Origins: origins, ClientID: c.ClientID, Realm: conn.Name, UserID: c.UserID}
	timeout := webauthnrules.Limits.NativeTimeout
	issued, err := h.Passkeys.Issue(ctx, c.TenantID, bind, timeout)
	if err != nil {
		h.fail(w, r, "issue a passkey challenge", err)
		return
	}
	opts, err := h.Passkeys.CreationOptions(ctx, c.TenantID, c.User, passkey.UserDisplay{}, rp.RPID, passkey.Progressive, issued.Challenge, issued.UserHandle, timeout)
	var raw []byte
	if err == nil {
		raw, err = opts.JSON()
	}
	if err != nil {
		_ = h.Store.MFA().ConsumeChallenge(ctx, c.TenantID, issued.ID, h.now())
		if isLimit(err) {
			writeProblem(w, r, errPasskeyLimit)
			return
		}
		h.fail(w, r, "build passkey options", err)
		return
	}
	session, err := h.newAuthSession(ctx, c, "passkey", "passkey|new", passkeySession{Challenge: issued.Session, Binding: bind, IdentityUserID: id.UserID})
	if err != nil {
		h.fail(w, r, "store an enrollment", err)
		return
	}
	logs.AddCredentials(ctx, session, issued.Session)
	w.Header().Set("Location", location(c, "passkey|new"))
	writeJSON(w, r, http.StatusAccepted, map[string]any{"auth_session": session, "authn_params_public_key": json.RawMessage(raw)})
}

func isLimit(err error) bool {
	var pe *identity.PolicyError
	return errors.As(err, &pe) && errors.Is(pe.Err, store.ErrPrecondition)
}

func (h *Handlers) verifyPasskey(w http.ResponseWriter, r *http.Request, c *Caller, s *authSession, b verifyBody) {
	ctx := r.Context()
	var ps passkeySession
	if err := json.Unmarshal(s.Data, &ps); err != nil || ps.Challenge == "" || h.Passkeys == nil {
		writeProblem(w, r, errSession())
		return
	}
	if len(b.AuthnResponse) == 0 {
		writeProblem(w, r, errInvalidAttestation)
		return
	}
	logs.AddCredentials(ctx, string(b.AuthnResponse), ps.Challenge)
	taken, err := h.Passkeys.Take(ctx, c.TenantID, secrets.HashToken(ps.Challenge), ps.Binding)
	if err != nil {
		writeProblem(w, r, errSession())
		return
	}
	a, err := h.Passkeys.Enroll(ctx, c.TenantID, c.User, ps.IdentityUserID, b.AuthnResponse, taken, r.UserAgent())
	switch {
	case isLimit(err):
		writeProblem(w, r, errPasskeyLimit)
		return
	case errors.Is(err, identity.ErrUserBlocked):
		writeProblem(w, r, unauthorized("The user is blocked."))
		return
	case err != nil:
		var we *webauthn.Error
		if errors.Is(err, passkey.ErrCeremony) || errors.As(err, &we) {
			writeProblem(w, r, errInvalidAttestation)
			return
		}
		h.fail(w, r, "enroll a passkey", err)
		return
	}
	h.created(w, r, c, a.ID)
}

func (h *Handlers) startWebAuthn(w http.ResponseWriter, r *http.Request, c *Caller, typ string) {
	ctx := r.Context()
	if h.Passkeys == nil {
		writeProblem(w, r, errFactorDisabled)
		return
	}
	res, _ := tenant.FromContext(ctx)
	policy := h.Passkeys.RPID
	policy.Store = h.Store
	rp, err := policy.For(ctx, res)
	if err != nil {
		h.fail(w, r, "resolve the RP ID", err)
		return
	}
	if !rp.Valid {
		writeProblem(w, r, errFactorDisabled)
		return
	}
	origins, err := h.origins(ctx, c, rp)
	if err != nil {
		h.fail(w, r, "load the application", err)
		return
	}
	bind := passkey.Binding{RPID: rp.RPID, Origins: origins, TxnID: "my-account", CookieHash: secrets.HashToken(secrets.RandomString(32))}
	svc := h.webAuthnService(typ, bind)
	e, opts, err := svc.BeginWebAuthnEnroll(ctx, c.TenantID, c.UserID, typ, rp, passkey.UserDisplay{})
	if err != nil {
		h.mfaProblem(w, r, "start a WebAuthn enrollment", err)
		return
	}
	raw, err := opts.JSON()
	if err != nil {
		h.fail(w, r, "build WebAuthn options", err)
		return
	}
	session, err := h.newAuthSession(ctx, c, typ, e.AuthenticatorID, webAuthnSession{Factor: typ, ChallengeID: e.ChallengeID, Binding: bind})
	if err != nil {
		h.fail(w, r, "store an enrollment", err)
		return
	}
	logs.AddCredentials(ctx, session, e.ChallengeID)
	w.Header().Set("Location", location(c, e.AuthenticatorID))
	writeJSON(w, r, http.StatusAccepted, map[string]any{"id": e.AuthenticatorID, "auth_session": session, "authn_params_public_key": json.RawMessage(raw)})
}

func (h *Handlers) webAuthnService(typ string, b passkey.Binding) *mfa.Service {
	svc := h.MFA.WithWebAuthnBinding(b).WithoutAutomaticRecovery()
	if typ == "webauthn-platform" {
		// The access token proves the user signed in; the MFA service still
		// requires another usable factor before a platform authenticator.
		svc = svc.WithPlatformEnrollmentProof()
	}
	return svc
}

func (h *Handlers) verifyWebAuthn(w http.ResponseWriter, r *http.Request, c *Caller, s *authSession, b verifyBody) {
	ctx := r.Context()
	var ws webAuthnSession
	if err := json.Unmarshal(s.Data, &ws); err != nil || ws.ChallengeID == "" || ws.Factor != s.Type {
		writeProblem(w, r, errSession())
		return
	}
	if len(b.AuthnResponse) == 0 {
		writeProblem(w, r, errInvalidAttestation)
		return
	}
	logs.AddCredentials(ctx, string(b.AuthnResponse))
	e := &mfa.Enrollment{Factor: ws.Factor, AuthenticatorID: s.MethodID, ChallengeID: ws.ChallengeID}
	_, err := h.webAuthnService(ws.Factor, ws.Binding).ConfirmWebAuthnEnroll(ctx, c.TenantID, c.UserID, e, b.AuthnResponse, webAuthnNames[ws.Factor], r.UserAgent())
	var we *webauthn.Error
	switch {
	case errors.Is(err, mfa.ErrAlreadyEnrolled):
		writeProblem(w, r, conflict("already_enrolled", "An authenticator of this kind is already enrolled."))
		return
	case errors.As(err, &we), errors.Is(err, passkey.ErrCeremony), errors.Is(err, mfa.ErrInvalidCode):
		writeProblem(w, r, errInvalidAttestation)
		return
	case err != nil:
		h.mfaProblem(w, r, "confirm a WebAuthn enrollment", err)
		return
	}
	h.created(w, r, c, s.MethodID)
}
