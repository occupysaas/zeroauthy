package mfa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// WebAuthnCapabilities is the browser result for this transaction. An absent
// result leaves Available false; it never grants a WebAuthn factor.
type WebAuthnCapabilities struct {
	Available, Platform bool
	RPID                string
	Device              webauthn.Device
}

// RoamingUV returns the operator's security-key user-verification setting.
func RoamingUV(g *store.GuardianSettings) string {
	var v struct {
		UV string `json:"user_verification"`
	}
	if g != nil {
		_ = json.Unmarshal(g.Stored["webauthn-roaming/settings"], &v)
	}
	if v.UV == "preferred" || v.UV == "required" {
		return v.UV
	}
	return "discouraged"
}

// WebAuthnAvailable checks negotiated storage support without connection policy:
// MFA security keys also work for non-database first factors.
func (s *Service) WebAuthnAvailable(ctx context.Context) (bool, error) {
	if c, ok := s.st.(store.WebAuthnSupporter); ok {
		if err := c.CheckWebAuthnSupport(ctx); err != nil {
			if errors.Is(err, store.ErrWebAuthnUnavailable) {
				return false, nil
			}
			return false, err
		}
		return c.WebAuthnSupported(), nil
	}
	switch s.st.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return false, nil
	}
	return true, nil
}

// WithWebAuthnBinding binds a request-local service to trusted transaction and
// browser values. A missing binding is refused; callers cannot synthesize one
// from submitted WebAuthn metadata.
func (s *Service) WithWebAuthnBinding(b passkey.Binding) *Service {
	c := *s
	c.webAuthnBinding = b
	c.webAuthnRPID = &b.RPID
	return &c
}

// WithWebAuthnBrowserError accepts only bounded DOM exception names. It does
// not bypass challenge consumption or the shared failure budget.
func (s *Service) WithWebAuthnBrowserError(name string) *Service {
	c := *s
	switch name {
	case "NotAllowedError", "InvalidStateError", "NotSupportedError", "SecurityError", "AbortError", "ConstraintError", "UnknownError":
		c.webAuthnBrowserError = name
	default:
		if name != "" {
			c.webAuthnBrowserError = "UnknownError"
		}
	}
	return &c
}

// WithWebAuthnRPID scopes ordinary first-only enrollment guards to the
// request's RP. Empty means WebAuthn is unavailable in this request. It grants
// no ceremony authority; WebAuthn proofs still require the full binding.
func (s *Service) WithWebAuthnRPID(rpID string) *Service {
	c := *s
	c.webAuthnRPID = &rpID
	return &c
}
func (s *Service) WithFirstWebAuthnEnrollment() *Service {
	c := *s
	c.webAuthnFirstOnly = true
	return &c
}
func (s *Service) webBinding(uid string, p passkey.Purpose, rp rpid.Result) (passkey.Binding, error) {
	b := s.webAuthnBinding
	if !rp.Valid || rp.RPID == "" || rp.Origin == "" || b.TxnID == "" || b.CookieHash == "" || b.RPID != rp.RPID || !slices.Equal(b.Origins, []string{rp.Origin}) {
		return b, ErrInvalidCode
	}
	b.Purpose = p
	b.UserID = uid
	b.RPID = rp.RPID
	b.Origins = []string{rp.Origin}
	return b, nil
}
func (s *Service) passkeys() *passkey.Service { return passkey.NewService(s.st, rpid.Policy{}, s.now) }

type webAuthnMetadata struct {
	Binding            passkey.Binding
	Factor             string
	Params             webauthn.Params
	Creation           webauthn.CreationOptions
	Request            webauthn.RequestOptions
	FirstOnly, NewOnly bool
	VerifiedUV         bool
	PlatformProof      bool
	Authenticator      *store.Authenticator
}

func metadataID(id, stage string) string {
	return secrets.HashToken("mfa-webauthn/" + stage + "/" + id)
}
func (s *Service) saveWebMetadata(ctx context.Context, tid, id, stage string, m webAuthnMetadata, expiry time.Time) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.st.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: tid, ID: metadataID(id, stage), Kind: "webauthn", Binding: raw, ExpiresAt: expiry})
}
func (s *Service) webMetadata(ctx context.Context, tid, uid, id, stage string) (webAuthnMetadata, *store.MFAChallenge, error) {
	var m webAuthnMetadata
	row, err := s.st.MFA().GetChallenge(ctx, tid, metadataID(id, stage), s.now())
	if err != nil {
		return m, nil, ErrExpired
	}
	if json.Unmarshal(row.Binding, &m) != nil {
		return m, nil, ErrInvalidCode
	}
	b := s.webAuthnBinding
	b.Purpose = m.Binding.Purpose
	b.UserID = uid

	if b.TxnID == "" || b.CookieHash == "" || !reflect.DeepEqual(b, m.Binding) {
		return m, nil, ErrInvalidCode
	}
	return m, row, nil
}
func webParams(factor string, g *store.GuardianSettings) (webauthn.Params, error) {
	if factor == "webauthn-platform" {
		return webauthn.ParamsFor(webauthn.CeremonyPlatform, "required"), nil
	}
	if factor != "webauthn-roaming" {
		return webauthn.Params{}, ErrNoFactor
	}
	return webauthn.ParamsFor(webauthn.CeremonyRoaming, RoamingUV(g)), nil
}
func (s *Service) webEnabled(ctx context.Context, tid, uid, factor string) (*store.GuardianSettings, error) {
	available, err := s.WebAuthnAvailable(ctx)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, ErrNoFactor
	}
	if !isWebAuthnFactor(factor) {
		return nil, ErrNoFactor
	}
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return nil, err
	}
	if !g.Factors[factor] {
		return nil, ErrNoFactor
	}
	u, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	if u.Blocked {
		return nil, ErrInvalidCode
	}
	if factor == "webauthn-platform" {
		list, x := s.st.MFA().ListAuthenticators(ctx, tid, uid)
		if x != nil {
			return nil, x
		}
		if !hasOtherPlatformFactor(u, list, g.Factors, s.webAuthnBinding.RPID) {
			return nil, ErrNoFactor
		}
	}
	return g, nil
}
func (s *Service) webEvent(ctx context.Context, tid, uid, typ, factor string, err error) {
	recorder := s.Recorder
	if recorder == nil {
		recorder = logs.RecorderFromContext(ctx)
	}
	details := map[string]any{"authenticator": map[string]any{"type": factor}}
	if err != nil {
		reason := webauthn.Reason(err)
		if reason == "" {
			reason = "UnknownError"
		}
		details["failure_details"] = map[string]any{"errorCode": reason}
		if typ == "gd_webauthn_challenge_failed" {
			details["first_factor"] = false
		}
	}
	logs.RecordEvent(ctx, recorder, logs.Event{TenantID: tid, UserID: uid, Type: typ, Date: s.now(), Details: details})
}
func (s *Service) maskWebAuthnCredential(ctx context.Context, c *webauthn.Credential) context.Context {
	for _, v := range [][]byte{c.ID, c.RawID, c.ClientDataJSON, c.AttestationObject, c.AuthenticatorData, c.Signature, c.UserHandle} {
		ctx = s.operationContext(ctx, string(v), base64.RawURLEncoding.EncodeToString(v), base64.StdEncoding.EncodeToString(v))
	}
	return ctx
}
func (s *Service) BeginWebAuthnEnroll(ctx context.Context, tid, uid, factor string, rp rpid.Result, display passkey.UserDisplay) (*Enrollment, webauthn.CreationOptions, error) {
	ctx = s.operationContext(ctx)
	var zero webauthn.CreationOptions
	g, err := s.webEnabled(ctx, tid, uid, factor)
	if err != nil {
		return nil, zero, err
	}
	if factor == "webauthn-platform" {
		list, x := s.st.MFA().ListAuthenticators(ctx, tid, uid)
		if x != nil {
			return nil, zero, x
		}
		u, x := s.st.Users().Get(ctx, tid, uid)
		if x != nil {
			return nil, zero, x
		}
		if !s.platformEnrollmentProof || !hasOtherPlatformFactor(u, list, g.Factors, rp.RPID) {
			return nil, zero, ErrNoFactor
		}
	}
	b, err := s.webBinding(uid, passkey.WebAuthnRegister, rp)
	if err != nil {
		return nil, zero, err
	}
	params, err := webParams(factor, g)
	if err != nil {
		return nil, zero, err
	}
	issued, err := s.passkeys().Issue(ctx, tid, b, webauthnrules.Limits.HostedChallengeTTL)
	if err != nil {
		return nil, zero, err
	}
	u, err := s.st.Users().Get(ctx, tid, uid)
	if err != nil {
		return nil, zero, err
	}
	name := display.Name
	if name == "" {
		name = u.Email
	}
	if name == "" {
		name = u.PhoneNumber
	}
	if name == "" {
		name = u.Username
	}
	if name == "" {
		name = uid
	}
	dn := display.DisplayName
	if dn == "" {
		dn = u.Name
	}
	if dn == "" {
		dn = name
	}
	o := webauthn.CreationOptions{Challenge: issued.Challenge, UserID: issued.UserHandle, RPID: rp.RPID, RPName: rp.RPID, UserName: name, DisplayName: dn, Attachment: params.Attachment, ResidentKey: params.ResidentKey, UserVerification: params.UserVerification, Timeout: webauthnrules.Limits.HostedChallengeTTL}
	aa, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, zero, err
	}
	for _, a := range aa {
		if a.RPID == rp.RPID && a.Type == factor {
			o.Exclude = append(o.Exclude, webauthn.Descriptor{ID: a.CredentialID})
		}
	}
	e := &Enrollment{Factor: factor, ChallengeID: issued.ID, AuthenticatorID: NewMethodID(factor)}
	m := webAuthnMetadata{Binding: b, Factor: factor, Params: params, Creation: o, PlatformProof: s.platformEnrollmentProof, FirstOnly: s.webAuthnFirstOnly, NewOnly: s.newFactorOnly, Authenticator: &store.Authenticator{ID: e.AuthenticatorID}}
	if err = s.saveWebMetadata(ctx, tid, issued.ID, "options", m, issued.ExpiresAt); err != nil {
		return nil, zero, err
	}
	s.emit(ctx, tid, uid, "gd_start_enroll")
	return e, o, nil
}

// WebAuthnOptions restores only trusted server-issued configuration on refresh.
func (s *Service) WebAuthnOptions(ctx context.Context, tid, uid, id string) (webauthn.CreationOptions, webauthn.RequestOptions, error) {
	m, _, err := s.webMetadata(ctx, tid, uid, id, "options")
	return m.Creation, m.Request, err
}

// StageWebAuthnEnroll consumes registration before parsing it and saves only
// the verified credential, until the nickname form atomically confirms it.
func (s *Service) StageWebAuthnEnroll(ctx context.Context, tid, uid string, e *Enrollment, raw []byte, userAgent string) (err error) {
	ctx = s.operationContext(ctx, string(raw))
	factor := "webauthn-roaming"
	defer func() {
		if err != nil {
			s.webEvent(ctx, tid, uid, "gd_webauthn_enrollment_failed", factor, err)
			s.emit(ctx, tid, uid, "gd_start_enroll_failed")
		}
	}()
	if e == nil {
		return ErrInvalidCode
	}
	m, row, metadataErr := s.webMetadata(ctx, tid, uid, e.ChallengeID, "options")
	expected := s.webAuthnBinding
	expected.UserID = uid
	expected.Purpose = passkey.WebAuthnRegister
	taken, err := s.passkeys().Take(ctx, tid, e.ChallengeID, expected)
	if metadataErr != nil {
		return metadataErr
	}
	if err != nil {
		return err
	}
	factor = m.Factor
	if m.Binding.Purpose != passkey.WebAuthnRegister {
		return ErrInvalidCode
	}
	if _, err = s.webEnabled(ctx, tid, uid, m.Factor); err != nil {
		return err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, m.Factor)
	if err != nil {
		return err
	}
	outcome := "failure"
	defer func() {
		if x := s.finishProof(ctx, tid, uid, m.Factor, receipt, outcome); x != nil {
			err = x
		}
	}()
	if s.webAuthnBrowserError != "" {
		return &webauthn.Error{Code: s.webAuthnBrowserError}
	}
	c, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return err
	}
	ctx = s.maskWebAuthnCredential(ctx, c)
	registration, err := webauthn.VerifyRegistration(c, webauthn.Expect{Challenge: taken.Challenge, RPID: m.Binding.RPID, Origins: m.Binding.Origins, RequireUV: m.Params.EnforceUV})
	if err != nil {
		return err
	}
	// Re-read the live setting too: tightening UV during a ceremony cannot be bypassed.
	g, err := s.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	p, _ := webParams(m.Factor, g)
	if p.EnforceUV && !registration.UV {
		return ErrInvalidCode
	}
	pub, _ := json.Marshal(map[string]any{"backup_eligible": registration.BE, "backed_up": registration.BS, "user_agent": userAgent, "transports": registration.Transports, "user_handle": base64.RawURLEncoding.EncodeToString(taken.UserHandle), "attachment": registration.Attachment})
	m.Authenticator = &store.Authenticator{TenantID: tid, UserID: uid, ID: m.Authenticator.ID, Type: m.Factor, RPID: m.Binding.RPID, CredentialID: registration.CredentialID, PublicKey: registration.PublicKeyCOSE, PublicData: pub, SignCount: registration.SignCount, Confirmed: true, CreatedAt: s.now()}
	// Options and offered handles no longer belong in the pending proof.
	m.Creation = webauthn.CreationOptions{}
	m.VerifiedUV = registration.UV
	err = s.saveWebMetadata(ctx, tid, e.ChallengeID, "verified", m, row.ExpiresAt)
	if err != nil {
		outcome = "refund"
		return err
	}
	outcome = "success"
	return nil
}
func (s *Service) ConfirmWebAuthnEnroll(ctx context.Context, tid, uid string, e *Enrollment, raw []byte, name, userAgent string) (result *Confirmed, err error) {
	ctx = s.operationContext(ctx, string(raw))
	if e == nil || !utf8.ValidString(name) || utf8.RuneCountInString(name) < webauthnrules.Limits.NicknameMin || utf8.RuneCountInString(name) > webauthnrules.Limits.NicknameMax || strings.ContainsAny(name, "\x00\r\n") {
		return nil, ErrInvalidCode
	}
	if len(raw) > 0 {
		if err = s.StageWebAuthnEnroll(ctx, tid, uid, e, raw, userAgent); err != nil {
			return nil, err
		}
	}
	m, _, err := s.webMetadata(ctx, tid, uid, e.ChallengeID, "verified")
	if err != nil {
		return nil, err
	}
	result = &Confirmed{AuthenticatorID: m.Authenticator.ID}
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		u, x := tx.Users().GetForUpdate(ctx, tid, uid)
		if x != nil {
			return x
		}
		if u.Blocked {
			return ErrInvalidCode
		}
		bound := s.WithStore(tx)
		if _, x = bound.webEnabled(ctx, tid, uid, m.Factor); x != nil {
			return x
		}
		list, x := tx.MFA().ListAuthenticators(ctx, tid, uid)
		if x != nil {
			return x
		}
		g, x := tx.MFA().GetGuardian(ctx, tid)
		if x != nil {
			return x
		}
		currentParams, _ := webParams(m.Factor, g)
		if currentParams.EnforceUV && !m.VerifiedUV {
			return &webauthn.Error{Code: "user_verified"}
		}
		if m.Factor == "webauthn-platform" {
			if !m.PlatformProof || !hasOtherPlatformFactor(u, list, g.Factors, m.Binding.RPID) {
				return ErrNoFactor
			}
			device := authenticatorDevice(*m.Authenticator)
			for _, a := range list {
				if a.Type == m.Factor && a.Confirmed && a.RPID == m.Binding.RPID && authenticatorDevice(a).Class == device.Class {
					return ErrAlreadyEnrolled
				}
			}
		}
		hasRecovery := false
		for _, a := range list {
			hasRecovery = hasRecovery || a.Type == "recovery-code"
			if m.FirstOnly && UsableMethod(u, a, g.Factors) && (!isWebAuthnFactor(a.Type) || a.RPID == m.Binding.RPID) {
				return ErrAlreadyEnrolled
			}
			if m.NewOnly && a.Confirmed && a.Type == m.Factor && a.RPID == m.Binding.RPID {
				return ErrAlreadyEnrolled
			}
		}
		// Spend the staged proof in the insertion/recovery/ticket transaction.
		if x = tx.MFA().ConsumeChallenge(ctx, tid, metadataID(e.ChallengeID, "verified"), s.now()); x != nil {
			return x
		}
		a := *m.Authenticator
		a.Name = name
		if x = tx.MFA().CreateAuthenticator(ctx, &a); x != nil {
			return x
		}
		if !hasRecovery {
			code := NewRecoveryCode()
			ctx = s.operationContext(ctx, code)
			if x = tx.MFA().ReplaceRecoveryCode(ctx, tid, uid, "", secrets.HashToken(code), s.now()); x != nil {
				return x
			}
			result.RecoveryCode = code
		}
		if s.proofCommit != nil {
			return s.proofCommit(tx)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.webEvent(ctx, tid, uid, "gd_enrollment_complete", m.Factor, nil)
	return result, nil
}
func (s *Service) BeginWebAuthnChallenge(ctx context.Context, tid, uid, factor string, rp rpid.Result, device webauthn.Device) (*Challenge, webauthn.RequestOptions, error) {
	ctx = s.operationContext(ctx)
	var zero webauthn.RequestOptions
	g, err := s.webEnabled(ctx, tid, uid, factor)
	if err != nil {
		return nil, zero, err
	}
	b, err := s.webBinding(uid, passkey.WebAuthnAssert, rp)
	if err != nil {
		return nil, zero, err
	}
	p, err := webParams(factor, g)
	if err != nil {
		return nil, zero, err
	}
	aa, err := s.st.MFA().ListAuthenticators(ctx, tid, uid)
	if err != nil {
		return nil, zero, err
	}
	o := webauthn.RequestOptions{RPID: rp.RPID, UserVerification: p.UserVerification, Timeout: webauthnrules.Limits.HostedChallengeTTL}
	for _, a := range aa {
		if a.Type == factor && a.Confirmed && a.RPID == rp.RPID && (factor != "webauthn-platform" || authenticatorDevice(a).Key() == device.Key()) {
			o.Allow = append(o.Allow, webauthn.Descriptor{ID: a.CredentialID})
		}
	}
	if len(o.Allow) == 0 {
		return nil, zero, ErrNoFactor
	}
	issued, err := s.passkeys().Issue(ctx, tid, b, webauthnrules.Limits.HostedChallengeTTL)
	if err != nil {
		return nil, zero, err
	}
	o.Challenge = issued.Challenge
	m := webAuthnMetadata{Binding: b, Factor: factor, Params: p, Request: o}
	if err = s.saveWebMetadata(ctx, tid, issued.ID, "options", m, issued.ExpiresAt); err != nil {
		return nil, zero, err
	}
	s.emit(ctx, tid, uid, "gd_start_auth")
	return &Challenge{ID: issued.ID, Factor: factor}, o, nil
}
func (s *Service) VerifyWebAuthn(ctx context.Context, tid, uid string, c *Challenge, raw []byte) (err error) {
	ctx = s.operationContext(ctx, string(raw))
	factor := "webauthn-roaming"
	defer func() {
		if err != nil {
			s.webEvent(ctx, tid, uid, "gd_webauthn_challenge_failed", factor, err)
			s.emit(ctx, tid, uid, "gd_auth_failed")
		} else {
			s.emit(ctx, tid, uid, "gd_auth_succeed")
		}
	}()
	if c == nil {
		return ErrInvalidCode
	}
	m, _, metadataErr := s.webMetadata(ctx, tid, uid, c.ID, "options")
	expected := s.webAuthnBinding
	expected.UserID = uid
	expected.Purpose = passkey.WebAuthnAssert
	taken, err := s.passkeys().Take(ctx, tid, c.ID, expected)
	if metadataErr != nil {
		return metadataErr
	}
	if err != nil {
		return err
	}
	factor = m.Factor
	if m.Binding.Purpose != passkey.WebAuthnAssert {
		return ErrInvalidCode
	}
	g, err := s.webEnabled(ctx, tid, uid, m.Factor)
	if err != nil {
		return err
	}
	receipt, err := s.reserveProof(ctx, tid, uid, m.Factor)
	if err != nil {
		return err
	}
	outcome := "failure"
	defer func() {
		if x := s.finishProof(ctx, tid, uid, m.Factor, receipt, outcome); x != nil {
			err = x
		}
	}()
	if s.webAuthnBrowserError != "" {
		return &webauthn.Error{Code: s.webAuthnBrowserError}
	}
	credential, err := webauthn.ParseCredentialJSON(raw)
	if err != nil {
		return err
	}
	ctx = s.maskWebAuthnCredential(ctx, credential)
	a, err := s.st.WebAuthn().GetAuthenticatorByCredentialID(ctx, tid, credential.RawID)
	if err != nil {
		return ErrInvalidCode
	}
	if a.UserID != uid || a.Type != m.Factor || !a.Confirmed || a.RPID != m.Binding.RPID || !slices.ContainsFunc(m.Request.Allow, func(d webauthn.Descriptor) bool { return slices.Equal(d.ID, a.CredentialID) }) {
		return ErrInvalidCode
	}
	var pub struct {
		BE     bool   `json:"backup_eligible"`
		Handle string `json:"user_handle"`
	}
	if len(a.PublicData) > 0 && json.Unmarshal(a.PublicData, &pub) != nil {
		return ErrInvalidCode
	}
	handle, x := base64.RawURLEncoding.DecodeString(pub.Handle)
	if x != nil || pub.Handle != "" && len(handle) != webauthnrules.Limits.UserHandleBytes {
		return ErrInvalidCode
	}
	params, _ := webParams(m.Factor, g)
	proof, err := webauthn.VerifyAssertion(credential, webauthn.Expect{Challenge: taken.Challenge, RPID: m.Binding.RPID, Origins: m.Binding.Origins, RequireUV: m.Params.EnforceUV || params.EnforceUV}, webauthn.Stored{PublicKeyCOSE: a.PublicKey, SignCount: a.SignCount, BE: pub.BE, UserHandle: handle})
	if err != nil {
		return err
	}
	outcome = "refund"
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		u, x := tx.Users().GetForUpdate(ctx, tid, uid)
		if x != nil {
			return x
		}
		if u.Blocked {
			return ErrInvalidCode
		}
		currentGuardian, x := s.WithStore(tx).webEnabled(ctx, tid, uid, m.Factor)
		if x != nil {
			return x
		}
		currentParams, _ := webParams(m.Factor, currentGuardian)
		if currentParams.EnforceUV && !proof.UV {
			return ErrInvalidCode
		}
		if x = tx.WebAuthn().AcceptAssertion(ctx, tid, uid, a.ID, proof.SignCount, proof.BS, s.now()); x != nil {
			return x
		}
		if s.proofCommit != nil {
			return s.proofCommit(tx)
		}
		return nil
	})
	if errors.Is(err, store.ErrPrecondition) {
		outcome = "failure"
		return ErrInvalidCode
	}
	if err == nil {
		outcome = "success"
	}
	return err
}

func isWebAuthnFactor(f string) bool { return f == "webauthn-roaming" || f == "webauthn-platform" }
func authenticatorDevice(a store.Authenticator) webauthn.Device {
	var p struct {
		UserAgent string `json:"user_agent"`
	}
	_ = json.Unmarshal(a.PublicData, &p)
	return webauthn.DeviceOf(p.UserAgent)
}
func hasOtherPlatformFactor(u *store.User, list []store.Authenticator, enabled map[string]bool, rp string) bool {
	for _, a := range list {
		if a.Type != "webauthn-platform" && UsableMethod(u, a, enabled) && (!isWebAuthnFactor(a.Type) || a.RPID == rp) {
			return true
		}
	}
	return false
}

// WithPlatformEnrollmentProof records trusted successful other-factor proof for
// this bound login. Hosted callers obtain it only from their sealed proven page.
func (s *Service) WithPlatformEnrollmentProof() *Service {
	c := *s
	c.platformEnrollmentProof = true
	return &c
}
