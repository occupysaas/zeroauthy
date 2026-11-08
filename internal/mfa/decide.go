package mfa

import (
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Requirement struct {
	Required, Enroll, AlwaysPrompt, AllowRemember bool
	Factors                                       []string
	Reason                                        string
	SelectFactor                                  bool
	PhonePreferredMethod                          string
	DetectWebAuthn                                bool
	// PlatformAfterProof requires another factor before explicit biometrics enrollment.
	PlatformAfterProof bool
}
type DecideInput struct {
	Settings                   *store.GuardianSettings
	Effects                    *actionresult.MFAEffects
	Authenticators             []store.Authenticator
	SessionMFAAt               time.Time
	RememberValid, KnownDevice bool
	CustomizeInActions         bool
	// User is the authenticating user. Email methods are usable only while
	// they match the user's current verified email; nil makes them unusable.
	User *store.User
	// MFAAPI marks a request for an MFA API (https://{host}/mfa/) token.
	// A user with a usable primary factor must complete MFA for it.
	MFAAPI      bool
	PhoneEnroll bool
	WebAuthn    WebAuthnCapabilities
}

// Decide is shared by hosted authorization and password grants. Only OTP and
// email are enforced in Plan 33; recovery is a fallback for an enrolled user.
func Decide(in DecideInput) (Requirement, error) {
	r := Requirement{AllowRemember: true}
	if in.Effects != nil {
		r.PhonePreferredMethod = in.Effects.PhonePreferredMethod
	}
	e := in.Effects
	enabled := map[string]bool{}
	if in.Settings != nil {
		enabled = in.Settings.Factors
	}
	// The MFA API can remove and replace factors, so its token requires MFA
	// whenever the user has a usable primary factor, regardless of policy or
	// an Action skip. Unenrolled users may still obtain an enrollment token.
	apiMFA := in.MFAAPI && hasPrimary(in.User, in.Authenticators, enabled)
	if e != nil && e.Provider == "none" && !apiMFA {
		return Requirement{}, nil
	}
	requested := []string{"otp", "email", "phone", "webauthn-roaming", "webauthn-platform", "recovery-code"}
	action := e != nil && e.Provider != "none" && (e.Provider != "" || e.Mode != "")
	if action {
		r.Required, r.Reason, r.AllowRemember = true, "action", e.AllowRememberBrowser
		if e.Mode != "" {
			if !in.CustomizeInActions {
				return r, errors.New("mfa: customize_mfa_in_postlogin_action must be enabled")
			}
			if e.Provider != "" || (e.Mode != "challenge" && e.Mode != "enroll") {
				return r, ErrNoFactor
			}
			r.AlwaysPrompt, r.AllowRemember, r.Enroll = true, false, e.Mode == "enroll"
			r.SelectFactor = e.Any
			requested = nil
			for _, group := range e.Factors {
				for _, f := range group {
					if f != "otp" && f != "email" && f != "phone" && f != "recovery-code" && f != "webauthn-roaming" && f != "webauthn-platform" {
						return r, ErrNoFactor
					}
					if !slices.Contains(requested, f) {
						requested = append(requested, f)
					}
				}
			}
		} else {
			switch e.Provider {
			case "any":
			case "google-authenticator":
				requested = []string{"otp"}
			case "guardian":
				requested = []string{"otp", "phone", "webauthn-roaming", "webauthn-platform", "recovery-code"}
			default:
				return r, ErrNoFactor
			}
		}
	} else if in.Settings != nil {
		switch {
		case slices.Contains(in.Settings.Policies, "all-applications"):
			r.Required, r.Reason = true, "policy"
		case slices.Contains(in.Settings.Policies, "confidence-score") && !in.KnownDevice:
			r.Required, r.Reason = true, "confidence"
		}
	}
	if apiMFA {
		if !r.Required {
			r.Required, r.Reason = true, "mfa-api"
		}
		// A remembered browser does not satisfy factor management.
		r.AllowRemember = false
	}
	if !r.Required {
		return r, nil
	}
	// A sole explicit biometrics target requires another factor's proof first.
	// Mixed enrollment alternatives keep their requested choices until selection.
	if r.Enroll && len(requested) == 1 && requested[0] == "webauthn-platform" {
		if !enabled["webauthn-platform"] || !in.WebAuthn.Available || !in.WebAuthn.Platform {
			return r, ErrNoFactor
		}
		r.PlatformAfterProof = true
		r.Enroll = false
		requested = []string{"otp", "email", "phone", "webauthn-roaming"}
	}
	confirmed := map[string]bool{}
	primary := false
	preferred := ""
	platformEnrolled := false
	// Without an RP scope (password and other native grants) every WebAuthn
	// key counts as enrolled: a key bound to another RP is foreign only to a
	// request that has an RP ID of its own (LR33b-5).
	scoped := in.WebAuthn.RPID != ""
	// held: an enrolled WebAuthn key this request cannot verify.
	held := false
	for _, a := range in.Authenticators {
		f := factorName(a.Type)
		if a.Type == "webauthn-platform" && a.Confirmed && a.RPID == in.WebAuthn.RPID && authenticatorDevice(a).Class == in.WebAuthn.Device.Class {
			platformEnrolled = true
		}
		if UsableMethod(in.User, a, enabled) && (!isWebAuthnFactor(a.Type) || !scoped || a.RPID == in.WebAuthn.RPID) {
			primary = true
			if !isWebAuthnFactor(a.Type) || scoped && in.WebAuthn.Available && (a.Type != "webauthn-platform" || in.WebAuthn.Platform && hasOtherPlatformFactor(in.User, in.Authenticators, enabled, in.WebAuthn.RPID) && authenticatorDevice(a).Key() == in.WebAuthn.Device.Key()) {
				confirmed[f] = true
			} else {
				held = true
			}
			if a.Preferred {
				preferred = f
			}
		}
	}
	if primary && enabled["recovery-code"] {
		for _, a := range in.Authenticators {
			if a.Confirmed && a.Type == "recovery-code" {
				confirmed["recovery-code"] = true
			}
		}
	}
	// Confidence only challenges an already enrolled user; it never enrolls.
	if r.Reason == "confidence" && !primary {
		return Requirement{}, nil
	}
	var usable, enroll []string
	for _, f := range requested {
		if !enabled[guardianFactor(f)] || isWebAuthnFactor(f) && !in.WebAuthn.Available || f == "webauthn-platform" && !in.WebAuthn.Platform {
			continue
		}
		if f == "otp" || f == "email" || f == "phone" && in.PhoneEnroll || f == "webauthn-roaming" && in.WebAuthn.Available || f == "webauthn-platform" && r.Enroll && !platformEnrolled {
			if e == nil || e.Mode != "enroll" || r.PlatformAfterProof || !confirmed[f] {
				enroll = append(enroll, f)
			}
		}
		if confirmed[f] {
			usable = append(usable, f)
		}
	}
	if e != nil && e.Mode == "challenge" && len(usable) == 0 {
		return r, ErrNoFactor
	}
	// An enrolled key that this request cannot use still requires an existing
	// proof. It cannot turn a required challenge into fresh factor enrollment.
	// Other factors keep their behavior: an Action requesting a factor the
	// user lacks still enrolls it.
	if held && len(usable) == 0 && !r.Enroll {
		return r, ErrNoFactor
	}
	if r.Enroll || len(usable) == 0 {
		r.Enroll = true
		r.Factors = enroll
	} else {
		r.Factors = usable
	}
	if len(r.Factors) == 0 {
		return r, ErrNoFactor
	}
	if !action && preferred != "" {
		if i := slices.Index(r.Factors, preferred); i > 0 {
			r.Factors = append([]string{preferred}, append(slices.Clone(r.Factors[:i]), r.Factors[i+1:]...)...)
		}
	}
	if !r.AlwaysPrompt && (!in.SessionMFAAt.IsZero() || r.AllowRemember && in.RememberValid) {
		r.Required = false
		r.Enroll = false
	}
	return r, nil
}

// UsableMethod is the single predicate for a confirmed primary factor that
// can satisfy a challenge: an enabled OTP method, or an enabled email method
// whose address still matches the user's verified email. Decide, Recover and
// first-enrollment restrictions all use it, so an unusable method can neither
// count as enrolled nor block enrollment of a replacement.
func UsableMethod(u *store.User, a store.Authenticator, enabled map[string]bool) bool {
	if !a.Confirmed || !enabled[guardianFactor(a.Type)] {
		return false
	}
	switch a.Type {
	case "totp":
		return true
	case "webauthn-roaming", "webauthn-platform":
		return a.RPID != "" && len(a.CredentialID) > 0 && len(a.PublicKey) > 0
	case "phone":
		return a.Phone != ""
	case "email":
		return u != nil && u.EmailVerified && a.Email != "" && u.Email == a.Email
	}
	return false
}

// hasPrimary reports whether a usable primary method exists.
func hasPrimary(u *store.User, list []store.Authenticator, enabled map[string]bool) bool {
	for _, a := range list {
		if UsableMethod(u, a, enabled) {
			return true
		}
	}
	return false
}
