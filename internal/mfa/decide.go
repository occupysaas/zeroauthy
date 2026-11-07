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
	requested := []string{"otp", "email", "phone", "webauthn-roaming", "recovery-code"}
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
					if f != "otp" && f != "email" && f != "phone" && f != "recovery-code" && f != "webauthn-roaming" {
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
				requested = []string{"otp", "phone", "webauthn-roaming", "recovery-code"}
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
	confirmed := map[string]bool{}
	primary := false
	preferred := ""
	for _, a := range in.Authenticators {
		f := factorName(a.Type)
		if UsableMethod(in.User, a, enabled) && (a.Type != "webauthn-roaming" || a.RPID == in.WebAuthn.RPID) {
			primary = true
			if a.Type != "webauthn-roaming" || in.WebAuthn.Available {
				confirmed[f] = true
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
		if !enabled[guardianFactor(f)] || f == "webauthn-roaming" && !in.WebAuthn.Available {
			continue
		}
		if f == "otp" || f == "email" || f == "phone" && in.PhoneEnroll || f == "webauthn-roaming" && in.WebAuthn.Available {
			if e == nil || e.Mode != "enroll" || !confirmed[f] {
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
	// An enrolled key that this browser cannot use still requires an existing
	// proof. It cannot turn a required challenge into fresh factor enrollment.
	if primary && len(usable) == 0 && !r.Enroll {
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
	case "webauthn-roaming":
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
