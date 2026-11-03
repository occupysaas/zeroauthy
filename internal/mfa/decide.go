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
}
type DecideInput struct {
	Settings                   *store.GuardianSettings
	Effects                    *actionresult.MFAEffects
	Authenticators             []store.Authenticator
	SessionMFAAt               time.Time
	RememberValid, KnownDevice bool
	CustomizeInActions         bool
	// MFAAPI marks a request for an MFA API (https://{host}/mfa/) token.
	// A user with a usable primary factor must complete MFA for it.
	MFAAPI bool
}

// Decide is shared by hosted authorization and password grants. Only OTP and
// email are enforced in Plan 33; recovery is a fallback for an enrolled user.
func Decide(in DecideInput) (Requirement, error) {
	r := Requirement{AllowRemember: true}
	e := in.Effects
	enabled := map[string]bool{}
	if in.Settings != nil {
		enabled = in.Settings.Factors
	}
	// The MFA API can remove and replace factors, so its token requires MFA
	// whenever the user has a usable primary factor, regardless of policy or
	// an Action skip. Unenrolled users may still obtain an enrollment token.
	apiMFA := in.MFAAPI && hasPrimary(in.Authenticators, enabled)
	if e != nil && e.Provider == "none" && !apiMFA {
		return Requirement{}, nil
	}
	requested := []string{"otp", "email", "recovery-code"}
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
					if f != "otp" && f != "email" && f != "recovery-code" {
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
				requested = []string{"otp", "recovery-code"}
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
		if a.Confirmed && enabled[f] && (f == "otp" || f == "email") {
			primary = true
			confirmed[f] = true
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
		if !enabled[f] {
			continue
		}
		if f == "otp" || f == "email" {
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

// hasPrimary reports whether a confirmed, enabled OTP or email method exists.
func hasPrimary(list []store.Authenticator, enabled map[string]bool) bool {
	for _, a := range list {
		f := factorName(a.Type)
		if a.Confirmed && enabled[f] && (f == "otp" || f == "email") {
			return true
		}
	}
	return false
}
