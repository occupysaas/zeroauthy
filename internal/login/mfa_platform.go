package login

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

func isWebAuthnMFA(f string) bool { return f == "webauthn-roaming" || f == "webauthn-platform" }
func platformStoredDevice(a store.Authenticator) webauthn.Device {
	var pub struct {
		UA string `json:"user_agent"`
	}
	_ = json.Unmarshal(a.PublicData, &pub)
	return webauthn.DeviceOf(pub.UA)
}
func mfaPlatformDevicePresent(list []store.Authenticator, caps mfa.WebAuthnCapabilities) bool {
	for _, a := range list {
		if a.Type == "webauthn-platform" && a.Confirmed && a.RPID == caps.RPID && platformStoredDevice(a).Key() == caps.Device.Key() {
			return true
		}
	}
	return false
}
func platformDefaultName(d webauthn.Device) string {
	browser := map[string]string{"chrome": "Chrome", "edge": "Edge", "safari": "Safari", "firefox": "Firefox", "other": "Browser"}[d.Browser]
	os := map[string]string{"windows": "Windows", "macos": "macOS", "ios": "iOS", "android": "Android", "other": "device"}[d.OS]
	return browser + " on " + os
}

// offerPlatformMFA runs only after proof of a different MFA factor in
// this sealed hosted transaction, including a recovery proof. Eligibility still
// requires a separate confirmed primary method; a remembered browser is no proof.
func (h *Handlers) offerPlatformMFA(w http.ResponseWriter, r *http.Request, f *mfaFlow) bool {
	explicit := f.pending.Requirement.PlatformAfterProof
	// Completing a requested enrollment alternative satisfies the Action.
	if !explicit && f.pending.Requirement.Reason == "action" && f.pending.Effects.MFA != nil && f.pending.Effects.MFA.Mode == "enroll" {
		return false
	}
	if f.page.Factor == "webauthn-platform" || f.pending.Requirement.Reason == "ticket" && !explicit {
		return false
	}
	if !f.page.WebAuthn.Platform || !f.page.WebAuthn.Available {
		if explicit {
			h.fail(w, r, mfa.ErrNoFactor, f.flow)
			return true
		}
		return false
	}
	g, err := h.Store.MFA().GetGuardian(r.Context(), f.res.Tenant.ID)
	if err != nil {
		h.fail(w, r, err, f.flow)
		return true
	}
	if !g.Factors["webauthn-platform"] {
		if explicit {
			h.fail(w, r, mfa.ErrNoFactor, f.flow)
			return true
		}
		return false
	}
	list, err := h.Store.MFA().ListAuthenticators(r.Context(), f.res.Tenant.ID, f.pending.UserID)
	if err != nil {
		h.fail(w, r, err, f.flow)
		return true
	}
	u, err := h.Store.Users().Get(r.Context(), f.res.Tenant.ID, f.pending.UserID)
	if err != nil {
		h.fail(w, r, err, f.flow)
		return true
	}
	if u.Blocked {
		h.fail(w, r, errTxn, f.flow)
		return true
	}
	// This advisory preflight avoids offering an ineligible optional prompt.
	// The service repeats this eligibility check under its insertion lock.
	eligible := false
	for _, a := range list {
		if a.Type != "webauthn-platform" && mfa.UsableMethod(u, a, g.Factors) && (!isWebAuthnMFA(a.Type) || a.RPID == f.page.WebAuthn.RPID) {
			eligible = true
		}
	}
	if !eligible {
		if explicit {
			h.fail(w, r, mfa.ErrNoFactor, f.flow)
			return true
		}
		return false
	}
	for _, a := range list {
		if a.Type == "webauthn-platform" && a.Confirmed && a.RPID == f.page.WebAuthn.RPID && platformStoredDevice(a).Class == f.page.WebAuthn.Device.Class {
			if explicit {
				h.fail(w, r, mfa.ErrAlreadyEnrolled, f.flow)
				return true
			}
			return false
		}
	}
	if !explicit {
		for _, kind := range []string{"platform-remind", "platform-refuse"} {
			_, err = h.Store.WebAuthn().GetSnooze(r.Context(), f.res.Tenant.ID, f.pending.UserID, kind, f.page.WebAuthn.Device.Key(), h.now())
			if err == nil {
				return false
			}
			if !errors.Is(err, store.ErrNotFound) {
				h.fail(w, r, err, f.flow)
				return true
			}
		}
		if cookie, e := r.Cookie("za_platform_refuse"); e == nil {
			raw, e := base64.RawURLEncoding.DecodeString(cookie.Value)
			if e == nil {
				raw, e = keys.OpenBound(h.Authz.Wrapper, "platform-refuse/v1", []string{f.res.Tenant.ID, f.pending.UserID, f.page.WebAuthn.Device.Key()}, raw)
				var until time.Time
				if e == nil && json.Unmarshal(raw, &until) == nil && h.now().Before(until) {
					return false
				}
			}
		}
	}
	req := mfa.Requirement{Required: true, Enroll: true, Factors: []string{"webauthn-platform"}, Reason: f.pending.Requirement.Reason, AllowRemember: f.pending.Requirement.AllowRemember, PlatformAfterProof: explicit}
	f.page = mfaPageState{Factor: "webauthn-platform", WebAuthn: f.page.WebAuthn, WebAuthnDetected: true, PlatformProof: true, PlatformConsidered: true, OtherProvenFactor: f.page.Factor, OtherRemember: f.page.Remember, Remember: f.page.Remember, Switched: &req}
	f.pending.Requirement = req
	if err = h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return true
	}
	if !h.startWebAuthnMFA(w, r, f) {
		return true
	}
	if err = h.saveMFAPage(r, f, "mfa-page"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return true
	}
	http.Redirect(w, r, mfaURL(f, mfaPath(f)), http.StatusSeeOther)
	return true
}
func (h *Handlers) skipPlatformMFA(w http.ResponseWriter, r *http.Request, f *mfaFlow, choice string) {
	if !f.page.PlatformProof || f.pending.Requirement.PlatformAfterProof || choice != "skip" && choice != "remind" && choice != "refuse" {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if err := h.saveMFAPage(r, f, "mfa-busy"); err != nil {
		h.fail(w, r, errTxn, f.flow)
		return
	}
	if choice != "skip" {
		days := 14
		if choice == "refuse" {
			days = 365
		}
		until := h.now().Add(time.Duration(days) * 24 * time.Hour)
		if err := h.Store.WebAuthn().PutSnooze(r.Context(), &store.WebAuthnSnooze{TenantID: f.res.Tenant.ID, UserID: f.pending.UserID, Kind: "platform-" + choice, ScopeKey: f.page.WebAuthn.Device.Key(), Until: until}); err != nil {
			h.fail(w, r, err, f.flow)
			return
		}
		if choice == "refuse" {
			raw, _ := json.Marshal(until)
			sealed, err := keys.SealBound(h.Authz.Wrapper, "platform-refuse/v1", []string{f.res.Tenant.ID, f.pending.UserID, f.page.WebAuthn.Device.Key()}, raw)
			if err != nil {
				h.fail(w, r, err, f.flow)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "za_platform_refuse", Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/u", MaxAge: days * 24 * 60 * 60, Expires: until, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		}
	}
	f.page.Factor = f.page.OtherProvenFactor
	f.page.OtherProvenFactor = ""
	f.page.Proven = true
	f.page.Remember = f.page.OtherRemember
	h.finishMFA(w, r, f)
}
