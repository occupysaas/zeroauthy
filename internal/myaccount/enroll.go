package myaccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// createBody is CreateAuthenticationMethod.
type createBody struct {
	Type                          string `json:"type"`
	Email                         string `json:"email"`
	PhoneNumber                   string `json:"phone_number"`
	PreferredAuthenticationMethod string `json:"preferred_authentication_method"`
	Connection                    string `json:"connection"`
	IdentityUserID                string `json:"identity_user_id"`
}

// verifyBody is VerifyAuthenticationMethod.
type verifyBody struct {
	AuthSession   string          `json:"auth_session"`
	OTPCode       string          `json:"otp_code"`
	NewPassword   string          `json:"new_password"`
	AuthnResponse json.RawMessage `json:"authn_response"`
}

var errFactorDisabled = badRequest("factor_not_enabled", "The factor is not enabled for this tenant.")

func errSession() *Problem {
	return badRequest("invalid_auth_session", "The auth_session is invalid, expired or already used.")
}

// decode reads a JSON object body into dst, refusing other media types
// (415), unknown members and trailing data (400).
func decode(r *http.Request, dst any) *Problem {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return problem(http.StatusUnsupportedMediaType, "unsupported_media_type", "Unsupported Media Type", "The body must be application/json.")
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return badRequest("invalid_body", "The body is too large or unreadable.")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return badRequest("invalid_body", "The body is not a valid request: "+jsonProblem(err))
	}
	if dec.More() {
		return badRequest("invalid_body", "The body has trailing data.")
	}
	return nil
}

// jsonProblem describes a decode error without echoing values.
func jsonProblem(err error) string {
	var unknown *json.UnmarshalTypeError
	switch {
	case errors.As(err, &unknown):
		return "member " + unknown.Field + " has the wrong type"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown member " + strings.TrimPrefix(err.Error(), "json: unknown field ")
	}
	return "malformed JSON"
}

// location is the URL of method id on the caller's host.
func location(c *Caller, id string) string {
	return "https://" + c.Host + Path + "/authentication-methods/" + url.PathEscape(id)
}

// mfaProblem maps an MFA service error.
func (h *Handlers) mfaProblem(w http.ResponseWriter, r *http.Request, what string, err error) {
	var p *Problem
	switch {
	case errors.As(err, &p):
	case errors.Is(err, mfa.ErrNoFactor):
		p = errFactorDisabled
	case errors.Is(err, mfa.ErrInvalidPhone), errors.Is(err, mfa.ErrCountryNotAllowed):
		p = badRequest("invalid_phone_number", "The phone number is invalid or not allowed.", ValidationError{Detail: "invalid phone number", Field: "phone_number", Source: "body"})
	case errors.Is(err, mfa.ErrThrottled):
		p = problem(http.StatusTooManyRequests, "too_many_requests", "Too Many Requests", "Too many attempts; try again later.")
	case errors.Is(err, mfa.ErrInvalidCode), errors.Is(err, mfa.ErrExpired):
		p = badRequest("invalid_otp_code", "The code is invalid or expired.", ValidationError{Detail: "invalid code", Field: "otp_code", Source: "body"})
	case errors.Is(err, mfa.ErrEmailDelivery), errors.Is(err, mfa.ErrPhoneDelivery):
		p = problem(http.StatusServiceUnavailable, "delivery_failed", "Service Unavailable", "The code could not be delivered.")
	case errors.Is(err, store.ErrNotFound):
		p = notFound("The authentication method does not exist.")
	default:
		h.log().ErrorContext(r.Context(), "my account: "+what, "err", err)
		p = serverError()
	}
	writeProblem(w, r, p)
}

// eventContext attributes the MFA service's log events to the caller.
func eventContext(r *http.Request, c *Caller) *http.Request {
	return r.WithContext(logs.WithEvent(r.Context(), logs.Event{TenantID: c.TenantID, ClientID: c.ClientID, UserID: c.UserID}))
}

func (h *Handlers) createMethod(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b createBody
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	r = eventContext(r, c)
	if h.MFA == nil {
		writeProblem(w, r, errFactorDisabled)
		return
	}
	switch b.Type {
	case "totp", "email", "phone":
		h.startOTP(w, r, c, b)
	case "recovery-code":
		h.startRecovery(w, r, c)
	case "passkey":
		h.startPasskey(w, r, c, b)
	case "webauthn-roaming", "webauthn-platform":
		h.startWebAuthn(w, r, c, b.Type)
	case "password":
		h.startPassword(w, r, c, b)
	case "push-notification":
		writeProblem(w, r, errFactorDisabled) // LR42a-2
	case "":
		writeProblem(w, r, badRequest("invalid_body", "type is required.", ValidationError{Detail: "required", Field: "type", Source: "body"}))
	default:
		writeProblem(w, r, badRequest("invalid_body", "type is not a supported authentication method type.", ValidationError{Detail: "unsupported", Field: "type", Source: "body"}))
	}
}

func (h *Handlers) verifyMethod(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b verifyBody
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	r = eventContext(r, c)
	id := chi.URLParam(r, "id")
	typ, _, _ := strings.Cut(id, "|")
	s, err := h.takeAuthSession(r.Context(), c, b.AuthSession, typ, id)
	if errors.Is(err, errAuthSession) {
		writeProblem(w, r, errSession())
		return
	}
	if err != nil {
		h.fail(w, r, "verify an enrollment", err)
		return
	}
	switch typ {
	case "totp", "email", "phone":
		h.verifyOTP(w, r, c, s, b)
	case "recovery-code":
		h.verifyRecovery(w, r, c, s)
	case "passkey":
		h.verifyPasskey(w, r, c, s, b)
	case "webauthn-roaming", "webauthn-platform":
		h.verifyWebAuthn(w, r, c, s, b)
	case "password":
		h.verifyPassword(w, r, c, s, b)
	default:
		writeProblem(w, r, errSession())
	}
}

// created answers a finished enrollment with the method.
func (h *Handlers) created(w http.ResponseWriter, r *http.Request, c *Caller, id string) {
	u, err := h.Store.Users().Get(r.Context(), c.TenantID, c.UserID)
	if err != nil {
		h.fail(w, r, "reload the user", err)
		return
	}
	m, err := findMethod(r, h, u, id)
	if err != nil {
		h.fail(w, r, "load the enrolled method", err)
		return
	}
	w.Header().Set("Location", location(c, m.ID))
	writeJSON(w, r, http.StatusCreated, methodView(*m))
}
