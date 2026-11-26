package myaccount

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// factorTypeEnum is the OpenAPI FactorTypeEnum.
var factorTypeEnum = []string{"password", "passkey", "webauthn-platform", "webauthn-roaming", "totp", "phone", "email", "push-notification", "recovery-code"}

// maxListed is the OpenAPI's bound on one listing.
const maxListed = 20

func timeString(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// methodView is m in the OpenAPI AuthenticationMethod* shape of its type.
func methodView(m authmethods.Method) map[string]any {
	out := map[string]any{"id": m.ID, "type": m.Type, "created_at": timeString(m.CreatedAt), "usage": m.Usage}
	if m.Type == "password" {
		out["identity_user_id"] = m.Identity.UserID
		if m.LastPasswordReset != nil {
			out["last_password_reset"] = timeString(*m.LastPasswordReset)
		}
		return out
	}
	a := m.Authenticator
	if !a.LastAuthAt.IsZero() {
		out["last_auth_at"] = timeString(a.LastAuthAt)
	}
	if a.Type != "passkey" {
		out["confirmed"] = a.Confirmed
	}
	if a.Name != "" && a.Type != "recovery-code" {
		out["name"] = a.Name
	}
	switch a.Type {
	case "email":
		out["email"] = a.Email
	case "phone":
		out["phone_number"] = a.Phone
		out["preferred_authentication_method"] = phoneMethod(a)
	case "webauthn-roaming", "webauthn-platform", "passkey":
		out["key_id"] = base64.RawURLEncoding.EncodeToString(a.CredentialID)
		out["public_key"] = base64.RawURLEncoding.EncodeToString(a.PublicKey)
	}
	if a.Type == "passkey" {
		var p struct {
			IdentityUserID string   `json:"identity_user_id"`
			UserHandle     string   `json:"user_handle"`
			BE             bool     `json:"backup_eligible"`
			BS             bool     `json:"backed_up"`
			Transports     []string `json:"transports"`
			UserAgent      string   `json:"user_agent"`
			AAGUID         string   `json:"aaguid"`
		}
		_ = json.Unmarshal(a.PublicData, &p)
		out["identity_user_id"], out["user_handle"], out["credential_backed_up"] = p.IdentityUserID, p.UserHandle, p.BS
		out["credential_device_type"] = "single_device"
		if p.BE {
			out["credential_device_type"] = "multi_device"
		}
		out["relying_party_id"] = a.RPID
		if len(p.Transports) > 0 {
			out["transports"] = p.Transports
		}
		if p.UserAgent != "" {
			out["user_agent"] = p.UserAgent
		}
		if p.AAGUID != "" {
			out["aaguid"] = p.AAGUID
		}
	}
	return out
}

func phoneMethod(a *store.Authenticator) string {
	if a.PhoneMethod == "" {
		return "sms"
	}
	return a.PhoneMethod
}

func (h *Handlers) listMethods(w http.ResponseWriter, r *http.Request, c *Caller) {
	typ := r.URL.Query().Get("type")
	if typ != "" && !slices.Contains(factorTypeEnum, typ) {
		writeProblem(w, r, badRequest("invalid_query", "type is not an authentication method type.", ValidationError{Detail: "unknown type", Field: "type", Source: "query"}))
		return
	}
	all, err := authmethods.List(r.Context(), h.Store, c.User)
	if err != nil {
		h.fail(w, r, "list authentication methods", err)
		return
	}
	out := []any{}
	for _, m := range all {
		if (typ == "" || m.Type == typ) && len(out) < maxListed {
			out = append(out, methodView(m))
		}
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"authentication_methods": out})
}

func (h *Handlers) getMethod(w http.ResponseWriter, r *http.Request, c *Caller) {
	m, err := authmethods.Find(r.Context(), h.Store, c.User, chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, r, "get an authentication method", err)
		return
	}
	writeJSON(w, r, http.StatusOK, methodView(*m))
}

// fail answers err: not found, or a logged server error.
func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	var p *Problem
	switch {
	case errors.As(err, &p):
	case errors.Is(err, store.ErrNotFound):
		p = notFound("The authentication method does not exist.")
	default:
		h.log().ErrorContext(r.Context(), "my account: "+what, "err", err)
		p = serverError()
	}
	writeProblem(w, r, p)
}
