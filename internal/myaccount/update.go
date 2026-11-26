package myaccount

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/authmethods"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// MaxMethodName bounds method names (LR42a-6).
const MaxMethodName = 100

// patchBody is UpdateAuthenticationMethod.
type patchBody struct {
	Name                          *string `json:"name"`
	PreferredAuthenticationMethod *string `json:"preferred_authentication_method"`
}

// named are the types that carry a name.
var named = map[string]bool{"passkey": true, "webauthn-roaming": true, "webauthn-platform": true, "totp": true, "email": true, "phone": true}

func validName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxMethodName {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

func fieldProblem(field, detail string) *Problem {
	return badRequest("invalid_body", detail, ValidationError{Detail: detail, Field: field, Source: "body"})
}

func (h *Handlers) patchMethod(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b patchBody
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	if b.Name == nil && b.PreferredAuthenticationMethod == nil {
		writeProblem(w, r, badRequest("invalid_body", "Nothing to update: send name or preferred_authentication_method."))
		return
	}
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		u, err := tx.Users().GetForUpdate(ctx, c.TenantID, c.UserID)
		if err != nil {
			return err
		}
		m, err := authmethods.Find(ctx, tx, u, id)
		if err != nil {
			return err
		}
		if m.Authenticator == nil {
			return fieldProblem("name", "This method cannot be updated.")
		}
		a := m.Authenticator
		if b.Name != nil {
			if !named[a.Type] {
				return fieldProblem("name", "This method has no name.")
			}
			if !validName(*b.Name) {
				return fieldProblem("name", "name must be 1 to 100 characters without control characters.")
			}
			a.Name = *b.Name
		}
		if v := b.PreferredAuthenticationMethod; v != nil {
			if a.Type != "phone" {
				return fieldProblem("preferred_authentication_method", "Only phone methods have a preferred_authentication_method.")
			}
			if *v != "sms" && *v != "voice" {
				return fieldProblem("preferred_authentication_method", "preferred_authentication_method must be sms or voice.")
			}
			a.PhoneMethod = *v
		}
		return tx.MFA().UpdateAuthenticator(ctx, a)
	})
	if err != nil {
		h.fail(w, r, "update an authentication method", err)
		return
	}
	logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: c.TenantID, UserID: c.UserID, ClientID: c.ClientID, Type: "gd_update_device_account", Date: h.now()})
	u, err := h.Store.Users().Get(ctx, c.TenantID, c.UserID)
	if err != nil {
		h.fail(w, r, "reload the user", err)
		return
	}
	m, err := authmethods.Find(ctx, h.Store, u, id)
	if err != nil {
		h.fail(w, r, "reload the method", err)
		return
	}
	writeJSON(w, r, http.StatusOK, methodView(*m))
}

var errLastFirstFactor = conflict("last_authentication_method", "The user's last way to sign in cannot be deleted.")

// deleteMethod removes a method. Passwords and passkeys sign the user in:
// the last of them cannot go (Y1). Second factors always may (Y8).
func (h *Handlers) deleteMethod(w http.ResponseWriter, r *http.Request, c *Caller) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	var deleted *authmethods.Method
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		u, err := tx.Users().GetForUpdate(ctx, c.TenantID, c.UserID)
		if err != nil {
			return err
		}
		all, err := authmethods.List(ctx, tx, u)
		if err != nil {
			return err
		}
		var m *authmethods.Method
		primary := 0
		for i := range all {
			if all[i].ID == id {
				m = &all[i]
			}
			if all[i].Type == "password" || all[i].Type == "passkey" {
				primary++
			}
		}
		if m == nil {
			return store.ErrNotFound
		}
		if (m.Type == "password" || m.Type == "passkey") && primary <= 1 {
			return errLastFirstFactor
		}
		deleted = m
		if m.Type == "password" {
			if m.Identity.Linked() {
				return fieldProblem("authentication_method_id", "The password of a linked identity cannot be deleted here.")
			}
			return tx.Users().SetPasswordHash(ctx, c.TenantID, c.UserID, m.Identity.Connection, "", h.now())
		}
		if err := tx.MFA().DeleteAuthenticator(ctx, c.TenantID, c.UserID, id); err != nil {
			return err
		}
		if m.Type == "passkey" {
			return nil
		}
		// Remembered browsers no longer stand in for a removed factor.
		return tx.MFA().BumpRememberEpoch(ctx, c.TenantID, c.UserID)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeProblem(w, r, notFound("The authentication method does not exist."))
		return
	}
	if err != nil {
		h.fail(w, r, "delete an authentication method", err)
		return
	}
	if deleted.Type != "password" && deleted.Type != "passkey" {
		logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: c.TenantID, UserID: c.UserID, ClientID: c.ClientID, Type: "gd_unenroll", Date: h.now()})
	}
	w.Header().Set("x-correlation-id", correlationID(r))
	w.WriteHeader(http.StatusNoContent)
}
