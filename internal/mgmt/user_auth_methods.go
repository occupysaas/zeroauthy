package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

func methodJSON(a store.Authenticator) map[string]any {
	out := map[string]any{}
	if len(a.PublicData) > 0 {
		var data map[string]any
		_ = json.Unmarshal(a.PublicData, &data)
		for _, key := range []string{"aaguid", "credential_device_type", "credential_backed_up", "identity_user_id", "user_agent", "user_handle", "transports"} {
			if v, ok := data[key]; ok {
				out[key] = v
			}
		}
	}
	for k, v := range map[string]any{"id": a.ID, "type": a.Type, "confirmed": a.Confirmed, "name": a.Name, "created_at": userTime(a.CreatedAt)} {
		out[k] = v
	}
	if a.PhoneMethod != "" {
		out["preferred_authentication_method"] = a.PhoneMethod
	}
	if !a.LastAuthAt.IsZero() {
		out["last_auth_at"] = userTime(a.LastAuthAt)
	}
	switch a.Type {
	case "email":
		out["email"] = a.Email
	case "phone":
		out["phone_number"] = a.Phone
		if a.PhoneMethod != "" {
			out["preferred_authentication_method"] = a.PhoneMethod
		}
	case "webauthn-roaming", "webauthn-platform":
		out["key_id"] = base64.RawURLEncoding.EncodeToString(a.CredentialID)
		out["public_key"] = base64.RawURLEncoding.EncodeToString(a.PublicKey)
		out["relying_party_identifier"] = a.RPID
	}
	return out
}
func decodeMFAKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if v, e := enc.DecodeString(s); e == nil && len(v) > 0 {
			return v, nil
		}
	}
	return nil, store.ErrInvalid
}
func (h *Handlers) newMethod(tid, uid string, b map[string]any) (store.Authenticator, error) {
	text := func(k string) string { v, _ := b[k].(string); return v }
	a := store.Authenticator{TenantID: tid, UserID: uid, Type: text("type"), Name: text("name"), Confirmed: true, LastStep: -1, CreatedAt: h.now(), PhoneMethod: text("preferred_authentication_method")}
	a.ID = a.Type + "|dev_" + secrets.RandomString(20)
	var err error
	switch a.Type {
	case "totp":
		a.SealedSecret, err = mfa.SealTOTPSecret(h.Wrapper, tid, uid, a.ID, text("totp_secret"))
	case "email":
		a.Email = text("email")
		if !mfaEmail(a.Email) {
			err = store.ErrInvalid
		}
	case "phone":
		a.Phone = text("phone_number")
		if len(a.Phone) < 2 {
			err = store.ErrInvalid
		}
	case "webauthn-roaming":
		a.CredentialID, err = decodeMFAKey(text("key_id"))
		if err == nil {
			a.PublicKey, err = decodeMFAKey(text("public_key"))
		}
		a.RPID = text("relying_party_identifier")
		parsed, parseErr := url.Parse("https://" + a.RPID)
		if a.RPID == "" || parseErr != nil || parsed.Host != a.RPID || parsed.Hostname() != a.RPID || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(a.RPID, " *@") || !validStoredCOSE(a.PublicKey) {
			err = store.ErrInvalid
		}
	default:
		err = store.ErrInvalid
	}
	if utf8.RuneCountInString(a.Name) > 20 {
		return a, store.ErrInvalid
	}
	public := map[string]any{}
	for _, key := range []string{"aaguid", "credential_device_type", "credential_backed_up", "identity_user_id", "user_agent", "user_handle", "transports"} {
		if v, ok := b[key]; ok {
			public[key] = v
		}
	}
	if len(public) > 0 {
		a.PublicData, _ = json.Marshal(public)
	}
	return a, err
}
func (h *Handlers) userMFA(w http.ResponseWriter, r *http.Request, route mfarules.RouteSchema, uid, id string, body any) {
	u, err := h.getUser(r, uid)
	if err != nil {
		Fail(w, err)
		return
	}
	tid := resolved(r).ID
	switch route.Operation {
	case "GetAuthenticationMethods", "GetUserEnrollments":
		all, e := h.Store.MFA().ListAuthenticators(r.Context(), tid, uid)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		out := []any{}
		if route.Operation == "GetUserEnrollments" {
			for _, a := range all {
				if a.Confirmed {
					out = append(out, enrollmentJSON(a))
				}
			}
			writeJSON(w, 200, out)
			return
		}
		page, per, totals, e := Page(r)
		if e != nil {
			Fail(w, e)
			return
		}
		start := min(page*per, len(all))
		end := min(start+per, len(all))
		for _, a := range all[start:end] {
			out = append(out, methodJSON(a))
		}
		if totals {
			writeJSON(w, 200, map[string]any{"authenticators": out, "start": page * per, "limit": per, "total": len(all)})
		} else {
			writeJSON(w, 200, out)
		}
		return
	case "GetAuthenticationMethod":
		a, e := h.Store.MFA().GetAuthenticator(r.Context(), tid, uid, id)
		if e != nil {
			h.mfaFail(w, r, e)
			return
		}
		writeJSON(w, 200, methodJSON(*a))
		return
	}
	var out any
	status := 204
	code := "gd_unenroll"
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		// Same user lock as service enrollment/proof commits: replace-all,
		// regeneration and deletions serialize with concurrent authenticators.
		if _, e := tx.Users().GetForUpdate(r.Context(), tid, uid); e != nil {
			return e
		}
		repo := tx.MFA()
		switch route.Operation {
		case "CreateAuthenticationMethods":
			a, e := h.newMethod(tid, uid, body.(map[string]any))
			if e != nil {
				return e
			}
			if e = repo.CreateAuthenticator(r.Context(), &a); e != nil {
				return e
			}
			out = methodJSON(a)
			delete(out.(map[string]any), "confirmed")
			delete(out.(map[string]any), "last_auth_at")
			status = 201
			code = "gd_enrollment_complete"
		case "SetAuthenticationMethods":
			methods := []store.Authenticator{}
			for _, v := range body.([]any) {
				a, e := h.newMethod(tid, uid, v.(map[string]any))
				if e != nil {
					return e
				}
				methods = append(methods, a)
			}
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, nil); e != nil {
				return e
			}
			list := []any{}
			for _, a := range methods {
				if e := repo.CreateAuthenticator(r.Context(), &a); e != nil {
					return e
				}
				view := methodJSON(a)
				delete(view, "confirmed")
				delete(view, "last_auth_at")
				list = append(list, view)
			}
			out = list
			status = 200
			code = "gd_update_device_account"
			if e := repo.BumpRememberEpoch(r.Context(), tid, uid); e != nil {
				return e
			}
		case "UpdateAuthenticationMethod":
			a, e := repo.GetAuthenticator(r.Context(), tid, uid, id)
			if e != nil {
				return e
			}
			patch := body.(map[string]any)
			if v, ok := patch["name"]; ok {
				if utf8.RuneCountInString(v.(string)) > 20 {
					return store.ErrInvalid
				}
				a.Name = v.(string)
			}
			if v, ok := patch["preferred_authentication_method"]; ok {
				a.PhoneMethod = v.(string)
			}
			if e = repo.UpdateAuthenticator(r.Context(), a); e != nil {
				return e
			}
			view := methodJSON(*a)
			for _, key := range []string{"credential_device_type", "credential_backed_up", "identity_user_id", "user_agent", "user_handle", "transports", "last_auth_at"} {
				delete(view, key)
			}
			out = view
			status = 200
			code = "gd_update_device_account"
		case "DeleteAuthenticationMethod":
			if e := repo.DeleteAuthenticator(r.Context(), tid, uid, id); e != nil {
				return e
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "DeleteAuthenticationMethods", "DeleteUserAuthenticators":
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, nil); e != nil {
				return e
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "DeleteUserMultifactor":
			types := []string{}
			switch id {
			case "google-authenticator":
				types = []string{"totp"}
			case "duo":
				types = []string{"duo"}
			default:
				return badBody("invalid multifactor provider")
			}
			if e := repo.DeleteUserAuthenticators(r.Context(), tid, uid, types); e != nil {
				return e
			}
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "CreateUserRememberBrowser":
			code = "gd_update_device_account"
			return repo.BumpRememberEpoch(r.Context(), tid, uid)
		case "CreateUserRecoveryCode":
			all, e := repo.ListAuthenticators(r.Context(), tid, uid)
			if e != nil {
				return e
			}
			old := ""
			hasFactor := false
			for _, a := range all {
				if a.Confirmed && a.Type != "recovery-code" {
					hasFactor = true
				}
				if a.Type == "recovery-code" {
					old = a.CodeHash
				}
			}
			if !hasFactor {
				return badBody("A confirmed authentication method is required")
			}
			raw := mfa.NewRecoveryCode()
			if e = repo.ReplaceRecoveryCode(r.Context(), tid, uid, old, secrets.HashToken(raw), h.now()); e != nil {
				return e
			}
			out = map[string]any{"recovery_code": raw}
			status = 200
			code = "gd_update_device_account"
		default:
			return errMFAMissing
		}
		return nil
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	h.domainEvent(r, code, u, nil, nil)
	logDetails(r, "manage user authentication methods", "user_id", uid, "operation", route.Operation)
	if status == 204 {
		w.WriteHeader(status)
	} else {
		writeJSON(w, status, out)
	}
}
func enrollmentJSON(a store.Authenticator) map[string]any {
	id := a.ID
	if _, v, ok := strings.Cut(id, "|"); ok {
		id = v
	}
	out := map[string]any{"id": id, "status": "confirmed", "identifier": a.Email, "enrolled_at": userTime(a.CreatedAt)}
	if a.Name != "" {
		out["name"] = a.Name
	}
	if a.Phone != "" {
		out["phone_number"] = a.Phone
		out["identifier"] = a.Phone
	}
	if !a.LastAuthAt.IsZero() {
		out["last_auth"] = userTime(a.LastAuthAt)
	}
	return out
}
func (h *Handlers) guardianEnrollment(w http.ResponseWriter, r *http.Request, id string, remove bool) {
	// The repository indexes methods by tenant/user. Walk tenant users in bounded
	// pages; never perform an unscoped search or infer another tenant's owner.
	tid := resolved(r).ID
	for offset := 0; ; offset += 100 {
		users, _, err := h.Store.Users().List(r.Context(), tid, nil, store.UserSort{}, store.Page{Offset: offset, Limit: 100})
		if err != nil {
			h.mfaFail(w, r, err)
			return
		}
		for _, u := range users {
			all, e := h.Store.MFA().ListAuthenticators(r.Context(), tid, u.UserID)
			if e != nil {
				h.mfaFail(w, r, e)
				return
			}
			for _, a := range all {
				_, enrollmentID, _ := strings.Cut(a.ID, "|")
				if !a.Confirmed || enrollmentID != id {
					continue
				}
				if !remove {
					writeJSON(w, 200, enrollmentJSON(a))
					return
				}
				err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
					if _, e := tx.Users().GetForUpdate(r.Context(), tid, u.UserID); e != nil {
						return e
					}
					if e := tx.MFA().DeleteAuthenticator(r.Context(), tid, u.UserID, a.ID); e != nil {
						return e
					}
					return tx.MFA().BumpRememberEpoch(r.Context(), tid, u.UserID)
				})
				if err != nil {
					h.mfaFail(w, r, err)
					return
				}
				h.domainEvent(r, "gd_unenroll", u, nil, nil)
				logDetails(r, "delete Guardian enrollment", "user_id", u.UserID)
				w.WriteHeader(204)
				return
			}
		}
		if len(users) < 100 {
			break
		}
	}
	Fail(w, errMFAMissing)
}
