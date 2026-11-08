package mgmt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
	"net/http"
	"net/url"
	"slices"
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
	case "passkey", "webauthn-roaming", "webauthn-platform":
		out["key_id"] = base64.RawURLEncoding.EncodeToString(a.CredentialID)
		out["public_key"] = base64.RawURLEncoding.EncodeToString(a.PublicKey)
		out["relying_party_identifier"] = a.RPID
	}
	if a.Type == "passkey" {
		delete(out, "confirmed")
		var data struct {
			BE bool `json:"backup_eligible"`
			BS bool `json:"backed_up"`
		}
		_ = json.Unmarshal(a.PublicData, &data)
		out["credential_device_type"] = "single_device"
		if data.BE {
			out["credential_device_type"] = "multi_device"
		}
		out["credential_backed_up"] = data.BS
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
	if t, ok := public["credential_device_type"].(string); ok && a.Type == "webauthn-roaming" {
		// The MFA assertion check compares this with the authenticator's flag.
		public["backup_eligible"] = t == "multi_device"
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
				if a.Confirmed && a.Type != "passkey" {
					out = append(out, enrollmentJSON(publicPhone(r, a)))
				}
			}
			writeJSON(w, 200, out)
			return
		}
		page, per, totals, e := pageWithMinimum(r, 0)
		if e != nil {
			Fail(w, e)
			return
		}
		start := min(page*per, len(all))
		end := min(start+per, len(all))
		for _, a := range all[start:end] {
			out = append(out, methodJSON(publicPhone(r, a)))
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
		writeJSON(w, 200, methodJSON(publicPhone(r, *a)))
		return
	}
	var out any
	status := 204
	code := "gd_unenroll"
	passkeyChange := false
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		// Same user lock as service enrollment/proof commits: replace-all,
		// regeneration and deletions serialize with concurrent authenticators.
		current, e := tx.Users().GetForUpdate(r.Context(), tid, uid)
		if e != nil {
			return e
		}
		repo := tx.MFA()
		switch route.Operation {
		case "CreateAuthenticationMethods":
			b := body.(map[string]any)
			var a store.Authenticator
			var e error
			if b["type"] == "passkey" {
				a, e = h.newPasskey(r.Context(), tx, resolved(r), current, b)
				passkeyChange = true
			} else {
				a, e = h.newMethod(tid, uid, b)
			}
			if e != nil {
				return e
			}
			if a.Type == "passkey" {
				e = tx.WebAuthn().CreatePasskey(r.Context(), &a, webauthnrules.Limits.MaxPasskeys)
				if errors.Is(e, store.ErrPrecondition) {
					return badBody("passkey enrollment limit reached")
				}
			} else {
				e = repo.CreateAuthenticator(r.Context(), &a)
			}
			if e != nil {
				return e
			}
			out = methodJSON(publicPhone(r, a))
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
				view := methodJSON(publicPhone(r, a))
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
			passkeyChange = a.Type == "passkey"
			patch := body.(map[string]any)
			if v, ok := patch["name"]; ok {
				if utf8.RuneCountInString(v.(string)) > 20 {
					return store.ErrInvalid
				}
				a.Name = v.(string)
			}
			if v, ok := patch["preferred_authentication_method"]; ok {
				if passkeyChange {
					return store.ErrInvalid
				}
				a.PhoneMethod = v.(string)
			}
			if e = repo.UpdateAuthenticator(r.Context(), a); e != nil {
				return e
			}
			view := methodJSON(publicPhone(r, *a))
			if !passkeyChange {
				for _, key := range []string{"credential_device_type", "credential_backed_up", "identity_user_id", "user_agent", "user_handle", "transports", "last_auth_at"} {
					delete(view, key)
				}
			}
			out = view
			status = 200
			code = "gd_update_device_account"
		case "DeleteAuthenticationMethod":
			a, e := repo.GetAuthenticator(r.Context(), tid, uid, id)
			if e != nil {
				return e
			}
			passkeyChange = a.Type == "passkey"
			if e := repo.DeleteAuthenticator(r.Context(), tid, uid, id); e != nil {
				return e
			}
			if passkeyChange {
				return nil
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
				if a.Confirmed && a.Type != "recovery-code" && a.Type != "passkey" {
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
	if !passkeyChange {
		h.domainEvent(r, code, u, nil, nil)
	}
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
	if a.Type == "webauthn-roaming" || a.Type == "webauthn-platform" {
		out["auth_method"] = a.Type
	}
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
	// An indexed tenant-scoped lookup by enrollment ID; never an unscoped search
	// or a walk over the tenant's users.
	tid := resolved(r).ID
	a, err := h.Store.MFA().GetAuthenticatorByEnrollmentID(r.Context(), tid, id)
	if err == nil && (!a.Confirmed || a.Type == "passkey") {
		err = store.ErrNotFound
	}
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	if !remove {
		writeJSON(w, 200, enrollmentJSON(publicPhone(r, *a)))
		return
	}
	var u *store.User
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		var e error
		if u, e = tx.Users().GetForUpdate(r.Context(), tid, a.UserID); e != nil {
			return e
		}
		if e = tx.MFA().DeleteAuthenticator(r.Context(), tid, a.UserID, a.ID); e != nil {
			return e
		}
		return tx.MFA().BumpRememberEpoch(r.Context(), tid, a.UserID)
	})
	if err != nil {
		h.mfaFail(w, r, err)
		return
	}
	h.domainEvent(r, "gd_unenroll", u, nil, nil)
	logDetails(r, "delete Guardian enrollment", "user_id", a.UserID)
	w.WriteHeader(204)
}

func publicPhone(r *http.Request, a store.Authenticator) store.Authenticator {
	if !tenantrules.PhoneSettingsOf(resolved(r)).DisableSMSObfuscation && a.Phone != "" {
		a.Phone = phone.Mask(a.Phone)
	}
	return a
}

// validStoredCOSE checks an imported public COSE_Key with the WebAuthn
// verifier's own parser, so stored keys are exactly the keys assertions can
// verify (Plan 33b).
func validStoredCOSE(raw []byte) bool {
	_, err := webauthn.ParseCOSEKey(raw)
	return err == nil
}

// webAuthnAvailable negotiates before accepting capability-dependent fields.
// A failed negotiation is different from the explicit absence of the feature.
func webAuthnAvailable(ctx context.Context, st store.Store) (bool, error) {
	if cap, ok := st.(store.WebAuthnSupporter); ok {
		if err := cap.CheckWebAuthnSupport(ctx); err != nil {
			if errors.Is(err, store.ErrWebAuthnUnavailable) {
				return false, nil
			}
			return false, err
		}
		return cap.WebAuthnSupported(), nil
	}
	switch st.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return false, nil
	}
	return true, nil
}

func (h *Handlers) newPasskey(ctx context.Context, tx store.Store, tn *store.Tenant, u *store.User, b map[string]any) (store.Authenticator, error) {
	a := store.Authenticator{TenantID: tn.ID, UserID: u.UserID, ID: "passkey|dev_" + secrets.RandomString(20), Type: "passkey", Confirmed: true, LastStep: -1, CreatedAt: h.now()}
	available, err := webAuthnAvailable(ctx, h.Store)
	if err != nil {
		return a, err
	}
	if !available {
		return a, store.ErrWebAuthnUnavailable
	}
	text := func(k string) string { v, _ := b[k].(string); return v }
	a.Name = text("name")
	if utf8.RuneCountInString(a.Name) > webauthnrules.Limits.NicknameMax {
		return a, store.ErrInvalid
	}
	a.CredentialID, err = decodeMFAKey(text("key_id"))
	if err != nil || len(a.CredentialID) > webauthnrules.Limits.CredentialIDMax {
		return a, store.ErrInvalid
	}
	a.PublicKey, err = decodeMFAKey(text("public_key"))
	if err != nil || !validStoredCOSE(a.PublicKey) {
		return a, store.ErrInvalid
	}
	a.RPID = text("relying_party_identifier")
	if a.RPID == "" {
		host := tn.CanonicalHost
		did, e := tx.CustomDomains().GetDefault(ctx, tn.ID)
		if e != nil {
			return a, e
		}
		if did != "" {
			d, e := tx.CustomDomains().Get(ctx, tn.ID, did)
			if e != nil {
				return a, e
			}
			host = d.Domain
		}
		policy := rpid.Policy{BaseDomain: h.BaseDomain, SystemHost: h.SystemHost, RestrictShared: h.RestrictSharedRPIDs, Store: tx}
		if h.Domains != nil {
			policy.OriginSuffix = h.Domains.Reserved().OriginSuffix
		}
		rp, e := policy.For(ctx, tenant.Resolved{Tenant: tn, Host: host})
		if e != nil {
			return a, e
		}
		if !rp.Valid {
			return a, store.ErrInvalid
		}
		a.RPID = rp.RPID
	}
	parsed, e := url.Parse("https://" + a.RPID)
	if e != nil || a.RPID == "" || len(a.RPID) > webauthnrules.Limits.RPIDMax || parsed.Host != a.RPID || parsed.Hostname() != a.RPID || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(a.RPID, " *@") {
		return a, store.ErrInvalid
	}
	identityID := text("identity_user_id")
	if _, supplied := b["identity_user_id"]; supplied && identityID == "" {
		return a, store.ErrInvalid
	}
	if identityID == "" {
		if id := u.OwnIdentity(); id != nil && id.Provider == store.StrategyDatabase {
			identityID = id.UserID
		} else {
			for _, id := range u.Identities {
				if id.Provider == store.StrategyDatabase {
					identityID = id.UserID
					break
				}
			}
		}
	}
	if identityID == "" || !slices.ContainsFunc(u.Identities, func(id store.Identity) bool { return id.Provider == store.StrategyDatabase && id.UserID == identityID }) {
		return a, store.ErrInvalid
	}
	public := map[string]any{"identity_user_id": identityID, "backup_eligible": text("credential_device_type") == "multi_device"}
	for _, k := range []string{"aaguid", "user_agent", "transports"} {
		if v, ok := b[k]; ok {
			public[k] = v
		}
	}
	if utf8.RuneCountInString(text("user_agent")) > 4096 {
		return a, store.ErrInvalid
	}
	backed, _ := b["credential_backed_up"].(bool)
	public["backed_up"] = backed
	handle := text("user_handle")
	if _, supplied := b["user_handle"]; supplied && handle == "" {
		return a, store.ErrInvalid
	}
	if handle == "" {
		all, e := tx.MFA().ListAuthenticators(ctx, tn.ID, u.UserID)
		if e != nil {
			return a, e
		}
		slices.SortFunc(all, func(a, b store.Authenticator) int {
			if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		for _, existing := range all {
			if existing.Type == "passkey" {
				var p struct {
					Handle string `json:"user_handle"`
				}
				if json.Unmarshal(existing.PublicData, &p) != nil || p.Handle == "" {
					return a, store.ErrInvalid
				}
				handle = p.Handle
				break
			}
		}
		if handle == "" {
			raw := make([]byte, webauthnrules.Limits.UserHandleBytes)
			if _, e = rand.Read(raw); e != nil {
				return a, e
			}
			handle = base64.RawURLEncoding.EncodeToString(raw)
		}
	}
	raw, e := decodeMFAKey(handle)
	if e != nil || len(raw) != webauthnrules.Limits.UserHandleBytes {
		return a, store.ErrInvalid
	}
	public["user_handle"] = base64.RawURLEncoding.EncodeToString(raw)
	a.PublicData, err = json.Marshal(public)
	return a, err
}
