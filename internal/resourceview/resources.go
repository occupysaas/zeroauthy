// Package resourceview contains the shared Management API resource serializers.
package resourceview

import (
	"encoding/json"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func User(u *store.User) map[string]any {
	m := map[string]any{"multifactor": []string{}, "user_id": u.UserID, "created_at": userTime(u.CreatedAt), "updated_at": userTime(u.UpdatedAt)}
	if u.Email != "" {
		m["email"] = u.Email
		m["email_verified"] = u.EmailVerified
	}
	for k, v := range map[string]string{"username": u.Username, "name": u.Name, "nickname": u.Nickname, "picture": u.Picture,
		"given_name": u.GivenName, "family_name": u.FamilyName} {
		if v != "" {
			m[k] = v
		}
	}
	if u.PhoneNumber != "" {
		m["phone_number"] = u.PhoneNumber
		m["phone_verified"] = u.PhoneVerified
	}
	// blocked appears only when true. Auth0 shows blocked:false once it has
	// been set, but the store cannot tell "set to false" from "never set";
	// a logged deviation (D-0043).
	if u.Blocked {
		m["blocked"] = true
	}
	if u.UserMetadata != nil {
		m["user_metadata"] = u.UserMetadata
	}
	if u.AppMetadata != nil {
		m["app_metadata"] = u.AppMetadata
	}
	ids := make([]map[string]any, len(u.Identities))
	for i := range u.Identities {
		ids[i] = Identity(&u.Identities[i])
	}
	m["identities"] = ids
	if u.LastLogin != nil {
		m["last_login"] = userTime(*u.LastLogin)
		m["logins_count"] = u.LoginsCount
		if u.LastIP != "" {
			m["last_ip"] = u.LastIP
		}
	}
	return m
}

func Identity(id *store.Identity) map[string]any {
	m := map[string]any{"connection": id.Connection, "user_id": id.UserID, "provider": id.Provider, "isSocial": rules.IsSocial(id.Provider)}
	if id.Linked() {
		m["profileData"] = id.ProfileData
	}
	return m
}

func Organization(o store.Organization) map[string]any {
	out := map[string]any{
		"id": o.ID, "name": o.Name, "display_name": o.DisplayName,
		"third_party_client_access": o.ThirdPartyClientAccess,
		"is_app_entitlement_active": o.IsAppEntitlementActive,
	}
	if b := o.Branding; b != nil {
		branding := map[string]any{}
		if b.LogoURL != nil {
			branding["logo_url"] = *b.LogoURL
		}
		if b.Colors != nil {
			branding["colors"] = map[string]any{"primary": b.Colors.Primary, "page_background": b.Colors.PageBackground}
		}
		out["branding"] = branding
	}
	if len(o.Metadata) > 0 {
		out["metadata"] = o.Metadata
	}
	return out
}

func userTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func Connection(spec *connrules.Spec, id string, withClients bool) (map[string]any, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["id"] = id
	if !withClients {
		delete(m, "enabled_clients")
	}
	if spec.Federated() {
		// Database options mean nothing here, and provider secrets are
		// write-only: never returned, not even as placeholders.
		if opts, ok := m["options"].(map[string]any); ok {
			for _, k := range federatedHiddenOptions {
				delete(opts, k)
			}
		}
	}
	return m, nil
}

// federatedHiddenOptions are left out of a federated connection's options.
var federatedHiddenOptions = []string{"client_secret", "disable_signup", "requires_username",
	"enabledDatabaseCustomization", "import_mode", "password_options", "brute_force_protection", "validation"}
