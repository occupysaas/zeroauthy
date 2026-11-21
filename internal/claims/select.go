package claims

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
)

var identityProfileStrings = []string{"middle_name", "preferred_username", "profile", "website", "gender", "birthdate", "zoneinfo", "locale"}
var addressStrings = []string{"formatted", "street_address", "locality", "region", "postal_code", "country"}

// IdentityClaims retains only supported standard attributes from a verified
// federated profile. It never propagates metadata or authorization properties.
func IdentityClaims(profile map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range identityProfileStrings {
		if value, ok := profile[key].(string); ok && value != "" {
			out[key] = value
		}
	}
	if address, ok := profile["address"].(map[string]any); ok {
		clean := map[string]any{}
		for _, key := range addressStrings {
			if value, ok := address[key].(string); ok && value != "" {
				clean[key] = value
			}
		}
		if len(clean) > 0 {
			out["address"] = clean
		}
	}
	return out
}

// PrimaryProfile selects only the user's own provider-owned identity data.
// Linking a secondary identity must never replace the primary user's claims.
func PrimaryProfile(u *store.User) map[string]any {
	if u == nil {
		return nil
	}
	for _, id := range u.Identities {
		if !id.Linked() && store.IsFederatedProvider(id.Provider) && u.UserID == id.Provider+"|"+id.UserID {
			return id.ProviderData
		}
	}
	return nil
}

// Select emits standard claims covered by granted scopes. Both targets retain
// Auth0's scope claims; optional claim requests cannot expand that authorization.
// Requested values may be declined (Core section 5.5), and essential requests
// do not fail issuance. Session-derived auth_time/acr are added by the minter.
func Select(u *store.User, identityProfile map[string]any, scopes []string, _ *Request, _ string) map[string]any {
	out := map[string]any{}
	if u == nil {
		return out
	}
	out["sub"] = u.UserID
	profile := IdentityClaims(identityProfile)
	if slices.Contains(scopes, "profile") {
		for _, key := range identityProfileStrings {
			if value, ok := profile[key]; ok {
				out[key] = value
			}
		}
		for key, value := range map[string]string{"name": Name(u), "nickname": Nickname(u), "picture": u.Picture, "given_name": u.GivenName, "family_name": u.FamilyName} {
			if value != "" {
				out[key] = value
			}
		}
		if !u.UpdatedAt.IsZero() {
			out["updated_at"] = u.UpdatedAt.Unix()
		}
	}
	if slices.Contains(scopes, "email") && u.Email != "" {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	if slices.Contains(scopes, "phone") && u.PhoneNumber != "" {
		out["phone_number"] = u.PhoneNumber
		out["phone_number_verified"] = u.PhoneVerified
	}
	if slices.Contains(scopes, "address") {
		if address, ok := profile["address"]; ok {
			out["address"] = address
		}
	}
	return out
}
