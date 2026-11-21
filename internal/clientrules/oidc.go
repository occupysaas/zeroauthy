package clientrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
)

func ParseOIDCSupport(raw json.RawMessage) (*store.OIDCSupport, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errors.New("must be an object or null")
	}
	out := &store.OIDCSupport{}
	for key, value := range fields {
		switch key {
		case "is_allowed":
			var b *bool
			if json.Unmarshal(value, &b) != nil || b == nil {
				return nil, errors.New("is_allowed must be a boolean")
			}
			out.IsAllowed = *b
		case "allow_all_scopes":
			if json.Unmarshal(value, &out.AllowAllScopes) != nil || out.AllowAllScopes == nil {
				return nil, errors.New("allow_all_scopes must be a boolean")
			}
		case "allowed_scopes":
			if json.Unmarshal(value, &out.AllowedScopes) != nil || out.AllowedScopes == nil {
				return nil, errors.New("allowed_scopes must be an array")
			}
		default:
			return nil, errors.New("unknown OIDC support property")
		}
	}
	if _, ok := fields["is_allowed"]; !ok {
		return nil, errors.New("is_allowed is required")
	}
	return out, ValidateOIDCSupport(out)
}
func ValidateOIDCSupport(s *store.OIDCSupport) error {
	if s == nil {
		return nil
	}
	if s.AllowAllScopes != nil && s.AllowedScopes != nil {
		return errors.New("allow_all_scopes and allowed_scopes are mutually exclusive")
	}
	seen := map[string]bool{}
	for _, scope := range s.AllowedScopes {
		if !slices.Contains([]string{"profile", "email", "address", "phone"}, scope) || seen[scope] {
			return errors.New("allowed_scopes must contain distinct supported OIDC scopes")
		}
		seen[scope] = true
	}
	return nil
}
