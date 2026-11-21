package clientrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"slices"
	"strings"
)

var logoutInitiators = []string{"rp-logout", "idp-logout", "password-changed", "session-expired", "session-revoked", "account-deleted", "email-identifier-changed", "mfa-phone-unenrolled", "account-deactivated", "profile-changed"}

func oidcObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errors.New("must be an object")
	}
	return fields, nil
}

func ParseOIDCLogout(raw json.RawMessage) (*store.OIDCLogout, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	fields, err := oidcObject(raw)
	if err != nil {
		return nil, err
	}
	out := &store.OIDCLogout{}
	for key, value := range fields {
		switch key {
		case "backchannel_logout_urls":
			if json.Unmarshal(value, &out.BackchannelURLs) != nil || out.BackchannelURLs == nil {
				return nil, errors.New("backchannel_logout_urls must be an array")
			}
		case "backchannel_logout_initiators":
			in, err := oidcObject(value)
			if err != nil {
				return nil, err
			}
			if json.Unmarshal(in["mode"], &out.InitiatorsMode) != nil || !slices.Contains([]string{"custom", "all"}, out.InitiatorsMode) {
				return nil, errors.New("initiators mode must be custom or all")
			}
			for name, value := range in {
				switch name {
				case "mode":
				case "selected_initiators":
					if json.Unmarshal(value, &out.Initiators) != nil || out.Initiators == nil {
						return nil, errors.New("selected_initiators must be an array")
					}
				default:
					return nil, errors.New("unknown initiator property")
				}
			}
		case "backchannel_logout_session_metadata":
			metadata, err := oidcObject(value)
			if err != nil {
				return nil, err
			}
			for name, value := range metadata {
				if name != "include" {
					return nil, errors.New("unknown logout metadata property")
				}
				if json.Unmarshal(value, &out.IncludeSessionMetadata) != nil || out.IncludeSessionMetadata == nil {
					return nil, errors.New("include must be a boolean")
				}
			}
		default:
			return nil, errors.New("unknown OIDC logout property")
		}
	}
	return out, NormalizeOIDCLogout(out)
}

func NormalizeOIDCLogout(s *store.OIDCLogout) error {
	if s == nil {
		return nil
	}
	if len(s.BackchannelURLs) > 1 {
		return errors.New("only one backchannel logout URL is allowed")
	}
	for _, raw := range s.BackchannelURLs {
		if len(raw) > 2048 {
			return errors.New("backchannel logout URL exceeds 2048 bytes")
		}
		safe := strings.NewReplacer("{organization_name}", "organization", "{organization_id}", "org_0123456789abcdef").Replace(raw)
		if strings.ContainsAny(safe, "{}") {
			return errors.New("unknown backchannel logout URL placeholder")
		}
		parsed, err := url.Parse(safe)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || strings.Contains(raw, "#") || parsed.Opaque != "" {
			return errors.New("backchannel logout URL must be absolute HTTPS without credentials or fragment")
		}
	}
	if s.InitiatorsMode == "" {
		s.InitiatorsMode = "custom"
		if s.Initiators == nil {
			s.Initiators = []string{"rp-logout", "idp-logout"}
		}
	}
	if s.InitiatorsMode != "all" && s.InitiatorsMode != "custom" {
		return errors.New("initiators mode must be custom or all")
	}
	seen := map[string]bool{}
	for _, value := range s.Initiators {
		if !slices.Contains(logoutInitiators, value) || seen[value] {
			return errors.New("selected_initiators must contain distinct known initiators")
		}
		seen[value] = true
	}
	if s.InitiatorsMode == "custom" && (!seen["rp-logout"] || !seen["idp-logout"]) {
		return errors.New("custom initiators must include rp-logout and idp-logout")
	}
	if s.IncludeSessionMetadata == nil {
		no := false
		s.IncludeSessionMetadata = &no
	}
	return nil
}

func PublicOIDCLogout(s *store.OIDCLogout) map[string]any {
	if s == nil {
		return nil
	}
	s = s.Clone()
	_ = NormalizeOIDCLogout(s)
	urls := slices.Clone(s.BackchannelURLs)
	if urls == nil {
		urls = []string{}
	}
	initiators := slices.Clone(s.Initiators)
	if initiators == nil {
		initiators = []string{}
	}
	include := s.IncludeSessionMetadata != nil && *s.IncludeSessionMetadata
	return map[string]any{"backchannel_logout_urls": urls, "backchannel_logout_initiators": map[string]any{"mode": s.InitiatorsMode, "selected_initiators": initiators}, "backchannel_logout_session_metadata": map[string]any{"include": include}}
}
