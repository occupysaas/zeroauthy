package store

import (
	"context"
	"errors"
	"slices"
)

type OIDCSupport struct {
	IsAllowed      bool     `json:"is_allowed"`
	AllowAllScopes *bool    `json:"allow_all_scopes,omitempty"`
	AllowedScopes  []string `json:"allowed_scopes"`
}

func (s *OIDCSupport) Clone() *OIDCSupport {
	if s == nil {
		return nil
	}
	out := *s
	out.AllowedScopes = slices.Clone(s.AllowedScopes)
	if s.AllowAllScopes != nil {
		v := *s.AllowAllScopes
		out.AllowAllScopes = &v
	}
	return &out
}

type OIDCLogout struct {
	BackchannelURLs        []string
	InitiatorsMode         string
	Initiators             []string
	IncludeSessionMetadata *bool
}

func (s *OIDCLogout) Clone() *OIDCLogout {
	if s == nil {
		return nil
	}
	out := *s
	out.BackchannelURLs = slices.Clone(s.BackchannelURLs)
	out.Initiators = slices.Clone(s.Initiators)
	if s.IncludeSessionMetadata != nil {
		v := *s.IncludeSessionMetadata
		out.IncludeSessionMetadata = &v
	}
	return &out
}

var ErrOIDCLogoutUnavailable = errors.New("store: oidc_logout.v1 unavailable")

type OIDCLogoutSupporter interface{ CheckOIDCLogoutSupport(context.Context) error }

func CheckOIDCLogoutSupport(ctx context.Context, s Store) error {
	if capability, ok := s.(OIDCLogoutSupporter); ok {
		return capability.CheckOIDCLogoutSupport(ctx)
	}
	return nil
}
func ClientNeedsOIDCLogout(c *Client) bool {
	return c != nil && (c.OIDCSupport != nil || c.OIDCLogout != nil || c.IDTokenAlg != "" && c.IDTokenAlg != "RS256")
}

// SessionOrganizationRecorder atomically records a participant and its latest
// validated organization. This state is separate from user-editable metadata.
type SessionOrganizationRecorder interface {
	RecordClientOrganization(ctx context.Context, tenantID, id, clientID, orgID string) error
}
