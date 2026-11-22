package logout

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"maps"
	"net/url"
	"slices"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// token takes a server-derived issuer and one of this session's participants.
// It never copies authentication claims, a nonce, or a client signing key.
func (s *Service) token(ctx context.Context, tid, issuer string, client *store.Client, session *store.LoginSession) (string, error) {
	if s.Keys == nil || tid == "" || client == nil || session == nil || client.TenantID != tid || session.TenantID != tid || client.ClientID == "" || session.ID == "" || session.UserID == "" || !slices.Contains(session.ClientIDs, client.ClientID) {
		return "", store.ErrInvalid
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", store.ErrInvalid
	}
	now := s.now().Unix()
	claims := map[string]any{"iss": issuer, "aud": client.ClientID, "sub": session.UserID, "sid": session.ID, "iat": now, "exp": now + 120, "jti": secrets.RandomString(32), "events": map[string]any{logoutEvent: map[string]any{}}}
	if settings := client.OIDCLogout; settings != nil && settings.IncludeSessionMetadata != nil && *settings.IncludeSessionMetadata {
		metadata := maps.Clone(session.Metadata)
		if metadata == nil {
			metadata = map[string]string{}
		}
		claims["session_metadata"] = metadata
	}
	tokenType := "logout+jwt"
	if s.Compat.LogoutTokenTypJWT {
		tokenType = "JWT"
	}
	return s.Keys.SignWithType(ctx, tid, claims, tokenType)
}
