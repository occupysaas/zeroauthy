package memory

import (
	"bytes"
	"maps"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func cloneTenant(t *store.Tenant) *store.Tenant { return t.Clone() }

func cloneClient(c *store.Client) *store.Client {
	out := *c
	out.Secrets = make([]store.ClientSecret, len(c.Secrets))
	for i, sec := range c.Secrets {
		out.Secrets[i] = sec
		out.Secrets[i].Sealed = bytes.Clone(sec.Sealed)
		if sec.ExpiresAt != nil {
			exp := *sec.ExpiresAt
			out.Secrets[i].ExpiresAt = &exp
		}
	}
	if c.Secrets == nil {
		out.Secrets = nil
	}
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.Callbacks = slices.Clone(c.Callbacks)
	out.AllowedLogoutURLs = slices.Clone(c.AllowedLogoutURLs)
	out.WebOrigins = slices.Clone(c.WebOrigins)
	out.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	if c.SkipNonVerifiableCallbackURIConfirmationPrompt != nil {
		v := *c.SkipNonVerifiableCallbackURIConfirmationPrompt
		out.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
	}
	return &out
}

func cloneResourceServer(rs *store.ResourceServer) *store.ResourceServer {
	out := *rs
	out.Scopes = slices.Clone(rs.Scopes)
	return &out
}

func cloneClientGrant(g *store.ClientGrant) *store.ClientGrant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &out
}

func cloneUserGrant(g *store.UserGrant) *store.UserGrant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &out
}

func cloneSigningKey(k *store.SigningKey) *store.SigningKey {
	out := *k
	out.PrivateKey = slices.Clone(k.PrivateKey)
	out.PublicJWK = slices.Clone(k.PublicJWK)
	out.CertificateDER = slices.Clone(k.CertificateDER)
	out.CurrentSince = cloneTime(k.CurrentSince)
	out.CurrentUntil = cloneTime(k.CurrentUntil)
	out.RevokedAt = cloneTime(k.RevokedAt)
	return &out
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneCustomSigningKeySet(s *store.CustomSigningKeySet) *store.CustomSigningKeySet {
	out := *s
	out.JWKS = slices.Clone(s.JWKS)
	return &out
}

func cloneConnection(c *store.Connection) *store.Connection {
	out := *c
	out.EnabledClients = slices.Clone(c.EnabledClients)
	out.CustomScripts = maps.Clone(c.CustomScripts)
	out.ConfigurationSealed = bytes.Clone(c.ConfigurationSealed)
	out.FederationSecretsSealed = bytes.Clone(c.FederationSecretsSealed)
	out.PasswordOptions.Complexity.CharacterTypes = slices.Clone(c.PasswordOptions.Complexity.CharacterTypes)
	out.PasswordOptions.Dictionary.Custom = slices.Clone(c.PasswordOptions.Dictionary.Custom)
	out.PasswordOptions.ProfileData.BlockedFields = slices.Clone(c.PasswordOptions.ProfileData.BlockedFields)
	out.Extra = cloneJSON(c.Extra)
	return &out
}

func cloneUser(u *store.User) *store.User {
	out := *u
	out.Identities = slices.Clone(u.Identities)
	for i := range out.Identities {
		out.Identities[i].ProfileData = cloneJSON(out.Identities[i].ProfileData)
	}
	if u.LastLogin != nil {
		t := *u.LastLogin
		out.LastLogin = &t
	}
	out.UserMetadata = cloneJSON(u.UserMetadata)
	out.AppMetadata = cloneJSON(u.AppMetadata)
	return &out
}

func cloneSession(s *store.LoginSession) *store.LoginSession {
	out := *s
	out.ClientIDs = slices.Clone(s.ClientIDs)
	return &out
}

func cloneAuthTransaction(t *store.AuthTransaction) *store.AuthTransaction {
	out := *t
	out.Params = maps.Clone(t.Params)
	out.HostedState = t.HostedState.Clone()
	return &out
}

func cloneAuthCode(c *store.AuthCode) *store.AuthCode {
	out := *c
	out.Scopes = slices.Clone(c.Scopes)
	out.ActionEffects = slices.Clone(c.ActionEffects)
	if c.UsedAt != nil {
		t := *c.UsedAt
		out.UsedAt = &t
	}
	if c.ReplayedAt != nil {
		t := *c.ReplayedAt
		out.ReplayedAt = &t
	}
	return &out
}

func clonePushedAuthRequest(p *store.PushedAuthRequest) *store.PushedAuthRequest {
	out := *p
	out.Params = maps.Clone(p.Params)
	if p.UsedAt != nil {
		t := *p.UsedAt
		out.UsedAt = &t
	}
	return &out
}

func cloneDeviceCode(d *store.DeviceCode) *store.DeviceCode {
	out := *d
	out.Scopes = slices.Clone(d.Scopes)
	out.GrantedScopes = slices.Clone(d.GrantedScopes)
	out.ActionEffects = slices.Clone(d.ActionEffects)
	if d.LastPolledAt != nil {
		t := *d.LastPolledAt
		out.LastPolledAt = &t
	}
	if d.ExpiredReportedAt != nil {
		t := *d.ExpiredReportedAt
		out.ExpiredReportedAt = &t
	}
	return &out
}

func cloneRefreshToken(t *store.RefreshToken) *store.RefreshToken {
	out := *t
	out.Scopes = slices.Clone(t.Scopes)
	if t.RotatedAt != nil {
		v := *t.RotatedAt
		out.RotatedAt = &v
	}
	if t.RevokedAt != nil {
		v := *t.RevokedAt
		out.RevokedAt = &v
	}
	return &out
}

func cloneResetTicket(t *store.PasswordResetTicket) *store.PasswordResetTicket {
	out := *t
	if t.UsedAt != nil {
		v := *t.UsedAt
		out.UsedAt = &v
	}
	return &out
}

func cloneVerifyTicket(t *store.EmailVerificationTicket) *store.EmailVerificationTicket {
	out := *t
	if t.UsedAt != nil {
		v := *t.UsedAt
		out.UsedAt = &v
	}
	return &out
}

// cloneJSON deep-copies JSON-like values (maps, slices, scalars).
func cloneJSON(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneJSONValue(v)
	}
	return out
}

func cloneJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneJSON(x)
	case []any:
		c := make([]any, len(x))
		for i, e := range x {
			c[i] = cloneJSONValue(e)
		}
		return c
	default:
		return x
	}
}
