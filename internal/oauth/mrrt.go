package oauth

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const disallowedMRRTAudience = "audience is not allowed by the refresh token policies"

// mrrtExchange authorizes the access token independently of the refresh
// family's stored audience and scopes, which rotation and conversion retain.
type mrrtExchange struct {
	family             *store.RefreshToken
	audience           string
	managementAudience string
	requested          []string
	// Captured from the actual authorization used by the signer. Actions may
	// have run between the first API lookup and signing.
	signedAPI   *store.ResourceServer
	issued      []string
	permissions []string
	frozenRBAC  bool
}

func (m mrrtExchange) resolve(ctx context.Context, h *Handlers, st store.Store, c *store.Client, rs *store.ResourceServer) ([]string, *Error) {
	if !c.IsFirstParty || len(c.RefreshToken.Policies) == 0 {
		return nil, invalidRequest(disallowedMRRTAudience)
	}
	cross := m.audience != m.family.Audience
	i := slices.IndexFunc(c.RefreshToken.Policies, func(p store.MRRTPolicy) bool { return p.Audience == m.audience })
	if cross && (i < 0 || rs == nil || !rs.SkipConsentForVerifiableFirstPartyClients) {
		return nil, invalidRequest(disallowedMRRTAudience)
	}
	var policy []string
	if i >= 0 {
		if rs == nil || rs.IsSystem || rs.Identifier == tenant.OperatorAudience || rs.Identifier == m.managementAudience {
			return nil, invalidRequest(disallowedMRRTAudience)
		}
		// A policy authorizes API permissions. OIDC and refresh scopes come
		// from the family; a policy cannot add a UserInfo audience or ID token.
		defined := make(map[string]bool, len(rs.Scopes))
		for _, def := range rs.Scopes {
			defined[def.Value] = true
		}
		for _, s := range c.RefreshToken.Policies[i].Scope {
			if !defined[s] || slices.Contains(oidcScopes, s) || s == "offline_access" || s == "online_access" || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
				continue
			}
			policy = append(policy, s)
			delete(defined, s)
		}
	}
	if cross {
		if len(m.requested) > 0 {
			return actions.CeilingOf(m.requested, policy), nil
		}
		return policy, nil
	}
	scopes := m.family.Scopes
	if len(m.requested) > 0 {
		scopes = actions.CeilingOf(m.requested, scopes)
	}
	// Clone before appending so stored scopes remain the family's ceiling.
	target := userScopes(append(slices.Clone(scopes), policy...), rs, true)
	return h.consentedAdditionsWithStore(ctx, st, c.TenantID, c, m.family.UserID, rs, m.family.Scopes, target)
}

// checkMint runs under the transaction's tenant lock. The scopes and API
// settings used to sign the response must still be eligible at consumption.
func (m mrrtExchange) checkMint(ctx context.Context, h *Handlers, tx store.Store, c *store.Client) error {
	if err := store.CheckRefreshTokensIISupport(ctx, tx); err != nil {
		return serverError()
	}
	if !slices.Contains(c.GrantTypes, "refresh_token") {
		return invalidRequest("the refresh grant is no longer enabled")
	}
	var current *store.ResourceServer
	if signed := m.signedAPI; signed != nil {
		var err error
		current, err = tx.ResourceServers().GetByIdentifier(ctx, c.TenantID, m.audience)
		if errors.Is(err, store.ErrNotFound) {
			return invalidRequest(disallowedMRRTAudience)
		}
		if err != nil {
			return err
		}
		if current.ID != signed.ID || current.IsSystem != signed.IsSystem ||
			current.SigningAlg != signed.SigningAlg || !bytes.Equal(current.SigningSecretSealed, signed.SigningSecretSealed) ||
			current.TokenLifetime != signed.TokenLifetime || current.TokenDialect != signed.TokenDialect || current.EnforcePolicies != signed.EnforcePolicies {
			return invalidRequest("the API configuration changed during refresh")
		}
	}
	scopes, oerr := m.resolve(ctx, h, tx, c, current)
	if oerr != nil {
		return oerr
	}
	d, oerr := h.decideWithStore(ctx, tx, c.TenantID, access.Refresh, c, current, scopes)
	if oerr != nil {
		return oerr
	}
	for _, s := range m.issued {
		if !slices.Contains(d.Scopes, s) {
			return invalidRequest(disallowedMRRTAudience)
		}
	}
	if current == nil || !current.EnforcePolicies {
		return nil
	}
	// Actions freeze assignments for their flow. Without an Action snapshot,
	// permission removals during signing apply to this exchange as well.
	var permissions []string
	if m.frozenRBAC {
		for _, s := range current.Scopes {
			permissions = append(permissions, s.Value)
		}
	} else {
		snap, err := store.OrganizationAuthorizationSnapshot(ctx, tx, c.TenantID, m.family.UserID, m.family.OrganizationID, m.audience)
		if err != nil {
			return err
		}
		if snap == nil || snap.API == nil || snap.API.ID != current.ID {
			return serverError()
		}
		permissions = snap.Permissions
	}
	for _, s := range m.issued {
		if !slices.Contains(oidcScopes, s) && s != "offline_access" && s != "online_access" && !slices.Contains(permissions, s) {
			return invalidRequest(disallowedMRRTAudience)
		}
	}
	for _, s := range m.permissions {
		if !slices.Contains(permissions, s) {
			return invalidRequest(disallowedMRRTAudience)
		}
	}
	return nil
}
