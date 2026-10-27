// Package grpcstore carries store.Store over the gRPC storage plugin
// protocol (proto/store/v1). This file is the lossless codec between the
// domain types and the protocol messages: nil and empty slices and maps stay
// distinct, pointer presence is preserved, and times round-trip in UTC.
package grpcstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// ---- times ----

func tsToPB(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

func tsFromPB(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime().UTC()
}

func optTSToPB(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optTSFromPB(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime().UTC()
	return &t
}

// checkTS rejects out-of-range timestamps; absent ones are fine.
func checkTS(tss ...*timestamppb.Timestamp) error {
	for _, ts := range tss {
		if ts == nil {
			continue
		}
		if err := ts.CheckValid(); err != nil {
			return fmt.Errorf("grpcstore: invalid timestamp: %w", err)
		}
	}
	return nil
}

// ---- slices and maps ----

func stringsToPB(v []string) *storev1.StringList {
	if v == nil {
		return nil
	}
	return &storev1.StringList{Values: v}
}

func stringsFromPB(l *storev1.StringList) []string {
	if l == nil {
		return nil
	}
	return append([]string{}, l.Values...)
}

func stringMapToPB(m map[string]string) *storev1.StringMap {
	if m == nil {
		return nil
	}
	return &storev1.StringMap{Values: m}
}

func stringMapFromPB(m *storev1.StringMap) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m.Values))
	for k, v := range m.Values {
		out[k] = v
	}
	return out
}

// cloneBool copies an optional bool so the result never aliases the input.
func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

// optBytes copies b, mapping empty to nil: proto3 bytes cannot tell the two
// apart, so the store side always sees nil for "unset".
func optBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return cloneBytes(b)
}

// ---- errors ----

func errToPB(err error) *storev1.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrRBACUnavailable):
		return &storev1.Error{Kind: storev1.Error_KIND_RBAC_UNAVAILABLE, Message: err.Error()}
	case errors.Is(err, store.ErrFederationUnavailable):
		return &storev1.Error{Kind: storev1.Error_KIND_FEDERATION_UNAVAILABLE, Message: err.Error()}
	case errors.Is(err, store.ErrCustomDomainRepositoryUnavailable):
		return &storev1.Error{Kind: storev1.Error_KIND_CUSTOM_DOMAIN_UNAVAILABLE, Message: err.Error()}
	case errors.Is(err, store.ErrTLSAssetRepositoryUnavailable):
		return &storev1.Error{Kind: storev1.Error_KIND_TLS_ASSET_UNAVAILABLE, Message: err.Error()}
	case errors.Is(err, store.ErrNotFound):
		return &storev1.Error{Kind: storev1.Error_KIND_NOT_FOUND, Message: err.Error()}
	case errors.Is(err, store.ErrConflict):
		return &storev1.Error{Kind: storev1.Error_KIND_CONFLICT, Message: err.Error()}
	case errors.Is(err, store.ErrInvalid):
		return &storev1.Error{Kind: storev1.Error_KIND_INVALID, Message: err.Error()}
	case errors.Is(err, store.ErrAlreadyUsed):
		return &storev1.Error{Kind: storev1.Error_KIND_ALREADY_USED, Message: err.Error()}
	default:
		return &storev1.Error{Kind: storev1.Error_KIND_UNSPECIFIED, Message: err.Error()}
	}
}

// errFromPB returns the sentinel itself for the known kinds, so callers'
// errors.Is checks and == comparisons both work.
func errFromPB(e *storev1.Error) error {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case storev1.Error_KIND_RBAC_UNAVAILABLE:
		return store.ErrRBACUnavailable
	case storev1.Error_KIND_FEDERATION_UNAVAILABLE:
		return store.ErrFederationUnavailable
	case storev1.Error_KIND_CUSTOM_DOMAIN_UNAVAILABLE:
		return store.ErrCustomDomainRepositoryUnavailable
	case storev1.Error_KIND_TLS_ASSET_UNAVAILABLE:
		return store.ErrTLSAssetRepositoryUnavailable
	case storev1.Error_KIND_NOT_FOUND:
		return store.ErrNotFound
	case storev1.Error_KIND_CONFLICT:
		return store.ErrConflict
	case storev1.Error_KIND_INVALID:
		return store.ErrInvalid
	case storev1.Error_KIND_ALREADY_USED:
		return store.ErrAlreadyUsed
	default:
		return errors.New(e.Message)
	}
}

// ---- tenant ----

func tenantToPB(t *store.Tenant) (*storev1.Tenant, error) {
	if t == nil {
		return nil, nil
	}
	pb := &storev1.Tenant{
		CanonicalHost: t.CanonicalHost,
		Id:            t.ID, Name: t.Name, FriendlyName: t.FriendlyName,
		SupportEmail: t.SupportEmail, SupportUrl: t.SupportURL, PictureUrl: t.PictureURL,
		ProtectionSettingsInitialized: t.ProtectionSettingsInitialized,
		EphemeralSessionLifetime:      int64(t.EphemeralSessionLifetime), IdleEphemeralSessionLifetime: int64(t.IdleEphemeralSessionLifetime), SessionCookieMode: t.SessionCookieMode,
		Domains: stringsToPB(t.Domains), DefaultAudience: t.DefaultAudience,
		AllowedLogoutUrls: stringsToPB(t.AllowedLogoutURLs), EnabledLocales: stringsToPB(t.EnabledLocales),
		SessionLifetime: int64(t.SessionLifetime), IdleSessionLifetime: int64(t.IdleSessionLifetime),
		Branding:         &storev1.Branding{LogoUrl: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor},
		DefaultDirectory: t.DefaultDirectory, CreatedAt: tsToPB(t.CreatedAt),
		SkipNonVerifiableCallbackUriConfirmationPrompt: t.SkipNonVerifiableCallbackURIConfirmationPrompt,
		UseScopeDescriptionsForConsent:                 t.UseScopeDescriptionsForConsent,
		PushedAuthorizationRequestsSupported:           t.PushedAuthorizationRequestsSupported,
		DeviceFlowCharset:                              t.DeviceFlowCharset, DeviceFlowMask: t.DeviceFlowMask,
		Reserved: t.Reserved, Seeded: t.Seeded, Origin: t.Origin,
		IdentityEpoch: t.IdentityEpoch,
	}

	for _, item := range []struct {
		name    string
		value   any
		dest    *[]byte
		present bool
	}{
		{"tenant settings", t.SettingsExtra, &pb.SettingsExtraJson, t.SettingsExtra != nil},
		{"settings presence", t.SettingsPresence, &pb.SettingsPresenceJson, t.SettingsPresence != nil},
		{"protection settings", t.ProtectionSettings, &pb.ProtectionSettingsJson, true},
	} {
		if item.present {
			b, err := json.Marshal(item.value)
			if err != nil {
				return nil, fmt.Errorf("grpcstore: encode %s: %w", item.name, err)
			}
			*item.dest = b
		}
	}
	if t.CustomText != nil {
		b, err := json.Marshal(t.CustomText)
		if err != nil {
			return nil, fmt.Errorf("grpcstore: encode custom text: %w", err)
		}
		pb.CustomTextJson = b
	}
	return pb, nil
}

func tenantFromPB(pb *storev1.Tenant) (*store.Tenant, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	t := &store.Tenant{
		CanonicalHost: pb.CanonicalHost,
		ID:            pb.Id, Name: pb.Name, FriendlyName: pb.FriendlyName,
		SupportEmail: pb.SupportEmail, SupportURL: pb.SupportUrl, PictureURL: pb.PictureUrl,
		ProtectionSettingsInitialized: pb.ProtectionSettingsInitialized,
		EphemeralSessionLifetime:      int(pb.EphemeralSessionLifetime), IdleEphemeralSessionLifetime: int(pb.IdleEphemeralSessionLifetime), SessionCookieMode: pb.SessionCookieMode,
		Domains: stringsFromPB(pb.Domains), DefaultAudience: pb.DefaultAudience,
		AllowedLogoutURLs: stringsFromPB(pb.AllowedLogoutUrls), EnabledLocales: stringsFromPB(pb.EnabledLocales),
		SessionLifetime: int(pb.SessionLifetime), IdleSessionLifetime: int(pb.IdleSessionLifetime),
		Branding:         store.Branding{LogoURL: pb.GetBranding().GetLogoUrl(), PrimaryColor: pb.GetBranding().GetPrimaryColor()},
		DefaultDirectory: pb.DefaultDirectory, CreatedAt: tsFromPB(pb.CreatedAt),
		SkipNonVerifiableCallbackURIConfirmationPrompt: pb.SkipNonVerifiableCallbackUriConfirmationPrompt,
		UseScopeDescriptionsForConsent:                 pb.UseScopeDescriptionsForConsent,
		PushedAuthorizationRequestsSupported:           pb.PushedAuthorizationRequestsSupported,
		DeviceFlowCharset:                              pb.DeviceFlowCharset, DeviceFlowMask: pb.DeviceFlowMask,
		Reserved: pb.Reserved, Seeded: pb.Seeded, Origin: pb.Origin,
		IdentityEpoch: pb.IdentityEpoch,
	}

	for _, item := range []struct {
		name string
		data []byte
		dest any
	}{
		{"tenant settings", pb.SettingsExtraJson, &t.SettingsExtra},
		{"settings presence", pb.SettingsPresenceJson, &t.SettingsPresence},
		{"protection settings", pb.ProtectionSettingsJson, &t.ProtectionSettings},
	} {
		if item.data != nil {
			// Retain Unmarshal's rejection of trailing data while preserving
			// exact JSON numbers in SettingsExtra and open CAPTCHA provider maps.
			if !json.Valid(item.data) {
				return nil, fmt.Errorf("grpcstore: decode %s: invalid JSON", item.name)
			}
			decoder := json.NewDecoder(bytes.NewReader(item.data))
			decoder.UseNumber()
			if err := decoder.Decode(item.dest); err != nil {
				return nil, fmt.Errorf("grpcstore: decode %s: %w", item.name, err)
			}
		}
	}
	if pb.CustomTextJson != nil {
		var ct store.CustomText
		if err := json.Unmarshal(pb.CustomTextJson, &ct); err != nil {
			return nil, fmt.Errorf("grpcstore: decode custom text: %w", err)
		}
		t.CustomText = ct
	}
	return t, nil
}

// ---- client ----

func clientToPB(c *store.Client) (*storev1.Client, error) {
	if c == nil {
		return nil, nil
	}
	pb := &storev1.Client{
		TenantId: c.TenantID, ClientId: c.ClientID, Name: c.Name, AppType: string(c.AppType),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		GrantTypes:              stringsToPB(c.GrantTypes), Callbacks: stringsToPB(c.Callbacks),
		AllowedLogoutUrls: stringsToPB(c.AllowedLogoutURLs), WebOrigins: stringsToPB(c.WebOrigins),
		AllowedOrigins:  stringsToPB(c.AllowedOrigins),
		IdTokenLifetime: int64(c.IDTokenLifetime),
		RefreshToken: &storev1.RefreshTokenPolicy{
			Rotating: c.RefreshToken.Rotating, Leeway: int64(c.RefreshToken.Leeway),
			Expiring: c.RefreshToken.Expiring, TokenLifetime: int64(c.RefreshToken.TokenLifetime),
			IdleTokenLifetime: int64(c.RefreshToken.IdleTokenLifetime),
		},
		CreatedAt:    tsToPB(c.CreatedAt),
		IsFirstParty: proto.Bool(c.IsFirstParty), ThirdPartySecurityMode: c.ThirdPartySecurityMode,
		RedirectionPolicy: c.RedirectionPolicy,
		SkipNonVerifiableCallbackUriConfirmationPrompt: cloneBool(c.SkipNonVerifiableCallbackURIConfirmationPrompt),
		RequirePushedAuthorizationRequests:             c.RequirePushedAuthorizationRequests,
		Origin:                                         c.Origin,
	}
	if c.Secrets != nil {
		pb.Secrets = &storev1.ClientSecretList{Values: make([]*storev1.ClientSecret, 0, len(c.Secrets))}
		for _, s := range c.Secrets {
			pb.Secrets.Values = append(pb.Secrets.Values, &storev1.ClientSecret{
				Hash: s.Hash, Sealed: optBytes(s.Sealed), CreatedAt: tsToPB(s.CreatedAt), ExpiresAt: optTSToPB(s.ExpiresAt)})
		}
	}
	return pb, nil
}

func clientFromPB(pb *storev1.Client) (*store.Client, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	rt := pb.GetRefreshToken()
	c := &store.Client{
		TenantID: pb.TenantId, ClientID: pb.ClientId, Name: pb.Name, AppType: store.AppType(pb.AppType),
		TokenEndpointAuthMethod: pb.TokenEndpointAuthMethod,
		GrantTypes:              stringsFromPB(pb.GrantTypes), Callbacks: stringsFromPB(pb.Callbacks),
		AllowedLogoutURLs: stringsFromPB(pb.AllowedLogoutUrls), WebOrigins: stringsFromPB(pb.WebOrigins),
		AllowedOrigins:  stringsFromPB(pb.AllowedOrigins),
		IDTokenLifetime: int(pb.IdTokenLifetime),
		RefreshToken: store.RefreshTokenPolicy{
			Rotating: rt.GetRotating(), Leeway: int(rt.GetLeeway()), Expiring: rt.GetExpiring(),
			TokenLifetime: int(rt.GetTokenLifetime()), IdleTokenLifetime: int(rt.GetIdleTokenLifetime()),
		},
		CreatedAt:    tsFromPB(pb.CreatedAt),
		IsFirstParty: pb.IsFirstParty == nil || *pb.IsFirstParty, ThirdPartySecurityMode: pb.ThirdPartySecurityMode,
		RedirectionPolicy: pb.RedirectionPolicy,
		SkipNonVerifiableCallbackURIConfirmationPrompt: cloneBool(pb.SkipNonVerifiableCallbackUriConfirmationPrompt),
		RequirePushedAuthorizationRequests:             pb.RequirePushedAuthorizationRequests,
		Origin:                                         pb.Origin,
	}
	if pb.Secrets != nil {
		c.Secrets = make([]store.ClientSecret, 0, len(pb.Secrets.Values))
		for _, s := range pb.Secrets.Values {
			if err := checkTS(s.GetCreatedAt(), s.GetExpiresAt()); err != nil {
				return nil, err
			}
			// Exactly one form is set. Neither means a plugin dropped the
			// sealed field (built before it existed): fail loudly instead
			// of storing or returning an unusable secret.
			if (s.GetHash() == "") == (len(s.GetSealed()) == 0) {
				return nil, fmt.Errorf("grpcstore: client %q: a client secret needs exactly one of hash and sealed (is the store plugin up to date?)", pb.ClientId)
			}
			c.Secrets = append(c.Secrets, store.ClientSecret{
				Hash: s.GetHash(), Sealed: optBytes(s.GetSealed()), CreatedAt: tsFromPB(s.GetCreatedAt()), ExpiresAt: optTSFromPB(s.GetExpiresAt())})
		}
	}
	return c, nil
}

// ---- resource server ----

func resourceServerToPB(r *store.ResourceServer) (*storev1.ResourceServer, error) {
	if r == nil {
		return nil, nil
	}
	pb := &storev1.ResourceServer{
		TenantId: r.TenantID, Id: r.ID, Identifier: r.Identifier, Name: r.Name, EnforcePolicies: r.EnforcePolicies, TokenDialect: r.TokenDialect,
		SigningAlg: r.SigningAlg, TokenLifetime: int64(r.TokenLifetime),
		AllowOfflineAccess: r.AllowOfflineAccess, CreatedAt: tsToPB(r.CreatedAt),
		SkipConsentForVerifiableFirstPartyClients: proto.Bool(r.SkipConsentForVerifiableFirstPartyClients),
		UserPolicy: r.SubjectTypeAuthorization.User, ClientPolicy: r.SubjectTypeAuthorization.Client,
		IsSystem: r.IsSystem, Origin: r.Origin, TokenLifetimeForWeb: int64(r.TokenLifetimeForWeb),
	}
	if r.Scopes != nil {
		pb.Scopes = &storev1.ScopeList{Values: make([]*storev1.Scope, 0, len(r.Scopes))}
		for _, s := range r.Scopes {
			pb.Scopes.Values = append(pb.Scopes.Values, &storev1.Scope{Value: s.Value, Description: s.Description})
		}
	}
	return pb, nil
}

func resourceServerFromPB(pb *storev1.ResourceServer) (*store.ResourceServer, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	r := &store.ResourceServer{
		TenantID: pb.TenantId, ID: pb.Id, Identifier: pb.Identifier, Name: pb.Name, EnforcePolicies: pb.EnforcePolicies, TokenDialect: pb.TokenDialect,
		SigningAlg: pb.SigningAlg, TokenLifetime: int(pb.TokenLifetime),
		AllowOfflineAccess: pb.AllowOfflineAccess, CreatedAt: tsFromPB(pb.CreatedAt),
		SkipConsentForVerifiableFirstPartyClients: pb.SkipConsentForVerifiableFirstPartyClients == nil || *pb.SkipConsentForVerifiableFirstPartyClients,
		SubjectTypeAuthorization:                  store.SubjectTypeAuthorization{User: pb.UserPolicy, Client: pb.ClientPolicy},
		IsSystem:                                  pb.IsSystem,
		Origin:                                    pb.Origin,
		TokenLifetimeForWeb:                       int(pb.TokenLifetimeForWeb),
	}
	if pb.Scopes != nil {
		r.Scopes = make([]store.Scope, 0, len(pb.Scopes.Values))
		for _, s := range pb.Scopes.Values {
			r.Scopes = append(r.Scopes, store.Scope{Value: s.GetValue(), Description: s.GetDescription()})
		}
	}
	return r, nil
}

// ---- client grant ----

func clientGrantToPB(g *store.ClientGrant) (*storev1.ClientGrant, error) {
	if g == nil {
		return nil, nil
	}
	return &storev1.ClientGrant{
		TenantId: g.TenantID, Id: g.ID, ClientId: g.ClientID, Audience: g.Audience,
		Scopes: stringsToPB(g.Scopes), CreatedAt: tsToPB(g.CreatedAt), SubjectType: g.SubjectType, Origin: g.Origin, AllowAllScopes: g.AllowAllScopes,
	}, nil
}

func clientGrantFromPB(pb *storev1.ClientGrant) (*store.ClientGrant, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	// Plugins older than Plan 9 leave subject_type empty: a client grant.
	subjectType := pb.SubjectType
	if subjectType == "" {
		subjectType = store.SubjectTypeClient
	}
	return &store.ClientGrant{
		TenantID: pb.TenantId, ID: pb.Id, ClientID: pb.ClientId, Audience: pb.Audience,
		Scopes: stringsFromPB(pb.Scopes), CreatedAt: tsFromPB(pb.CreatedAt), SubjectType: subjectType, Origin: pb.Origin, AllowAllScopes: pb.AllowAllScopes,
	}, nil
}

// ---- user grant ----

func userGrantToPB(g *store.UserGrant) (*storev1.UserGrant, error) {
	if g == nil {
		return nil, nil
	}
	return &storev1.UserGrant{
		TenantId: g.TenantID, Id: g.ID, ClientId: g.ClientID, UserId: g.UserID, Audience: g.Audience,
		Scopes: stringsToPB(g.Scopes), CreatedAt: tsToPB(g.CreatedAt), UpdatedAt: tsToPB(g.UpdatedAt),
	}, nil
}

func userGrantFromPB(pb *storev1.UserGrant) (*store.UserGrant, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt, pb.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.UserGrant{
		TenantID: pb.TenantId, ID: pb.Id, ClientID: pb.ClientId, UserID: pb.UserId, Audience: pb.Audience,
		Scopes: stringsFromPB(pb.Scopes), CreatedAt: tsFromPB(pb.CreatedAt), UpdatedAt: tsFromPB(pb.UpdatedAt),
	}, nil
}

// ---- signing key ----

func signingKeyToPB(k *store.SigningKey) (*storev1.SigningKey, error) {
	if k == nil {
		return nil, nil
	}
	return &storev1.SigningKey{
		TenantId: k.TenantID, Kid: k.KID, Alg: k.Alg, Status: string(k.Status),
		PrivateKey: cloneBytes(k.PrivateKey), PublicJwk: cloneBytes(k.PublicJWK), CreatedAt: tsToPB(k.CreatedAt),
		CertificateDer: cloneBytes(k.CertificateDER), CurrentSince: optTSToPB(k.CurrentSince),
		CurrentUntil: optTSToPB(k.CurrentUntil), RevokedAt: optTSToPB(k.RevokedAt),
	}, nil
}

func signingKeyFromPB(pb *storev1.SigningKey) (*store.SigningKey, error) {
	if pb == nil {
		return nil, nil
	}
	for _, ts := range []*timestamppb.Timestamp{pb.CreatedAt, pb.CurrentSince, pb.CurrentUntil, pb.RevokedAt} {
		if err := checkTS(ts); err != nil {
			return nil, err
		}
	}
	return &store.SigningKey{
		TenantID: pb.TenantId, KID: pb.Kid, Alg: pb.Alg, Status: store.KeyStatus(pb.Status),
		PrivateKey: cloneBytes(pb.PrivateKey), PublicJWK: cloneBytes(pb.PublicJwk), CreatedAt: tsFromPB(pb.CreatedAt),
		CertificateDER: cloneBytes(pb.CertificateDer), CurrentSince: optTSFromPB(pb.CurrentSince),
		CurrentUntil: optTSFromPB(pb.CurrentUntil), RevokedAt: optTSFromPB(pb.RevokedAt),
	}, nil
}

func signingKeyRotationToPB(r *store.SigningKeyRotation) (*storev1.SigningKeyRotation, error) {
	if r == nil {
		return nil, nil
	}
	curr, err := signingKeyToPB(r.Current)
	if err != nil {
		return nil, err
	}
	next, err := signingKeyToPB(r.Next)
	if err != nil {
		return nil, err
	}
	return &storev1.SigningKeyRotation{Current: curr, Next: next}, nil
}

func signingKeyRotationFromPB(pb *storev1.SigningKeyRotation) (*store.SigningKeyRotation, error) {
	if pb == nil {
		return nil, nil
	}
	curr, err := signingKeyFromPB(pb.Current)
	if err != nil {
		return nil, err
	}
	next, err := signingKeyFromPB(pb.Next)
	if err != nil {
		return nil, err
	}
	return &store.SigningKeyRotation{Current: curr, Next: next}, nil
}

func customSigningKeySetToPB(set *store.CustomSigningKeySet) (*storev1.CustomSigningKeySet, error) {
	if set == nil {
		return nil, nil
	}
	return &storev1.CustomSigningKeySet{TenantId: set.TenantID, Jwks: cloneBytes(set.JWKS)}, nil
}

func customSigningKeySetFromPB(pb *storev1.CustomSigningKeySet) (*store.CustomSigningKeySet, error) {
	if pb == nil {
		return nil, nil
	}
	return &store.CustomSigningKeySet{TenantID: pb.TenantId, JWKS: cloneBytes(pb.Jwks)}, nil
}

func emailProviderToPB(p *store.EmailProvider) (*storev1.EmailProvider, error) {
	if p == nil {
		return nil, nil
	}
	b, err := json.Marshal(p.PublicConfig)
	if err != nil {
		return nil, err
	}
	return &storev1.EmailProvider{TenantId: p.TenantID, Name: p.Name, Enabled: p.Enabled, DefaultFrom: p.DefaultFrom, PublicConfigJson: string(b), SealedCredentials: cloneBytes(p.SealedCredentials), Revision: p.Revision}, nil
}
func emailProviderFromPB(pb *storev1.EmailProvider) (*store.EmailProvider, error) {
	if pb == nil {
		return nil, nil
	}
	p := &store.EmailProvider{TenantID: pb.TenantId, Name: pb.Name, Enabled: pb.Enabled, DefaultFrom: pb.DefaultFrom, SealedCredentials: cloneBytes(pb.SealedCredentials), Revision: pb.Revision}
	if pb.PublicConfigJson != "" && pb.PublicConfigJson != "null" {
		if err := json.Unmarshal([]byte(pb.PublicConfigJson), &p.PublicConfig); err != nil {
			return nil, err
		}
	}
	return p, nil
}
func emailTemplateToPB(t *store.EmailTemplate) (*storev1.EmailTemplate, error) {
	if t == nil {
		return nil, nil
	}
	b, err := json.Marshal(t.Fields)
	if err != nil {
		return nil, err
	}
	return &storev1.EmailTemplate{TenantId: t.TenantID, Name: t.Name, FieldsJson: string(b), Revision: t.Revision}, nil
}
func emailTemplateFromPB(pb *storev1.EmailTemplate) (*store.EmailTemplate, error) {
	if pb == nil {
		return nil, nil
	}
	t := &store.EmailTemplate{TenantID: pb.TenantId, Name: pb.Name, Revision: pb.Revision}
	if pb.FieldsJson != "" && pb.FieldsJson != "null" {
		if err := json.Unmarshal([]byte(pb.FieldsJson), &t.Fields); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// ---- connection ----

func connectionToPB(c *store.Connection) (*storev1.Connection, error) {
	if c == nil {
		return nil, nil
	}
	pb := &storev1.Connection{
		TenantId: c.TenantID, Id: c.ID, Name: c.Name, Strategy: c.Strategy,
		EnabledClients: stringsToPB(c.EnabledClients), DisableSignup: c.DisableSignup,
		RequiresUsername:             c.RequiresUsername,
		PasswordPolicy:               legacyPolicyToPB(c.PasswordOptions.Complexity),
		PasswordOptions:              passwordOptionsToPB(c.PasswordOptions),
		CreatedAt:                    tsToPB(c.CreatedAt),
		EnabledDatabaseCustomization: c.EnabledDatabaseCustomization, ImportMode: c.ImportMode,
		CustomScripts: stringMapToPB(c.CustomScripts), SetUserRootAttributes: c.SetUserRootAttributes,
		IsDomainConnection:   c.IsDomainConnection,
		BruteForceProtection: c.BruteForceProtection, UsernameMin: int64(c.UsernameMin), UsernameMax: int64(c.UsernameMax),
		Origin: c.Origin, FederationRevision: c.FederationRevision,
	}
	if len(c.FederationSecretsSealed) > 0 {
		pb.FederationSecretsSealed = cloneBytes(c.FederationSecretsSealed)
	}
	if c.Extra != nil {
		b, err := json.Marshal(c.Extra)
		if err != nil {
			return nil, err
		}
		pb.ExtraJson = b
	}
	// Empty sealed bytes normalize to absent (nil): the SQL drivers store
	// them as NULL too.
	if len(c.ConfigurationSealed) > 0 {
		pb.ConfigurationSealed = cloneBytes(c.ConfigurationSealed)
	}
	return pb, nil
}

func connectionFromPB(pb *storev1.Connection) (*store.Connection, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	c := &store.Connection{
		TenantID: pb.TenantId, ID: pb.Id, Name: pb.Name, Strategy: pb.Strategy,
		EnabledClients: stringsFromPB(pb.EnabledClients), DisableSignup: pb.DisableSignup,
		RequiresUsername:             pb.RequiresUsername,
		PasswordOptions:              passwordOptionsFromPB(pb),
		CreatedAt:                    tsFromPB(pb.CreatedAt),
		EnabledDatabaseCustomization: pb.EnabledDatabaseCustomization, ImportMode: pb.ImportMode,
		CustomScripts: stringMapFromPB(pb.CustomScripts), SetUserRootAttributes: pb.SetUserRootAttributes,
		IsDomainConnection:   pb.IsDomainConnection,
		BruteForceProtection: pb.BruteForceProtection, UsernameMin: int(pb.UsernameMin), UsernameMax: int(pb.UsernameMax),
		Origin: pb.Origin, FederationRevision: pb.FederationRevision,
	}
	if len(pb.FederationSecretsSealed) > 0 {
		c.FederationSecretsSealed = cloneBytes(pb.FederationSecretsSealed)
	}
	if pb.PasswordOptions == nil {
		// A plugin older than Plan 15 knows no such field; protection
		// was always on for what it stores.
		c.BruteForceProtection = true
	}
	if pb.ExtraJson != nil {
		var m map[string]any
		if err := json.Unmarshal(pb.ExtraJson, &m); err != nil {
			return nil, err
		}
		c.Extra = m
	}
	if len(pb.ConfigurationSealed) > 0 {
		c.ConfigurationSealed = cloneBytes(pb.ConfigurationSealed)
	}
	return c, nil
}

func passwordOptionsToPB(o store.PasswordOptions) *storev1.PasswordOptions {
	return &storev1.PasswordOptions{
		Complexity: &storev1.PasswordComplexity{
			MinLength:            int64(o.Complexity.MinLength),
			CharacterTypes:       stringsToPB(o.Complexity.CharacterTypes),
			CharacterTypeRule:    o.Complexity.CharacterTypeRule,
			IdenticalCharacters:  o.Complexity.IdenticalCharacters,
			SequentialCharacters: o.Complexity.SequentialCharacters,
			MaxLengthExceeded:    o.Complexity.MaxLengthExceeded,
			MinCharacterClasses:  int64(o.Complexity.MinCharacterClasses),
		},
		History:     &storev1.PasswordHistorySettings{Active: o.History.Active, Size: int64(o.History.Size)},
		Dictionary:  &storev1.PasswordDictionary{Active: o.Dictionary.Active, Default: o.Dictionary.Default, Custom: stringsToPB(o.Dictionary.Custom)},
		ProfileData: &storev1.PasswordProfileData{Active: o.ProfileData.Active, BlockedFields: stringsToPB(o.ProfileData.BlockedFields)},
	}
}

// passwordOptionsFromPB reads password_options; a connection from a plugin
// older than Plan 15 has only the legacy password_policy.
func passwordOptionsFromPB(pb *storev1.Connection) store.PasswordOptions {
	o := pb.PasswordOptions
	if o == nil {
		return store.PasswordOptions{Complexity: store.LegacyComplexity(
			int(pb.GetPasswordPolicy().GetMinLength()), int(pb.GetPasswordPolicy().GetRequireCharacterClasses()))}
	}
	return store.PasswordOptions{
		Complexity: store.PasswordComplexity{
			MinLength:            int(o.GetComplexity().GetMinLength()),
			CharacterTypes:       stringsFromPB(o.GetComplexity().GetCharacterTypes()),
			CharacterTypeRule:    o.GetComplexity().GetCharacterTypeRule(),
			IdenticalCharacters:  o.GetComplexity().GetIdenticalCharacters(),
			SequentialCharacters: o.GetComplexity().GetSequentialCharacters(),
			MaxLengthExceeded:    o.GetComplexity().GetMaxLengthExceeded(),
			MinCharacterClasses:  int(o.GetComplexity().GetMinCharacterClasses()),
		},
		History:     store.PasswordHistory{Active: o.GetHistory().GetActive(), Size: int(o.GetHistory().GetSize())},
		Dictionary:  store.PasswordDictionary{Active: o.GetDictionary().GetActive(), Default: o.GetDictionary().GetDefault(), Custom: stringsFromPB(o.GetDictionary().GetCustom())},
		ProfileData: store.PasswordProfileData{Active: o.GetProfileData().GetActive(), BlockedFields: stringsFromPB(o.GetProfileData().GetBlockedFields())},
	}
}

// legacyPolicyToPB is the password policy as a plugin older than Plan 15
// understands it: the minimum length and a class count (4 for all four
// types, 3 for three of the four, else MinCharacterClasses).
func legacyPolicyToPB(c store.PasswordComplexity) *storev1.PasswordPolicy {
	classes := c.MinCharacterClasses
	switch {
	case c.CharacterTypeRule == store.CharacterTypeRuleThreeOfFour && len(c.CharacterTypes) == len(store.CharacterTypes):
		classes = 3
	case len(c.CharacterTypes) == len(store.CharacterTypes):
		classes = 4
	}
	return &storev1.PasswordPolicy{MinLength: int64(c.MinLength), RequireCharacterClasses: int64(classes)}
}

// ---- user ----

func userToPB(u *store.User) (*storev1.User, error) {
	if u == nil {
		return nil, nil
	}
	pb := &storev1.User{
		TenantId: u.TenantID, UserId: u.UserID, Email: u.Email, EmailVerified: u.EmailVerified,
		Username: u.Username, Name: u.Name, Nickname: u.Nickname, Picture: u.Picture,
		GivenName: u.GivenName, FamilyName: u.FamilyName, Blocked: u.Blocked,
		LastLogin: optTSToPB(u.LastLogin), LoginsCount: int64(u.LoginsCount),
		CreatedAt: tsToPB(u.CreatedAt), UpdatedAt: tsToPB(u.UpdatedAt),
		PhoneNumber: u.PhoneNumber, PhoneVerified: u.PhoneVerified, LastIp: u.LastIP, Version: u.Version,
	}
	if u.UserMetadata != nil {
		b, err := json.Marshal(u.UserMetadata)
		if err != nil {
			return nil, fmt.Errorf("grpcstore: encode user metadata: %w", err)
		}
		pb.UserMetadataJson = b
	}
	if u.AppMetadata != nil {
		b, err := json.Marshal(u.AppMetadata)
		if err != nil {
			return nil, fmt.Errorf("grpcstore: encode app metadata: %w", err)
		}
		pb.AppMetadataJson = b
	}
	if u.Identities != nil {
		pb.Identities = &storev1.IdentityList{Values: make([]*storev1.Identity, 0, len(u.Identities))}
		for _, id := range u.Identities {
			pid := &storev1.Identity{Connection: id.Connection, Provider: id.Provider, UserId: id.UserID, PasswordHash: id.PasswordHash, ImportedHash: id.ImportedHash}
			if id.ProfileData != nil {
				b, err := json.Marshal(id.ProfileData)
				if err != nil {
					return nil, fmt.Errorf("grpcstore: encode identity profile data: %w", err)
				}
				pid.ProfileDataJson = b
			}
			pb.Identities.Values = append(pb.Identities.Values, pid)
		}
	}
	return pb, nil
}

func userFromPB(pb *storev1.User) (*store.User, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.LastLogin, pb.CreatedAt, pb.UpdatedAt); err != nil {
		return nil, err
	}
	u := &store.User{
		TenantID: pb.TenantId, UserID: pb.UserId, Email: pb.Email, EmailVerified: pb.EmailVerified,
		Username: pb.Username, Name: pb.Name, Nickname: pb.Nickname, Picture: pb.Picture,
		GivenName: pb.GivenName, FamilyName: pb.FamilyName, Blocked: pb.Blocked,
		LastLogin: optTSFromPB(pb.LastLogin), LoginsCount: int(pb.LoginsCount),
		CreatedAt: tsFromPB(pb.CreatedAt), UpdatedAt: tsFromPB(pb.UpdatedAt),
		PhoneNumber: pb.PhoneNumber, PhoneVerified: pb.PhoneVerified, LastIP: pb.LastIp, Version: pb.Version,
	}
	if pb.UserMetadataJson != nil {
		var m map[string]any
		if err := json.Unmarshal(pb.UserMetadataJson, &m); err != nil {
			return nil, fmt.Errorf("grpcstore: decode user metadata: %w", err)
		}
		u.UserMetadata = m
	}
	if pb.AppMetadataJson != nil {
		var m map[string]any
		if err := json.Unmarshal(pb.AppMetadataJson, &m); err != nil {
			return nil, fmt.Errorf("grpcstore: decode app metadata: %w", err)
		}
		u.AppMetadata = m
	}
	if pb.Identities != nil {
		u.Identities = make([]store.Identity, 0, len(pb.Identities.Values))
		for _, id := range pb.Identities.Values {
			sid := store.Identity{Connection: id.GetConnection(), Provider: id.GetProvider(), UserID: id.GetUserId(), PasswordHash: id.GetPasswordHash(), ImportedHash: id.GetImportedHash()}
			if id.ProfileDataJson != nil {
				if err := json.Unmarshal(id.ProfileDataJson, &sid.ProfileData); err != nil {
					return nil, fmt.Errorf("grpcstore: decode identity profile data: %w", err)
				}
			}
			u.Identities = append(u.Identities, sid)
		}
	}
	return u, nil
}

// ---- login session ----

func sessionToPB(s *store.LoginSession) (*storev1.LoginSession, error) {
	if s == nil {
		return nil, nil
	}
	return &storev1.LoginSession{
		Origin:     s.Origin,
		CookieMode: s.CookieMode,
		TenantId:   s.TenantID, Id: s.ID, TokenHash: s.TokenHash, UserId: s.UserID,
		Connection: s.Connection, AuthenticatedAt: tsToPB(s.AuthenticatedAt),
		ClientIds: stringsToPB(s.ClientIDs), ExpiresAt: tsToPB(s.ExpiresAt),
		IdleExpiresAt: tsToPB(s.IdleExpiresAt), CreatedAt: tsToPB(s.CreatedAt),
		UpdatedAt: tsToPB(s.UpdatedAt), LastInteractedAt: tsToPB(s.LastInteractedAt),
		InitialIp: s.InitialIP, InitialUserAgent: s.InitialUserAgent, LastIp: s.LastIP, LastUserAgent: s.LastUserAgent,
	}, nil
}

func sessionFromPB(pb *storev1.LoginSession) (*store.LoginSession, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.AuthenticatedAt, pb.ExpiresAt, pb.IdleExpiresAt, pb.CreatedAt, pb.UpdatedAt, pb.LastInteractedAt); err != nil {
		return nil, err
	}
	return &store.LoginSession{
		Origin:     pb.Origin,
		CookieMode: pb.CookieMode,
		TenantID:   pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, UserID: pb.UserId,
		Connection: pb.Connection, AuthenticatedAt: tsFromPB(pb.AuthenticatedAt),
		ClientIDs: stringsFromPB(pb.ClientIds), ExpiresAt: tsFromPB(pb.ExpiresAt),
		IdleExpiresAt: tsFromPB(pb.IdleExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
		UpdatedAt: tsFromPB(pb.UpdatedAt), LastInteractedAt: tsFromPB(pb.LastInteractedAt),
		InitialIP: pb.InitialIp, InitialUserAgent: pb.InitialUserAgent, LastIP: pb.LastIp, LastUserAgent: pb.LastUserAgent,
	}, nil
}

// ---- auth transaction ----

func authTransactionToPB(a *store.AuthTransaction) (*storev1.AuthTransaction, error) {
	if a == nil {
		return nil, nil
	}
	hosted, err := json.Marshal(a.HostedState)
	if err != nil {
		return nil, err
	}
	return &storev1.AuthTransaction{
		Origin:   a.Origin,
		TenantId: a.TenantID, Id: a.ID, CookieHash: a.CookieHash, CsrfToken: a.CSRFToken,
		ClientId: a.ClientID, Params: stringMapToPB(a.Params),
		ExpiresAt: tsToPB(a.ExpiresAt), CreatedAt: tsToPB(a.CreatedAt), HostedStateJson: string(hosted),
	}, nil
}

func authTransactionFromPB(pb *storev1.AuthTransaction) (*store.AuthTransaction, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	a := &store.AuthTransaction{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, ID: pb.Id, CookieHash: pb.CookieHash, CSRFToken: pb.CsrfToken,
		ClientID: pb.ClientId, Params: stringMapFromPB(pb.Params),
		ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}
	if pb.HostedStateJson != "" {
		if err := json.Unmarshal([]byte(pb.HostedStateJson), &a.HostedState); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// ---- auth code ----

func authCodeToPB(c *store.AuthCode) (*storev1.AuthCode, error) {
	if c == nil {
		return nil, nil
	}
	return &storev1.AuthCode{
		Origin:   c.Origin,
		TenantId: c.TenantID, CodeHash: c.CodeHash, ClientId: c.ClientID, RedirectUri: c.RedirectURI,
		UserId: c.UserID, SessionId: c.SessionID, Scopes: stringsToPB(c.Scopes), Audience: c.Audience,
		Nonce: c.Nonce, CodeChallenge: c.CodeChallenge, CodeChallengeMethod: c.CodeChallengeMethod,
		AuthTime: tsToPB(c.AuthTime), ExpiresAt: tsToPB(c.ExpiresAt), CreatedAt: tsToPB(c.CreatedAt),
		UsedAt: optTSToPB(c.UsedAt), ReplayedAt: optTSToPB(c.ReplayedAt),
	}, nil
}

func authCodeFromPB(pb *storev1.AuthCode) (*store.AuthCode, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.AuthTime, pb.ExpiresAt, pb.CreatedAt, pb.UsedAt, pb.ReplayedAt); err != nil {
		return nil, err
	}
	return &store.AuthCode{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, CodeHash: pb.CodeHash, ClientID: pb.ClientId, RedirectURI: pb.RedirectUri,
		UserID: pb.UserId, SessionID: pb.SessionId, Scopes: stringsFromPB(pb.Scopes), Audience: pb.Audience,
		Nonce: pb.Nonce, CodeChallenge: pb.CodeChallenge, CodeChallengeMethod: pb.CodeChallengeMethod,
		AuthTime: tsFromPB(pb.AuthTime), ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
		UsedAt: optTSFromPB(pb.UsedAt), ReplayedAt: optTSFromPB(pb.ReplayedAt),
	}, nil
}

// ---- pushed auth request ----

func pushedAuthRequestToPB(p *store.PushedAuthRequest) (*storev1.PushedAuthRequest, error) {
	if p == nil {
		return nil, nil
	}
	return &storev1.PushedAuthRequest{
		Origin:   p.Origin,
		TenantId: p.TenantID, IdHash: p.IDHash, ClientId: p.ClientID, Params: stringMapToPB(p.Params),
		ExpiresAt: tsToPB(p.ExpiresAt), CreatedAt: tsToPB(p.CreatedAt), UsedAt: optTSToPB(p.UsedAt),
	}, nil
}

func pushedAuthRequestFromPB(pb *storev1.PushedAuthRequest) (*store.PushedAuthRequest, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.CreatedAt, pb.UsedAt); err != nil {
		return nil, err
	}
	return &store.PushedAuthRequest{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, IDHash: pb.IdHash, ClientID: pb.ClientId, Params: stringMapFromPB(pb.Params),
		ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt), UsedAt: optTSFromPB(pb.UsedAt),
	}, nil
}

// ---- device code ----

func deviceCodeToPB(d *store.DeviceCode) (*storev1.DeviceCode, error) {
	if d == nil {
		return nil, nil
	}
	return &storev1.DeviceCode{
		Origin:   d.Origin,
		TenantId: d.TenantID, DeviceCodeHash: d.DeviceCodeHash, UserCodeHash: d.UserCodeHash, ClientId: d.ClientID,
		Scopes: stringsToPB(d.Scopes), Audience: d.Audience, Status: string(d.Status), UserId: d.UserID,
		GrantedScopes: stringsToPB(d.GrantedScopes),
		LastPolledAt:  optTSToPB(d.LastPolledAt), ExpiredReportedAt: optTSToPB(d.ExpiredReportedAt),
		ExpiresAt: tsToPB(d.ExpiresAt), CreatedAt: tsToPB(d.CreatedAt),
	}, nil
}

func deviceCodeFromPB(pb *storev1.DeviceCode) (*store.DeviceCode, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.LastPolledAt, pb.ExpiredReportedAt, pb.ExpiresAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.DeviceCode{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, DeviceCodeHash: pb.DeviceCodeHash, UserCodeHash: pb.UserCodeHash, ClientID: pb.ClientId,
		Scopes: stringsFromPB(pb.Scopes), Audience: pb.Audience, Status: store.DeviceCodeStatus(pb.Status), UserID: pb.UserId,
		GrantedScopes: stringsFromPB(pb.GrantedScopes),
		LastPolledAt:  optTSFromPB(pb.LastPolledAt), ExpiredReportedAt: optTSFromPB(pb.ExpiredReportedAt),
		ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}

// devicePollOutcomeFromPB rejects an outcome this host does not know rather
// than letting a misbehaving plugin steer the token endpoint with it.
func devicePollOutcomeFromPB(s string) (store.DevicePollOutcome, error) {
	switch o := store.DevicePollOutcome(s); o {
	case store.PollPending, store.PollSlowDown, store.PollApproved, store.PollDenied, store.PollExpired, store.PollInvalid:
		return o, nil
	}
	return "", fmt.Errorf("grpcstore: unknown device poll outcome %q", s)
}

// ---- refresh token ----

func refreshTokenToPB(r *store.RefreshToken) (*storev1.RefreshToken, error) {
	if r == nil {
		return nil, nil
	}
	return &storev1.RefreshToken{
		Origin:   r.Origin,
		TenantId: r.TenantID, Id: r.ID, TokenHash: r.TokenHash, FamilyId: r.FamilyID,
		ClientId: r.ClientID, UserId: r.UserID, SessionId: r.SessionID, Scopes: stringsToPB(r.Scopes),
		Audience: r.Audience, AuthTime: tsToPB(r.AuthTime), Rotating: r.Rotating,
		ExpiresAt: tsToPB(r.ExpiresAt), IdleExpiresAt: tsToPB(r.IdleExpiresAt),
		RotatedAt: optTSToPB(r.RotatedAt), RevokedAt: optTSToPB(r.RevokedAt), CreatedAt: tsToPB(r.CreatedAt),
	}, nil
}

func refreshTokenFromPB(pb *storev1.RefreshToken) (*store.RefreshToken, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.AuthTime, pb.ExpiresAt, pb.IdleExpiresAt, pb.RotatedAt, pb.RevokedAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.RefreshToken{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, FamilyID: pb.FamilyId,
		ClientID: pb.ClientId, UserID: pb.UserId, SessionID: pb.SessionId, Scopes: stringsFromPB(pb.Scopes),
		Audience: pb.Audience, AuthTime: tsFromPB(pb.AuthTime), Rotating: pb.Rotating,
		ExpiresAt: tsFromPB(pb.ExpiresAt), IdleExpiresAt: tsFromPB(pb.IdleExpiresAt),
		RotatedAt: optTSFromPB(pb.RotatedAt), RevokedAt: optTSFromPB(pb.RevokedAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}

// ---- password reset ticket ----

func passwordResetTicketToPB(p *store.PasswordResetTicket) (*storev1.PasswordResetTicket, error) {
	if p == nil {
		return nil, nil
	}
	return &storev1.PasswordResetTicket{
		Origin:   p.Origin,
		TenantId: p.TenantID, Id: p.ID, TokenHash: p.TokenHash, UserId: p.UserID,
		Connection: p.Connection, ClientId: p.ClientID, Lang: p.Lang,
		ExpiresAt: tsToPB(p.ExpiresAt), UsedAt: optTSToPB(p.UsedAt), CreatedAt: tsToPB(p.CreatedAt),
		ResultUrl: p.ResultURL, IncludeEmailInRedirect: p.IncludeEmailInRedirect, MarkEmailVerified: p.MarkEmailVerified,
	}, nil
}

func passwordResetTicketFromPB(pb *storev1.PasswordResetTicket) (*store.PasswordResetTicket, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.UsedAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.PasswordResetTicket{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, UserID: pb.UserId,
		Connection: pb.Connection, ClientID: pb.ClientId, Lang: pb.Lang,
		ExpiresAt: tsFromPB(pb.ExpiresAt), UsedAt: optTSFromPB(pb.UsedAt), CreatedAt: tsFromPB(pb.CreatedAt),
		ResultURL: pb.ResultUrl, IncludeEmailInRedirect: pb.IncludeEmailInRedirect, MarkEmailVerified: pb.MarkEmailVerified,
	}, nil
}

// ---- email verification ticket ----

func emailVerificationTicketToPB(p *store.EmailVerificationTicket) (*storev1.EmailVerificationTicket, error) {
	if p == nil {
		return nil, nil
	}
	return &storev1.EmailVerificationTicket{
		Origin:   p.Origin,
		TenantId: p.TenantID, Id: p.ID, TokenHash: p.TokenHash, UserId: p.UserID,
		Connection: p.Connection, ClientId: p.ClientID, Lang: p.Lang,
		ExpiresAt: tsToPB(p.ExpiresAt), UsedAt: optTSToPB(p.UsedAt), CreatedAt: tsToPB(p.CreatedAt),
		ResultUrl: p.ResultURL, IncludeEmailInRedirect: p.IncludeEmailInRedirect, Email: p.Email,
	}, nil
}

func emailVerificationTicketFromPB(pb *storev1.EmailVerificationTicket) (*store.EmailVerificationTicket, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.UsedAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.EmailVerificationTicket{
		Origin:   pb.Origin,
		TenantID: pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, UserID: pb.UserId,
		Connection: pb.Connection, ClientID: pb.ClientId, Lang: pb.Lang,
		ExpiresAt: tsFromPB(pb.ExpiresAt), UsedAt: optTSFromPB(pb.UsedAt), CreatedAt: tsFromPB(pb.CreatedAt),
		ResultURL: pb.ResultUrl, IncludeEmailInRedirect: pb.IncludeEmailInRedirect, Email: pb.Email,
	}, nil
}

// ---- operator ----

func operatorToPB(o *store.Operator) (*storev1.Operator, error) {
	if o == nil {
		return nil, nil
	}
	return &storev1.Operator{
		TenantId: o.TenantID, UserId: o.UserID, Tenants: stringsToPB(o.Tenants),
		CreatedAt: tsToPB(o.CreatedAt), UpdatedAt: tsToPB(o.UpdatedAt),
	}, nil
}

func operatorFromPB(pb *storev1.Operator) (*store.Operator, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt, pb.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.Operator{
		TenantID: pb.TenantId, UserID: pb.UserId, Tenants: stringsFromPB(pb.Tenants),
		CreatedAt: tsFromPB(pb.CreatedAt), UpdatedAt: tsFromPB(pb.UpdatedAt),
	}, nil
}

// ---- jobs ----

func jobToPB(j *store.Job) (*storev1.Job, error) {
	if j == nil {
		return nil, nil
	}
	pb := &storev1.Job{
		TenantId: j.TenantID, Id: j.ID, Type: string(j.Type), Status: string(j.Status),
		ConnectionId: j.ConnectionID, Connection: j.Connection, ExternalId: j.ExternalID,
		Input: cloneBytes(j.Input), Progress: int64(j.Progress), Summary: jobSummaryToPB(j.Summary),
		StatusDetails: j.StatusDetails, Attempts: int64(j.Attempts), LeaseOwner: j.LeaseOwner,
		LeaseUntil: tsToPB(j.LeaseUntil), FirstClaimedAt: tsToPB(j.FirstClaimedAt),
		CreatedAt: tsToPB(j.CreatedAt), UpdatedAt: tsToPB(j.UpdatedAt), ExpiresAt: tsToPB(j.ExpiresAt),
		FileSize: j.FileSize,
	}
	if j.Params != nil {
		b, err := json.Marshal(j.Params)
		if err != nil {
			return nil, fmt.Errorf("grpcstore: encode job params: %w", err)
		}
		pb.ParamsJson = b
	}
	return pb, nil
}

func jobFromPB(pb *storev1.Job) (*store.Job, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.LeaseUntil, pb.FirstClaimedAt, pb.CreatedAt, pb.UpdatedAt, pb.ExpiresAt); err != nil {
		return nil, err
	}
	j := &store.Job{
		TenantID: pb.TenantId, ID: pb.Id, Type: store.JobType(pb.Type), Status: store.JobStatus(pb.Status),
		ConnectionID: pb.ConnectionId, Connection: pb.Connection, ExternalID: pb.ExternalId,
		Input: optBytes(pb.Input), Progress: int(pb.Progress), Summary: jobSummaryFromPB(pb.Summary),
		StatusDetails: pb.StatusDetails, Attempts: int(pb.Attempts), LeaseOwner: pb.LeaseOwner,
		LeaseUntil: tsFromPB(pb.LeaseUntil), FirstClaimedAt: tsFromPB(pb.FirstClaimedAt),
		CreatedAt: tsFromPB(pb.CreatedAt), UpdatedAt: tsFromPB(pb.UpdatedAt), ExpiresAt: tsFromPB(pb.ExpiresAt),
		FileSize: pb.FileSize,
	}
	if pb.ParamsJson != nil {
		var m map[string]any
		if err := json.Unmarshal(pb.ParamsJson, &m); err != nil {
			return nil, fmt.Errorf("grpcstore: decode job params: %w", err)
		}
		j.Params = m
	}
	return j, nil
}

func jobSummaryToPB(s store.JobSummary) *storev1.JobSummary {
	return &storev1.JobSummary{Failed: int64(s.Failed), Updated: int64(s.Updated), Inserted: int64(s.Inserted), Total: int64(s.Total)}
}

func jobSummaryFromPB(pb *storev1.JobSummary) store.JobSummary {
	return store.JobSummary{Failed: int(pb.GetFailed()), Updated: int(pb.GetUpdated()), Inserted: int(pb.GetInserted()), Total: int(pb.GetTotal())}
}

func jobErrorToPB(e *store.JobError) (*storev1.JobError, error) {
	if e == nil {
		return nil, nil
	}
	pb := &storev1.JobError{Index: int64(e.Index)}
	if e.User != nil {
		b, err := json.Marshal(e.User)
		if err != nil {
			return nil, fmt.Errorf("grpcstore: encode job error user: %w", err)
		}
		pb.UserJson = b
	}
	if e.Errors != nil {
		pb.Errors = &storev1.JobErrorItems{Values: make([]*storev1.JobErrorItem, 0, len(e.Errors))}
		for _, it := range e.Errors {
			pb.Errors.Values = append(pb.Errors.Values, &storev1.JobErrorItem{Code: it.Code, Message: it.Message, Path: it.Path})
		}
	}
	return pb, nil
}

func jobErrorFromPB(pb *storev1.JobError) (*store.JobError, error) {
	if pb == nil {
		return nil, nil
	}
	e := &store.JobError{Index: int(pb.Index)}
	if pb.UserJson != nil {
		var v any
		if err := json.Unmarshal(pb.UserJson, &v); err != nil {
			return nil, fmt.Errorf("grpcstore: decode job error user: %w", err)
		}
		e.User = v
	}
	if pb.Errors != nil {
		e.Errors = make([]store.JobErrorItem, 0, len(pb.Errors.Values))
		for _, it := range pb.Errors.Values {
			e.Errors = append(e.Errors, store.JobErrorItem{Code: it.GetCode(), Message: it.GetMessage(), Path: it.GetPath()})
		}
	}
	return e, nil
}

// userQueryToPB carries a query tree over the plugin boundary; nil stays nil.
// Operators and kinds keep their numeric values on both sides.
func userQueryToPB(q *store.UserQuery) *storev1.UserQuery {
	if q == nil {
		return nil
	}
	pb := &storev1.UserQuery{Op: storev1.UserQuery_Op(q.Op), Field: q.Field, Kind: storev1.UserQuery_Kind(q.Kind),
		Value: q.Value, Lo: q.Lo, Hi: q.Hi, LoIncl: q.LoIncl, HiIncl: q.HiIncl}
	for _, k := range q.Kids {
		pb.Kids = append(pb.Kids, userQueryToPB(k))
	}
	return pb
}

// userQueryFromPB is the inverse of userQueryToPB.
func userQueryFromPB(pb *storev1.UserQuery) *store.UserQuery {
	if pb == nil {
		return nil
	}
	q := &store.UserQuery{Op: store.QueryOp(pb.Op), Field: pb.Field, Kind: store.ValueKind(pb.Kind),
		Value: pb.Value, Lo: pb.Lo, Hi: pb.Hi, LoIncl: pb.LoIncl, HiIncl: pb.HiIncl}
	for _, k := range pb.Kids {
		q.Kids = append(q.Kids, userQueryFromPB(k))
	}
	return q
}

func hostedLoginConfigToPB(c *store.HostedLoginConfig) (*storev1.HostedLoginConfig, error) {
	if c == nil {
		return nil, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &storev1.HostedLoginConfig{TenantId: c.TenantID, Revision: c.Revision, ConfigJson: string(raw)}, nil
}
func hostedLoginConfigFromPB(pb *storev1.HostedLoginConfig) (*store.HostedLoginConfig, error) {
	if pb == nil {
		return nil, nil
	}
	var c store.HostedLoginConfig
	if err := json.Unmarshal([]byte(pb.ConfigJson), &c); err != nil {
		return nil, err
	}
	c.TenantID = pb.TenantId
	c.Revision = pb.Revision
	return &c, nil
}
