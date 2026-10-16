// Package grpcstore carries store.Store over the gRPC storage plugin
// protocol (proto/store/v1). This file is the lossless codec between the
// domain types and the protocol messages: nil and empty slices and maps stay
// distinct, pointer presence is preserved, and times round-trip in UTC.
package grpcstore

import (
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

// ---- errors ----

func errToPB(err error) *storev1.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return &storev1.Error{Kind: storev1.Error_KIND_NOT_FOUND, Message: err.Error()}
	case errors.Is(err, store.ErrConflict):
		return &storev1.Error{Kind: storev1.Error_KIND_CONFLICT, Message: err.Error()}
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
	case storev1.Error_KIND_NOT_FOUND:
		return store.ErrNotFound
	case storev1.Error_KIND_CONFLICT:
		return store.ErrConflict
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
		Id: t.ID, Name: t.Name, FriendlyName: t.FriendlyName,
		Domains: stringsToPB(t.Domains), DefaultAudience: t.DefaultAudience,
		AllowedLogoutUrls: stringsToPB(t.AllowedLogoutURLs), EnabledLocales: stringsToPB(t.EnabledLocales),
		SessionLifetime: int64(t.SessionLifetime), IdleSessionLifetime: int64(t.IdleSessionLifetime),
		Branding:         &storev1.Branding{LogoUrl: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor},
		DefaultDirectory: t.DefaultDirectory, CreatedAt: tsToPB(t.CreatedAt),
		SkipNonVerifiableCallbackUriConfirmationPrompt: t.SkipNonVerifiableCallbackURIConfirmationPrompt,
		UseScopeDescriptionsForConsent:                 t.UseScopeDescriptionsForConsent,
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
		ID: pb.Id, Name: pb.Name, FriendlyName: pb.FriendlyName,
		Domains: stringsFromPB(pb.Domains), DefaultAudience: pb.DefaultAudience,
		AllowedLogoutURLs: stringsFromPB(pb.AllowedLogoutUrls), EnabledLocales: stringsFromPB(pb.EnabledLocales),
		SessionLifetime: int(pb.SessionLifetime), IdleSessionLifetime: int(pb.IdleSessionLifetime),
		Branding:         store.Branding{LogoURL: pb.GetBranding().GetLogoUrl(), PrimaryColor: pb.GetBranding().GetPrimaryColor()},
		DefaultDirectory: pb.DefaultDirectory, CreatedAt: tsFromPB(pb.CreatedAt),
		SkipNonVerifiableCallbackURIConfirmationPrompt: pb.SkipNonVerifiableCallbackUriConfirmationPrompt,
		UseScopeDescriptionsForConsent:                 pb.UseScopeDescriptionsForConsent,
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
	}
	if c.Secrets != nil {
		pb.Secrets = &storev1.ClientSecretList{Values: make([]*storev1.ClientSecret, 0, len(c.Secrets))}
		for _, s := range c.Secrets {
			pb.Secrets.Values = append(pb.Secrets.Values, &storev1.ClientSecret{
				Hash: s.Hash, CreatedAt: tsToPB(s.CreatedAt), ExpiresAt: optTSToPB(s.ExpiresAt)})
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
	}
	if pb.Secrets != nil {
		c.Secrets = make([]store.ClientSecret, 0, len(pb.Secrets.Values))
		for _, s := range pb.Secrets.Values {
			if err := checkTS(s.GetCreatedAt(), s.GetExpiresAt()); err != nil {
				return nil, err
			}
			c.Secrets = append(c.Secrets, store.ClientSecret{
				Hash: s.GetHash(), CreatedAt: tsFromPB(s.GetCreatedAt()), ExpiresAt: optTSFromPB(s.GetExpiresAt())})
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
		TenantId: r.TenantID, Id: r.ID, Identifier: r.Identifier, Name: r.Name,
		SigningAlg: r.SigningAlg, TokenLifetime: int64(r.TokenLifetime),
		AllowOfflineAccess: r.AllowOfflineAccess, CreatedAt: tsToPB(r.CreatedAt),
		SkipConsentForVerifiableFirstPartyClients: proto.Bool(r.SkipConsentForVerifiableFirstPartyClients),
		UserPolicy: r.SubjectTypeAuthorization.User, ClientPolicy: r.SubjectTypeAuthorization.Client,
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
		TenantID: pb.TenantId, ID: pb.Id, Identifier: pb.Identifier, Name: pb.Name,
		SigningAlg: pb.SigningAlg, TokenLifetime: int(pb.TokenLifetime),
		AllowOfflineAccess: pb.AllowOfflineAccess, CreatedAt: tsFromPB(pb.CreatedAt),
		SkipConsentForVerifiableFirstPartyClients: pb.SkipConsentForVerifiableFirstPartyClients == nil || *pb.SkipConsentForVerifiableFirstPartyClients,
		SubjectTypeAuthorization:                  store.SubjectTypeAuthorization{User: pb.UserPolicy, Client: pb.ClientPolicy},
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
		Scopes: stringsToPB(g.Scopes), CreatedAt: tsToPB(g.CreatedAt), SubjectType: g.SubjectType,
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
		Scopes: stringsFromPB(pb.Scopes), CreatedAt: tsFromPB(pb.CreatedAt), SubjectType: subjectType,
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
		PrivateKey: k.PrivateKey, PublicJwk: k.PublicJWK, CreatedAt: tsToPB(k.CreatedAt),
	}, nil
}

func signingKeyFromPB(pb *storev1.SigningKey) (*store.SigningKey, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.SigningKey{
		TenantID: pb.TenantId, KID: pb.Kid, Alg: pb.Alg, Status: store.KeyStatus(pb.Status),
		PrivateKey: cloneBytes(pb.PrivateKey), PublicJWK: cloneBytes(pb.PublicJwk), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}

// ---- connection ----

func connectionToPB(c *store.Connection) (*storev1.Connection, error) {
	if c == nil {
		return nil, nil
	}
	pb := &storev1.Connection{
		TenantId: c.TenantID, Id: c.ID, Name: c.Name, Strategy: c.Strategy,
		EnabledClients: stringsToPB(c.EnabledClients), DisableSignup: c.DisableSignup,
		RequiresUsername: c.RequiresUsername,
		PasswordPolicy: &storev1.PasswordPolicy{
			MinLength: int64(c.PasswordPolicy.MinLength), RequireCharacterClasses: int64(c.PasswordPolicy.RequireCharacterClasses)},
		CreatedAt:                    tsToPB(c.CreatedAt),
		EnabledDatabaseCustomization: c.EnabledDatabaseCustomization, ImportMode: c.ImportMode,
		CustomScripts: stringMapToPB(c.CustomScripts), SetUserRootAttributes: c.SetUserRootAttributes,
		IsDomainConnection: c.IsDomainConnection,
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
		RequiresUsername: pb.RequiresUsername,
		PasswordPolicy: store.PasswordPolicy{
			MinLength: int(pb.GetPasswordPolicy().GetMinLength()), RequireCharacterClasses: int(pb.GetPasswordPolicy().GetRequireCharacterClasses())},
		CreatedAt:                    tsFromPB(pb.CreatedAt),
		EnabledDatabaseCustomization: pb.EnabledDatabaseCustomization, ImportMode: pb.ImportMode,
		CustomScripts: stringMapFromPB(pb.CustomScripts), SetUserRootAttributes: pb.SetUserRootAttributes,
		IsDomainConnection: pb.IsDomainConnection,
	}
	if len(pb.ConfigurationSealed) > 0 {
		c.ConfigurationSealed = cloneBytes(pb.ConfigurationSealed)
	}
	return c, nil
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
			pb.Identities.Values = append(pb.Identities.Values, &storev1.Identity{
				Connection: id.Connection, Provider: id.Provider, UserId: id.UserID, PasswordHash: id.PasswordHash})
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
			u.Identities = append(u.Identities, store.Identity{
				Connection: id.GetConnection(), Provider: id.GetProvider(), UserID: id.GetUserId(), PasswordHash: id.GetPasswordHash()})
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
		TenantId: s.TenantID, Id: s.ID, TokenHash: s.TokenHash, UserId: s.UserID,
		Connection: s.Connection, AuthenticatedAt: tsToPB(s.AuthenticatedAt),
		ClientIds: stringsToPB(s.ClientIDs), ExpiresAt: tsToPB(s.ExpiresAt),
		IdleExpiresAt: tsToPB(s.IdleExpiresAt), CreatedAt: tsToPB(s.CreatedAt),
	}, nil
}

func sessionFromPB(pb *storev1.LoginSession) (*store.LoginSession, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.AuthenticatedAt, pb.ExpiresAt, pb.IdleExpiresAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.LoginSession{
		TenantID: pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, UserID: pb.UserId,
		Connection: pb.Connection, AuthenticatedAt: tsFromPB(pb.AuthenticatedAt),
		ClientIDs: stringsFromPB(pb.ClientIds), ExpiresAt: tsFromPB(pb.ExpiresAt),
		IdleExpiresAt: tsFromPB(pb.IdleExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}

// ---- auth transaction ----

func authTransactionToPB(a *store.AuthTransaction) (*storev1.AuthTransaction, error) {
	if a == nil {
		return nil, nil
	}
	return &storev1.AuthTransaction{
		TenantId: a.TenantID, Id: a.ID, CookieHash: a.CookieHash, CsrfToken: a.CSRFToken,
		ClientId: a.ClientID, Params: stringMapToPB(a.Params),
		ExpiresAt: tsToPB(a.ExpiresAt), CreatedAt: tsToPB(a.CreatedAt),
	}, nil
}

func authTransactionFromPB(pb *storev1.AuthTransaction) (*store.AuthTransaction, error) {
	if pb == nil {
		return nil, nil
	}
	if err := checkTS(pb.ExpiresAt, pb.CreatedAt); err != nil {
		return nil, err
	}
	return &store.AuthTransaction{
		TenantID: pb.TenantId, ID: pb.Id, CookieHash: pb.CookieHash, CSRFToken: pb.CsrfToken,
		ClientID: pb.ClientId, Params: stringMapFromPB(pb.Params),
		ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}

// ---- auth code ----

func authCodeToPB(c *store.AuthCode) (*storev1.AuthCode, error) {
	if c == nil {
		return nil, nil
	}
	return &storev1.AuthCode{
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
		TenantID: pb.TenantId, CodeHash: pb.CodeHash, ClientID: pb.ClientId, RedirectURI: pb.RedirectUri,
		UserID: pb.UserId, SessionID: pb.SessionId, Scopes: stringsFromPB(pb.Scopes), Audience: pb.Audience,
		Nonce: pb.Nonce, CodeChallenge: pb.CodeChallenge, CodeChallengeMethod: pb.CodeChallengeMethod,
		AuthTime: tsFromPB(pb.AuthTime), ExpiresAt: tsFromPB(pb.ExpiresAt), CreatedAt: tsFromPB(pb.CreatedAt),
		UsedAt: optTSFromPB(pb.UsedAt), ReplayedAt: optTSFromPB(pb.ReplayedAt),
	}, nil
}

// ---- refresh token ----

func refreshTokenToPB(r *store.RefreshToken) (*storev1.RefreshToken, error) {
	if r == nil {
		return nil, nil
	}
	return &storev1.RefreshToken{
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
		TenantId: p.TenantID, Id: p.ID, TokenHash: p.TokenHash, UserId: p.UserID,
		Connection: p.Connection, ClientId: p.ClientID, Lang: p.Lang,
		ExpiresAt: tsToPB(p.ExpiresAt), UsedAt: optTSToPB(p.UsedAt), CreatedAt: tsToPB(p.CreatedAt),
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
		TenantID: pb.TenantId, ID: pb.Id, TokenHash: pb.TokenHash, UserID: pb.UserId,
		Connection: pb.Connection, ClientID: pb.ClientId, Lang: pb.Lang,
		ExpiresAt: tsFromPB(pb.ExpiresAt), UsedAt: optTSFromPB(pb.UsedAt), CreatedAt: tsFromPB(pb.CreatedAt),
	}, nil
}
