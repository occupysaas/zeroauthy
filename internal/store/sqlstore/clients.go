package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clients struct{ s *Store }

func (s *Store) Clients() store.Clients { return clients{s} }

const clientCols = `tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method, grant_types, callbacks,
 allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime, refresh_token, created_at,
 is_first_party, third_party_security_mode, redirection_policy, skip_non_verifiable_callback_uri_confirmation_prompt, require_pushed_authorization_requests, origin,
 organization_usage, organization_require_behavior, organization_discovery_methods, initiate_login_uri, mobile,
 client_authentication_methods, signed_request_object, token_exchange, native_social_login, token_quota, require_proof_of_possession, oidc_support, oidc_logout, id_token_alg, addons, client_aliases, form_template, async_approval_notification_channels`

// secretJSON is the stored form of store.ClientSecret: times are micros, as
// everywhere else.
type secretJSON struct {
	Hash      string `json:"hash"`
	Sealed    []byte `json:"sealed,omitempty"` // base64 in the JSON
	CreatedAt int64  `json:"created_at"`
	ExpiresAt *int64 `json:"expires_at"`
}

func (r clients) Create(ctx context.Context, c *store.Client) error {
	args, err := clientArgs(c)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.exec(ctx, `INSERT INTO clients (`+clientCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return tx.syncClientAliases(ctx, c)
	})
}

// syncClientAliases replaces the alias index rows of c (Plan 37b). The
// primary key (tenant, alias hash) makes an alias unique within a tenant
// (LR37b-3): a taken alias is ErrConflict.
func (s *Store) syncClientAliases(ctx context.Context, c *store.Client) error {
	if _, err := s.exec(ctx, `DELETE FROM client_aliases WHERE tenant_id = ? AND client_id = ?`, c.TenantID, c.ClientID); err != nil {
		return err
	}
	for _, a := range c.ClientAliases {
		if _, err := s.exec(ctx, `INSERT INTO client_aliases (tenant_id, alias_hash, alias, client_id) VALUES (?,?,?,?)`, c.TenantID, aliasHash(a), a, c.ClientID); err != nil {
			return s.conflict(err)
		}
	}
	return nil
}

// aliasHash keys an alias: aliases may be longer than an indexable column.
func aliasHash(alias string) string {
	sum := sha256.Sum256([]byte(alias))
	return hex.EncodeToString(sum[:])
}

func (r clients) Get(ctx context.Context, tenantID, clientID string) (*store.Client, error) {
	if err := r.s.policyRead(ctx, tenantID); err != nil {
		return nil, err
	}
	c, err := scanClient(r.s.queryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE tenant_id = ? AND client_id = ?`, tenantID, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r clients) Update(ctx context.Context, c *store.Client) error {
	args, err := clientArgs(c)
	if err != nil {
		return err
	}
	// args: tenant_id, client_id, then the mutable columns in clientCols order.
	return r.s.policyWrite(ctx, c.TenantID, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE clients SET name=?, app_type=?, secrets=?, token_endpoint_auth_method=?, grant_types=?,
 callbacks=?, allowed_logout_urls=?, web_origins=?, allowed_origins=?, id_token_lifetime=?, refresh_token=?, created_at=?,
 is_first_party=?, third_party_security_mode=?, redirection_policy=?, skip_non_verifiable_callback_uri_confirmation_prompt=?, require_pushed_authorization_requests=?, origin=?,
 organization_usage=?, organization_require_behavior=?, organization_discovery_methods=?, initiate_login_uri=?, mobile=?,
 client_authentication_methods=?, signed_request_object=?, token_exchange=?, native_social_login=?, token_quota=?, require_proof_of_possession=?, oidc_support=?, oidc_logout=?, id_token_alg=?, addons=?, client_aliases=?, form_template=?, async_approval_notification_channels=?
 WHERE tenant_id=? AND client_id=?`, append(args[2:], c.TenantID, c.ClientID)...)
		if err != nil {
			return tx.conflict(err)
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return tx.syncClientAliases(ctx, c)
	})
}

func (r clients) Delete(ctx context.Context, tenantID, clientID string) error {
	return r.s.policyWrite(ctx, tenantID, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM clients WHERE tenant_id = ? AND client_id = ?`, tenantID, clientID)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		for _, table := range []string{"client_grants", "user_grants", "refresh_tokens", "mfa_tokens", "client_credentials", "client_assertion_jtis", "client_aliases", "my_org_client_configs", "ciba_requests"} {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND client_id = ?`, tenantID, clientID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r clients) List(ctx context.Context, tenantID string, f store.ClientFilter, p store.Page) ([]*store.Client, int, error) {
	where, args := []string{"tenant_id = ?"}, []any{tenantID}
	if len(f.AppTypes) > 0 {
		where = append(where, "app_type IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.AppTypes)), ",")+")")
		for _, t := range f.AppTypes {
			args = append(args, t)
		}
	}
	if f.IsFirstParty != nil {
		where = append(where, "is_first_party = ?")
		args = append(args, *f.IsFirstParty)
	}
	if f.Alias != "" {
		where = append(where, "client_id IN (SELECT client_id FROM client_aliases WHERE tenant_id = ? AND alias_hash = ? AND alias = ?)")
		args = append(args, tenantID, aliasHash(f.Alias), f.Alias)
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM clients WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.s.query(ctx, `SELECT `+clientCols+` FROM clients WHERE `+cond+` ORDER BY created_at, client_id`+r.s.d.byteOrder+pageClause(p), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*store.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func scanClient(row scanner) (*store.Client, error) {
	var c store.Client
	var secrets, grants, callbacks, logout, webOrigins, origins, refresh string
	var created int64
	var skipPrompt sql.NullBool
	var discovery, mobile, authMethods, signedRO, exchange, native, formTemplate sql.NullString
	if err := row.Scan(&c.TenantID, &c.ClientID, &c.Name, &c.AppType, &secrets, &c.TokenEndpointAuthMethod, &grants,
		&callbacks, &logout, &webOrigins, &origins, &c.IDTokenLifetime, &refresh, &created,
		&c.IsFirstParty, &c.ThirdPartySecurityMode, &c.RedirectionPolicy, &skipPrompt, &c.RequirePushedAuthorizationRequests, &c.Origin,
		&c.OrganizationUsage, &c.OrganizationRequireBehavior, &discovery, &c.InitiateLoginURI, &mobile, &authMethods, &signedRO, &exchange, &native, jsonColumn{&c.TokenQuota}, &c.RequireProofOfPossession, jsonColumn{&c.OIDCSupport}, jsonColumn{&c.OIDCLogout}, &c.IDTokenAlg, jsonColumn{&c.Addons}, jsonColumn{&c.ClientAliases}, &formTemplate, jsonColumn{&c.AsyncApprovalNotificationChannels}); err != nil {
		return nil, err
	}
	c.FormTemplate = formTemplate.String
	var ss []secretJSON
	for _, j := range []struct {
		s string
		v any
	}{{secrets, &ss}, {grants, &c.GrantTypes}, {callbacks, &c.Callbacks}, {logout, &c.AllowedLogoutURLs},
		{webOrigins, &c.WebOrigins}, {origins, &c.AllowedOrigins}, {refresh, &c.RefreshToken}} {
		if err := fromJSON(j.s, j.v); err != nil {
			return nil, err
		}
	}
	if ss != nil {
		c.Secrets = make([]store.ClientSecret, len(ss))
		for i, s := range ss {
			c.Secrets[i] = store.ClientSecret{Hash: s.Hash, Sealed: s.Sealed, CreatedAt: fromMicros(s.CreatedAt)}
			if s.ExpiresAt != nil {
				t := fromMicros(*s.ExpiresAt)
				c.Secrets[i].ExpiresAt = &t
			}
		}
	}
	if discovery.Valid {
		if err := fromJSON(discovery.String, &c.OrganizationDiscoveryMethods); err != nil {
			return nil, err
		}
	}
	if mobile.Valid {
		if err := fromJSON(mobile.String, &c.Mobile); err != nil {
			return nil, err
		}
	}
	if native.Valid {
		if err := fromJSON(native.String, &c.NativeSocialLogin); err != nil {
			return nil, err
		}
	}
	if err := scanClientCredentialSettings(&c, authMethods, signedRO, exchange); err != nil {
		return nil, err
	}
	c.SkipNonVerifiableCallbackURIConfirmationPrompt = fromNullBool(skipPrompt)
	c.CreatedAt = fromMicros(created)
	return &c, nil
}

func clientArgs(c *store.Client) ([]any, error) {
	var ss []secretJSON
	if c.Secrets != nil {
		ss = make([]secretJSON, len(c.Secrets))
		for i, s := range c.Secrets {
			ss[i] = secretJSON{Hash: s.Hash, Sealed: s.Sealed, CreatedAt: micros(s.CreatedAt)}
			if s.ExpiresAt != nil {
				v := micros(*s.ExpiresAt)
				ss[i].ExpiresAt = &v
			}
		}
	}
	js := make([]string, 0, 7)
	for _, v := range []any{ss, c.GrantTypes, c.Callbacks, c.AllowedLogoutURLs, c.WebOrigins, c.AllowedOrigins, c.RefreshToken} {
		s, err := toJSON(v)
		if err != nil {
			return nil, err
		}
		js = append(js, s)
	}
	var discovery any // NULL while unset
	if c.OrganizationDiscoveryMethods != nil {
		s, err := toJSON(c.OrganizationDiscoveryMethods)
		if err != nil {
			return nil, err
		}
		discovery = s
	}
	mobile, err := nullJSON(c.Mobile, c.Mobile == nil)
	if err != nil {
		return nil, err
	}
	native, err := nullJSON(c.NativeSocialLogin, c.NativeSocialLogin == nil)
	if err != nil {
		return nil, err
	}
	authMethods, signedRO, exchange, err := clientCredentialSettingsArgs(c)
	if err != nil {
		return nil, err
	}
	return []any{c.TenantID, c.ClientID, c.Name, string(c.AppType), js[0], c.TokenEndpointAuthMethod, js[1], js[2],
		js[3], js[4], js[5], c.IDTokenLifetime, js[6], micros(c.CreatedAt),
		c.IsFirstParty, c.ThirdPartySecurityMode, c.RedirectionPolicy, nullBool(c.SkipNonVerifiableCallbackURIConfirmationPrompt), c.RequirePushedAuthorizationRequests, c.Origin,
		c.OrganizationUsage, c.OrganizationRequireBehavior, discovery, c.InitiateLoginURI, mobile, authMethods, signedRO, exchange, native, jsonColumn{&c.TokenQuota}, c.RequireProofOfPossession, jsonColumn{&c.OIDCSupport}, jsonColumn{&c.OIDCLogout}, c.IDTokenAlg, jsonColumn{&c.Addons}, jsonColumn{&c.ClientAliases}, nullString(c.FormTemplate), jsonColumn{&c.AsyncApprovalNotificationChannels}}, nil
}
