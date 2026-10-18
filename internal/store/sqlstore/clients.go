package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clients struct{ s *Store }

func (s *Store) Clients() store.Clients { return clients{s} }

const clientCols = `tenant_id, client_id, name, app_type, secrets, token_endpoint_auth_method, grant_types, callbacks,
 allowed_logout_urls, web_origins, allowed_origins, id_token_lifetime, refresh_token, created_at,
 is_first_party, third_party_security_mode, redirection_policy, skip_non_verifiable_callback_uri_confirmation_prompt, require_pushed_authorization_requests`

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
	_, err = r.s.write(ctx, nil, `INSERT INTO clients (`+clientCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
	return r.s.conflict(err)
}

func (r clients) Get(ctx context.Context, tenantID, clientID string) (*store.Client, error) {
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
	// args: tenant_id, client_id, then the 17 mutable columns.
	res, err := r.s.write(ctx, nil, `UPDATE clients SET name=?, app_type=?, secrets=?, token_endpoint_auth_method=?, grant_types=?,
 callbacks=?, allowed_logout_urls=?, web_origins=?, allowed_origins=?, id_token_lifetime=?, refresh_token=?, created_at=?,
 is_first_party=?, third_party_security_mode=?, redirection_policy=?, skip_non_verifiable_callback_uri_confirmation_prompt=?, require_pushed_authorization_requests=?
 WHERE tenant_id=? AND client_id=?`, append(args[2:], c.TenantID, c.ClientID)...)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r clients) Delete(ctx context.Context, tenantID, clientID string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM clients WHERE tenant_id = ? AND client_id = ?`, tenantID, clientID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r clients) List(ctx context.Context, tenantID string) ([]*store.Client, error) {
	rows, err := r.s.query(ctx, `SELECT `+clientCols+` FROM clients WHERE tenant_id = ? ORDER BY client_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanClient(row scanner) (*store.Client, error) {
	var c store.Client
	var secrets, grants, callbacks, logout, webOrigins, origins, refresh string
	var created int64
	var skipPrompt sql.NullBool
	if err := row.Scan(&c.TenantID, &c.ClientID, &c.Name, &c.AppType, &secrets, &c.TokenEndpointAuthMethod, &grants,
		&callbacks, &logout, &webOrigins, &origins, &c.IDTokenLifetime, &refresh, &created,
		&c.IsFirstParty, &c.ThirdPartySecurityMode, &c.RedirectionPolicy, &skipPrompt, &c.RequirePushedAuthorizationRequests); err != nil {
		return nil, err
	}
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
	return []any{c.TenantID, c.ClientID, c.Name, string(c.AppType), js[0], c.TokenEndpointAuthMethod, js[1], js[2],
		js[3], js[4], js[5], c.IDTokenLifetime, js[6], micros(c.CreatedAt),
		c.IsFirstParty, c.ThirdPartySecurityMode, c.RedirectionPolicy, nullBool(c.SkipNonVerifiableCallbackURIConfirmationPrompt), c.RequirePushedAuthorizationRequests}, nil
}
