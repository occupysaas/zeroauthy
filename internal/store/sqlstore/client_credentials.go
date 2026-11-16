package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientCredentials struct{ s *Store }

func (s *Store) ClientCredentials() store.ClientCredentials { return clientCredentials{s} }

// CheckClientCredentialsSupport: SQL drivers carry the client credentials
// schema (0036).
func (s *Store) CheckClientCredentialsSupport(context.Context) error { return nil }

// ClientCredentialsSupported is always true for SQL drivers.
func (s *Store) ClientCredentialsSupported() bool { return true }

const clientCredentialCols = `tenant_id, client_id, id, type, name, kid, alg, public_key_der, thumbprint, expires_at, created_at, updated_at`

const profileCols = `tenant_id, id, name, subject_token_type, action_id, type, created_at, updated_at`

func scanClientCredential(row scanner) (*store.ClientCredential, error) {
	var c store.ClientCredential
	var exp sql.NullInt64
	var created, updated int64
	if err := row.Scan(&c.TenantID, &c.ClientID, &c.ID, &c.Type, &c.Name, &c.KID, &c.Alg, &c.PublicKeyDER, &c.Thumbprint, &exp, &created, &updated); err != nil {
		return nil, err
	}
	c.ExpiresAt, c.CreatedAt, c.UpdatedAt = fromNullMicros(exp), fromMicros(created), fromMicros(updated)
	return &c, nil
}

func scanProfile(row scanner) (*store.TokenExchangeProfile, error) {
	var p store.TokenExchangeProfile
	var created, updated int64
	if err := row.Scan(&p.TenantID, &p.ID, &p.Name, &p.SubjectTokenType, &p.ActionID, &p.Type, &created, &updated); err != nil {
		return nil, err
	}
	p.CreatedAt, p.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &p, nil
}

// lockClient takes the client row's lock (a no-op suffix on SQLite, whose
// writes are serialized) and reports store.ErrNotFound when it is missing.
func lockClient(ctx context.Context, tx *Store, tid, clientID string) error {
	var one int
	return missing(tx.queryRow(ctx, `SELECT 1 FROM clients WHERE tenant_id=? AND client_id=?`+tx.d.forUpdate, tid, clientID).Scan(&one))
}

// has reports whether the query returns a row.
func has(ctx context.Context, tx *Store, q string, args ...any) (bool, error) {
	var one int
	err := tx.queryRow(ctx, q, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (r clientCredentials) Create(ctx context.Context, c *store.ClientCredential, limit int) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// The client row lock serializes concurrent creates for one client, so
		// the count below cannot be overtaken.
		if err := lockClient(ctx, tx, c.TenantID, c.ClientID); err != nil {
			return err
		}
		dup, err := has(ctx, tx, `SELECT 1 FROM client_credentials WHERE tenant_id=? AND client_id=? AND id=?`, c.TenantID, c.ClientID, c.ID)
		if err != nil {
			return err
		}
		if dup {
			return store.ErrConflict
		}
		var n int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM client_credentials WHERE tenant_id=? AND client_id=?`, c.TenantID, c.ClientID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return store.ErrPrecondition
		}
		_, err = tx.exec(ctx, `INSERT INTO client_credentials (`+clientCredentialCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.TenantID, c.ClientID, c.ID, c.Type, c.Name, c.KID, c.Alg, c.PublicKeyDER, c.Thumbprint, nullMicros(c.ExpiresAt), micros(c.CreatedAt), micros(c.UpdatedAt))
		return tx.conflict(err)
	})
}

func (r clientCredentials) Get(ctx context.Context, tid, clientID, id string) (*store.ClientCredential, error) {
	c, err := scanClientCredential(r.s.queryRow(ctx, `SELECT `+clientCredentialCols+` FROM client_credentials WHERE tenant_id=? AND client_id=? AND id=?`, tid, clientID, id))
	return c, missing(err)
}

func (r clientCredentials) List(ctx context.Context, tid, clientID string) ([]*store.ClientCredential, error) {
	rows, err := r.s.query(ctx, `SELECT `+clientCredentialCols+` FROM client_credentials WHERE tenant_id=? AND client_id=? ORDER BY created_at, id`+r.s.d.byteOrder, tid, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ClientCredential
	for rows.Next() {
		c, err := scanClientCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r clientCredentials) UpdateExpiry(ctx context.Context, tid, clientID, id string, exp *time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// Some drivers report changed rows rather than matched rows, so a
		// repeated identical update is detected by lookup, not by the count.
		if _, err := tx.exec(ctx, `UPDATE client_credentials SET expires_at=?, updated_at=? WHERE tenant_id=? AND client_id=? AND id=?`,
			nullMicros(exp), micros(time.Now()), tid, clientID, id); err != nil {
			return err
		}
		ok, err := has(ctx, tx, `SELECT 1 FROM client_credentials WHERE tenant_id=? AND client_id=? AND id=?`, tid, clientID, id)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrNotFound
		}
		return nil
	})
}

func (r clientCredentials) Delete(ctx context.Context, tid, clientID, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// Client row first, the order Create uses, so the two cannot deadlock.
		if err := lockClient(ctx, tx, tid, clientID); err != nil {
			return err
		}
		res, err := tx.exec(ctx, `DELETE FROM client_credentials WHERE tenant_id=? AND client_id=? AND id=?`, tid, clientID, id)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		var authMethods, signedRO sql.NullString
		if err := tx.queryRow(ctx, `SELECT client_authentication_methods, signed_request_object FROM clients WHERE tenant_id=? AND client_id=?`, tid, clientID).Scan(&authMethods, &signedRO); err != nil {
			return err
		}
		var c store.Client
		if err := scanClientCredentialSettings(&c, authMethods, signedRO, sql.NullString{}); err != nil {
			return err
		}
		drop := func(x string) bool { return x == id }
		c.PrivateKeyJWTCredentials = slices.DeleteFunc(c.PrivateKeyJWTCredentials, drop)
		if c.SignedRequestObject != nil {
			c.SignedRequestObject.Credentials = slices.DeleteFunc(c.SignedRequestObject.Credentials, drop)
		}
		am, sr, _, err := clientCredentialSettingsArgs(&c)
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE clients SET client_authentication_methods=?, signed_request_object=? WHERE tenant_id=? AND client_id=?`, am, sr, tid, clientID)
		return err
	})
}

// UseJTI records the hashed jti until exp. A present, unexpired row is a
// replay. The lookup takes the row lock, so of concurrent callers for an
// expired row exactly one rewrites it; for an absent row the primary key
// admits exactly one insert and the others see a unique violation.
func (r clientCredentials) UseJTI(ctx context.Context, tid, clientID, jti string, exp time.Time) error {
	sum := sha256.Sum256([]byte(jti))
	hash := hex.EncodeToString(sum[:])
	return r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		var old int64
		err := tx.queryRow(ctx, `SELECT expires_at FROM client_assertion_jtis WHERE tenant_id=? AND client_id=? AND jti_hash=?`+tx.d.forUpdate, tid, clientID, hash).Scan(&old)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.exec(ctx, `INSERT INTO client_assertion_jtis (tenant_id, client_id, jti_hash, expires_at) VALUES (?,?,?,?)`, tid, clientID, hash, micros(exp))
			return tx.conflict(err)
		case err != nil:
			return err
		case old > micros(time.Now()):
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE client_assertion_jtis SET expires_at=? WHERE tenant_id=? AND client_id=? AND jti_hash=?`, micros(exp), tid, clientID, hash)
		return err
	})
}

func (r clientCredentials) PurgeJTIs(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		n = 0
		rows, err := tx.query(ctx, `SELECT tenant_id, client_id, jti_hash FROM client_assertion_jtis WHERE expires_at<=? ORDER BY expires_at LIMIT ?`, micros(before), limit)
		if err != nil {
			return err
		}
		type k struct{ tid, client, hash string }
		var keys []k
		for rows.Next() {
			var x k
			if err := rows.Scan(&x.tid, &x.client, &x.hash); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, x := range keys {
			m, err := affected(tx.exec(ctx, `DELETE FROM client_assertion_jtis WHERE tenant_id=? AND client_id=? AND jti_hash=? AND expires_at<=?`, x.tid, x.client, x.hash, micros(before)))
			if err != nil {
				return err
			}
			n += m
		}
		return nil
	})
	return n, err
}

func (r clientCredentials) CreateProfile(ctx context.Context, p *store.TokenExchangeProfile, limit int) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// The tenant row lock serializes the count against concurrent creates.
		if err := lockTenant(ctx, tx, p.TenantID); err != nil {
			return err
		}
		taken, err := has(ctx, tx, `SELECT 1 FROM token_exchange_profiles WHERE tenant_id=? AND (id=? OR subject_token_type=?)`, p.TenantID, p.ID, p.SubjectTokenType)
		if err != nil {
			return err
		}
		if taken {
			return store.ErrConflict
		}
		var n int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM token_exchange_profiles WHERE tenant_id=?`, p.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return store.ErrPrecondition
		}
		_, err = tx.exec(ctx, `INSERT INTO token_exchange_profiles (`+profileCols+`) VALUES (?,?,?,?,?,?,?,?)`,
			p.TenantID, p.ID, p.Name, p.SubjectTokenType, p.ActionID, p.Type, micros(p.CreatedAt), micros(p.UpdatedAt))
		return tx.conflict(err)
	})
}

func (r clientCredentials) GetProfile(ctx context.Context, tid, id string) (*store.TokenExchangeProfile, error) {
	p, err := scanProfile(r.s.queryRow(ctx, `SELECT `+profileCols+` FROM token_exchange_profiles WHERE tenant_id=? AND id=?`, tid, id))
	return p, missing(err)
}

func (r clientCredentials) GetProfileByType(ctx context.Context, tid, subjectTokenType string) (*store.TokenExchangeProfile, error) {
	p, err := scanProfile(r.s.queryRow(ctx, `SELECT `+profileCols+` FROM token_exchange_profiles WHERE tenant_id=? AND subject_token_type=?`, tid, subjectTokenType))
	return p, missing(err)
}

func (r clientCredentials) ListProfiles(ctx context.Context, tid, from string, take int) ([]*store.TokenExchangeProfile, string, error) {
	q := `SELECT ` + profileCols + ` FROM token_exchange_profiles WHERE tenant_id=? AND id` + r.s.d.byteOrder + ` > ? ORDER BY id` + r.s.d.byteOrder
	args := []any{tid, from}
	if take >= 0 {
		q += ` LIMIT ?`
		args = append(args, take+1)
	}
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []*store.TokenExchangeProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if take >= 0 && len(out) > take {
		out = out[:take]
		if take > 0 {
			next = out[take-1].ID
		}
	}
	return out, next, nil
}

func (r clientCredentials) UpdateProfile(ctx context.Context, p *store.TokenExchangeProfile) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockTenant(ctx, tx, p.TenantID); err != nil {
			return err
		}
		ok, err := has(ctx, tx, `SELECT 1 FROM token_exchange_profiles WHERE tenant_id=? AND id=?`+tx.d.forUpdate, p.TenantID, p.ID)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrNotFound
		}
		taken, err := has(ctx, tx, `SELECT 1 FROM token_exchange_profiles WHERE tenant_id=? AND id<>? AND subject_token_type=?`, p.TenantID, p.ID, p.SubjectTokenType)
		if err != nil {
			return err
		}
		if taken {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE token_exchange_profiles SET name=?, subject_token_type=?, action_id=?, updated_at=? WHERE tenant_id=? AND id=?`,
			p.Name, p.SubjectTokenType, p.ActionID, micros(p.UpdatedAt), p.TenantID, p.ID)
		return tx.conflict(err)
	})
}

func (r clientCredentials) DeleteProfile(ctx context.Context, tid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM token_exchange_profiles WHERE tenant_id=? AND id=?`, tid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r clientCredentials) ProfilesForAction(ctx context.Context, tid, actionID string) (int, error) {
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM token_exchange_profiles WHERE tenant_id=? AND action_id=?`, tid, actionID).Scan(&n)
	return n, err
}

// The three client settings are nullable JSON text; NULL is "unset".

type privateKeyJWTJSON struct {
	Credentials []string `json:"credentials"`
}
type authMethodsJSON struct {
	PrivateKeyJWT *privateKeyJWTJSON `json:"private_key_jwt,omitempty"`
}
type signedRequestObjectJSON struct {
	Required    bool     `json:"required"`
	Credentials []string `json:"credentials"`
}
type tokenExchangeJSON struct {
	AllowAnyProfileOfType []string `json:"allow_any_profile_of_type"`
}

func scanClientCredentialSettings(c *store.Client, authMethods, signedRO, exchange sql.NullString) error {
	if authMethods.Valid {
		var v authMethodsJSON
		if err := fromJSON(authMethods.String, &v); err != nil {
			return err
		}
		if v.PrivateKeyJWT != nil {
			c.PrivateKeyJWTCredentials = v.PrivateKeyJWT.Credentials
			if c.PrivateKeyJWTCredentials == nil {
				c.PrivateKeyJWTCredentials = []string{}
			}
		}
	}
	if signedRO.Valid {
		var v signedRequestObjectJSON
		if err := fromJSON(signedRO.String, &v); err != nil {
			return err
		}
		c.SignedRequestObject = &store.SignedRequestObject{Required: v.Required, Credentials: v.Credentials}
	}
	if exchange.Valid {
		var v tokenExchangeJSON
		if err := fromJSON(exchange.String, &v); err != nil {
			return err
		}
		c.TokenExchangeTypes = v.AllowAnyProfileOfType
	}
	return nil
}

func clientCredentialSettingsArgs(c *store.Client) (authMethods, signedRO, exchange any, err error) {
	var v authMethodsJSON
	if c.PrivateKeyJWTCredentials != nil {
		v.PrivateKeyJWT = &privateKeyJWTJSON{Credentials: c.PrivateKeyJWTCredentials}
	}
	if authMethods, err = nullJSON(v, c.PrivateKeyJWTCredentials == nil); err != nil {
		return
	}
	var sr signedRequestObjectJSON
	if c.SignedRequestObject != nil {
		sr = signedRequestObjectJSON{Required: c.SignedRequestObject.Required, Credentials: c.SignedRequestObject.Credentials}
	}
	if signedRO, err = nullJSON(sr, c.SignedRequestObject == nil); err != nil {
		return
	}
	exchange, err = nullJSON(tokenExchangeJSON{AllowAnyProfileOfType: c.TokenExchangeTypes}, c.TokenExchangeTypes == nil)
	return
}
