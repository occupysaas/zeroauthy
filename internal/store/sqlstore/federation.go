package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type federation struct{ s *Store }

func (s *Store) Federation() store.Federation { return federation{s} }

const attemptCols = `tenant_id, state_hash, transaction_id, connection_id, revision, identity_epoch, cookie_hash, origin,
 callback_url, issuer, endpoints, sealed_proof, expires_at, status, superseded, created_at`

func (r federation) IdentityEpoch(ctx context.Context, tenantID string) (int64, error) {
	var epoch int64
	err := r.s.queryRow(ctx, `SELECT identity_epoch FROM tenants WHERE id = ?`, tenantID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, store.ErrNotFound
	}
	return epoch, err
}

func (r federation) BumpIdentityEpoch(ctx context.Context, tenantID string) error {
	res, err := r.s.write(ctx, nil, `UPDATE tenants SET identity_epoch = identity_epoch + 1 WHERE id = ?`, tenantID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

// bumpEpoch moves the tenant's identity epoch inside tx. A missing tenant is
// not an error here: there are no attempts to cancel.
func bumpEpoch(ctx context.Context, tx *Store, tenantID string) error {
	_, err := tx.exec(ctx, `UPDATE tenants SET identity_epoch = identity_epoch + 1 WHERE id = ?`, tenantID)
	return err
}

func (r federation) CreateAttempt(ctx context.Context, a *store.FederationAttempt) error {
	endpoints, err := toJSON(a.Endpoints)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.exec(ctx, `UPDATE federation_attempts SET superseded = ? WHERE tenant_id = ? AND transaction_id = ? AND superseded = ?`,
			true, a.TenantID, a.TransactionID, false); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `INSERT INTO federation_attempts (`+attemptCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			a.TenantID, a.StateHash, a.TransactionID, a.ConnectionID, a.Revision, a.IdentityEpoch, a.CookieHash, a.Origin,
			a.CallbackURL, a.Issuer, endpoints, nullBytes(a.SealedProof), micros(a.ExpiresAt), store.AttemptPending, false, micros(a.CreatedAt))
		return tx.conflict(err)
	})
}

func (r federation) GetAttempt(ctx context.Context, tenantID, stateHash string) (*store.FederationAttempt, error) {
	return getAttempt(ctx, r.s, tenantID, stateHash, "")
}

func getAttempt(ctx context.Context, s *Store, tenantID, stateHash, suffix string) (*store.FederationAttempt, error) {
	var a store.FederationAttempt
	var endpoints string
	var proof []byte
	var expires, created int64
	err := s.queryRow(ctx, `SELECT `+attemptCols+` FROM federation_attempts WHERE tenant_id = ? AND state_hash = ?`+suffix, tenantID, stateHash).Scan(
		&a.TenantID, &a.StateHash, &a.TransactionID, &a.ConnectionID, &a.Revision, &a.IdentityEpoch, &a.CookieHash, &a.Origin,
		&a.CallbackURL, &a.Issuer, &endpoints, &proof, &expires, &a.Status, &a.Superseded, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(endpoints, &a.Endpoints); err != nil {
		return nil, err
	}
	if len(proof) > 0 {
		a.SealedProof = proof
	}
	a.ExpiresAt, a.CreatedAt = fromMicros(expires), fromMicros(created)
	return &a, nil
}

// ClaimAttempt is one conditional UPDATE, so exactly one of any number of
// concurrent callers on any replica wins; the losers read why.
func (r federation) ClaimAttempt(ctx context.Context, tenantID, stateHash, cookieHash, origin string, now time.Time) (*store.FederationAttempt, error) {
	var out *store.FederationAttempt
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE federation_attempts SET status = ? WHERE tenant_id = ? AND state_hash = ? AND status = ?
 AND superseded = ? AND expires_at > ? AND cookie_hash = ? AND origin = ?`,
			store.AttemptClaimed, tenantID, stateHash, store.AttemptPending, false, micros(now), cookieHash, origin)
		if err != nil {
			return err
		}
		a, err := getAttempt(ctx, tx, tenantID, stateHash, "")
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			out = a
			return nil
		}
		switch {
		case a.Superseded || micros(now) >= micros(a.ExpiresAt):
			return store.ErrNotFound
		case a.Status != store.AttemptPending:
			return store.ErrAlreadyUsed
		default:
			return store.ErrInvalid
		}
	})
	return out, err
}

func (r federation) FinishAttempt(ctx context.Context, tenantID, stateHash string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE federation_attempts SET status = ? WHERE tenant_id = ? AND state_hash = ? AND status = ? AND superseded = ?`,
			store.AttemptFinished, tenantID, stateHash, store.AttemptClaimed, false)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		if _, err := getAttempt(ctx, tx, tenantID, stateHash, ""); err != nil {
			return err
		}
		return store.ErrAlreadyUsed
	})
}

func (r federation) PutIdentity(ctx context.Context, k store.FederatedIdentityKey, userID string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error { return putIdentity(ctx, tx, k, userID) })
}

func putIdentity(ctx context.Context, tx *Store, k store.FederatedIdentityKey, userID string) error {
	var owner string
	err := tx.queryRow(ctx, `SELECT user_id FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`+tx.d.forUpdate,
		k.TenantID, k.ConnectionID, k.Subject).Scan(&owner)
	switch {
	case err == nil && owner == userID:
		return nil
	case err == nil:
		return store.ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	_, err = tx.exec(ctx, `INSERT INTO federated_identities (tenant_id, connection_id, subject, user_id) VALUES (?,?,?,?)`,
		k.TenantID, k.ConnectionID, k.Subject, userID)
	return tx.conflict(err)
}

func (r federation) DeleteIdentity(ctx context.Context, k store.FederatedIdentityKey, expectedUserID string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var owner string
		err := tx.queryRow(ctx, `SELECT user_id FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`+tx.d.forUpdate,
			k.TenantID, k.ConnectionID, k.Subject).Scan(&owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return store.ErrNotFound
		case err != nil:
			return err
		case owner != expectedUserID:
			return store.ErrConflict
		}
		if _, err := tx.exec(ctx, `DELETE FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
			k.TenantID, k.ConnectionID, k.Subject); err != nil {
			return err
		}
		res, err := tx.exec(ctx, `UPDATE tenants SET identity_epoch = identity_epoch + 1 WHERE id = ?`, k.TenantID)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
}

func (r federation) GetTokens(ctx context.Context, k store.FederatedIdentityKey) ([]byte, error) {
	var sealed []byte
	err := r.s.queryRow(ctx, `SELECT sealed FROM federated_tokens WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
		k.TenantID, k.ConnectionID, k.Subject).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return sealed, err
}

func (r federation) PutTokens(ctx context.Context, k store.FederatedIdentityKey, sealed []byte) error {
	if len(sealed) == 0 {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE federated_tokens SET sealed = ? WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
			sealed, k.TenantID, k.ConnectionID, k.Subject)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		var one int
		err = tx.queryRow(ctx, `SELECT 1 FROM tenants WHERE id = ?`, k.TenantID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `INSERT INTO federated_tokens (tenant_id, connection_id, subject, sealed) VALUES (?,?,?,?)`,
			k.TenantID, k.ConnectionID, k.Subject, sealed)
		return tx.conflict(err)
	})
}

func (r federation) DeleteTokens(ctx context.Context, k store.FederatedIdentityKey) error {
	_, err := r.s.write(ctx, nil, `DELETE FROM federated_tokens WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
		k.TenantID, k.ConnectionID, k.Subject)
	return err
}

func (r federation) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := r.s.write(ctx, r.s.sweep(), `DELETE FROM federation_attempts WHERE expires_at < ?`, micros(before))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (r users) FindByIdentity(ctx context.Context, tenantID, connectionID, subject string) (*store.User, error) {
	var owner string
	err := r.s.queryRow(ctx, `SELECT user_id FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
		tenantID, connectionID, subject).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, tenantID, owner)
}

// ownedIdentities returns the index keys userID owns, in key order.
func ownedIdentities(ctx context.Context, tx *Store, tenantID, userID string) ([]store.FederatedIdentityKey, error) {
	rows, err := tx.query(ctx, `SELECT connection_id, subject FROM federated_identities WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	var out []store.FederatedIdentityKey
	for rows.Next() {
		k := store.FederatedIdentityKey{TenantID: tenantID}
		var sub []byte
		if err := rows.Scan(&k.ConnectionID, &sub); err != nil {
			rows.Close()
			return nil, err
		}
		k.Subject = string(sub)
		out = append(out, k)
	}
	err = rows.Err()
	rows.Close() // release the single SQLite connection before writing
	slices.SortFunc(out, store.CompareIdentityKeys)
	return out, err
}

// syncIdentities brings u's index entries to its federated identities inside
// tx: additions first (ErrConflict if another user owns one), then removals
// by primary key, which bump the tenant's identity epoch. Token records stay
// with their identity key for its next owner.
func syncIdentities(ctx context.Context, tx *Store, u *store.User, existing bool) error {
	want, err := store.ResolveFederatedKeys(u, func(name string) (*store.Connection, error) {
		return (connections{tx}).GetByName(ctx, u.TenantID, name)
	})
	if err != nil {
		return err
	}
	var have []store.FederatedIdentityKey
	if existing {
		if have, err = ownedIdentities(ctx, tx, u.TenantID, u.UserID); err != nil {
			return err
		}
	}
	for _, k := range want {
		if !slices.Contains(have, k) {
			if err := putIdentity(ctx, tx, k, u.UserID); err != nil {
				return err
			}
		}
	}
	removed := false
	for _, k := range have {
		if slices.Contains(want, k) {
			continue
		}
		if _, err := tx.exec(ctx, `DELETE FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
			k.TenantID, k.ConnectionID, k.Subject); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return bumpEpoch(ctx, tx, u.TenantID)
	}
	return nil
}

// dropUserFederation removes the index entries and token records of a user
// being deleted and bumps the identity epoch, inside tx.
func dropUserFederation(ctx context.Context, tx *Store, tenantID, userID string) error {
	keys, err := ownedIdentities(ctx, tx, tenantID, userID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		for _, table := range []string{"federated_identities", "federated_tokens"} {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
				k.TenantID, k.ConnectionID, k.Subject); err != nil {
				return err
			}
		}
	}
	return bumpEpoch(ctx, tx, tenantID)
}

// backfillFederatedIdentities indexes the federated identities that existed
// before migration 0021 (imported or linked users). Any identity that does
// not resolve to exactly one connection of its strategy, or that two users
// claim, stops the migration with a report of IDs; no token is ever read.
func backfillFederatedIdentities(ctx context.Context, tx *Store) error {
	// Migration 0021 runs before 0024 adds last_password_reset. Supply NULL
	// to the current scanner without requiring a future schema column.
	rows, err := tx.query(ctx, `SELECT `+userColsBeforeActionsII+`,NULL FROM users WHERE identities LIKE ? OR identities LIKE ? OR identities LIKE ? ORDER BY tenant_id, user_id`,
		`%"Provider":"google-oauth2"%`, `%"Provider":"oauth2"%`, `%"Provider":"oidc"%`)
	if err != nil {
		return err
	}
	var found []*store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return err
		}
		found = append(found, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var problems []string
	for _, u := range found {
		// Migration 0021 owns only Plan 24 strategies, even on mixed legacy rows.
		legacy := *u
		legacy.Identities = slices.DeleteFunc(slices.Clone(u.Identities), func(id store.Identity) bool {
			return id.Provider != "google-oauth2" && id.Provider != "oauth2" && id.Provider != "oidc"
		})
		keys, err := store.ResolveFederatedKeys(&legacy, func(name string) (*store.Connection, error) {
			return (connections{tx}).GetByName(ctx, u.TenantID, name)
		})
		if errors.Is(err, store.ErrInvalid) {
			problems = append(problems, fmt.Sprintf("tenant %s user %s: %v", u.TenantID, u.UserID, err))
			continue
		}
		if err != nil {
			return err
		}
		for _, k := range keys {
			var owner string
			err := tx.queryRow(ctx, `SELECT user_id FROM federated_identities WHERE tenant_id = ? AND connection_id = ? AND subject = ?`,
				k.TenantID, k.ConnectionID, k.Subject).Scan(&owner)
			switch {
			case err == nil:
				problems = append(problems, fmt.Sprintf("tenant %s users %s and %s both hold the identity %q of connection %s",
					u.TenantID, owner, u.UserID, k.Subject, k.ConnectionID))
				continue
			case !errors.Is(err, sql.ErrNoRows):
				return err
			}
			if _, err := tx.exec(ctx, `INSERT INTO federated_identities (tenant_id, connection_id, subject, user_id) VALUES (?,?,?,?)`,
				k.TenantID, k.ConnectionID, k.Subject, u.UserID); err != nil {
				return err
			}
		}
	}
	// Federated identities no longer log in by email or username.
	if _, err := tx.exec(ctx, `DELETE FROM user_logins WHERE EXISTS (SELECT 1 FROM connections c WHERE c.tenant_id = user_logins.tenant_id
 AND c.name = user_logins.connection AND c.strategy IN (?,?,?))`, "google-oauth2", "oauth2", "oidc"); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("federated identity backfill needs operator correction before upgrading:\n%s", strings.Join(problems, "\n"))
	}
	return nil
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// MicrosoftFederationSupported reports support for canonical Microsoft identities.
func (s *Store) MicrosoftFederationSupported(context.Context) error { return nil }
