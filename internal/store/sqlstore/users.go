package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type users struct{ s *Store }

func (s *Store) Users() store.Users { return users{s} }

const userCols = `tenant_id, user_id, email, email_verified, username, name, nickname, picture, given_name, family_name,
 user_metadata, blocked, identities, last_login, logins_count, created_at, updated_at`

func (r users) Create(ctx context.Context, u *store.User) error {
	args, err := userArgs(u)
	if err != nil {
		return err
	}
	return r.s.atomic(ctx, func(tx *Store) error {
		if _, err := tx.exec(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return putLogins(ctx, tx, u)
	})
}

// putLogins replaces the user's rows in user_logins. A duplicate value on
// the same connection is a unique violation, mapped to ErrConflict; the
// first violation ends the call (the caller's transaction rolls back).
// Values are inserted in a fixed order so concurrent writers wait on each
// other's rows in the same sequence.
func putLogins(ctx context.Context, tx *Store, u *store.User) error {
	if _, err := tx.exec(ctx, `DELETE FROM user_logins WHERE tenant_id = ? AND user_id = ?`, u.TenantID, u.UserID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, id := range u.Identities {
		if seen[id.Connection] {
			continue
		}
		seen[id.Connection] = true
		for _, l := range [...]struct{ kind, value string }{{"email", u.Email}, {"username", u.Username}} {
			if l.value == "" {
				continue
			}
			if _, err := tx.exec(ctx, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES (?,?,?,?,?)`,
				u.TenantID, id.Connection, l.kind, l.value, u.UserID); err != nil {
				return tx.conflict(err)
			}
		}
	}
	return nil
}

func (r users) Get(ctx context.Context, tenantID, userID string) (*store.User, error) {
	u, err := scanUser(r.s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id = ? AND user_id = ?`, tenantID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (r users) Update(ctx context.Context, u *store.User) error {
	args, err := userArgs(u)
	if err != nil {
		return err
	}
	return r.s.atomic(ctx, func(tx *Store) error {
		// Login stats are owned by RecordLogin; Update never changes them.
		// Relies on MySQL clientFoundRows so an unchanged row still counts.
		res, err := tx.exec(ctx, `UPDATE users SET email=?, email_verified=?, username=?, name=?, nickname=?, picture=?,
 given_name=?, family_name=?, user_metadata=?, blocked=?, identities=?, created_at=?, updated_at=?
 WHERE tenant_id=? AND user_id=?`,
			args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12],
			args[15], args[16], u.TenantID, u.UserID)
		if err != nil {
			return tx.conflict(err)
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return putLogins(ctx, tx, u)
	})
}

func (r users) FindByLogin(ctx context.Context, tenantID, connection, login string) (*store.User, error) {
	if login == "" {
		return nil, store.ErrNotFound
	}
	var userID string
	err := r.s.queryRow(ctx, `SELECT user_id FROM user_logins WHERE tenant_id=? AND connection=? AND value=? ORDER BY kind LIMIT 1`,
		tenantID, connection, login).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, tenantID, userID)
}

func (r users) RecordLogin(ctx context.Context, tenantID, userID string, at time.Time) error {
	res, err := r.s.exec(ctx, `UPDATE users SET last_login=?, logins_count=logins_count+1 WHERE tenant_id=? AND user_id=?`,
		micros(at), tenantID, userID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r users) SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		var raw string
		err := tx.queryRow(ctx, `SELECT identities FROM users WHERE tenant_id=? AND user_id=?`+tx.d.forUpdate, tenantID, userID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		var ids []store.Identity
		if err := fromJSON(raw, &ids); err != nil {
			return err
		}
		found := false
		for i := range ids {
			if ids[i].Connection == connection {
				ids[i].PasswordHash = hash
				found = true
				break
			}
		}
		if !found {
			return store.ErrNotFound
		}
		enc, err := toJSON(ids)
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE users SET identities=?, updated_at=? WHERE tenant_id=? AND user_id=?`,
			enc, micros(at), tenantID, userID)
		return err
	})
}

func scanUser(row scanner) (*store.User, error) {
	var u store.User
	var meta, ids string
	var last sql.NullInt64
	var created, updated int64
	if err := row.Scan(&u.TenantID, &u.UserID, &u.Email, &u.EmailVerified, &u.Username, &u.Name, &u.Nickname, &u.Picture,
		&u.GivenName, &u.FamilyName, &meta, &u.Blocked, &ids, &last, &u.LoginsCount, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(meta, &u.UserMetadata); err != nil {
		return nil, err
	}
	if err := fromJSON(ids, &u.Identities); err != nil {
		return nil, err
	}
	u.LastLogin = fromNullMicros(last)
	u.CreatedAt, u.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &u, nil
}

func userArgs(u *store.User) ([]any, error) {
	meta, err := toJSON(u.UserMetadata)
	if err != nil {
		return nil, err
	}
	ids, err := toJSON(u.Identities)
	if err != nil {
		return nil, err
	}
	return []any{u.TenantID, u.UserID, u.Email, u.EmailVerified, u.Username, u.Name, u.Nickname, u.Picture, u.GivenName,
		u.FamilyName, meta, u.Blocked, ids, nullMicros(u.LastLogin), u.LoginsCount, micros(u.CreatedAt), micros(u.UpdatedAt)}, nil
}
