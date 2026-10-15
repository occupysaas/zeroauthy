package sqlstore

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type users struct{ s *Store }

func (s *Store) Users() store.Users { return users{s} }

const userCols = `tenant_id, user_id, email, email_verified, username, name, nickname, picture, given_name, family_name,
 user_metadata, blocked, identities, last_login, logins_count, created_at, updated_at, app_metadata`

func (r users) Create(ctx context.Context, u *store.User) error {
	args, err := userArgs(u)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.exec(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return putLogins(ctx, tx, u, false)
	})
}

// login is one row of user_logins, minus tenant and user.
type login struct{ connection, kind, value string }

// desiredLogins is the sorted, deduplicated set of login rows for u.
func desiredLogins(u *store.User) []login {
	var out []login
	for _, id := range u.Identities {
		for _, l := range [...]login{{id.Connection, "email", u.Email}, {id.Connection, "username", u.Username}} {
			if l.value != "" {
				out = append(out, l)
			}
		}
	}
	slices.SortFunc(out, func(a, b login) int {
		return cmp.Or(cmp.Compare(a.connection, b.connection), cmp.Compare(a.kind, b.kind), cmp.Compare(a.value, b.value))
	})
	return slices.Compact(out)
}

// putLogins brings the user's rows in user_logins to the desired set. When
// existing is false (Create) it only inserts. Otherwise it reads the current
// rows (safe: the caller holds the users row), inserts the added rows first
// and then deletes the removed ones, both in primary-key order. It never
// runs a DELETE by user_id or any predicate that can match nothing: on MySQL
// that takes gap locks and deadlocks concurrent writers. A duplicate value on
// the same connection is a unique violation, mapped to ErrConflict; the
// first violation ends the call and the caller's transaction rolls back.
func putLogins(ctx context.Context, tx *Store, u *store.User, existing bool) error {
	want := desiredLogins(u)
	var have []login
	if existing {
		rows, err := tx.query(ctx, `SELECT connection, kind, value FROM user_logins WHERE tenant_id = ? AND user_id = ?`, u.TenantID, u.UserID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var l login
			if err := rows.Scan(&l.connection, &l.kind, &l.value); err != nil {
				rows.Close()
				return err
			}
			have = append(have, l)
		}
		err = rows.Err()
		rows.Close() // release the single SQLite connection before writing
		if err != nil {
			return err
		}
	}
	for _, l := range want {
		if slices.Contains(have, l) {
			continue
		}
		if _, err := tx.exec(ctx, `INSERT INTO user_logins (tenant_id, connection, kind, value, user_id) VALUES (?,?,?,?,?)`,
			u.TenantID, l.connection, l.kind, l.value, u.UserID); err != nil {
			return tx.conflict(err)
		}
	}
	slices.SortFunc(have, func(a, b login) int {
		return cmp.Or(cmp.Compare(a.connection, b.connection), cmp.Compare(a.kind, b.kind), cmp.Compare(a.value, b.value))
	})
	for _, l := range have {
		if slices.Contains(want, l) {
			continue
		}
		if _, err := tx.exec(ctx, `DELETE FROM user_logins WHERE tenant_id = ? AND connection = ? AND kind = ? AND value = ?`,
			u.TenantID, l.connection, l.kind, l.value); err != nil {
			return err
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
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// Login stats are owned by RecordLogin; Update never changes them.
		// Relies on MySQL clientFoundRows so an unchanged row still counts.
		res, err := tx.exec(ctx, `UPDATE users SET email=?, email_verified=?, username=?, name=?, nickname=?, picture=?,
 given_name=?, family_name=?, user_metadata=?, blocked=?, identities=?, created_at=?, updated_at=?, app_metadata=?
 WHERE tenant_id=? AND user_id=?`,
			args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12],
			args[15], args[16], args[17], u.TenantID, u.UserID)
		if err != nil {
			return tx.conflict(err)
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return putLogins(ctx, tx, u, true)
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
	res, err := r.s.write(ctx, nil, `UPDATE users SET last_login=?, logins_count=logins_count+1 WHERE tenant_id=? AND user_id=?`,
		micros(at), tenantID, userID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r users) SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
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
	var meta, ids, appMeta string
	var last sql.NullInt64
	var created, updated int64
	if err := row.Scan(&u.TenantID, &u.UserID, &u.Email, &u.EmailVerified, &u.Username, &u.Name, &u.Nickname, &u.Picture,
		&u.GivenName, &u.FamilyName, &meta, &u.Blocked, &ids, &last, &u.LoginsCount, &created, &updated, &appMeta); err != nil {
		return nil, err
	}
	if err := fromJSON(appMeta, &u.AppMetadata); err != nil {
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
	appMeta, err := toJSON(u.AppMetadata)
	if err != nil {
		return nil, err
	}
	return []any{u.TenantID, u.UserID, u.Email, u.EmailVerified, u.Username, u.Name, u.Nickname, u.Picture, u.GivenName,
		u.FamilyName, meta, u.Blocked, ids, nullMicros(u.LastLogin), u.LoginsCount, micros(u.CreatedAt), micros(u.UpdatedAt), appMeta}, nil
}
