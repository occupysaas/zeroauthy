package sqlstore

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

type users struct{ s *Store }

func (s *Store) Users() store.Users { return users{s} }

const userCols = `tenant_id, user_id, email, email_verified, username, name, nickname, picture, given_name, family_name,
 user_metadata, blocked, identities, last_login, logins_count, created_at, updated_at, app_metadata,
 phone_number, phone_verified, last_ip, version`

func (r users) Create(ctx context.Context, u *store.User) error {
	args, err := userArgs(u)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.exec(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...); err != nil {
			return tx.conflict(err)
		}
		return putLogins(ctx, tx, u, false)
	})
}

// login is one row of user_logins, minus tenant and user.
type login struct{ connection, kind, value string }

// desiredLogins is the sorted, deduplicated set of login rows for u: one
// per login of each identity (store.User.LoginKeys).
func desiredLogins(u *store.User) []login {
	keys := u.LoginKeys()
	out := make([]login, len(keys))
	for i, k := range keys {
		out[i] = login{k.Connection, k.Kind, k.Value}
	}
	return out
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

// GetForUpdate locks the row with the dialect's FOR UPDATE inside a
// transaction. SQLite has no row locks; its transactions are serialized
// (BEGIN IMMEDIATE on one connection).
func (r users) GetForUpdate(ctx context.Context, tenantID, userID string) (*store.User, error) {
	suffix := ""
	if r.s.tx != nil {
		suffix = r.s.d.forUpdate
	}
	u, err := scanUser(r.s.queryRow(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id = ? AND user_id = ?`+suffix, tenantID, userID))
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
		// The stored email and blocked flag decide whether Version moves.
		var oldEmail string
		var oldBlocked bool
		err := tx.queryRow(ctx, `SELECT email, blocked FROM users WHERE tenant_id=? AND user_id=?`+tx.d.forUpdate,
			u.TenantID, u.UserID).Scan(&oldEmail, &oldBlocked)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		bump := 0
		if (u.Blocked && !oldBlocked) || u.Email != oldEmail {
			bump = 1
		}
		// Login stats and Version are owned by the store; Update never
		// replaces them. Relies on MySQL clientFoundRows so an unchanged row
		// still counts.
		res, err := tx.exec(ctx, `UPDATE users SET email=?, email_verified=?, username=?, name=?, nickname=?, picture=?,
 given_name=?, family_name=?, user_metadata=?, blocked=?, identities=?, created_at=?, updated_at=?, app_metadata=?,
 phone_number=?, phone_verified=?, version=version+?
 WHERE tenant_id=? AND user_id=?`,
			args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12],
			args[15], args[16], args[17], args[18], args[19], bump, u.TenantID, u.UserID)
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

func (r users) RecordLogin(ctx context.Context, tenantID, userID string, at time.Time, ip string) error {
	res, err := r.s.write(ctx, nil, `UPDATE users SET last_login=?, last_ip=?, logins_count=logins_count+1 WHERE tenant_id=? AND user_id=?`,
		micros(at), ip, tenantID, userID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r users) SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.setHash(ctx, tenantID, userID, connection, hash, at, false)
}

func (r users) SetPasswordHashIfEmpty(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.setHash(ctx, tenantID, userID, connection, hash, at, true)
}

// setHash reads the identities under a row lock, so the empty check and the
// write are one step.
func (r users) setHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time, onlyIfEmpty bool) error {
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
			// The user's own identity; a linked one keeps its hash (D-0043).
			if ids[i].Connection == connection && !ids[i].Linked() {
				if onlyIfEmpty && (ids[i].PasswordHash != "" || ids[i].ImportedHash != "") {
					return store.ErrConflict
				}
				ids[i].PasswordHash = hash
				ids[i].ImportedHash = ""
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
		_, err = tx.exec(ctx, `UPDATE users SET identities=?, updated_at=?, version=version+1 WHERE tenant_id=? AND user_id=?`,
			enc, micros(at), tenantID, userID)
		return err
	})
}

// UpgradeImportedHash reads the identities under a row lock, so the
// comparison with imported and the write are one step.
func (r users) UpgradeImportedHash(ctx context.Context, tenantID, userID, connection, imported, hash string, at time.Time) error {
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
			if imported != "" && ids[i].Connection == connection && ids[i].ImportedHash == imported {
				ids[i].PasswordHash = hash
				ids[i].ImportedHash = ""
				found = true
				break
			}
		}
		if !found {
			return store.ErrConflict
		}
		enc, err := toJSON(ids)
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE users SET identities=?, updated_at=?, version=version+1 WHERE tenant_id=? AND user_id=?`,
			enc, micros(at), tenantID, userID)
		return err
	})
}

func (r users) BumpVersion(ctx context.Context, tenantID, userID string) (int64, error) {
	var v int64
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE users SET version=version+1 WHERE tenant_id=? AND user_id=?`, tenantID, userID)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return tx.queryRow(ctx, `SELECT version FROM users WHERE tenant_id=? AND user_id=?`, tenantID, userID).Scan(&v)
	})
	return v, err
}

func (r users) FindByEmail(ctx context.Context, tenantID, email string) ([]*store.User, error) {
	if email == "" {
		return nil, nil
	}
	rows, err := r.s.query(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id=? AND email=? ORDER BY user_id`+r.s.d.byteOrder, tenantID, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// userDependents are the tables whose rows name a user by (tenant_id,
// user_id), in the order deleteUser clears them; users itself goes last.
var userDependents = []string{"sessions", "refresh_tokens", "user_grants", "password_reset_tickets", "email_verification_tickets", "password_history",
	"auth_codes", "device_codes", "operators", "user_logins", "users"}

// deleteUser removes the user and every row that names it. Connections.Delete
// uses it for each of the connection's users.
func deleteUser(ctx context.Context, tx *Store, tenantID, userID string) error {
	u, e := (users{tx}).Get(ctx, tenantID, userID)
	if e != nil {
		return e
	}
	var cs []*store.Connection
	for _, identity := range u.Identities {
		c, err := (connections{tx}).GetByName(ctx, tenantID, identity.Connection)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		cs = append(cs, c)
	}
	for _, f := range protectionstate.UserFilters(u, cs) {
		if e = tx.clearProtectionIfTenant(ctx, tenantID, f); e != nil {
			return e
		}
	}
	if _, e = tx.exec(ctx, `DELETE FROM email_notifications WHERE tenant_id=? AND subject_id=?`, tenantID, userID); e != nil {
		return e
	}

	for _, table := range userDependents {
		if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND user_id = ?`, tenantID, userID); err != nil {
			return err
		}
	}
	return nil
}

func (r users) Delete(ctx context.Context, tenantID, userID string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var one int
		err := tx.queryRow(ctx, `SELECT 1 FROM users WHERE tenant_id = ? AND user_id = ?`+tx.d.forUpdate, tenantID, userID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		return deleteUser(ctx, tx, tenantID, userID)
	})
}

func scanUser(row scanner) (*store.User, error) {
	var u store.User
	var meta, ids, appMeta string
	var last sql.NullInt64
	var created, updated int64
	if err := row.Scan(&u.TenantID, &u.UserID, &u.Email, &u.EmailVerified, &u.Username, &u.Name, &u.Nickname, &u.Picture,
		&u.GivenName, &u.FamilyName, &meta, &u.Blocked, &ids, &last, &u.LoginsCount, &created, &updated, &appMeta,
		&u.PhoneNumber, &u.PhoneVerified, &u.LastIP, &u.Version); err != nil {
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
		u.FamilyName, meta, u.Blocked, ids, nullMicros(u.LastLogin), u.LoginsCount, micros(u.CreatedAt), micros(u.UpdatedAt), appMeta,
		u.PhoneNumber, u.PhoneVerified, u.LastIP, int64(0)}, nil
}
