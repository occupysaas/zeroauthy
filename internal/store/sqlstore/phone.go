package sqlstore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/phonenumber"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type phoneRepo struct{ s *Store }

func (s *Store) Phone() store.Phone { return phoneRepo{s} }

const (
	phoneProviderCols = `tenant_id,id,name,disabled,configuration,sealed_credentials,created_at,updated_at`
	phoneTemplateCols = `tenant_id,id,type,disabled,content,customizable,created_at,updated_at`
	passwordlessCols  = `tenant_id,connection_id,identifier,kind,client_id,code_hash,request,attempts,expires_at,created_at`
)

// lockTenant takes the tenant row for the rest of the transaction and reports
// ErrNotFound if the tenant does not exist.
func lockTenant(ctx context.Context, tx *Store, tid string) error {
	var one int
	return mfaMissing(tx.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`+tx.d.forUpdate, tid).Scan(&one))
}

func scanPhoneProvider(row scanner) (*store.PhoneProvider, error) {
	var p store.PhoneProvider
	var cfg string
	var created, updated int64
	if err := row.Scan(&p.TenantID, &p.ID, &p.Name, &p.Disabled, &cfg, &p.SealedCredentials, &created, &updated); err != nil {
		return nil, err
	}
	p.Configuration = json.RawMessage(cfg)
	p.CreatedAt, p.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &p, nil
}

func (r phoneRepo) ListPhoneProviders(ctx context.Context, tid string) ([]store.PhoneProvider, error) {
	rows, err := r.s.query(ctx, `SELECT `+phoneProviderCols+` FROM phone_providers WHERE tenant_id=? ORDER BY id`+r.s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.PhoneProvider{}
	for rows.Next() {
		p, err := scanPhoneProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (r phoneRepo) GetPhoneProvider(ctx context.Context, tid, id string) (*store.PhoneProvider, error) {
	p, err := scanPhoneProvider(r.s.queryRow(ctx, `SELECT `+phoneProviderCols+` FROM phone_providers WHERE tenant_id=? AND id=?`, tid, id))
	return p, mfaMissing(err)
}

func (r phoneRepo) CreatePhoneProvider(ctx context.Context, p *store.PhoneProvider) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockTenant(ctx, tx, p.TenantID); err != nil {
			return err
		}
		var one int
		err := tx.queryRow(ctx, `SELECT 1 FROM phone_providers WHERE tenant_id=?`, p.TenantID).Scan(&one)
		if err == nil {
			return store.ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.exec(ctx, `INSERT INTO phone_providers (`+phoneProviderCols+`) VALUES (?,?,?,?,?,?,?,?)`,
			p.TenantID, p.ID, p.Name, p.Disabled, string(p.Configuration), nonNilBytes(p.SealedCredentials), micros(p.CreatedAt), micros(p.UpdatedAt))
		return tx.conflict(err)
	})
}

func (r phoneRepo) UpdatePhoneProvider(ctx context.Context, p *store.PhoneProvider) error {
	res, err := r.s.write(ctx, nil, `UPDATE phone_providers SET name=?,disabled=?,configuration=?,sealed_credentials=?,updated_at=? WHERE tenant_id=? AND id=?`,
		p.Name, p.Disabled, string(p.Configuration), nonNilBytes(p.SealedCredentials), micros(p.UpdatedAt), p.TenantID, p.ID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r phoneRepo) DeletePhoneProvider(ctx context.Context, tid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM phone_providers WHERE tenant_id=? AND id=?`, tid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func scanPhoneTemplate(row scanner) (*store.PhoneTemplate, error) {
	var t store.PhoneTemplate
	var content string
	var created, updated int64
	if err := row.Scan(&t.TenantID, &t.ID, &t.Type, &t.Disabled, &content, &t.Customizable, &created, &updated); err != nil {
		return nil, err
	}
	t.Content = json.RawMessage(content)
	t.CreatedAt, t.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &t, nil
}

func (r phoneRepo) ListPhoneTemplates(ctx context.Context, tid string) ([]store.PhoneTemplate, error) {
	rows, err := r.s.query(ctx, `SELECT `+phoneTemplateCols+` FROM phone_templates WHERE tenant_id=? ORDER BY id`+r.s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.PhoneTemplate{}
	for rows.Next() {
		t, err := scanPhoneTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (r phoneRepo) GetPhoneTemplate(ctx context.Context, tid, id string) (*store.PhoneTemplate, error) {
	t, err := scanPhoneTemplate(r.s.queryRow(ctx, `SELECT `+phoneTemplateCols+` FROM phone_templates WHERE tenant_id=? AND id=?`, tid, id))
	return t, mfaMissing(err)
}

func (r phoneRepo) PutPhoneTemplate(ctx context.Context, t *store.PhoneTemplate) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockTenant(ctx, tx, t.TenantID); err != nil {
			return err
		}
		var other string
		err := tx.queryRow(ctx, `SELECT id FROM phone_templates WHERE tenant_id=? AND type=? AND id<>?`, t.TenantID, t.Type, t.ID).Scan(&other)
		if err == nil {
			return store.ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		q := `INSERT INTO phone_templates (` + phoneTemplateCols + `) VALUES (?,?,?,?,?,?,?,?)`
		if tx.d.name == "mysql" {
			q += ` ON DUPLICATE KEY UPDATE type=VALUES(type),disabled=VALUES(disabled),content=VALUES(content),customizable=VALUES(customizable),updated_at=VALUES(updated_at)`
		} else {
			q += ` ON CONFLICT (tenant_id,id) DO UPDATE SET type=excluded.type,disabled=excluded.disabled,content=excluded.content,customizable=excluded.customizable,updated_at=excluded.updated_at`
		}
		_, err = tx.exec(ctx, q, t.TenantID, t.ID, t.Type, t.Disabled, string(t.Content), t.Customizable, micros(t.CreatedAt), micros(t.UpdatedAt))
		return tx.conflict(err)
	})
}

func (r phoneRepo) DeletePhoneTemplate(ctx context.Context, tid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM phone_templates WHERE tenant_id=? AND id=?`, tid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func scanPasswordlessCode(row scanner) (*store.PasswordlessCode, error) {
	var c store.PasswordlessCode
	var request string
	var attempts, expires, created int64
	if err := row.Scan(&c.TenantID, &c.ConnectionID, &c.Identifier, &c.Kind, &c.ClientID, &c.CodeHash, &request, &attempts, &expires, &created); err != nil {
		return nil, err
	}
	c.Request = json.RawMessage(request)
	c.Attempts = int(attempts)
	c.ExpiresAt, c.CreatedAt = fromMicros(expires), fromMicros(created)
	return &c, nil
}

// PutPasswordlessCode replaces the row for the key in one upsert, which also
// resets attempts.
func (r phoneRepo) PutPasswordlessCode(ctx context.Context, c *store.PasswordlessCode) error {
	var one int
	if err := mfaMissing(r.s.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`, c.TenantID).Scan(&one)); err != nil {
		return err
	}
	q := `INSERT INTO passwordless_codes (` + passwordlessCols + `) VALUES (?,?,?,?,?,?,?,?,?,?)`
	if r.s.d.name == "mysql" {
		q += ` ON DUPLICATE KEY UPDATE client_id=VALUES(client_id),code_hash=VALUES(code_hash),request=VALUES(request),attempts=VALUES(attempts),expires_at=VALUES(expires_at),created_at=VALUES(created_at)`
	} else {
		q += ` ON CONFLICT (tenant_id,connection_id,identifier,kind) DO UPDATE SET client_id=excluded.client_id,code_hash=excluded.code_hash,request=excluded.request,attempts=excluded.attempts,expires_at=excluded.expires_at,created_at=excluded.created_at`
	}
	request := string(c.Request)
	if request == "" {
		request = "null"
	}
	_, err := r.s.write(ctx, nil, q, c.TenantID, c.ConnectionID, c.Identifier, c.Kind, c.ClientID, c.CodeHash, request, int64(c.Attempts), micros(c.ExpiresAt), micros(c.CreatedAt))
	return err
}

// FailPasswordlessCode increments attempts regardless of expiry.
func (r phoneRepo) FailPasswordlessCode(ctx context.Context, tid, conn, ident, kind string, _ time.Time) (int, error) {
	var attempts int
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE passwordless_codes SET attempts=attempts+1 WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=?`, tid, conn, ident, kind)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return tx.queryRow(ctx, `SELECT attempts FROM passwordless_codes WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=?`, tid, conn, ident, kind).Scan(&attempts)
	})
	return attempts, err
}

// ConsumePasswordlessCode compares the hash in constant time, then deletes the
// row (match) or increments its attempts (mismatch) with a statement
// conditioned on the attempts it read. When callers race, the statement's row
// count lets exactly one of them act on each observed state; the losers read
// again, so every wrong guess is counted once and at most maxAttempts guesses
// are accepted.
func (r phoneRepo) ConsumePasswordlessCode(ctx context.Context, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*store.PasswordlessCode, error) {
	for range maxAttempts + 16 {
		c, err := scanPasswordlessCode(r.s.queryRow(ctx, `SELECT `+passwordlessCols+` FROM passwordless_codes WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=?`, tid, conn, ident, kind))
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrPrecondition
		}
		if err != nil {
			return nil, err
		}
		if c.Attempts >= maxAttempts || !now.Before(c.ExpiresAt) {
			return nil, store.ErrPrecondition
		}
		match := subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(hash)) == 1
		stmt := `UPDATE passwordless_codes SET attempts=attempts+1 WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=? AND code_hash=? AND attempts=? AND expires_at=?`
		if match {
			stmt = `DELETE FROM passwordless_codes WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=? AND code_hash=? AND attempts=? AND expires_at=?`
		}
		res, err := r.s.write(ctx, nil, stmt, tid, conn, ident, kind, c.CodeHash, int64(c.Attempts), micros(c.ExpiresAt))
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // the row changed under us: read it again
		}
		if !match {
			return nil, store.ErrPrecondition
		}
		return c, nil
	}
	return nil, store.ErrPrecondition
}

func (r phoneRepo) PeekPasswordlessLink(ctx context.Context, tid, hash string, now time.Time) (*store.PasswordlessCode, error) {
	rows, err := r.s.query(ctx, `SELECT `+passwordlessCols+` FROM passwordless_codes WHERE tenant_id=? AND code_hash=? AND kind='link' AND expires_at>?`, tid, hash, micros(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanPasswordlessCode(rows)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(c.CodeHash), []byte(hash)) == 1 {
			return c, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, store.ErrNotFound
}

func (r phoneRepo) FindUsersByPhone(ctx context.Context, tid, connection, e164 string) ([]store.User, error) {
	out := []store.User{}
	if e164 == "" {
		return out, nil
	}
	rows, err := r.s.query(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id=? AND (phone_normalized=? OR phone_normalized IS NULL OR phone_normalized='') ORDER BY user_id`+r.s.d.byteOrder, tid, e164)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		n, _ := phonenumber.NormalizeE164(u.PhoneNumber, "")
		if n != e164 {
			continue
		}
		for _, id := range u.Identities {
			if id.Connection == connection {
				out = append(out, *u)
				break
			}
		}
	}
	return out, rows.Err()
}

func (r phoneRepo) PurgePhone(ctx context.Context, before time.Time, limit int) (int, error) {
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(s *Store) error {
		n = 0 // a retry starts after the previous transaction was rolled back
		q := `SELECT tenant_id,connection_id,identifier,kind FROM passwordless_codes WHERE expires_at<?`
		args := []any{micros(before)}
		if limit > 0 {
			q += ` LIMIT ?`
			args = append(args, limit)
		}
		rows, err := s.query(ctx, q, args...)
		if err != nil {
			return err
		}
		var keys [][4]string
		for rows.Next() {
			var k [4]string
			if err = rows.Scan(&k[0], &k[1], &k[2], &k[3]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, k := range keys {
			res, err := s.exec(ctx, `DELETE FROM passwordless_codes WHERE tenant_id=? AND connection_id=? AND identifier=? AND kind=? AND expires_at<?`, k[0], k[1], k[2], k[3], micros(before))
			if err != nil {
				return err
			}
			a, err := res.RowsAffected()
			if err != nil {
				return err
			}
			n += int(a)
		}
		return nil
	})
	return n, err
}

func (r phoneRepo) DeleteTenantPhone(ctx context.Context, tid string) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		for _, table := range []string{"passwordless_codes", "phone_templates", "phone_providers"} {
			if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=?`, tid); err != nil {
				return err
			}
		}
		return nil
	})
}
