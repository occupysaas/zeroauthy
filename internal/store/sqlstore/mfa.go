package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type mfa struct{ s *Store }

func (s *Store) MFA() store.MFA { return mfa{s} }
func mfaMissing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func (r mfa) user(ctx context.Context, tid, uid string) error {
	var x int
	return mfaMissing(r.s.queryRow(ctx, `SELECT 1 FROM users WHERE tenant_id=? AND user_id=?`+r.s.d.forUpdate, tid, uid).Scan(&x))
}
func (r mfa) GetGuardian(ctx context.Context, tid string) (*store.GuardianSettings, error) {
	var x int
	if err := r.s.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`, tid).Scan(&x); err != nil {
		return nil, mfaMissing(err)
	}
	var raw string
	var ver int
	err := r.s.queryRow(ctx, `SELECT data,version FROM mfa_guardian WHERE tenant_id=?`, tid).Scan(&raw, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		v := &store.GuardianSettings{TenantID: tid, Factors: map[string]bool{}, Policies: []string{}}
		for _, f := range mfarules.Factors() {
			v.Factors[f.Name] = false
		}
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	var v store.GuardianSettings
	if err = fromJSON(raw, &v); err != nil {
		return nil, err
	}
	v.Version = ver
	return &v, nil
}
func (r mfa) PutGuardian(ctx context.Context, v *store.GuardianSettings, ver int) error {
	raw, err := toJSON(v)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		var x int
		if err := s.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`+s.d.forUpdate, v.TenantID).Scan(&x); err != nil {
			return mfaMissing(err)
		}
		if ver == 0 {
			_, err := s.exec(ctx, `INSERT INTO mfa_guardian (tenant_id,data,version) VALUES (?,?,1)`, v.TenantID, raw)
			return s.conflict(err)
		}
		res, err := s.exec(ctx, `UPDATE mfa_guardian SET data=?,version=version+1 WHERE tenant_id=? AND version=?`, raw, v.TenantID, ver)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrConflict
		}
		return nil
	})
}

const authCols = `tenant_id,user_id,id,type,name,confirmed,preferred,sealed_secret,last_step,code_hash,email,phone,credential_id,public_key,rp_id,sign_count,created_at,last_auth_at,phone_method,public_data`

func scanAuth(row scanner) (*store.Authenticator, error) {
	var a store.Authenticator
	var created, last int64
	err := row.Scan(&a.TenantID, &a.UserID, &a.ID, &a.Type, &a.Name, &a.Confirmed, &a.Preferred, &a.SealedSecret, &a.LastStep, &a.CodeHash, &a.Email, &a.Phone, &a.CredentialID, &a.PublicKey, &a.RPID, &a.SignCount, &created, &last, &a.PhoneMethod, &a.PublicData)
	a.CreatedAt = fromMicros(created)
	a.LastAuthAt = fromMicros(last)
	if err != nil {
		return nil, mfaMissing(err)
	}
	return &a, nil
}
func (r mfa) CreateAuthenticator(ctx context.Context, a *store.Authenticator) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, a.TenantID, a.UserID); err != nil {
			return err
		}
		var recovery, credential any
		if a.Type == "recovery-code" {
			recovery = a.UserID
		}
		if len(a.CredentialID) > 0 {
			credential = a.CredentialID
		}
		_, err := s.exec(ctx, `INSERT INTO mfa_authenticators (`+authCols+`,recovery_user) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.TenantID, a.UserID, a.ID, a.Type, a.Name, a.Confirmed, a.Preferred, a.SealedSecret, a.LastStep, a.CodeHash, a.Email, a.Phone, credential, a.PublicKey, a.RPID, a.SignCount, micros(a.CreatedAt), micros(a.LastAuthAt), a.PhoneMethod, a.PublicData, recovery)
		return s.conflict(err)
	})
}
func (r mfa) GetAuthenticator(ctx context.Context, tid, uid, id string) (*store.Authenticator, error) {
	return scanAuth(r.s.queryRow(ctx, `SELECT `+authCols+` FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND id=?`, tid, uid, id))
}
func (r mfa) ListAuthenticators(ctx context.Context, tid, uid string) ([]store.Authenticator, error) {
	rows, err := r.s.query(ctx, `SELECT `+authCols+` FROM mfa_authenticators WHERE tenant_id=? AND user_id=? ORDER BY id`+r.s.d.byteOrder, tid, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Authenticator{}
	for rows.Next() {
		a, err := scanAuth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}
func (r mfa) UpdateAuthenticator(ctx context.Context, a *store.Authenticator) error {
	res, err := r.s.write(ctx, nil, `UPDATE mfa_authenticators SET name=?,preferred=?,confirmed=?,phone_method=? WHERE tenant_id=? AND user_id=? AND id=?`, a.Name, a.Preferred, a.Confirmed, a.PhoneMethod, a.TenantID, a.UserID, a.ID)
	if err != nil {
		return err
	}
	return expectRow(res)
}
func (r mfa) DeleteAuthenticator(ctx context.Context, tid, uid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND id=?`, tid, uid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}
func (r mfa) DeleteUserAuthenticators(ctx context.Context, tid, uid string, types []string) error {
	if types != nil && len(types) == 0 {
		return nil
	}
	q := `DELETE FROM mfa_authenticators WHERE tenant_id=? AND user_id=?`
	args := []any{tid, uid}
	if types != nil {
		q += ` AND type IN (`
		for i, t := range types {
			if i > 0 {
				q += ","
			}
			q += "?"
			args = append(args, t)
		}
		q += `)`
	}
	_, err := r.s.write(ctx, nil, q, args...)
	return err
}
func (r mfa) conditional(ctx context.Context, tid, uid, id, q string, args ...any) error {
	res, err := r.s.write(ctx, nil, q, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 0 {
		return nil
	}
	_, err = r.GetAuthenticator(ctx, tid, uid, id)
	if err != nil {
		return err
	}
	return store.ErrPrecondition
}
func (r mfa) AcceptTOTPStep(ctx context.Context, tid, uid, id string, step int64, at time.Time) error {
	return r.conditional(ctx, tid, uid, id, `UPDATE mfa_authenticators SET last_step=?,last_auth_at=? WHERE tenant_id=? AND user_id=? AND id=? AND last_step<?`, step, micros(at), tid, uid, id, step)
}
func (r mfa) AcceptSignCount(ctx context.Context, tid, uid, id string, count uint32, at time.Time) error {
	return r.conditional(ctx, tid, uid, id, `UPDATE mfa_authenticators SET sign_count=?,last_auth_at=? WHERE tenant_id=? AND user_id=? AND id=? AND (sign_count<? OR (sign_count=0 AND ?=0))`, count, micros(at), tid, uid, id, count, count)
}
func (r mfa) ReplaceRecoveryCode(ctx context.Context, tid, uid, old, new string, at time.Time) error {
	if new == "" {
		return store.ErrInvalid
	}
	if old == "" {
		err := r.CreateAuthenticator(ctx, &store.Authenticator{TenantID: tid, UserID: uid, ID: "recovery-code|dev_" + secrets.RandomString(20), Type: "recovery-code", Confirmed: true, CodeHash: new, CreatedAt: at})
		if errors.Is(err, store.ErrConflict) {
			return store.ErrPrecondition
		}
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, tid, uid); err != nil {
			return err
		}
		res, err := s.exec(ctx, `UPDATE mfa_authenticators SET code_hash=?,last_auth_at=? WHERE tenant_id=? AND user_id=? AND type='recovery-code' AND code_hash=?`, new, micros(at), tid, uid, old)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrPrecondition
		}
		return nil
	})
}
func (r mfa) createJSON(ctx context.Context, table, keycol, tid, key, uid, client string, v any, expiry time.Time) error {
	raw, err := toJSON(v)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, tid, uid); err != nil {
			return err
		}
		if client != "" {
			var x int
			if err := s.queryRow(ctx, `SELECT 1 FROM clients WHERE tenant_id=? AND client_id=?`+s.d.forUpdate, tid, client).Scan(&x); err != nil {
				return mfaMissing(err)
			}
		}
		q := `INSERT INTO ` + table + ` (tenant_id,` + keycol + `,user_id,data,expires_at`
		args := []any{tid, key, uid, raw, micros(expiry)}
		if table == "mfa_tokens" {
			q += `,client_id`
			args = append(args, client)
		}
		if table == "mfa_challenges" {
			q += `,attempts`
			args = append(args, v.(*store.MFAChallenge).Attempts)
		}
		q += `) VALUES (?,?,?,?,?`
		if table == "mfa_tokens" || table == "mfa_challenges" {
			q += `,?`
		}
		q += `)`
		_, err := s.exec(ctx, q, args...)
		return s.conflict(err)
	})
}
func (r mfa) CreateMFAToken(ctx context.Context, v *store.MFAToken) error {
	return r.createJSON(ctx, "mfa_tokens", "hash", v.TenantID, v.Hash, v.UserID, v.ClientID, v, v.ExpiresAt)
}
func (r mfa) PeekMFAToken(ctx context.Context, tid, hash string, now time.Time) (*store.MFAToken, error) {
	var raw string
	err := r.s.queryRow(ctx, `SELECT data FROM mfa_tokens WHERE tenant_id=? AND hash=? AND expires_at>?`, tid, hash, micros(now)).Scan(&raw)
	if err != nil {
		return nil, mfaMissing(err)
	}
	var v store.MFAToken
	err = fromJSON(raw, &v)
	return &v, err
}
func (r mfa) ConsumeMFAToken(ctx context.Context, tid, hash, client string, now time.Time) (*store.MFAToken, error) {
	var v *store.MFAToken
	err := r.s.atomicRetry(ctx, nil, func(s *Store) error {
		var err error
		v, err = (mfa{s}).PeekMFAToken(ctx, tid, hash, now)
		if err != nil {
			return err
		}
		if v.ClientID != client {
			return store.ErrNotFound
		}
		res, err := s.exec(ctx, `DELETE FROM mfa_tokens WHERE tenant_id=? AND hash=? AND client_id=? AND expires_at>?`, tid, hash, client, micros(now))
		if err != nil {
			return err
		}
		return expectRow(res)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}
func (r mfa) CreateChallenge(ctx context.Context, v *store.MFAChallenge) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if v.AuthenticatorID != "" {
			if _, err := (mfa{s}).GetAuthenticator(ctx, v.TenantID, v.UserID, v.AuthenticatorID); err != nil {
				return err
			}
		}
		return (mfa{s}).createJSON(ctx, "mfa_challenges", "id", v.TenantID, v.ID, v.UserID, "", v, v.ExpiresAt)
	})
}
func (r mfa) GetChallenge(ctx context.Context, tid, id string, now time.Time) (*store.MFAChallenge, error) {
	var raw string
	var attempts int
	err := r.s.queryRow(ctx, `SELECT data,attempts FROM mfa_challenges WHERE tenant_id=? AND id=? AND expires_at>?`, tid, id, micros(now)).Scan(&raw, &attempts)
	if err != nil {
		return nil, mfaMissing(err)
	}
	var v store.MFAChallenge
	err = fromJSON(raw, &v)
	v.Attempts = attempts
	return &v, err
}
func (r mfa) FailChallenge(ctx context.Context, tid, id string) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, nil, func(s *Store) error {
		res, err := s.exec(ctx, `UPDATE mfa_challenges SET attempts=attempts+1 WHERE tenant_id=? AND id=? AND attempts<5`, tid, id)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			var attempts int
			if err := s.queryRow(ctx, `SELECT attempts FROM mfa_challenges WHERE tenant_id=? AND id=?`, tid, id).Scan(&attempts); err != nil {
				return mfaMissing(err)
			}
			return store.ErrPrecondition
		}
		return s.queryRow(ctx, `SELECT attempts FROM mfa_challenges WHERE tenant_id=? AND id=?`, tid, id).Scan(&n)
	})
	return n, err
}
func (r mfa) ConsumeChallenge(ctx context.Context, tid, id string, now time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		// Kind is stored in data. Lock the record while inspecting it, and keep
		// the attempt predicate on the delete that decides which proof wins.
		var raw string
		err := s.queryRow(ctx, `SELECT data FROM mfa_challenges WHERE tenant_id=? AND id=? AND expires_at>?`+s.d.forUpdate, tid, id, micros(now)).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrPrecondition
		}
		if err != nil {
			return err
		}
		var v store.MFAChallenge
		if err := fromJSON(raw, &v); err != nil {
			return err
		}
		q := `DELETE FROM mfa_challenges WHERE tenant_id=? AND id=? AND expires_at>?`
		if v.Kind == "email" || v.Kind == "oob" {
			q += ` AND attempts<5`
		}
		res, err := s.exec(ctx, q, tid, id, micros(now))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrPrecondition
		}
		return nil
	})
}
func (r mfa) CreateTicket(ctx context.Context, v *store.EnrollmentTicket) error {
	return r.createJSON(ctx, "mfa_tickets", "hash", v.TenantID, v.Hash, v.UserID, "", v, v.ExpiresAt)
}
func (r mfa) ConsumeTicket(ctx context.Context, tid, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	var v store.EnrollmentTicket
	err := r.s.atomicRetry(ctx, nil, func(s *Store) error {
		var raw string
		err := s.queryRow(ctx, `SELECT data FROM mfa_tickets WHERE tenant_id=? AND hash=? AND expires_at>?`+s.d.forUpdate, tid, hash, micros(now)).Scan(&raw)
		if err != nil {
			return mfaMissing(err)
		}
		if err = fromJSON(raw, &v); err != nil {
			return err
		}
		res, err := s.exec(ctx, `DELETE FROM mfa_tickets WHERE tenant_id=? AND hash=? AND expires_at>?`, tid, hash, micros(now))
		if err != nil {
			return err
		}
		return expectRow(res)
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}
func (r mfa) PutBrowser(ctx context.Context, v *store.MFABrowser) error {
	raw, err := toJSON(v)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := (mfa{s}).user(ctx, v.TenantID, v.UserID); err != nil {
			return err
		}
		_, err := s.exec(ctx, `DELETE FROM mfa_browsers WHERE tenant_id=? AND hash=?`, v.TenantID, v.Hash)
		if err != nil {
			return err
		}
		_, err = s.exec(ctx, `INSERT INTO mfa_browsers (tenant_id,hash,user_id,data,expires_at) VALUES (?,?,?,?,?)`, v.TenantID, v.Hash, v.UserID, raw, micros(v.ExpiresAt))
		return err
	})
}
func (r mfa) GetBrowser(ctx context.Context, tid, hash string, now time.Time) (*store.MFABrowser, error) {
	var raw string
	err := r.s.queryRow(ctx, `SELECT data FROM mfa_browsers WHERE tenant_id=? AND hash=? AND expires_at>?`, tid, hash, micros(now)).Scan(&raw)
	if err != nil {
		return nil, mfaMissing(err)
	}
	var v store.MFABrowser
	err = fromJSON(raw, &v)
	return &v, err
}
func (r mfa) BumpRememberEpoch(ctx context.Context, tid, uid string) error {
	res, err := r.s.write(ctx, nil, `UPDATE users SET remember_browser_epoch=remember_browser_epoch+1 WHERE tenant_id=? AND user_id=?`, tid, uid)
	if err != nil {
		return err
	}
	return expectRow(res)
}
func (r mfa) PurgeMFA(ctx context.Context, before time.Time, limit int) (int, error) {
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(s *Store) error {
		n = 0 // a retry starts after the previous transaction was rolled back
		for _, v := range []struct{ table, key string }{{"mfa_tokens", "hash"}, {"mfa_challenges", "id"}, {"mfa_tickets", "hash"}, {"mfa_browsers", "hash"}} {
			if limit > 0 && n >= limit {
				break
			}
			q := `SELECT tenant_id,` + v.key + ` FROM ` + v.table + ` WHERE expires_at<?`
			args := []any{micros(before)}
			if limit > 0 {
				q += ` LIMIT ?`
				args = append(args, limit-n)
			}
			rows, err := s.query(ctx, q, args...)
			if err != nil {
				return err
			}
			var keys [][2]string
			for rows.Next() {
				var k [2]string
				if err = rows.Scan(&k[0], &k[1]); err != nil {
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
				res, err := s.exec(ctx, `DELETE FROM `+v.table+` WHERE tenant_id=? AND `+v.key+`=? AND expires_at<?`, k[0], k[1], micros(before))
				if err != nil {
					return err
				}
				a, err := res.RowsAffected()
				if err != nil {
					return err
				}
				n += int(a)
			}
		}
		return nil
	})
	return n, err
}
func (r mfa) DeleteUserMFA(ctx context.Context, tid, uid string) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		for _, table := range []string{"mfa_authenticators", "mfa_tokens", "mfa_challenges", "mfa_tickets", "mfa_browsers"} {
			if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=? AND user_id=?`, tid, uid); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r mfa) DeleteTenantMFA(ctx context.Context, tid string) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		for _, table := range []string{"mfa_guardian", "mfa_authenticators", "mfa_tokens", "mfa_challenges", "mfa_tickets", "mfa_browsers"} {
			if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=?`, tid); err != nil {
				return err
			}
		}
		return nil
	})
}
