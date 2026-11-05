package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type webauthnRepo struct{ s *Store }

func (s *Store) WebAuthn() store.WebAuthn { return webauthnRepo{s} }

// CheckWebAuthnSupport: SQL drivers carry the webauthn.v1 schema (0035).
func (s *Store) CheckWebAuthnSupport(context.Context) error { return nil }

// WebAuthnSupported is always true for SQL drivers.
func (s *Store) WebAuthnSupported() bool { return true }

// scopeHash keeps the snooze key within MySQL's index limit; the scope is an
// RP ID (up to 255 bytes), a device key or a hashed browser cookie.
func scopeHash(scope string) string {
	h := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(h[:])
}

func (r webauthnRepo) GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	if len(credID) == 0 {
		return nil, store.ErrNotFound
	}
	return scanAuth(r.s.queryRow(ctx, `SELECT `+authCols+` FROM mfa_authenticators WHERE tenant_id=? AND credential_id=?`, tid, credID))
}

// insertPasskey counts and inserts with the user row locked, so concurrent
// creates for one user serialize; deadlocks retry through atomicRetry.
func insertPasskey(ctx context.Context, s *Store, a *store.Authenticator, limit int) error {
	if err := (mfa{s}).user(ctx, a.TenantID, a.UserID); err != nil {
		return err
	}
	if limit > 0 {
		var n int
		if err := s.queryRow(ctx, `SELECT COUNT(*) FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND type='passkey'`, a.TenantID, a.UserID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return store.ErrPrecondition
		}
	}
	_, err := s.exec(ctx, `INSERT INTO mfa_authenticators (`+authCols+`,recovery_user) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.TenantID, a.UserID, a.ID, a.Type, a.Name, a.Confirmed, a.Preferred, a.SealedSecret, a.LastStep, a.CodeHash, a.Email, a.Phone,
		a.CredentialID, a.PublicKey, a.RPID, a.SignCount, micros(a.CreatedAt), micros(a.LastAuthAt), a.PhoneMethod, a.PublicData, nil)
	return s.conflict(err)
}

func (r webauthnRepo) CreatePasskey(ctx context.Context, a *store.Authenticator, limit int) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error { return insertPasskey(ctx, s, a, limit) })
}

func (r webauthnRepo) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	return r.s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		return insertPasskey(ctx, tx.(*Store), a, 0)
	})
}

func (r webauthnRepo) AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		var pubRaw []byte
		var stored int64
		err := s.queryRow(ctx, `SELECT public_data,sign_count FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND id=?`+s.d.forUpdate, tid, uid, id).Scan(&pubRaw, &stored)
		if err != nil {
			return mfaMissing(err)
		}
		pub := map[string]any{}
		if len(pubRaw) > 0 {
			_ = json.Unmarshal(pubRaw, &pub)
		}
		pub["backed_up"] = backedUp
		b, err := json.Marshal(pub)
		if err != nil {
			return err
		}
		res, err := s.exec(ctx, `UPDATE mfa_authenticators SET sign_count=?,last_auth_at=?,public_data=? WHERE tenant_id=? AND user_id=? AND id=? AND (sign_count<? OR (sign_count=0 AND ?=0))`,
			count, micros(at), b, tid, uid, id, count, count)
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

func (r webauthnRepo) MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		rows, err := s.query(ctx, `SELECT id,public_data FROM mfa_authenticators WHERE tenant_id=? AND user_id=? AND type='passkey'`+s.d.forUpdate, tid, fromUID)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			var pub []byte
			if err := rows.Scan(&id, &pub); err != nil {
				rows.Close()
				return err
			}
			if identityUserID != "" {
				var p struct {
					IdentityUserID string `json:"identity_user_id"`
				}
				_ = json.Unmarshal(pub, &p)
				if p.IdentityUserID != identityUserID {
					continue
				}
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := s.exec(ctx, `UPDATE mfa_authenticators SET user_id=? WHERE tenant_id=? AND id=?`, toUID, tid, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r webauthnRepo) PutSnooze(ctx context.Context, v *store.WebAuthnSnooze) error {
	return r.s.atomicRetry(ctx, nil, func(s *Store) error {
		if err := lockTenant(ctx, s, v.TenantID); err != nil {
			return err
		}
		h := scopeHash(v.ScopeKey)
		if _, err := s.exec(ctx, `DELETE FROM webauthn_snoozes WHERE tenant_id=? AND user_id=? AND kind=? AND scope_hash=?`, v.TenantID, v.UserID, v.Kind, h); err != nil {
			return err
		}
		_, err := s.exec(ctx, `INSERT INTO webauthn_snoozes (tenant_id,user_id,kind,scope_hash,until_at) VALUES (?,?,?,?,?)`, v.TenantID, v.UserID, v.Kind, h, micros(v.Until))
		return s.conflict(err)
	})
}

func (r webauthnRepo) GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	var until int64
	err := r.s.queryRow(ctx, `SELECT until_at FROM webauthn_snoozes WHERE tenant_id=? AND user_id=? AND kind=? AND scope_hash=? AND until_at>?`, tid, uid, kind, scopeHash(scope), micros(now)).Scan(&until)
	if err != nil {
		return nil, mfaMissing(err)
	}
	return &store.WebAuthnSnooze{TenantID: tid, UserID: uid, Kind: kind, ScopeKey: scope, Until: fromMicros(until)}, nil
}

func (r webauthnRepo) HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error) {
	// Suffix match by SUBSTR, not LIKE, so "_" in a host is not a wildcard
	// and "ample.com" is never under "example.com".
	dotted := "." + suffix
	rows, err := r.s.query(ctx, `SELECT DISTINCT tenant_id FROM host_bindings WHERE host=? OR (LENGTH(host)>? AND SUBSTR(host,LENGTH(host)-?+1)=?)`, suffix, len(dotted), len(dotted), dotted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return nil, err
		}
		out = append(out, tid)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Sorted in Go: PostgreSQL refuses DISTINCT with a collated ORDER BY.
	slices.Sort(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r webauthnRepo) PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) {
	total := 0
	err := r.s.atomicRetry(ctx, nil, func(s *Store) error {
		total = 0
		rows, err := s.query(ctx, `SELECT tenant_id,user_id,kind,scope_hash FROM webauthn_snoozes WHERE until_at<? ORDER BY until_at LIMIT ?`, micros(before), limit)
		if err != nil {
			return err
		}
		var keys [][4]string
		for rows.Next() {
			var k [4]string
			if err := rows.Scan(&k[0], &k[1], &k[2], &k[3]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, k := range keys {
			res, err := s.exec(ctx, `DELETE FROM webauthn_snoozes WHERE tenant_id=? AND user_id=? AND kind=? AND scope_hash=? AND until_at<?`, k[0], k[1], k[2], k[3], micros(before))
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			total += int(n)
		}
		return nil
	})
	return total, err
}
