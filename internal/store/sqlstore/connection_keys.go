package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

type connectionKeys struct{ s *Store }

func (s *Store) ConnectionKeys() store.ConnectionKeys { return connectionKeys{s} }
func (s *Store) ConnectionKeysSupported() bool        { return true }

const connectionKeyCols = `tenant_id,connection_id,kid,key_use,alg,state,cert_der,private_sealed,current_since,created_at`

func scanConnectionKey(row scanner) (*store.ConnectionKey, error) {
	var k store.ConnectionKey
	var since sql.NullInt64
	var created int64
	if e := row.Scan(&k.TenantID, &k.ConnectionID, &k.KID, &k.Use, &k.Alg, &k.State, &k.CertDER, &k.PrivateSealed, &since, &created); e != nil {
		return nil, e
	}
	k.CurrentSince = fromNullMicros(since)
	k.CreatedAt = fromMicros(created)
	return &k, nil
}
func (r connectionKeys) List(ctx context.Context, tid, cid string) ([]*store.ConnectionKey, error) {
	rows, e := r.s.query(ctx, `SELECT `+connectionKeyCols+` FROM connection_keys WHERE tenant_id=? AND connection_id=? ORDER BY CASE key_use WHEN 'signing' THEN 0 ELSE 1 END,CASE state WHEN 'current' THEN 0 WHEN 'next' THEN 1 ELSE 2 END`, tid, cid)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []*store.ConnectionKey{}
	for rows.Next() {
		k, e := scanConnectionKey(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func lockConnectionKeys(ctx context.Context, tx *Store, tid, cid string) error {
	var one int
	return missing(tx.queryRow(ctx, `SELECT 1 FROM connections WHERE tenant_id=? AND id=?`+tx.d.forUpdate, tid, cid).Scan(&one))
}
func insertConnectionKey(ctx context.Context, tx *Store, k *store.ConnectionKey, state string) error {
	_, e := tx.exec(ctx, `INSERT INTO connection_keys (`+connectionKeyCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, k.TenantID, k.ConnectionID, k.KID, k.Use, k.Alg, state, k.CertDER, k.PrivateSealed, nullMicros(k.CurrentSince), micros(k.CreatedAt))
	return tx.conflict(e)
}
func (r connectionKeys) Create(ctx context.Context, tid, cid, use string, current, next *store.ConnectionKey) error {
	if e := store.ValidateConnectionKeyPair(tid, cid, use, current, next); e != nil {
		return e
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := lockConnectionKeys(ctx, tx, tid, cid); e != nil {
			return e
		}
		var n int
		if e := tx.queryRow(ctx, `SELECT COUNT(*) FROM connection_keys WHERE tenant_id=? AND connection_id=? AND key_use=?`, tid, cid, use).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return store.ErrConflict
		}
		if e := insertConnectionKey(ctx, tx, current, "current"); e != nil {
			return e
		}
		return insertConnectionKey(ctx, tx, next, "next")
	})
}
func (r connectionKeys) Rotate(ctx context.Context, tid, cid, use string, next *store.ConnectionKey, now time.Time) (current *store.ConnectionKey, err error) {
	if next == nil || next.TenantID != tid || next.ConnectionID != cid || next.Use != use || next.KID == "" {
		return nil, store.ErrInvalid
	}
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := lockConnectionKeys(ctx, tx, tid, cid); e != nil {
			return e
		}
		var e error
		current, e = scanConnectionKey(tx.queryRow(ctx, `SELECT `+connectionKeyCols+` FROM connection_keys WHERE tenant_id=? AND connection_id=? AND key_use=? AND state='next'`, tid, cid, use))
		if e != nil {
			return missing(e)
		}
		// Free each unique state before promoting its successor.
		for _, q := range []string{`DELETE FROM connection_keys WHERE tenant_id=? AND connection_id=? AND key_use=? AND state='previous'`, `UPDATE connection_keys SET state='previous' WHERE tenant_id=? AND connection_id=? AND key_use=? AND state='current'`} {
			if _, e := tx.exec(ctx, q, tid, cid, use); e != nil {
				return tx.conflict(e)
			}
		}
		if _, e := tx.exec(ctx, `UPDATE connection_keys SET state='current',current_since=? WHERE tenant_id=? AND connection_id=? AND key_use=? AND state='next'`, micros(now), tid, cid, use); e != nil {
			return tx.conflict(e)
		}
		if e := insertConnectionKey(ctx, tx, next, "next"); e != nil {
			return e
		}
		current.State = "current"
		current.CurrentSince = &now
		return nil
	})
	return current, err
}

// Existing connections omitted type before front-channel support. Backfill in
// Go so all dialects preserve every other stored option exactly.
func (s *Store) backfillOIDCChannel(ctx context.Context) error {
	rows, e := s.query(ctx, `SELECT tenant_id,id,extra FROM connections WHERE strategy='oidc'`)
	if e != nil {
		return e
	}
	type update struct{ tid, id, extra string }
	var updates []update
	for rows.Next() {
		var u update
		if e := rows.Scan(&u.tid, &u.id, &u.extra); e != nil {
			rows.Close()
			return e
		}
		var m map[string]any
		if e := json.Unmarshal([]byte(u.extra), &m); e != nil {
			rows.Close()
			return e
		}
		if m == nil {
			m = map[string]any{}
		}
		if _, ok := m["type"]; !ok {
			m["type"] = "back_channel"
			b, e := json.Marshal(m)
			if e != nil {
				rows.Close()
				return e
			}
			u.extra = string(b)
			updates = append(updates, u)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, u := range updates {
		if _, e := s.exec(ctx, `UPDATE connections SET extra=? WHERE tenant_id=? AND id=?`, u.extra, u.tid, u.id); e != nil {
			return e
		}
	}
	return nil
}
