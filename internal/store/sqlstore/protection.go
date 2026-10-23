package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

type protection struct{ s *Store }

func (s *Store) Protection() store.Protection { return protection{s} }
func protectionTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}
func protectionFromTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.UnixMicro(n).UTC()
}
func (s *Store) protectionLock(ctx context.Context, tenant string) error {
	var n int
	err := s.queryRow(ctx, "SELECT 1 FROM tenants WHERE id=?"+s.d.forUpdate, tenant).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// loadProtection loads only selected buckets and their completion history. The
// tenant row is held before this query, including on first bucket insertion.
func (s *Store) loadProtection(ctx context.Context, tenant, where string, args ...any) (*protectionstate.State, error) {
	p := protectionstate.NewState()
	rows, err := s.query(ctx, `SELECT bucket_id,kind,connection_id,identifier,ip,generation,algorithm,capacity,window_us,refill_us,lockout_us,tokens,next_sequence,updated_at,blocked_until,expires_at FROM protection_buckets WHERE tenant_id=?`+where+s.d.forUpdate, append([]any{tenant}, args...)...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		b := &protectionstate.Bucket{Members: map[string]protectionstate.Member{}}
		l := &b.Limit
		l.Key.TenantID = tenant
		var window, refill, lockout, updated, blocked, expires int64
		if err = rows.Scan(&b.ID, &l.Key.Kind, &l.Key.ConnectionID, &l.Key.Identifier, &l.Key.IP, &b.Generation, &l.Algorithm, &l.Capacity, &window, &refill, &lockout, &b.Tokens, &b.NextSequence, &updated, &blocked, &expires); err != nil {
			break
		}
		l.Window = time.Duration(window) * time.Microsecond
		l.Refill = time.Duration(refill) * time.Microsecond
		l.Lockout = time.Duration(lockout) * time.Microsecond
		b.UpdatedAt = protectionFromTime(updated)
		b.BlockedUntil = protectionFromTime(blocked)
		b.ExpiresAt = protectionFromTime(expires)
		p.Buckets[b.ID] = b
	}
	if e := rows.Err(); err == nil {
		err = e
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	for id, b := range p.Buckets {
		rows, err = s.query(ctx, `SELECT m.receipt_id,m.generation,m.admission_sequence,m.outcome,r.reserved_at,r.expires_at,r.completed,r.outcome FROM protection_reservations m JOIN protection_receipts r ON r.tenant_id=m.tenant_id AND r.id=m.receipt_id WHERE m.tenant_id=? AND m.bucket_id=?`+s.d.forUpdate, tenant, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var m protectionstate.Member
			var r protectionstate.Receipt
			var reserved, expires int64
			if err = rows.Scan(&r.ID, &m.Generation, &m.Sequence, &m.Outcome, &reserved, &expires, &r.Completed, &r.Outcome); err != nil {
				break
			}
			r.ReservedAt = protectionFromTime(reserved)
			r.ExpiresAt = protectionFromTime(expires)
			m.ReservedAt = r.ReservedAt
			b.Members[r.ID] = m
			p.Receipts[r.ID] = r
		}
		if e := rows.Err(); err == nil {
			err = e
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}
func (s *Store) saveProtection(ctx context.Context, tenant string, before, after *protectionstate.State) error {
	for id, r := range after.Receipts {
		old, exists := before.Receipts[id]
		if exists && old == r {
			continue
		}
		var err error
		if exists {
			_, err = s.exec(ctx, `UPDATE protection_receipts SET completed=?,outcome=?,expires_at=? WHERE tenant_id=? AND id=?`, r.Completed, r.Outcome, protectionTime(r.ExpiresAt), tenant, id)
		} else {
			_, err = s.exec(ctx, `INSERT INTO protection_receipts (tenant_id,id,reserved_at,completed,outcome,expires_at) VALUES (?,?,?,?,?,?)`, tenant, id, protectionTime(r.ReservedAt), r.Completed, r.Outcome, protectionTime(r.ExpiresAt))
		}
		if err != nil {
			return err
		}
	}
	for id, old := range before.Buckets {
		if _, ok := after.Buckets[id]; !ok {
			if _, err := s.exec(ctx, `DELETE FROM protection_reservations WHERE tenant_id=? AND bucket_id=?`, tenant, id); err != nil {
				return err
			}
			if _, err := s.exec(ctx, `DELETE FROM protection_buckets WHERE tenant_id=? AND bucket_id=? AND generation=?`, tenant, id, old.Generation); err != nil {
				return err
			}
		}
	}
	for id, b := range after.Buckets {
		old, exists := before.Buckets[id]
		if exists && reflect.DeepEqual(old, b) {
			continue
		}
		f, p := b.Counts()
		l := b.Limit
		args := []any{l.Key.Kind, l.Key.ConnectionID, l.Key.Identifier, l.Key.IP, b.Generation, l.Algorithm, l.Capacity, l.Window.Microseconds(), l.Refill.Microseconds(), l.Lockout.Microseconds(), b.Tokens, f, p, b.NextSequence, protectionTime(b.UpdatedAt), protectionTime(b.BlockedUntil), protectionTime(b.ExpiresAt), tenant, id}
		var err error
		if exists {
			_, err = s.exec(ctx, `UPDATE protection_buckets SET kind=?,connection_id=?,identifier=?,ip=?,generation=?,algorithm=?,capacity=?,window_us=?,refill_us=?,lockout_us=?,tokens=?,failures=?,reserved=?,next_sequence=?,updated_at=?,blocked_until=?,expires_at=? WHERE tenant_id=? AND bucket_id=?`, args...)
		} else {
			_, err = s.exec(ctx, `INSERT INTO protection_buckets (kind,connection_id,identifier,ip,generation,algorithm,capacity,window_us,refill_us,lockout_us,tokens,failures,reserved,next_sequence,updated_at,blocked_until,expires_at,tenant_id,bucket_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
		}
		if err != nil {
			return err
		}
		if exists {
			for receipt := range old.Members {
				if _, ok := b.Members[receipt]; !ok {
					if _, err = s.exec(ctx, `DELETE FROM protection_reservations WHERE tenant_id=? AND receipt_id=? AND bucket_id=?`, tenant, receipt, id); err != nil {
						return err
					}
				}
			}
		}
		for receipt, m := range b.Members {
			previous, has := protectionstate.Member{}, false
			if exists {
				previous, has = old.Members[receipt]
			}
			if has && previous == m {
				continue
			}
			if has {
				_, err = s.exec(ctx, `UPDATE protection_reservations SET generation=?,admission_sequence=?,outcome=? WHERE tenant_id=? AND receipt_id=? AND bucket_id=?`, m.Generation, m.Sequence, m.Outcome, tenant, receipt, id)
			} else {
				_, err = s.exec(ctx, `INSERT INTO protection_reservations (generation,admission_sequence,outcome,tenant_id,receipt_id,bucket_id) VALUES (?,?,?,?,?,?)`, m.Generation, m.Sequence, m.Outcome, tenant, receipt, id)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (r protection) Reserve(ctx context.Context, ls []store.ProtectionLimit, now time.Time) (a store.ProtectionAdmission, err error) {
	if err = protectionstate.Validate(ls); err != nil {
		return
	}
	if len(ls) == 0 {
		return store.ProtectionAdmission{Allowed: true}, nil
	}
	ids := make([]string, len(ls))
	args := make([]any, len(ls))
	for i, l := range ls {
		ids[i] = protectionstate.ID(l.Key)
		args[i] = ids[i]
	}
	id, gen := protectionstate.NewID(), protectionstate.NewID()
	tenant := ls[0].Key.TenantID
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, tenant); e != nil {
			return e
		}
		p, e := tx.loadProtection(ctx, tenant, " AND bucket_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+")", args...)
		if e != nil {
			return e
		}
		before := p.Clone()
		a = p.Reserve(ls, ids, id, gen, now)
		return tx.saveProtection(ctx, tenant, before, p)
	})
	return
}
func (r protection) Complete(ctx context.Context, receipt store.ProtectionReceipt, outcome string, now time.Time) error {
	if outcome != "failure" && outcome != "success" && outcome != "refund" {
		return store.ErrInvalid
	}
	if receipt.ID == "" {
		return nil
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, receipt.TenantID); e != nil {
			return e
		}
		rows, e := tx.query(ctx, `SELECT bucket_id FROM protection_reservations WHERE tenant_id=? AND receipt_id=?`+tx.d.forUpdate, receipt.TenantID, receipt.ID)
		if e != nil {
			return e
		}
		var ids []any
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		if x := rows.Err(); e == nil {
			e = x
		}
		rows.Close()
		if e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		p, e := tx.loadProtection(ctx, receipt.TenantID, " AND bucket_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+")", ids...)
		if e != nil {
			return e
		}
		before := p.Clone()
		p.Complete(receipt.ID, outcome, now)
		return tx.saveProtection(ctx, receipt.TenantID, before, p)
	})
}
func protectionWhere(f store.ProtectionFilter) (string, []any) {
	q := ""
	var args []any
	for _, v := range []struct{ name, value string }{{"kind", f.Kind}, {"connection_id", f.ConnectionID}, {"identifier", f.Identifier}, {"ip", f.IP}} {
		if v.value != "" {
			q += " AND " + v.name + "=?"
			args = append(args, v.value)
		}
	}
	return q, args
}
func (r protection) Blocks(ctx context.Context, tenant string, f store.ProtectionFilter, now time.Time) (blocks []store.ProtectionBlock, err error) {
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, tenant); e != nil {
			return e
		}
		q, args := protectionWhere(f)
		p, e := tx.loadProtection(ctx, tenant, q, args...)
		if e != nil {
			return e
		}
		before := p.Clone()
		blocks = p.Blocks(f, now)
		return tx.saveProtection(ctx, tenant, before, p)
	})
	return
}
func (r protection) Clear(ctx context.Context, tenant string, f store.ProtectionFilter) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, tenant); e != nil {
			return e
		}
		q, args := protectionWhere(f)
		p, e := tx.loadProtection(ctx, tenant, q, args...)
		if e != nil {
			return e
		}
		before := p.Clone()
		p.Clear(f)
		return tx.saveProtection(ctx, tenant, before, p)
	})
}
func (r protection) UseProof(ctx context.Context, hash string, now, expires time.Time) (used bool, err error) {
	if hash == "" || !expires.After(now) {
		return false, store.ErrInvalid
	}
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		used = false
		if _, e := tx.exec(ctx, `DELETE FROM protection_proofs WHERE proof_hash=? AND expires_at<=?`, hash, protectionTime(now)); e != nil {
			return e
		}
		// Use a savepoint so a PostgreSQL uniqueness collision does not poison tx.
		e := tx.atomic(ctx, nil, func(t *Store) error {
			_, e := t.exec(ctx, `INSERT INTO protection_proofs (proof_hash,expires_at) VALUES (?,?)`, hash, protectionTime(expires))
			return e
		})
		if tx.d.isUniqueViolation(e) {
			return nil
		}
		if e != nil {
			return e
		}
		used = true
		return nil
	})
	return
}
func (r protection) RecordRisk(ctx context.Context, tenant, id, ip string, now time.Time) error {
	if id == "" || ip == "" {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, tenant); e != nil {
			return e
		}
		var one int
		e := tx.queryRow(ctx, `SELECT 1 FROM protection_risk_events WHERE tenant_id=? AND attempt_id=?`, tenant, id).Scan(&one)
		if e == nil {
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, e = tx.exec(ctx, `INSERT INTO protection_risk_events (tenant_id,attempt_id,ip,occurred_at,expires_at) VALUES (?,?,?,?,?)`, tenant, id, ip, protectionTime(now), protectionTime(now.Add(15*time.Minute)))
		return e
	})
}
func (r protection) RiskCount(ctx context.Context, tenant, ip string, now time.Time) (n int, err error) {
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if e := tx.protectionLock(ctx, tenant); e != nil {
			return e
		}
		return tx.queryRow(ctx, `SELECT COUNT(*) FROM protection_risk_events WHERE tenant_id=? AND ip=? AND occurred_at<=? AND expires_at>?`, tenant, ip, protectionTime(now), protectionTime(now)).Scan(&n)
	})
	return
}
func (r protection) Sweep(ctx context.Context, now time.Time, limit int) (n int, err error) {
	if limit <= 0 {
		return 0, store.ErrInvalid
	}
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		n = 0
		// Every selected item consumes one unit, including abandoned conversions.
		rows, e := tx.query(ctx, `SELECT tenant_id,id FROM protection_receipts WHERE completed=? AND reserved_at<=? ORDER BY reserved_at LIMIT ?`, false, protectionTime(now.Add(-time.Minute)), limit)
		if e != nil {
			return e
		}
		var receipts []store.ProtectionReceipt
		for rows.Next() {
			var a store.ProtectionReceipt
			if e = rows.Scan(&a.TenantID, &a.ID); e != nil {
				break
			}
			receipts = append(receipts, a)
		}
		if x := rows.Err(); e == nil {
			e = x
		}
		rows.Close()
		if e != nil {
			return e
		}
		for _, a := range receipts {
			if e = (protection{tx}).Complete(ctx, a, "failure", now); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
			if _, e = tx.exec(ctx, `UPDATE protection_receipts SET completed=?,outcome=? WHERE tenant_id=? AND id=?`, true, "failure", a.TenantID, a.ID); e != nil {
				return e
			}
			n++
		}
		for _, table := range []string{"protection_buckets", "protection_receipts", "protection_risk_events", "protection_proofs"} {
			if n >= limit {
				break
			}
			idcol := "id"
			switch table {
			case "protection_buckets":
				idcol = "bucket_id"
			case "protection_risk_events":
				idcol = "attempt_id"
			case "protection_proofs":
				idcol = "proof_hash"
			}
			cols := "tenant_id," + idcol
			if table == "protection_proofs" {
				cols = "'',proof_hash"
			}
			extra := ""
			if table == "protection_receipts" {
				extra = ` AND NOT EXISTS (SELECT 1 FROM protection_reservations m WHERE m.tenant_id=protection_receipts.tenant_id AND m.receipt_id=protection_receipts.id)`
			}
			rows, e = tx.query(ctx, `SELECT `+cols+` FROM `+table+` WHERE expires_at<=?`+extra+` ORDER BY expires_at LIMIT ?`, protectionTime(now), limit-n)
			if e != nil {
				return e
			}
			var keys [][2]string
			for rows.Next() {
				var k [2]string
				if e = rows.Scan(&k[0], &k[1]); e != nil {
					break
				}
				keys = append(keys, k)
			}
			if x := rows.Err(); e == nil {
				e = x
			}
			rows.Close()
			if e != nil {
				return e
			}
			for _, k := range keys {
				if table != "protection_proofs" {
					if e = tx.protectionLock(ctx, k[0]); errors.Is(e, store.ErrNotFound) {
						continue
					} else if e != nil {
						return e
					}
				}
				if table == "protection_buckets" {
					if _, e = tx.exec(ctx, `DELETE FROM protection_reservations WHERE tenant_id=? AND bucket_id=? AND EXISTS (SELECT 1 FROM protection_buckets b WHERE b.tenant_id=? AND b.bucket_id=? AND b.expires_at<=?)`, k[0], k[1], k[0], k[1], protectionTime(now)); e != nil {
						return e
					}
				}
				q := `DELETE FROM ` + table + ` WHERE ` + idcol + `=? AND expires_at<=?`
				args := []any{k[1], protectionTime(now)}
				if table != "protection_proofs" {
					q += " AND tenant_id=?"
					args = append(args, k[0])
				}
				res, e := tx.exec(ctx, q, args...)
				if e != nil {
					return e
				}
				count, e := res.RowsAffected()
				if e != nil {
					return e
				}
				n += int(count)
			}
		}
		return nil
	})
	return
}

func (s *Store) clearProtectionIfTenant(ctx context.Context, tenant string, f store.ProtectionFilter) error {
	e := (protection{s}).Clear(ctx, tenant, f)
	if errors.Is(e, store.ErrNotFound) {
		return nil
	}
	return e
}
