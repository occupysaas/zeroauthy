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

// directorySync is Plan 37c Phase C state (migration 0048).
type directorySync struct{ s *Store }

func (s *Store) DirectorySync() store.DirectorySync { return directorySync{s} }
func (s *Store) DirectorySyncSupported() bool       { return true }

const provisioningCols = `tenant_id, connection_id, doc, admin_grant, created_at, updated_at, last_sync_at, last_sync_status, last_sync_error, sync_id, next_sync_at, lease_until`

func scanProvisioning(row scanner) (*store.DirectoryProvisioning, error) {
	var p store.DirectoryProvisioning
	var doc string
	var grant []byte
	var created, updated int64
	var last, next, lease sql.NullInt64
	if err := row.Scan(&p.TenantID, &p.ConnectionID, &doc, &grant, &created, &updated, &last, &p.LastSyncStatus, &p.LastSyncError, &p.SyncID, &next, &lease); err != nil {
		return nil, err
	}
	p.Doc, p.CreatedAt, p.UpdatedAt = []byte(doc), fromMicros(created), fromMicros(updated)
	if len(grant) > 0 {
		p.AdminGrant = slices.Clone(grant)
	}
	p.LastSyncAt, p.NextSyncAt, p.LeaseUntil = fromNullMicros(last), fromNullMicros(next), fromNullMicros(lease)
	return &p, nil
}

func (r directorySync) CreateProvisioning(ctx context.Context, p *store.DirectoryProvisioning) error {
	_, err := r.s.write(ctx, nil, `INSERT INTO directory_provisionings (`+provisioningCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.TenantID, p.ConnectionID, string(p.Doc), nullBytes(p.AdminGrant), micros(p.CreatedAt), micros(p.UpdatedAt), nullMicros(p.LastSyncAt),
		p.LastSyncStatus, p.LastSyncError, p.SyncID, nullMicros(p.NextSyncAt), nullMicros(p.LeaseUntil))
	return r.s.conflict(err)
}

func (r directorySync) GetProvisioning(ctx context.Context, tid, conn string) (*store.DirectoryProvisioning, error) {
	p, err := scanProvisioning(r.s.queryRow(ctx, `SELECT `+provisioningCols+` FROM directory_provisionings WHERE tenant_id = ? AND connection_id = ?`, tid, conn))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (r directorySync) UpdateProvisioning(ctx context.Context, p *store.DirectoryProvisioning) error {
	res, err := r.s.write(ctx, nil, `UPDATE directory_provisionings SET doc = ?, admin_grant = ?, updated_at = ?, last_sync_at = ?, last_sync_status = ?, last_sync_error = ?, sync_id = ?, next_sync_at = ?, lease_until = ? WHERE tenant_id = ? AND connection_id = ?`,
		string(p.Doc), nullBytes(p.AdminGrant), micros(p.UpdatedAt), nullMicros(p.LastSyncAt), p.LastSyncStatus, p.LastSyncError, p.SyncID,
		nullMicros(p.NextSyncAt), nullMicros(p.LeaseUntil), p.TenantID, p.ConnectionID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r directorySync) DeleteProvisioning(ctx context.Context, tid, conn string) error {
	return r.s.atomic(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM directory_provisionings WHERE tenant_id = ? AND connection_id = ?`, tid, conn)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		_, err = tx.exec(ctx, `DELETE FROM directory_synchronized_groups WHERE tenant_id = ? AND connection_id = ?`, tid, conn)
		return err
	})
}

func (r directorySync) ListProvisionings(ctx context.Context, tid string, p store.Page) ([]*store.DirectoryProvisioning, int, error) {
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM directory_provisionings WHERE tenant_id = ?`, tid).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.s.query(ctx, `SELECT `+provisioningCols+` FROM directory_provisionings WHERE tenant_id = ? ORDER BY connection_id`+r.s.d.byteOrder+pageClause(p), tid)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*store.DirectoryProvisioning{}
	for rows.Next() {
		v, err := scanProvisioning(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

func (r directorySync) ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*store.DirectoryProvisioning, error) {
	var out []*store.DirectoryProvisioning
	if limit <= 0 {
		return out, nil
	}
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		out = nil
		lock := ""
		if tx.d.name != "sqlite" {
			lock = " FOR UPDATE SKIP LOCKED"
		}
		rows, err := tx.query(ctx, `SELECT `+provisioningCols+` FROM directory_provisionings WHERE next_sync_at <= ? AND (lease_until IS NULL OR lease_until <= ?) ORDER BY next_sync_at, tenant_id`+tx.d.byteOrder+`, connection_id`+tx.d.byteOrder+` LIMIT ?`+lock,
			micros(now), micros(now), limit)
		if err != nil {
			return err
		}
		for rows.Next() {
			v, err := scanProvisioning(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		until := fromMicros(micros(now.Add(lease)))
		for _, v := range out {
			if _, err := tx.exec(ctx, `UPDATE directory_provisionings SET lease_until = ? WHERE tenant_id = ? AND connection_id = ?`, micros(until), v.TenantID, v.ConnectionID); err != nil {
				return err
			}
			v.LeaseUntil = &until
		}
		return nil
	})
	return out, err
}

func (r directorySync) ReplaceGroups(ctx context.Context, tid, conn string, groups []store.SynchronizedGroup) error {
	next := slices.Clone(groups)
	slices.SortStableFunc(next, func(a, b store.SynchronizedGroup) int { return cmp.Compare(a.GroupID, b.GroupID) })
	next = slices.CompactFunc(next, func(a, b store.SynchronizedGroup) bool { return a.GroupID == b.GroupID })
	return r.s.atomic(ctx, nil, func(tx *Store) error {
		var one int
		if err := tx.queryRow(ctx, `SELECT 1 FROM directory_provisionings WHERE tenant_id = ? AND connection_id = ?`+tx.d.forUpdate, tid, conn).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM directory_synchronized_groups WHERE tenant_id = ? AND connection_id = ?`, tid, conn); err != nil {
			return err
		}
		for _, g := range next {
			if _, err := tx.exec(ctx, `INSERT INTO directory_synchronized_groups (tenant_id, connection_id, group_id, doc) VALUES (?,?,?,?)`, tid, conn, g.GroupID, string(g.Doc)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r directorySync) ListGroups(ctx context.Context, tid, conn string) ([]store.SynchronizedGroup, error) {
	if _, err := r.GetProvisioning(ctx, tid, conn); err != nil {
		return nil, err
	}
	rows, err := r.s.query(ctx, `SELECT group_id, doc FROM directory_synchronized_groups WHERE tenant_id = ? AND connection_id = ? ORDER BY group_id`+r.s.d.byteOrder, tid, conn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.SynchronizedGroup{}
	for rows.Next() {
		var g store.SynchronizedGroup
		var doc string
		if err := rows.Scan(&g.GroupID, &doc); err != nil {
			return nil, err
		}
		g.Doc = []byte(doc)
		out = append(out, g)
	}
	return out, rows.Err()
}
