package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type events struct{ s *Store }

func (s *Store) Events() store.Events                     { return events{s} }
func (s *Store) CheckEventsSupport(context.Context) error { return nil }
func (s *Store) EventsSupported() bool                    { return true }
func (s *Store) eventNow() time.Time {
	if s.eventsClock != nil {
		return s.eventsClock().UTC()
	}
	return time.Now().UTC()
}

func (r events) AppendEvents(ctx context.Context, es []store.TenantEvent) error {
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		ids := []string{}
		for _, e := range es {
			ids = append(ids, e.TenantID)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		// Use the same lock as business/RBAC mutations and tenant deletion. Sorted
		// acquisition avoids introducing a second ordering for multi-tenant appends.
		// The lock survives this savepoint until the business transaction commits;
		// higher tenant sequences cannot commit ahead of an earlier append.
		for _, id := range ids {
			if err := t.lockRBAC(ctx, id); err != nil {
				return err
			}
		}
		stamps := map[string]string{}
		now := logTime(t.eventNow())
		for _, id := range ids {
			var previous string
			err := t.queryRow(ctx, `SELECT committed_at FROM tenant_events WHERE tenant_id=? ORDER BY seq DESC LIMIT 1`+t.d.forUpdate, id).Scan(&previous)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			stamps[id] = now
			// A locking read also sees the latest commit under MySQL REPEATABLE READ.
			// Clamp clock skew so a later sequence never settles ahead of its predecessor.
			if previous > now {
				stamps[id] = previous
			}
		}
		seqs := make([]int64, len(es))
		for i, e := range es {
			body := e.Body
			if body == nil {
				body = []byte{}
			}
			q := `INSERT INTO tenant_events (tenant_id,event_id,type,event_time,committed_at,body) VALUES (?,?,?,?,?,?)`
			args := []any{e.TenantID, e.ID, e.Type, logTime(e.Time), stamps[e.TenantID], body}
			if t.d.name == "postgres" {
				if err := t.queryRow(ctx, q+` RETURNING seq`, args...).Scan(&seqs[i]); err != nil {
					return t.conflict(err)
				}
			} else {
				res, err := t.exec(ctx, q, args...)
				if err != nil {
					return t.conflict(err)
				}
				seqs[i], err = res.LastInsertId()
				if err != nil {
					return err
				}
			}
		}
		for i := range es {
			es[i].Seq = seqs[i]
		}
		return nil
	})
}

const eventCols = `tenant_id,seq,event_id,type,event_time,body`

func scanEvent(row scanner) (store.TenantEvent, error) {
	var e store.TenantEvent
	var at string
	err := row.Scan(&e.TenantID, &e.Seq, &e.ID, &e.Type, &at, &e.Body)
	if errors.Is(err, sql.ErrNoRows) {
		err = store.ErrNotFound
	}
	e.Time = fromLogTime(at)
	return e, err
}
func (r events) GetEvent(ctx context.Context, tid, id string) (*store.TenantEvent, error) {
	e, err := scanEvent(r.s.queryRow(ctx, `SELECT `+eventCols+` FROM tenant_events WHERE tenant_id=? AND event_id=?`, tid, id))
	if err != nil {
		return nil, err
	}
	return &e, nil
}
func eventTake(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 100 {
		return 100
	}
	return n
}
func eventIn(q string, args []any, col string, values []string) (string, []any) {
	if len(values) == 0 {
		return q, args
	}
	q += ` AND ` + col + ` IN (` + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + `)`
	for _, v := range values {
		args = append(args, v)
	}
	return q, args
}
func (r events) read(ctx context.Context, tid string, after int64, from time.Time, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	q := `SELECT ` + eventCols + ` FROM tenant_events WHERE tenant_id=? AND seq>? AND committed_at<=?`
	args := []any{tid, after, logTime(settled)}
	if !from.IsZero() {
		q += ` AND event_time>=?`
		args = append(args, logTime(from))
	}
	q, args = eventIn(q, args, "type", types)
	q += ` ORDER BY seq LIMIT ?`
	args = append(args, eventTake(take))
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.TenantEvent{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r events) EventsAfter(ctx context.Context, tid string, after int64, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	return r.read(ctx, tid, after, time.Time{}, types, take, settled)
}
func (r events) EventsFromTime(ctx context.Context, tid string, from time.Time, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	return r.read(ctx, tid, 0, from, types, take, settled)
}
func (r events) LatestEventSeq(ctx context.Context, tid string) (int64, error) {
	var n int64
	err := r.s.queryRow(ctx, `SELECT COALESCE(MAX(seq),0) FROM tenant_events WHERE tenant_id=?`, tid).Scan(&n)
	return n, err
}
func (r events) OldestEventSeq(ctx context.Context, tid string) (int64, error) {
	var n int64
	err := r.s.queryRow(ctx, `SELECT COALESCE(MIN(seq),0) FROM tenant_events WHERE tenant_id=?`, tid).Scan(&n)
	return n, err
}
func (r events) PurgeEvents(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(t *Store) error {
		n = 0
		// Select a bounded batch first, close its cursor, then acquire tenant locks
		// in the same order as AppendEvents. All delivery writers use those locks.
		rows, err := t.query(ctx, `SELECT tenant_id,event_id,seq FROM tenant_events WHERE event_time<? ORDER BY event_time,seq LIMIT ?`, logTime(before), limit)
		if err != nil {
			return err
		}
		type ref struct {
			tid, id string
			seq     int64
		}
		batch := []ref{}
		tenants := []string{}
		for rows.Next() {
			var v ref
			if err := rows.Scan(&v.tid, &v.id, &v.seq); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, v)
			tenants = append(tenants, v.tid)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		slices.Sort(tenants)
		tenants = slices.Compact(tenants)
		for _, tid := range tenants {
			if err := t.lockRBAC(ctx, tid); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		for _, v := range batch {
			// Match the selected identity, not a replacement inserted after another
			// purge removed the candidate. Only delete deliveries of removed rows.
			res, err := t.exec(ctx, `DELETE FROM tenant_events WHERE tenant_id=? AND event_id=? AND seq=? AND event_time<?`, v.tid, v.id, v.seq, logTime(before))
			if err != nil {
				return err
			}
			k, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if k > 0 {
				if _, err := t.exec(ctx, `DELETE FROM event_deliveries WHERE tenant_id=? AND event_id=?`, v.tid, v.id); err != nil {
					return err
				}
				n += int(k)
			}
		}
		// Deleting a retained failure changes the stream's extant count, but
		// does not reset its consecutive failure streak. Tenant locks fence
		// workers and management updates across this count and the deletion.
		for _, tid := range tenants {
			count := `(SELECT COUNT(*) FROM event_deliveries d WHERE d.tenant_id=event_streams.tenant_id AND d.stream_id=event_streams.id)`
			if _, err := t.exec(ctx, `UPDATE event_streams SET total_failures=`+count+`,version=version+1,updated_at=? WHERE tenant_id=? AND total_failures<>`+count, logTime(t.eventNow()), tid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
func (r events) DeleteTenantEvents(ctx context.Context, tid string) error {
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, tid); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		for _, table := range []string{"event_deliveries", "event_streams", "tenant_events"} {
			if _, err := t.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=?`, tid); err != nil {
				return err
			}
		}
		return nil
	})
}

const eventStreamCols = `tenant_id,id,name,status,config,checkpoint,lease_owner,lease_until,consecutive_failures,total_failures,version,created_at,updated_at`

func eventStreamConfig(v *store.EventStream) (string, error) {
	b, err := json.Marshal(struct {
		DestType      string
		Subscriptions []string
		Config        map[string]any
		SealedSecret  []byte
	}{v.DestType, v.Subscriptions, v.Config, v.SealedSecret})
	if err != nil {
		return "", store.ErrInvalid
	}
	return string(b), nil
}
func scanEventStream(row scanner) (*store.EventStream, error) {
	v := new(store.EventStream)
	var config, lease, created, updated string
	err := row.Scan(&v.TenantID, &v.ID, &v.Name, &v.Status, &config, &v.Checkpoint, &v.LeaseOwner, &lease, &v.ConsecutiveFailures, &v.TotalFailures, &v.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(config))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return nil, err
	}
	v.LeaseUntil = fromLogTime(lease)
	v.CreatedAt = fromLogTime(created)
	v.UpdatedAt = fromLogTime(updated)
	return v, nil
}
func (r events) CreateEventStream(ctx context.Context, v *store.EventStream) error {
	if v == nil {
		return store.ErrInvalid
	}
	config, err := eventStreamConfig(v)
	if err != nil {
		return err
	}
	err = r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, v.TenantID); err != nil {
			return err
		}
		_, err := t.exec(ctx, `INSERT INTO event_streams (`+eventStreamCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.TenantID, v.ID, v.Name, v.Status, config, v.Checkpoint, v.LeaseOwner, logTime(v.LeaseUntil), v.ConsecutiveFailures, v.TotalFailures, 1, logTime(v.CreatedAt), logTime(v.UpdatedAt))
		return t.conflict(err)
	})
	if err == nil {
		v.Version = 1
	}
	return err
}
func (r events) GetEventStream(ctx context.Context, tid, id string) (*store.EventStream, error) {
	return scanEventStream(r.s.queryRow(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE tenant_id=? AND id=?`, tid, id))
}
func (r events) ListEventStreams(ctx context.Context, tid, after string, take int) ([]store.EventStream, string, error) {
	rows, err := r.s.query(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE tenant_id=? AND id`+r.s.d.byteOrder+`>? ORDER BY id`+r.s.d.byteOrder+` LIMIT ?`, tid, after, eventTake(take)+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []store.EventStream{}
	for rows.Next() {
		v, err := scanEventStream(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > eventTake(take) {
		out = out[:eventTake(take)]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}
func (r events) CountEventStreams(ctx context.Context, tid string) (int, error) {
	// A transactional count is a quota check: serialize it with create/update
	// before reading even an empty stream table, holding the tenant lock to commit.
	if r.s.tx != nil {
		if err := r.s.lockRBAC(ctx, tid); err != nil {
			return 0, err
		}
	}
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM event_streams WHERE tenant_id=?`, tid).Scan(&n)
	return n, err
}
func (r events) UpdateEventStream(ctx context.Context, v *store.EventStream, version int) error {
	if v == nil {
		return store.ErrInvalid
	}
	config, err := eventStreamConfig(v)
	if err != nil {
		return err
	}
	err = r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, v.TenantID); err != nil {
			return err
		}
		old, err := scanEventStream(t.queryRow(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE tenant_id=? AND id=?`+t.d.forUpdate, v.TenantID, v.ID))
		if err != nil {
			return err
		}
		if old.Version != version {
			return store.ErrConflict
		}
		res, err := t.exec(ctx, `UPDATE event_streams SET name=?,status=?,config=?,checkpoint=?,lease_owner=?,lease_until=?,consecutive_failures=?,total_failures=?,version=version+1,created_at=?,updated_at=? WHERE tenant_id=? AND id=? AND version=?`, v.Name, v.Status, config, v.Checkpoint, v.LeaseOwner, logTime(v.LeaseUntil), v.ConsecutiveFailures, v.TotalFailures, logTime(v.CreatedAt), logTime(v.UpdatedAt), v.TenantID, v.ID, version)
		if err != nil {
			return t.conflict(err)
		}
		return expectRow(res)
	})
	if err == nil {
		v.Version = version + 1
	}
	return err
}
func (r events) DeleteEventStream(ctx context.Context, tid, id string) error {
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, tid); err != nil {
			return err
		}
		res, err := t.exec(ctx, `DELETE FROM event_streams WHERE tenant_id=? AND id=?`, tid, id)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		_, err = t.exec(ctx, `DELETE FROM event_deliveries WHERE tenant_id=? AND stream_id=?`, tid, id)
		return err
	})
}
func (r events) LeaseEventStream(ctx context.Context, owner string, now, until time.Time) (*store.EventStream, error) {
	if owner == "" || !until.After(now) {
		return nil, store.ErrInvalid
	}
	var out *store.EventStream
	err := r.s.atomicRetry(ctx, nil, func(t *Store) error {
		// Queueing is independent of stream status: disabled streams may redeliver.
		due := `((status='enabled' AND EXISTS (SELECT 1 FROM tenant_events e WHERE e.tenant_id=event_streams.tenant_id AND e.seq>event_streams.checkpoint)) OR EXISTS (SELECT 1 FROM event_deliveries d WHERE d.tenant_id=event_streams.tenant_id AND d.stream_id=event_streams.id AND d.queued=true))`
		available := `(lease_until<=? OR lease_owner=? OR lease_owner='')`
		v, err := scanEventStream(t.queryRow(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE `+available+` AND `+due+` ORDER BY tenant_id,id LIMIT 1`+t.d.forUpdate, logTime(now), owner))
		if err != nil {
			return err
		}
		res, err := t.exec(ctx, `UPDATE event_streams SET lease_owner=?,lease_until=? WHERE tenant_id=? AND id=? AND `+available, owner, logTime(until), v.TenantID, v.ID, logTime(now), owner)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		v.LeaseOwner = owner
		v.LeaseUntil = until
		out = v
		return nil
	})
	return out, err
}
func (r events) RecordEventDelivery(ctx context.Context, tid, id, owner string, o store.DeliveryOutcome) error {
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, tid); err != nil {
			return err
		}
		v, err := scanEventStream(t.queryRow(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE tenant_id=? AND id=?`+t.d.forUpdate, tid, id))
		if err != nil {
			return err
		}
		// Read the clock after acquiring locks; acquisition can outlive the lease.
		now := t.eventNow()
		if owner == "" || v.LeaseOwner != owner || !v.LeaseUntil.After(now) {
			return store.ErrPrecondition
		}
		if o.Failed != nil && (o.Failed.TenantID != tid || o.Failed.StreamID != id || o.Failed.Status != "failed") {
			return store.ErrInvalid
		}
		if o.Checkpoint < v.Checkpoint {
			return store.ErrPrecondition
		}
		refs := slices.Clone(o.Succeeded)
		if o.Failed != nil {
			refs = append(refs, o.Failed.EventID)
		}
		// Purges and delivery writers hold the same tenant lock. Validate every
		// reference before changing counters, checkpoint, status or delivery rows.
		for _, eid := range refs {
			var one int
			err := t.queryRow(ctx, `SELECT 1 FROM tenant_events WHERE tenant_id=? AND event_id=?`+t.d.forUpdate, tid, eid).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		if o.Failed != nil {
			d := o.Failed
			attempts, err := json.Marshal(d.Attempts)
			if err != nil {
				return store.ErrInvalid
			}
			q := `INSERT INTO event_deliveries (` + eventDeliveryCols + `) VALUES (?,?,?,?,?,?,?,?,?)`
			if t.d.name == "mysql" {
				q += ` ON DUPLICATE KEY UPDATE type=VALUES(type),status=VALUES(status),attempts=VALUES(attempts),queued=VALUES(queued),event_time=VALUES(event_time),updated_at=VALUES(updated_at)`
			} else {
				q += ` ON CONFLICT (tenant_id,stream_id,event_id) DO UPDATE SET type=excluded.type,status=excluded.status,attempts=excluded.attempts,queued=excluded.queued,event_time=excluded.event_time,updated_at=excluded.updated_at`
			}
			if _, err := t.exec(ctx, q, tid, id, d.EventID, d.EventType, d.Status, string(attempts), d.Queued, logTime(d.EventTime), logTime(now)); err != nil {
				return err
			}
		}
		for _, eid := range o.Succeeded {
			if _, err := t.exec(ctx, `DELETE FROM event_deliveries WHERE tenant_id=? AND stream_id=? AND event_id=?`, tid, id, eid); err != nil {
				return err
			}
		}
		status := v.Status
		if o.Disable {
			status = "disabled"
		}
		_, err = t.exec(ctx, `UPDATE event_streams SET checkpoint=?,consecutive_failures=?,total_failures=?,status=?,updated_at=?,version=version+1 WHERE tenant_id=? AND id=?`, o.Checkpoint, o.ConsecutiveFailures, o.TotalFailures, status, logTime(now), tid, id)
		return err
	})
}

const eventDeliveryCols = `tenant_id,stream_id,event_id,type,status,attempts,queued,event_time,updated_at`

func scanEventDelivery(row scanner) (*store.EventDelivery, error) {
	v := new(store.EventDelivery)
	var attempts, at, updated string
	err := row.Scan(&v.TenantID, &v.StreamID, &v.EventID, &v.EventType, &v.Status, &attempts, &v.Queued, &at, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(attempts), &v.Attempts); err != nil {
		return nil, err
	}
	v.EventTime = fromLogTime(at)
	v.UpdatedAt = fromLogTime(updated)
	return v, nil
}
func (r events) GetDelivery(ctx context.Context, tid, sid, eid string) (*store.EventDelivery, error) {
	return scanEventDelivery(r.s.queryRow(ctx, `SELECT `+eventDeliveryCols+` FROM event_deliveries WHERE tenant_id=? AND stream_id=? AND event_id=?`, tid, sid, eid))
}
func eventDeliveryFilter(q string, args []any, f store.DeliveryFilter) (string, []any) {
	q, args = eventIn(q, args, "status", f.Statuses)
	q, args = eventIn(q, args, "type", f.EventTypes)
	if !f.From.IsZero() {
		q += ` AND event_time>=?`
		args = append(args, logTime(f.From))
	}
	if !f.To.IsZero() {
		q += ` AND event_time<?`
		args = append(args, logTime(f.To))
	}
	return q, args
}
func (r events) deliveryRows(ctx context.Context, q string, args ...any) ([]store.EventDelivery, error) {
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.EventDelivery{}
	for rows.Next() {
		v, err := scanEventDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (r events) ListDeliveries(ctx context.Context, tid, sid string, f store.DeliveryFilter, after string, take int) ([]store.EventDelivery, string, error) {
	if _, err := r.GetEventStream(ctx, tid, sid); err != nil {
		return nil, "", err
	}
	q, args := eventDeliveryFilter(`SELECT `+eventDeliveryCols+` FROM event_deliveries WHERE tenant_id=? AND stream_id=? AND event_id`+r.s.d.byteOrder+`>?`, []any{tid, sid, after}, f)
	q += ` ORDER BY event_id` + r.s.d.byteOrder + ` LIMIT ?`
	args = append(args, eventTake(take)+1)
	out, err := r.deliveryRows(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > eventTake(take) {
		out = out[:eventTake(take)]
		next = out[len(out)-1].EventID
	}
	return out, next, nil
}
func (r events) QueuedDeliveries(ctx context.Context, tid, sid string, take int) ([]store.EventDelivery, error) {
	if _, err := r.GetEventStream(ctx, tid, sid); err != nil {
		return nil, err
	}
	return r.deliveryRows(ctx, `SELECT `+eventDeliveryCols+` FROM event_deliveries WHERE tenant_id=? AND stream_id=? AND queued=true ORDER BY event_id`+r.s.d.byteOrder+` LIMIT ?`, tid, sid, eventTake(take))
}
func (r events) QueueRedelivery(ctx context.Context, tid, sid string, ids []string, f *store.DeliveryFilter) (int, error) {
	n := 0
	err := r.s.atomicRetry(ctx, nil, func(t *Store) error {
		n = 0
		if err := t.lockRBAC(ctx, tid); err != nil {
			return err
		}
		if _, err := scanEventStream(t.queryRow(ctx, `SELECT `+eventStreamCols+` FROM event_streams WHERE tenant_id=? AND id=?`+t.d.forUpdate, tid, sid)); err != nil {
			return err
		}
		q := `SELECT ` + eventDeliveryCols + ` FROM event_deliveries WHERE tenant_id=? AND stream_id=?`
		args := []any{tid, sid}
		if len(ids) > 0 {
			q, args = eventIn(q, args, "event_id", ids)
		} else if f != nil {
			q, args = eventDeliveryFilter(q, args, *f)
		}
		out, err := (events{t}).deliveryRows(ctx, q+t.d.forUpdate, args...)
		if err != nil {
			return err
		}
		unique := map[string]bool{}
		for _, id := range ids {
			unique[id] = true
		}
		if len(out) == 0 || (len(ids) > 0 && len(out) != len(unique)) {
			return store.ErrPrecondition
		}
		for _, d := range out {
			if d.Status != "failed" || d.Queued {
				return store.ErrPrecondition
			}
		}
		now := logTime(t.eventNow())
		for _, d := range out {
			if _, err := t.exec(ctx, `UPDATE event_deliveries SET queued=true,updated_at=? WHERE tenant_id=? AND stream_id=? AND event_id=?`, now, tid, sid, d.EventID); err != nil {
				return err
			}
		}
		n = len(out)
		return nil
	})
	return n, err
}
