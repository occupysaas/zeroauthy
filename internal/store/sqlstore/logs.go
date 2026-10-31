package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type logs struct{ s *Store }

func (s *Store) Logs() store.Logs                       { return logs{s} }
func (s *Store) CheckLogsSupport(context.Context) error { return nil }
func (s *Store) LogsSupported() bool                    { return true }
func (s *Store) logNow() time.Time {
	if s.logsClock != nil {
		return s.logsClock().UTC()
	}
	return time.Now().UTC()
}

func (r logs) AppendLogs(ctx context.Context, events []store.LogEvent, stats []store.DailyStatDelta) error {
	if err := store.ValidateLogEvents(events); err != nil {
		return err
	}
	for _, d := range stats {
		if err := store.ValidateLogTimes(d.Day); err != nil {
			return err
		}
	}
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		tenants := map[string]bool{}
		for _, e := range events {
			tenants[e.TenantID] = true
		}
		for _, d := range stats {
			tenants[d.TenantID] = true
		}
		ids := make([]string, 0, len(tenants))
		for id := range tenants {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		// Held through the outermost transaction commit, including WithTx. An identity
		// allocated by a later writer of this tenant cannot become visible first.
		for _, id := range ids {
			if err := t.lockRBAC(ctx, id); err != nil {
				return err
			}
		}
		now := logTime(t.logNow())
		committed := make(map[string]string, len(ids))
		// Clock skew between instances must not make a higher sequence settle
		// before an earlier one. The locking read sees the latest commit even
		// under MySQL REPEATABLE READ with an existing transaction snapshot.
		for _, id := range ids {
			stamp := now
			var previous string
			err := t.queryRow(ctx, `SELECT committed_at FROM tenant_logs WHERE tenant_id=? ORDER BY seq DESC LIMIT 1`+t.d.forUpdate, id).Scan(&previous)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if previous > stamp {
				stamp = previous
			}
			committed[id] = stamp
		}
		for _, e := range events {
			body := e.Body
			if body == nil {
				body = []byte{}
			}
			args := []any{e.TenantID, logTime(e.Date), committed[e.TenantID], e.Type, e.UserID, e.ClientID, e.ConnectionID, e.OrganizationID, e.IP, body, logSearchBody(body)}
			q := `INSERT INTO tenant_logs (tenant_id,date,committed_at,type,user_id,client_id,connection_id,organization_id,ip,body,searchable_body) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
			var seq int64
			if t.d.name == "postgres" {
				if err := t.queryRow(ctx, q+` RETURNING seq`, args...).Scan(&seq); err != nil {
					return err
				}
			} else {
				res, err := t.exec(ctx, q, args...)
				if err != nil {
					return err
				}
				seq, err = res.LastInsertId()
				if err != nil {
					return err
				}
			}
			if _, err := t.exec(ctx, `UPDATE tenant_logs SET log_id=? WHERE seq=?`, store.FormatLogID(seq), seq); err != nil {
				return err
			}
		}
		for _, d := range stats {
			q := `INSERT INTO log_stats_daily (tenant_id,day,logins,signups,leaked_passwords,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`
			if t.d.name == "mysql" {
				q += ` ON DUPLICATE KEY UPDATE logins=logins+VALUES(logins),signups=signups+VALUES(signups),leaked_passwords=leaked_passwords+VALUES(leaked_passwords),updated_at=VALUES(updated_at)`
			} else {
				q += ` ON CONFLICT (tenant_id,day) DO UPDATE SET logins=log_stats_daily.logins+excluded.logins,signups=log_stats_daily.signups+excluded.signups,leaked_passwords=log_stats_daily.leaked_passwords+excluded.leaked_passwords,updated_at=excluded.updated_at`
			}
			if _, err := t.exec(ctx, q, d.TenantID, logTime(logDay(d.Day)), d.Logins, d.Signups, d.LeakedPasswords, now, now); err != nil {
				return err
			}
		}
		return nil
	})
}

const logCols = `tenant_id,seq,log_id,date,type,user_id,client_id,connection_id,organization_id,ip,body`

func scanLog(row interface{ Scan(...any) error }) (store.LogEvent, error) {
	var e store.LogEvent
	var at string
	err := row.Scan(&e.TenantID, &e.Seq, &e.ID, &at, &e.Type, &e.UserID, &e.ClientID, &e.ConnectionID, &e.OrganizationID, &e.IP, &e.Body)
	e.Date = fromLogTime(at)
	return e, err
}
func (r logs) GetLog(ctx context.Context, tid, id string) (*store.LogEvent, error) {
	if _, err := store.ParseLogID(id); err != nil {
		return nil, err
	}
	e, err := scanLog(r.s.queryRow(ctx, `SELECT `+logCols+` FROM tenant_logs WHERE tenant_id=? AND log_id=?`, tid, id))
	if errors.Is(err, sql.ErrNoRows) {
		err = store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}
func (r logs) readLogs(ctx context.Context, q string, args ...any) ([]store.LogEvent, error) {
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.LogEvent
	for rows.Next() {
		e, err := scanLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r logs) SearchLogs(ctx context.Context, tid string, q *store.LogQuery, p store.LogPage) ([]store.LogEvent, int, error) {
	if p.PerPage == 0 {
		p.PerPage = 50
	}
	if p.Page < 0 || p.PerPage < 1 || p.PerPage > 100 || p.Page > 1000/p.PerPage-1 {
		return nil, 0, store.ErrInvalid
	}
	where, args, err := logsearch.SQL(q, r.s.d.name)
	if err != nil {
		return nil, 0, err
	}
	args = append([]any{tid}, args...)
	total := 0
	if p.IncludeTotals {
		if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM tenant_logs WHERE tenant_id=? AND (`+where+`)`, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	order := " DESC"
	if p.Ascending {
		order = " ASC"
	}
	args = append(args, p.PerPage, p.Page*p.PerPage)
	rows, err := r.readLogs(ctx, `SELECT `+logCols+` FROM tenant_logs WHERE tenant_id=? AND (`+where+`) ORDER BY date`+order+`,seq`+order+` LIMIT ? OFFSET ?`, args...)
	return rows, total, err
}
func (r logs) checkpoint(ctx context.Context, tid string, after int64, q *store.LogQuery, take int, settled time.Time, latest bool) ([]store.LogEvent, error) {
	if err := store.ValidateLogTimes(settled); err != nil {
		return nil, err
	}
	if after < 0 || take < 1 || take > 100 {
		return nil, store.ErrInvalid
	}
	where, args, err := logsearch.SQL(q, r.s.d.name)
	if err != nil {
		return nil, err
	}
	args = append([]any{tid, after, logTime(settled)}, args...)
	args = append(args, take)
	order := " ASC"
	if latest {
		order = " DESC"
	}
	out, err := r.readLogs(ctx, `SELECT `+logCols+` FROM tenant_logs WHERE tenant_id=? AND seq>? AND committed_at<=? AND (`+where+`) ORDER BY seq`+order+` LIMIT ?`, args...)
	if latest {
		slices.Reverse(out)
	}
	return out, err
}
func (r logs) LogsAfter(ctx context.Context, tid string, after int64, q *store.LogQuery, take int, settled time.Time) ([]store.LogEvent, error) {
	return r.checkpoint(ctx, tid, after, q, take, settled, false)
}
func (r logs) LatestLogs(ctx context.Context, tid string, q *store.LogQuery, take int, settled time.Time) ([]store.LogEvent, error) {
	return r.checkpoint(ctx, tid, 0, q, take, settled, true)
}
func (r logs) PurgeLogs(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := store.ValidateLogTimes(before); err != nil {
		return 0, err
	}
	if limit < 1 {
		return 0, store.ErrInvalid
	}
	q := `DELETE FROM tenant_logs WHERE seq IN (SELECT seq FROM tenant_logs WHERE date<? ORDER BY date,seq LIMIT ?)`
	if r.s.d.name == "mysql" {
		q = `DELETE FROM tenant_logs WHERE seq IN (SELECT seq FROM (SELECT seq FROM tenant_logs WHERE date<? ORDER BY date,seq LIMIT ?) AS expired)`
	}
	res, err := r.s.write(ctx, r.s.sweep(), q, logTime(before), limit)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
func (r logs) DeleteTenantLogs(ctx context.Context, tid string) error {
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, tid); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		for _, table := range []string{"tenant_logs", "log_streams", "log_stats_daily"} {
			if _, err := t.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=?`, tid); err != nil {
				return err
			}
		}
		return nil
	})
}

// Stream configuration is JSON (UseNumber preserves sink integer precision);
// mutable worker state lives in separate columns so admin updates cannot erase it.
const streamCols = `tenant_id,id,config,status,start_from,checkpoint,lease_owner,lease_until,next_at,failing_since,last_success_at,failures,last_error_class,version,created_at,updated_at`

func streamConfig(s *store.LogStream) (string, error) {
	b, err := json.Marshal(struct {
		Name, Type    string
		Sink          map[string]any
		SealedSecrets []byte
		Filters       []store.LogStreamFilter
		IsPriority    bool
		PII           *store.LogStreamPII
	}{s.Name, s.Type, s.Sink, s.SealedSecrets, s.Filters, s.IsPriority, s.PII})
	if err != nil {
		return "", store.ErrInvalid
	}
	return string(b), nil
}
func scanStream(row interface{ Scan(...any) error }) (*store.LogStream, error) {
	s := new(store.LogStream)
	var config string
	var start, lease, next, failing, success, created, updated string
	err := row.Scan(&s.TenantID, &s.ID, &config, &s.Status, &start, &s.Checkpoint, &s.LeaseOwner, &lease, &next, &failing, &success, &s.Failures, &s.LastErrorClass, &s.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(config))
	dec.UseNumber()
	if err := dec.Decode(s); err != nil {
		return nil, err
	}
	s.StartFrom = fromLogTime(start)
	s.LeaseUntil = fromLogTime(lease)
	s.NextAt = fromLogTime(next)
	s.FailingSince = fromLogTime(failing)
	s.LastSuccessAt = fromLogTime(success)
	s.CreatedAt = fromLogTime(created)
	s.UpdatedAt = fromLogTime(updated)
	return s, nil
}
func (r logs) CreateLogStream(ctx context.Context, in *store.LogStream) error {
	if in != nil {
		if err := store.ValidateLogTimes(in.StartFrom, in.NextAt, in.FailingSince, in.LastSuccessAt); err != nil {
			return err
		}
	}
	if in == nil || in.TenantID == "" || in.ID == "" {
		return store.ErrInvalid
	}
	config, err := streamConfig(in)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		if err := t.lockRBAC(ctx, in.TenantID); err != nil {
			return err
		}
		var checkpoint int64
		if err := t.queryRow(ctx, `SELECT COALESCE(MAX(seq),0) FROM tenant_logs WHERE tenant_id=?`, in.TenantID).Scan(&checkpoint); err != nil {
			return err
		}
		if !in.StartFrom.IsZero() {
			var first sql.NullInt64
			if err := t.queryRow(ctx, `SELECT MIN(seq) FROM tenant_logs WHERE tenant_id=? AND date>=?`, in.TenantID, logTime(in.StartFrom)).Scan(&first); err != nil {
				return err
			}
			if first.Valid {
				checkpoint = first.Int64 - 1
			}
		}
		now := logTime(t.logNow())
		_, err := t.exec(ctx, `INSERT INTO log_streams (`+streamCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, in.TenantID, in.ID, config, in.Status, logTime(in.StartFrom), checkpoint, "", logTime(time.Time{}), logTime(in.NextAt), logTime(in.FailingSince), logTime(in.LastSuccessAt), in.Failures, in.LastErrorClass, 1, now, now)
		return t.conflict(err)
	})
}
func (r logs) GetLogStream(ctx context.Context, tid, id string) (*store.LogStream, error) {
	return scanStream(r.s.queryRow(ctx, `SELECT `+streamCols+` FROM log_streams WHERE tenant_id=? AND id=?`, tid, id))
}
func (r logs) ListLogStreams(ctx context.Context, tid string) ([]store.LogStream, error) {
	rows, err := r.s.query(ctx, `SELECT `+streamCols+` FROM log_streams WHERE tenant_id=? ORDER BY id`+r.s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.LogStream
	for rows.Next() {
		s, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}
func (r logs) UpdateLogStream(ctx context.Context, in *store.LogStream, version int) error {
	if in == nil {
		return store.ErrInvalid
	}
	config, err := streamConfig(in)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		old, err := scanStream(t.queryRow(ctx, `SELECT `+streamCols+` FROM log_streams WHERE tenant_id=? AND id=?`+t.d.forUpdate, in.TenantID, in.ID))
		if err != nil {
			return err
		}
		if old.Version != version {
			return store.ErrConflict
		}
		if old.Type != in.Type {
			return store.ErrInvalid
		}
		now := t.logNow()
		if old.Status != "active" && in.Status == "active" {
			old.NextAt = now
			old.Failures = 0
			old.FailingSince = time.Time{}
			old.LastErrorClass = ""
		}
		res, err := t.exec(ctx, `UPDATE log_streams SET config=?,status=?,lease_owner='',lease_until='0001-01-01T00:00:00.000000000Z',next_at=?,failures=?,failing_since=?,last_error_class=?,version=version+1,updated_at=? WHERE tenant_id=? AND id=? AND version=?`, config, in.Status, logTime(old.NextAt), old.Failures, logTime(old.FailingSince), old.LastErrorClass, logTime(now), in.TenantID, in.ID, version)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
}
func (r logs) DeleteLogStream(ctx context.Context, tid, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM log_streams WHERE tenant_id=? AND id=?`, tid, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}
func (r logs) LeaseLogStream(ctx context.Context, owner string, now, until time.Time) (*store.LogStream, error) {
	if err := store.ValidateLogTimes(now, until); err != nil {
		return nil, err
	}
	if owner == "" || !until.After(now) {
		return nil, store.ErrInvalid
	}
	var out *store.LogStream
	err := r.s.atomicRetry(ctx, nil, func(t *Store) error {
		candidate, err := scanStream(t.queryRow(ctx, `SELECT `+streamCols+` FROM log_streams WHERE status='active' AND next_at<=? AND lease_until<=? ORDER BY next_at,tenant_id,id LIMIT 1`+t.d.forUpdate, logTime(now), logTime(now)))
		if err != nil {
			return err
		}
		res, err := t.exec(ctx, `UPDATE log_streams SET lease_owner=?,lease_until=? WHERE tenant_id=? AND id=? AND status='active' AND next_at<=? AND lease_until<=?`, owner, logTime(until), candidate.TenantID, candidate.ID, logTime(now), logTime(now))
		if err != nil {
			return err
		}
		if err = expectRow(res); err != nil {
			return err
		}
		candidate.LeaseOwner = owner
		candidate.LeaseUntil = fromLogTime(logTime(until))
		out = candidate
		return nil
	})
	return out, err
}
func (r logs) RecordDelivery(ctx context.Context, tid, id, owner string, d store.LogStreamDelivery) error {
	if err := store.ValidateLogTimes(d.NextAt, d.FailingSince, d.LastSuccessAt); err != nil {
		return err
	}
	if owner == "" {
		return store.ErrPrecondition
	}
	return r.s.atomicRetry(ctx, nil, func(t *Store) error {
		// Lock before reading the clock: acquiring this row may wait longer than
		// the remaining lease lifetime. A timestamp captured before waiting is stale.
		var one int
		if err := t.queryRow(ctx, `SELECT 1 FROM log_streams WHERE tenant_id=? AND id=?`+t.d.forUpdate, tid, id).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrPrecondition
			}
			return err
		}
		now := logTime(t.logNow())
		res, err := t.exec(ctx, `UPDATE log_streams SET checkpoint=?,status=CASE WHEN ?='' THEN status ELSE ? END,next_at=?,failing_since=?,last_success_at=?,failures=?,last_error_class=?,lease_owner='',lease_until='0001-01-01T00:00:00.000000000Z',updated_at=? WHERE tenant_id=? AND id=? AND lease_owner=? AND lease_until>? AND status='active' AND checkpoint<=?`, d.Checkpoint, d.Status, d.Status, logTime(d.NextAt), logTime(d.FailingSince), logTime(d.LastSuccessAt), d.Failures, d.LastErrorClass, now, tid, id, owner, now, d.Checkpoint)
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
func logDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
func (r logs) DailyStats(ctx context.Context, tid string, from, to time.Time) ([]store.DailyStat, error) {
	if err := store.ValidateLogTimes(from, to); err != nil {
		return nil, err
	}
	from = logDay(from)
	to = logDay(to)
	if to.Before(from) {
		return nil, store.ErrInvalid
	}
	rows, err := r.s.query(ctx, `SELECT day,logins,signups,leaked_passwords,created_at,updated_at FROM log_stats_daily WHERE tenant_id=? AND day>=? AND day<=? ORDER BY day`, tid, logTime(from), logTime(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.DailyStat
	for rows.Next() {
		var s store.DailyStat
		var day, c, u string
		if err := rows.Scan(&day, &s.Logins, &s.Signups, &s.LeakedPasswords, &c, &u); err != nil {
			return nil, err
		}
		s.Day = fromLogTime(day)
		s.CreatedAt = fromLogTime(c)
		s.UpdatedAt = fromLogTime(u)
		out = append(out, s)
	}
	return out, rows.Err()
}
func (r logs) ActiveUsers(ctx context.Context, tid string, since time.Time) (int, error) {
	if err := store.ValidateLogTimes(since); err != nil {
		return 0, err
	}
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id=? AND last_login>=?`, tid, micros(since)).Scan(&n)
	return n, err
}

// logTime is fixed-width UTC so SQL comparison preserves chronology over the
// full RFC3339 year range while retaining nanoseconds and the Unix epoch.
// The Go zero time has its ordinary year0001 encoding, distinct from epoch.
func logTime(t time.Time) string {
	return t.UTC().Format(store.LogTimeLayout)
}
func fromLogTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, _ := time.Parse(store.LogTimeLayout, v)
	return t
}
