package memory

import (
	"context"
	"sort"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logsearch"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const logCapacity = 10000

type storedLog struct {
	event     store.LogEvent
	committed time.Time
	pending   bool
}
type logRing struct {
	events []storedLog
	start  int
}

func (r *logRing) append(e storedLog) {
	if len(r.events) < logCapacity {
		r.events = append(r.events, e)
		return
	}
	r.events[r.start] = e
	r.start = (r.start + 1) % logCapacity
}
func (r *logRing) each(fn func(storedLog)) {
	if r == nil {
		return
	}
	for i := range len(r.events) {
		fn(r.events[(r.start+i)%len(r.events)])
	}
}

type logs struct{ s *Store }

func (s *Store) Logs() store.Logs                    { return logs{s} }
func (s *Store) LogsSupported(context.Context) error { return nil }

func (r logs) AppendLogs(ctx context.Context, events []store.LogEvent, deltas []store.DailyStatDelta) error {
	for _, e := range events {
		if err := store.ValidateLogTimes(e.Date); err != nil {
			return err
		}
	}
	for _, d := range deltas {
		if err := store.ValidateLogTimes(d.Day); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	if int64(len(events)) > int64(^uint64(0)>>1)-r.s.logSeq {
		return store.ErrPrecondition
	}
	now := r.s.now().UTC()
	committed := now
	if r.s.tx {
		committed = time.Time{}
	}
	for _, e := range events {
		r.s.logSeq++
		e.Seq = r.s.logSeq
		e.ID = store.FormatLogID(e.Seq)
		ring := r.s.logEvents[e.TenantID]
		if ring == nil {
			ring = &logRing{}
			r.s.logEvents[e.TenantID] = ring
		}
		stamp := committed
		if !r.s.tx && len(ring.events) > 0 {
			previous := ring.events[(ring.start+len(ring.events)-1)%len(ring.events)]
			if previous.committed.After(stamp) {
				stamp = previous.committed
			}
		}
		ring.append(storedLog{event: cloneLog(e), committed: stamp, pending: r.s.tx})
	}
	for _, d := range deltas {
		day := utcDay(d.Day)
		k := key{d.TenantID, day.Format("2006-01-02")}
		stat := r.s.logStats[k]
		if stat == nil {
			stat = &store.DailyStat{Day: day, CreatedAt: now}
			r.s.logStats[k] = stat
		}
		stat.Logins += d.Logins
		stat.Signups += d.Signups
		stat.LeakedPasswords += d.LeakedPasswords
		stat.UpdatedAt = now
	}
	return nil
}
func (r logs) GetLog(ctx context.Context, tid, id string) (*store.LogEvent, error) {
	if _, err := store.ParseLogID(id); err != nil {
		return nil, store.ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var out *store.LogEvent
	r.s.logEvents[tid].each(func(e storedLog) {
		if e.event.ID == id {
			c := cloneLog(e.event)
			out = &c
		}
	})
	if out == nil {
		return nil, store.ErrNotFound
	}
	return out, nil
}
func (r logs) SearchLogs(ctx context.Context, tid string, q *store.LogQuery, p store.LogPage) ([]store.LogEvent, int, error) {
	if p.PerPage == 0 {
		p.PerPage = 50
	}
	if p.Page < 0 || p.PerPage < 1 || p.PerPage > 100 || p.Page > 1000/p.PerPage-1 {
		return nil, 0, store.ErrInvalid
	}
	if err := logsearch.Validate(q); err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var rows []store.LogEvent
	r.s.logEvents[tid].each(func(e storedLog) {
		if logsearch.Match(q, e.event) {
			rows = append(rows, e.event)
		}
	})
	sort.Slice(rows, func(i, j int) bool {
		cmp := rows[i].Date.Compare(rows[j].Date)
		if cmp == 0 {
			cmp = compareSeq(rows[i].Seq, rows[j].Seq)
		}
		if p.Ascending {
			return cmp < 0
		}
		return cmp > 0
	})
	total := 0
	if p.IncludeTotals {
		total = len(rows)
	}
	start := p.Page * p.PerPage
	if start >= len(rows) {
		return nil, total, nil
	}
	end := min(start+p.PerPage, len(rows))
	out := make([]store.LogEvent, end-start)
	for i, e := range rows[start:end] {
		out[i] = cloneLog(e)
	}
	return out, total, nil
}
func compareSeq(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func (r logs) checkpoint(ctx context.Context, tid string, after int64, q *store.LogQuery, take int, settled time.Time, latest bool) ([]store.LogEvent, error) {
	if err := store.ValidateLogTimes(settled); err != nil {
		return nil, err
	}
	if take < 1 || take > 100 || after < 0 {
		return nil, store.ErrInvalid
	}
	if err := logsearch.Validate(q); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var rows []store.LogEvent
	r.s.logEvents[tid].each(func(e storedLog) {
		if e.event.Seq > after && !e.committed.After(settled) && logsearch.Match(q, e.event) {
			rows = append(rows, e.event)
		}
	})
	if latest && len(rows) > take {
		rows = rows[len(rows)-take:]
	} else if len(rows) > take {
		rows = rows[:take]
	}
	for i := range rows {
		rows[i] = cloneLog(rows[i])
	}
	return rows, nil
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
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for _, ring := range r.s.logEvents {
		kept := make([]storedLog, 0, len(ring.events))
		ring.each(func(e storedLog) {
			if n < limit && e.event.Date.Before(before) {
				n++
			} else {
				kept = append(kept, e)
			}
		})
		ring.events = kept
		ring.start = 0
		if n == limit {
			break
		}
	}
	return n, nil
}
func (s *Store) deleteTenantLogs(tid string) {
	delete(s.logEvents, tid)
	purge(s.logStreams, tid)
	purge(s.logStats, tid)
}
func (r logs) DeleteTenantLogs(ctx context.Context, tid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	r.s.deleteTenantLogs(tid)
	return nil
}
func (r logs) CreateLogStream(ctx context.Context, in *store.LogStream) error {
	if in != nil {
		if err := store.ValidateLogTimes(in.StartFrom, in.NextAt, in.FailingSince, in.LastSuccessAt); err != nil {
			return err
		}
	}
	if in == nil || in.ID == "" || in.TenantID == "" {
		return store.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fields, err := cloneLogStreamInput(in)
	if err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{in.TenantID, in.ID}
	if r.s.logStreams[k] != nil {
		return store.ErrConflict
	}
	out := fields
	out.Version = 1
	out.CreatedAt = r.s.now().UTC()
	out.UpdatedAt = out.CreatedAt
	out.LeaseOwner = ""
	out.LeaseUntil = time.Time{}
	out.Checkpoint = 0
	found := false
	r.s.logEvents[in.TenantID].each(func(e storedLog) {
		if !out.StartFrom.IsZero() && !found && !e.event.Date.Before(out.StartFrom) {
			out.Checkpoint = e.event.Seq - 1
			found = true
		}
		if !found {
			out.Checkpoint = e.event.Seq
		}
	})
	r.s.logStreams[k] = out
	return nil
}
func (r logs) GetLogStream(ctx context.Context, tid, id string) (*store.LogStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	s := r.s.logStreams[key{tid, id}]
	if s == nil {
		return nil, store.ErrNotFound
	}
	return cloneLogStream(s), nil
}
func (r logs) ListLogStreams(ctx context.Context, tid string) ([]store.LogStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var out []store.LogStream
	for k, s := range r.s.logStreams {
		if k.tenant == tid {
			out = append(out, *cloneLogStream(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r logs) UpdateLogStream(ctx context.Context, in *store.LogStream, version int) error {
	if in == nil {
		return store.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fields, err := cloneLogStreamInput(in)
	if err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{in.TenantID, in.ID}
	old := r.s.logStreams[k]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Version != version {
		return store.ErrConflict
	}
	if in.Type != old.Type {
		return store.ErrInvalid
	}
	// Preserve delivery fields even if the admin loaded its snapshot before a worker completed.
	out := cloneLogStream(old)
	out.Name = fields.Name
	out.Status = fields.Status
	out.Sink = fields.Sink
	out.SealedSecrets = fields.SealedSecrets
	out.Filters = fields.Filters
	out.IsPriority = fields.IsPriority
	out.PII = fields.PII
	if old.Status != "active" && out.Status == "active" {
		out.NextAt = r.s.now().UTC()
		out.Failures = 0
		out.FailingSince = time.Time{}
		out.LastErrorClass = ""
	}
	out.Version++
	out.UpdatedAt = r.s.now().UTC()
	out.LeaseOwner = ""
	out.LeaseUntil = time.Time{}
	r.s.logStreams[k] = out
	return nil
}
func (r logs) DeleteLogStream(ctx context.Context, tid, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	if r.s.logStreams[k] == nil {
		return store.ErrNotFound
	}
	delete(r.s.logStreams, k)
	return nil
}
func (r logs) LeaseLogStream(ctx context.Context, owner string, now, until time.Time) (*store.LogStream, error) {
	if err := store.ValidateLogTimes(now, until); err != nil {
		return nil, err
	}
	if owner == "" || !until.After(now) {
		return nil, store.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.lock()
	defer r.s.unlock()
	var due []*store.LogStream
	for _, s := range r.s.logStreams {
		if s.Status == "active" && !s.NextAt.After(now) && !s.LeaseUntil.After(now) {
			due = append(due, s)
		}
	}
	if len(due) == 0 {
		return nil, store.ErrNotFound
	}
	sort.Slice(due, func(i, j int) bool {
		a, b := due[i], due[j]
		if !a.NextAt.Equal(b.NextAt) {
			return a.NextAt.Before(b.NextAt)
		}
		if a.TenantID != b.TenantID {
			return a.TenantID < b.TenantID
		}
		return a.ID < b.ID
	})
	s := due[0]
	s.LeaseOwner = owner
	s.LeaseUntil = until
	return cloneLogStream(s), nil
}
func (r logs) RecordDelivery(ctx context.Context, tid, id, owner string, d store.LogStreamDelivery) error {
	if err := store.ValidateLogTimes(d.NextAt, d.FailingSince, d.LastSuccessAt); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s.logStreams[key{tid, id}]
	if s == nil || owner == "" || s.LeaseOwner != owner || !s.LeaseUntil.After(r.s.now()) || s.Status != "active" {
		return store.ErrPrecondition
	}
	if d.Checkpoint < s.Checkpoint {
		return store.ErrPrecondition
	}
	s.Checkpoint = d.Checkpoint
	if d.Status != "" {
		s.Status = d.Status
	}
	s.NextAt = d.NextAt
	s.FailingSince = d.FailingSince
	s.LastSuccessAt = d.LastSuccessAt
	s.Failures = d.Failures
	s.LastErrorClass = d.LastErrorClass
	s.LeaseOwner = ""
	s.LeaseUntil = time.Time{}
	s.UpdatedAt = r.s.now().UTC()
	return nil
}
func utcDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
func (r logs) DailyStats(ctx context.Context, tid string, from, to time.Time) ([]store.DailyStat, error) {
	if err := store.ValidateLogTimes(from, to); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	from = utcDay(from)
	to = utcDay(to)
	if to.Before(from) {
		return nil, store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var out []store.DailyStat
	for k, s := range r.s.logStats {
		if k.tenant == tid && !s.Day.Before(from) && !s.Day.After(to) {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day.Before(out[j].Day) })
	return out, nil
}
func (r logs) ActiveUsers(ctx context.Context, tid string, since time.Time) (int, error) {
	if err := store.ValidateLogTimes(since); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	n := 0
	for k, u := range r.s.users {
		if k.tenant == tid && u.LastLogin != nil && !u.LastLogin.Before(since) {
			n++
		}
	}
	return n, nil
}
