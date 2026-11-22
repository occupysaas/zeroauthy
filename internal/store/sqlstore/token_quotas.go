package sqlstore

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tokenQuotas struct{ s *Store }

func (s *Store) TokenQuotas() store.TokenQuotas { return tokenQuotas{s} }

type bucketKey struct {
	kind, id, bucket string
	start            int64
}
type quotaRow struct {
	key    bucketKey
	state  *store.QuotaState
	bucket *store.QuotaBucket
	count  int64
	warned uint8
}

func quotaRows(states []store.QuotaState) []quotaRow {
	var rows []quotaRow
	for i := range states {
		st := &states[i]
		for j := range st.Buckets {
			b := &st.Buckets[j]
			period := time.Hour
			if b.Name == "per_day" {
				period = 24 * time.Hour
			}
			rows = append(rows, quotaRow{key: bucketKey{st.Subject.Kind, st.Subject.ID, b.Name, micros(b.Reset.Add(-period))}, state: st, bucket: b})
		}
	}
	// All consumers take locks in the same order even when subjects arrive reversed.
	slices.SortFunc(rows, func(a, b quotaRow) int {
		return cmp.Or(cmp.Compare(a.key.kind, b.key.kind), cmp.Compare(a.key.id, b.key.id), cmp.Compare(a.key.bucket, b.key.bucket))
	})
	return rows
}

func (k bucketKey) args(tid string) []any { return []any{tid, k.kind, k.id, k.bucket, k.start} }

const quotaMatch = "tenant_id=? AND subject_kind=? AND subject_id=? AND bucket=? AND window_start=?"

func (r *quotaRow) observe(count int64) bool {
	r.count = count
	r.bucket.Remaining = int(max(0, int64(r.bucket.Limit)-count))
	if r.bucket.Remaining == 0 && r.state.Subject.Quota.Enforce {
		r.state.Exceeded = true
		return true
	}
	return false
}

func (r tokenQuotas) Peek(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	states, err := store.QuotaWindows(tid, subjects, now)
	if err != nil {
		return nil, err
	}
	buckets := quotaRows(states)
	if len(buckets) == 0 {
		return states, nil
	}
	// Read every window in a single snapshot, without creating counters.
	var args []any
	var terms []string
	byKey := make(map[bucketKey]*quotaRow, len(buckets))
	for i := range buckets {
		k := buckets[i].key
		byKey[k] = &buckets[i]
		terms = append(terms, "("+quotaMatch+")")
		args = append(args, k.args(tid)...)
	}
	rows, err := r.s.query(ctx, "SELECT subject_kind,subject_id,bucket,window_start,count FROM token_quota_counters WHERE "+strings.Join(terms, " OR "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k bucketKey
		var count int64
		if err := rows.Scan(&k.kind, &k.id, &k.bucket, &k.start, &count); err != nil {
			return nil, err
		}
		byKey[k].observe(count)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return states, nil
}

func (r tokenQuotas) Consume(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	var states []store.QuotaState
	refused := errors.New("quota refused")
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		states, err = store.QuotaWindows(tid, subjects, now)
		if err != nil {
			return err
		}
		rows := quotaRows(states)
		reject := false
		for i := range rows {
			row := &rows[i]
			key := row.key.args(tid)
			if err := tx.insertIgnore(ctx, "token_quota_counters (tenant_id,subject_kind,subject_id,bucket,window_start,resets_at) VALUES (?,?,?,?,?,?)", append(key, micros(row.bucket.Reset))...); err != nil {
				return err
			}
			if err := tx.queryRow(ctx, "SELECT count,warned FROM token_quota_counters WHERE "+quotaMatch+tx.d.forUpdate, key...).Scan(&row.count, &row.warned); err != nil {
				return err
			}
			if row.observe(row.count) {
				reject = true
			}
		}
		if reject {
			return refused // roll back newly created zero rows as well
		}
		for i := range rows {
			row := &rows[i]
			row.count++
			row.warned = row.bucket.ClaimWarnings(row.count, row.warned)
			args := append([]any{row.count, row.warned}, row.key.args(tid)...)
			if _, err := tx.exec(ctx, "UPDATE token_quota_counters SET count=?,warned=? WHERE "+quotaMatch, args...); err != nil {
				return err
			}
			row.bucket.Remaining = max(0, row.bucket.Remaining-1)
		}
		return nil
	})
	if err != nil && !errors.Is(err, refused) {
		return nil, err
	}
	return states, nil
}

func (r tokenQuotas) PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error) {
	return r.s.purgeExpiredKeys(ctx, "token_quota_counters", "tenant_id,subject_kind,subject_id,bucket,window_start", "resets_at", before, limit)
}
