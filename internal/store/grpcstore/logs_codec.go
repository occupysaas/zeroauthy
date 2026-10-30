package grpcstore

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// UTC text preserves the complete Logs timestamp range, including year0000.
func logTimesFromPB(raw []string, out ...*time.Time) error {
	for i, s := range raw {
		if s == "" {
			*out[i] = time.Time{}
			continue
		}
		t, err := time.Parse(store.LogTimeLayout, s)
		if err != nil {
			return store.ErrInvalid
		}
		*out[i] = t.UTC()
	}
	return nil
}

func logEventToPB(v *store.LogEvent) (*storev1.LogEventMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.Date); err != nil {
		return nil, err
	}
	out := &storev1.LogEventMsg{
		TenantId:       v.TenantID,
		Id:             v.ID,
		Type:           v.Type,
		Seq:            v.Seq,
		UserId:         v.UserID,
		ClientId:       v.ClientID,
		ConnectionId:   v.ConnectionID,
		OrganizationId: v.OrganizationID,
		Ip:             v.IP,
		Date:           v.Date.UTC().Format(store.LogTimeLayout),
		Body:           cloneBytes(v.Body),
	}
	return out, nil
}

func logEventFromPB(v *storev1.LogEventMsg) (*store.LogEvent, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.LogEvent{
		TenantID:       v.TenantId,
		ID:             v.Id,
		Type:           v.Type,
		Seq:            v.Seq,
		UserID:         v.UserId,
		ClientID:       v.ClientId,
		ConnectionID:   v.ConnectionId,
		OrganizationID: v.OrganizationId,
		IP:             v.Ip,
		Body:           cloneBytes(v.Body),
	}
	if err := logTimesFromPB([]string{v.Date}, &out.Date); err != nil {
		return nil, err
	}
	return out, nil
}

func dailyStatDeltaToPB(v *store.DailyStatDelta) (*storev1.DailyStatDeltaMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.Day); err != nil {
		return nil, err
	}
	out := &storev1.DailyStatDeltaMsg{
		TenantId:        v.TenantID,
		Logins:          int64(v.Logins),
		Signups:         int64(v.Signups),
		LeakedPasswords: int64(v.LeakedPasswords),
		Day:             v.Day.UTC().Format(store.LogTimeLayout),
	}
	return out, nil
}

func dailyStatDeltaFromPB(v *storev1.DailyStatDeltaMsg) (*store.DailyStatDelta, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.DailyStatDelta{
		TenantID:        v.TenantId,
		Logins:          int(v.Logins),
		Signups:         int(v.Signups),
		LeakedPasswords: int(v.LeakedPasswords),
	}
	if err := logTimesFromPB([]string{v.Day}, &out.Day); err != nil {
		return nil, err
	}
	return out, nil
}

func dailyStatToPB(v *store.DailyStat) (*storev1.DailyStatMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.Day, v.CreatedAt, v.UpdatedAt); err != nil {
		return nil, err
	}
	out := &storev1.DailyStatMsg{
		Logins:          int64(v.Logins),
		Signups:         int64(v.Signups),
		LeakedPasswords: int64(v.LeakedPasswords),
		Day:             v.Day.UTC().Format(store.LogTimeLayout),
		CreatedAt:       v.CreatedAt.UTC().Format(store.LogTimeLayout),
		UpdatedAt:       v.UpdatedAt.UTC().Format(store.LogTimeLayout),
	}
	return out, nil
}

func dailyStatFromPB(v *storev1.DailyStatMsg) (*store.DailyStat, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.DailyStat{
		Logins:          int(v.Logins),
		Signups:         int(v.Signups),
		LeakedPasswords: int(v.LeakedPasswords),
	}
	if err := logTimesFromPB([]string{v.Day, v.CreatedAt, v.UpdatedAt}, &out.Day, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return nil, err
	}
	return out, nil
}

func logStreamToPB(v *store.LogStream) (*storev1.LogStreamMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.StartFrom, v.LeaseUntil, v.NextAt, v.FailingSince, v.LastSuccessAt, v.CreatedAt, v.UpdatedAt); err != nil {
		return nil, err
	}
	out := &storev1.LogStreamMsg{
		TenantId:       v.TenantID,
		Id:             v.ID,
		Name:           v.Name,
		Type:           v.Type,
		Status:         v.Status,
		IsPriority:     v.IsPriority,
		Checkpoint:     v.Checkpoint,
		LeaseOwner:     v.LeaseOwner,
		Failures:       int64(v.Failures),
		LastErrorClass: v.LastErrorClass,
		Version:        int64(v.Version),
		StartFrom:      v.StartFrom.UTC().Format(store.LogTimeLayout),
		LeaseUntil:     v.LeaseUntil.UTC().Format(store.LogTimeLayout),
		NextAt:         v.NextAt.UTC().Format(store.LogTimeLayout),
		FailingSince:   v.FailingSince.UTC().Format(store.LogTimeLayout),
		LastSuccessAt:  v.LastSuccessAt.UTC().Format(store.LogTimeLayout),
		CreatedAt:      v.CreatedAt.UTC().Format(store.LogTimeLayout),
		UpdatedAt:      v.UpdatedAt.UTC().Format(store.LogTimeLayout),
		SealedSecrets:  cloneBytes(v.SealedSecrets),
	}

	b, err := json.Marshal(v.Sink)
	if err != nil {
		return nil, store.ErrInvalid
	}
	out.SinkJson = b
	if v.Filters != nil {
		out.Filters = &storev1.LogStreamFiltersMsg{}
		for _, f := range v.Filters {
			out.Filters.Values = append(out.Filters.Values, &storev1.LogStreamFilterMsg{Type: f.Type, Name: f.Name})
		}
	}
	if v.PII != nil {
		out.Pii = &storev1.LogStreamPIIMsg{LogFields: stringsToPB(v.PII.LogFields), Method: v.PII.Method, Algorithm: v.PII.Algorithm}
	}
	return out, nil
}

func logStreamFromPB(v *storev1.LogStreamMsg) (*store.LogStream, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.LogStream{
		TenantID:       v.TenantId,
		ID:             v.Id,
		Name:           v.Name,
		Type:           v.Type,
		Status:         v.Status,
		IsPriority:     v.IsPriority,
		Checkpoint:     v.Checkpoint,
		LeaseOwner:     v.LeaseOwner,
		Failures:       int(v.Failures),
		LastErrorClass: v.LastErrorClass,
		Version:        int(v.Version),
		SealedSecrets:  cloneBytes(v.SealedSecrets),
	}
	if err := logTimesFromPB([]string{v.StartFrom, v.LeaseUntil, v.NextAt, v.FailingSince, v.LastSuccessAt, v.CreatedAt, v.UpdatedAt}, &out.StartFrom, &out.LeaseUntil, &out.NextAt, &out.FailingSince, &out.LastSuccessAt, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return nil, err
	}

	if len(v.SinkJson) > 0 {
		d := json.NewDecoder(bytes.NewReader(v.SinkJson))
		d.UseNumber()
		if err := d.Decode(&out.Sink); err != nil || !json.Valid(v.SinkJson) {
			return nil, store.ErrInvalid
		}
	}
	if v.Filters != nil {
		out.Filters = make([]store.LogStreamFilter, 0, len(v.Filters.Values))
		for _, f := range v.Filters.Values {
			if f == nil {
				return nil, store.ErrInvalid
			}
			out.Filters = append(out.Filters, store.LogStreamFilter{Type: f.Type, Name: f.Name})
		}
	}
	if v.Pii != nil {
		out.PII = &store.LogStreamPII{LogFields: stringsFromPB(v.Pii.LogFields), Method: v.Pii.Method, Algorithm: v.Pii.Algorithm}
	}
	return out, nil
}

func logStreamDeliveryToPB(v *store.LogStreamDelivery) (*storev1.LogStreamDeliveryMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.NextAt, v.FailingSince, v.LastSuccessAt); err != nil {
		return nil, err
	}
	out := &storev1.LogStreamDeliveryMsg{
		Checkpoint:     v.Checkpoint,
		Status:         v.Status,
		Failures:       int64(v.Failures),
		LastErrorClass: v.LastErrorClass,
		NextAt:         v.NextAt.UTC().Format(store.LogTimeLayout),
		FailingSince:   v.FailingSince.UTC().Format(store.LogTimeLayout),
		LastSuccessAt:  v.LastSuccessAt.UTC().Format(store.LogTimeLayout),
	}
	return out, nil
}

func logStreamDeliveryFromPB(v *storev1.LogStreamDeliveryMsg) (*store.LogStreamDelivery, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.LogStreamDelivery{
		Checkpoint:     v.Checkpoint,
		Status:         v.Status,
		Failures:       int(v.Failures),
		LastErrorClass: v.LastErrorClass,
	}
	if err := logTimesFromPB([]string{v.NextAt, v.FailingSince, v.LastSuccessAt}, &out.NextAt, &out.FailingSince, &out.LastSuccessAt); err != nil {
		return nil, err
	}
	return out, nil
}

func logQueryToPB(v *store.LogQuery) *storev1.LogQueryMsg {
	if v == nil {
		return nil
	}
	return &storev1.LogQueryMsg{Op: v.Op, Field: v.Field, Value: v.Value, Upper: v.Upper, Left: logQueryToPB(v.Left), Right: logQueryToPB(v.Right), LowerExclusive: v.LowerExclusive, UpperExclusive: v.UpperExclusive}
}
func logQueryFromPB(v *storev1.LogQueryMsg) *store.LogQuery {
	if v == nil {
		return nil
	}
	return &store.LogQuery{Op: v.Op, Field: v.Field, Value: v.Value, Upper: v.Upper, Left: logQueryFromPB(v.Left), Right: logQueryFromPB(v.Right), LowerExclusive: v.LowerExclusive, UpperExclusive: v.UpperExclusive}
}
func logPageToPB(v store.LogPage) *storev1.LogPageMsg {
	return &storev1.LogPageMsg{Page: int64(v.Page), PerPage: int64(v.PerPage), Ascending: v.Ascending, IncludeTotals: v.IncludeTotals}
}
func logPageFromPB(v *storev1.LogPageMsg) store.LogPage {
	if v == nil {
		return store.LogPage{}
	}
	return store.LogPage{Page: int(v.Page), PerPage: int(v.PerPage), Ascending: v.Ascending, IncludeTotals: v.IncludeTotals}
}

func logsEncodeMany[T, P any](vs []T, enc func(*T) (*P, error)) ([]*P, error) {
	if vs == nil {
		return nil, nil
	}
	out := make([]*P, 0, len(vs))
	for i := range vs {
		v, err := enc(&vs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func logsDecodeMany[T, P any](vs []*P, dec func(*P) (*T, error)) ([]T, error) {
	if vs == nil {
		return nil, nil
	}
	out := make([]T, 0, len(vs))
	for _, x := range vs {
		v, err := dec(x)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, store.ErrInvalid
		}
		out = append(out, *v)
	}
	return out, nil
}
