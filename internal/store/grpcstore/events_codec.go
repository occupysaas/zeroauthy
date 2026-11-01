package grpcstore

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Events shares Logs' canonical UTC timestamp range and generic collection
// codecs. List and byte presence, exact JSON numbers and all integer bits are
// preserved. Neither direction exposes mutable aliases to protocol messages.
func eventStringsToPB(v []string) *storev1.StringList {
	if v == nil {
		return nil
	}
	return &storev1.StringList{Values: slices.Clone(v)}
}
func eventTime(t time.Time) string { return t.UTC().Format(store.LogTimeLayout) }
func tenantEventToPB(v *store.TenantEvent) (*storev1.TenantEventMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.Time); err != nil {
		return nil, err
	}
	out := &storev1.TenantEventMsg{
		TenantId: v.TenantID,
		Id:       v.ID,
		Type:     v.Type,
		Seq:      v.Seq,
		Time:     eventTime(v.Time),
		Body:     cloneBytes(v.Body),
	}
	return out, nil
}
func tenantEventFromPB(v *storev1.TenantEventMsg) (*store.TenantEvent, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.TenantEvent{
		TenantID: v.TenantId,
		ID:       v.Id,
		Type:     v.Type,
		Seq:      v.Seq,
		Body:     cloneBytes(v.Body),
	}
	if err := logTimesFromPB([]string{v.Time}, &out.Time); err != nil {
		return nil, err
	}
	return out, nil
}
func eventStreamToPB(v *store.EventStream) (*storev1.EventStreamMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.LeaseUntil, v.CreatedAt, v.UpdatedAt); err != nil {
		return nil, err
	}
	out := &storev1.EventStreamMsg{
		TenantId:            v.TenantID,
		Id:                  v.ID,
		Name:                v.Name,
		Status:              v.Status,
		DestType:            v.DestType,
		Checkpoint:          v.Checkpoint,
		LeaseOwner:          v.LeaseOwner,
		ConsecutiveFailures: int64(v.ConsecutiveFailures),
		TotalFailures:       int64(v.TotalFailures),
		Version:             int64(v.Version),
		LeaseUntil:          eventTime(v.LeaseUntil),
		CreatedAt:           eventTime(v.CreatedAt),
		UpdatedAt:           eventTime(v.UpdatedAt),
		SealedSecret:        cloneBytes(v.SealedSecret),
	}
	out.Subscriptions = eventStringsToPB(v.Subscriptions)
	config, err := json.Marshal(v.Config)
	if err != nil {
		return nil, store.ErrInvalid
	}
	out.ConfigJson = config
	return out, nil
}
func eventStreamFromPB(v *storev1.EventStreamMsg) (*store.EventStream, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.EventStream{
		TenantID:            v.TenantId,
		ID:                  v.Id,
		Name:                v.Name,
		Status:              v.Status,
		DestType:            v.DestType,
		Checkpoint:          v.Checkpoint,
		LeaseOwner:          v.LeaseOwner,
		ConsecutiveFailures: int(v.ConsecutiveFailures),
		TotalFailures:       int(v.TotalFailures),
		Version:             int(v.Version),
		SealedSecret:        cloneBytes(v.SealedSecret),
	}
	if err := logTimesFromPB([]string{v.LeaseUntil, v.CreatedAt, v.UpdatedAt}, &out.LeaseUntil, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return nil, err
	}
	out.Subscriptions = stringsFromPB(v.Subscriptions)
	if len(v.ConfigJson) > 0 {
		d := json.NewDecoder(bytes.NewReader(v.ConfigJson))
		d.UseNumber()
		if err := d.Decode(&out.Config); err != nil || !json.Valid(v.ConfigJson) {
			return nil, store.ErrInvalid
		}
	}
	return out, nil
}
func deliveryAttemptToPB(v *store.DeliveryAttempt) (*storev1.DeliveryAttemptMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.Timestamp); err != nil {
		return nil, err
	}
	out := &storev1.DeliveryAttemptMsg{
		Status:       v.Status,
		ErrorMessage: v.ErrorMessage,
		DurationMs:   v.DurationMS,
		Timestamp:    eventTime(v.Timestamp),
	}
	return out, nil
}
func deliveryAttemptFromPB(v *storev1.DeliveryAttemptMsg) (*store.DeliveryAttempt, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.DeliveryAttempt{
		Status:       v.Status,
		ErrorMessage: v.ErrorMessage,
		DurationMS:   v.DurationMs,
	}
	if err := logTimesFromPB([]string{v.Timestamp}, &out.Timestamp); err != nil {
		return nil, err
	}
	return out, nil
}
func eventDeliveryToPB(v *store.EventDelivery) (*storev1.EventDeliveryMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.EventTime, v.UpdatedAt); err != nil {
		return nil, err
	}
	out := &storev1.EventDeliveryMsg{
		TenantId:  v.TenantID,
		StreamId:  v.StreamID,
		EventId:   v.EventID,
		EventType: v.EventType,
		Status:    v.Status,
		Queued:    v.Queued,
		EventTime: eventTime(v.EventTime),
		UpdatedAt: eventTime(v.UpdatedAt),
	}
	if v.Attempts != nil {
		attempts, err := logsEncodeMany(v.Attempts, deliveryAttemptToPB)
		if err != nil {
			return nil, err
		}
		out.Attempts = &storev1.DeliveryAttemptsMsg{Values: attempts}
	}
	return out, nil
}
func eventDeliveryFromPB(v *storev1.EventDeliveryMsg) (*store.EventDelivery, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.EventDelivery{
		TenantID:  v.TenantId,
		StreamID:  v.StreamId,
		EventID:   v.EventId,
		EventType: v.EventType,
		Status:    v.Status,
		Queued:    v.Queued,
	}
	if err := logTimesFromPB([]string{v.EventTime, v.UpdatedAt}, &out.EventTime, &out.UpdatedAt); err != nil {
		return nil, err
	}
	if v.Attempts != nil {
		attempts, err := logsDecodeMany(v.Attempts.Values, deliveryAttemptFromPB)
		if err != nil {
			return nil, err
		}
		if attempts == nil {
			attempts = []store.DeliveryAttempt{}
		}
		out.Attempts = attempts
	}
	return out, nil
}
func deliveryFilterToPB(v *store.DeliveryFilter) (*storev1.DeliveryFilterMsg, error) {
	if v == nil {
		return nil, nil
	}
	if err := store.ValidateLogTimes(v.From, v.To); err != nil {
		return nil, err
	}
	out := &storev1.DeliveryFilterMsg{
		From: eventTime(v.From),
		To:   eventTime(v.To),
	}
	out.Statuses = eventStringsToPB(v.Statuses)
	out.EventTypes = eventStringsToPB(v.EventTypes)
	return out, nil
}
func deliveryFilterFromPB(v *storev1.DeliveryFilterMsg) (*store.DeliveryFilter, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.DeliveryFilter{}
	if err := logTimesFromPB([]string{v.From, v.To}, &out.From, &out.To); err != nil {
		return nil, err
	}
	out.Statuses = stringsFromPB(v.Statuses)
	out.EventTypes = stringsFromPB(v.EventTypes)
	return out, nil
}
func deliveryOutcomeToPB(v *store.DeliveryOutcome) (*storev1.DeliveryOutcomeMsg, error) {
	if v == nil {
		return nil, nil
	}
	out := &storev1.DeliveryOutcomeMsg{
		Checkpoint:          v.Checkpoint,
		ConsecutiveFailures: int64(v.ConsecutiveFailures),
		TotalFailures:       int64(v.TotalFailures),
		Disable:             v.Disable,
	}
	out.Succeeded = eventStringsToPB(v.Succeeded)
	failed, err := eventDeliveryToPB(v.Failed)
	if err != nil {
		return nil, err
	}
	out.Failed = failed
	return out, nil
}
func deliveryOutcomeFromPB(v *storev1.DeliveryOutcomeMsg) (*store.DeliveryOutcome, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.DeliveryOutcome{
		Checkpoint:          v.Checkpoint,
		ConsecutiveFailures: int(v.ConsecutiveFailures),
		TotalFailures:       int(v.TotalFailures),
		Disable:             v.Disable,
	}
	out.Succeeded = stringsFromPB(v.Succeeded)
	failed, err := eventDeliveryFromPB(v.Failed)
	if err != nil {
		return nil, err
	}
	out.Failed = failed
	return out, nil
}
