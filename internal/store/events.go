package store

import (
	"context"
	"errors"
	"time"
)

var ErrEventsUnavailable = errors.New("store: Events capability unavailable")

type EventsSupporter interface {
	CheckEventsSupport(context.Context) error
	EventsSupported() bool
}
type TenantEvent struct {
	TenantID, ID, Type string
	Seq                int64     // assigned by AppendEvents
	Time               time.Time // event time; CommittedAt is store-internal
	Body               []byte    // CloudEvent JSON without a0stream/a0purpose
}
type EventStream struct {
	TenantID, ID, Name, Status, DestType string
	Subscriptions                        []string
	Config                               map[string]any // public destination configuration
	SealedSecret                         []byte         // master-key wrapped password/token/header_value
	Checkpoint                           int64
	LeaseOwner                           string
	LeaseUntil                           time.Time
	ConsecutiveFailures, TotalFailures   int
	Version                              int
	CreatedAt, UpdatedAt                 time.Time
}
type DeliveryAttempt struct {
	Status       string // "failed" or "success"
	Timestamp    time.Time
	ErrorMessage string
	DurationMS   float64
}
type EventDelivery struct {
	TenantID, StreamID, EventID, EventType, Status string // Status "failed"
	Attempts                                       []DeliveryAttempt
	Queued                                         bool // redelivery requested
	EventTime, UpdatedAt                           time.Time
}
type DeliveryFilter struct {
	Statuses, EventTypes []string
	From, To             time.Time // inclusive, exclusive; zero = open
}
type DeliveryOutcome struct {
	Checkpoint                         int64          // new checkpoint, or unchanged for redeliveries
	Failed                             *EventDelivery // upsert when non-nil
	Succeeded                          []string       // event IDs whose failure records are removed
	ConsecutiveFailures, TotalFailures int
	Disable                            bool
}

type Events interface {
	AppendEvents(ctx context.Context, events []TenantEvent) error // inside the caller's tx; assigns Seq and records CommittedAt
	GetEvent(ctx context.Context, tid, id string) (*TenantEvent, error)
	EventsAfter(ctx context.Context, tid string, afterSeq int64, types []string, take int, settled time.Time) ([]TenantEvent, error)
	EventsFromTime(ctx context.Context, tid string, from time.Time, types []string, take int, settled time.Time) ([]TenantEvent, error)
	LatestEventSeq(ctx context.Context, tid string) (int64, error)
	OldestEventSeq(ctx context.Context, tid string) (int64, error)             // 0 when none
	PurgeEvents(ctx context.Context, before time.Time, limit int) (int, error) // also removes their deliveries
	DeleteTenantEvents(ctx context.Context, tid string) error

	CreateEventStream(ctx context.Context, s *EventStream) error // ErrConflict on duplicate name
	GetEventStream(ctx context.Context, tid, id string) (*EventStream, error)
	ListEventStreams(ctx context.Context, tid, after string, take int) ([]EventStream, string, error) // next cursor
	CountEventStreams(ctx context.Context, tid string) (int, error)
	UpdateEventStream(ctx context.Context, s *EventStream, version int) error // ErrConflict on version mismatch
	DeleteEventStream(ctx context.Context, tid, id string) error              // deletes its deliveries
	// LeaseEventStream selects the eligible due stream with the earliest expiry,
	// then tenant/ID. Enabled new events or queued redeliveries qualify. Renewals
	// advance expiry by at least 1ns; ErrNotFound means no eligible stream is due.
	LeaseEventStream(ctx context.Context, owner string, now, until time.Time) (*EventStream, error)
	RecordEventDelivery(ctx context.Context, tid, id, owner string, o DeliveryOutcome) error // ErrPrecondition if lease lost

	ListDeliveries(ctx context.Context, tid, streamID string, f DeliveryFilter, after string, take int) ([]EventDelivery, string, error)
	GetDelivery(ctx context.Context, tid, streamID, eventID string) (*EventDelivery, error)
	QueueRedelivery(ctx context.Context, tid, streamID string, eventIDs []string, f *DeliveryFilter) (int, error) // ErrPrecondition when a named event is not failed or already queued
	QueuedDeliveries(ctx context.Context, tid, streamID string, take int) ([]EventDelivery, error)
}

type UnimplementedEvents struct{}

func (UnimplementedEvents) AppendEvents(ctx context.Context, events []TenantEvent) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) GetEvent(ctx context.Context, tid, id string) (*TenantEvent, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) EventsAfter(ctx context.Context, tid string, afterSeq int64, types []string, take int, settled time.Time) ([]TenantEvent, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) EventsFromTime(ctx context.Context, tid string, from time.Time, types []string, take int, settled time.Time) ([]TenantEvent, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) LatestEventSeq(ctx context.Context, tid string) (int64, error) {
	return 0, ErrEventsUnavailable
}
func (UnimplementedEvents) OldestEventSeq(ctx context.Context, tid string) (int64, error) {
	return 0, ErrEventsUnavailable
}
func (UnimplementedEvents) PurgeEvents(ctx context.Context, before time.Time, limit int) (int, error) {
	return 0, ErrEventsUnavailable
}
func (UnimplementedEvents) DeleteTenantEvents(ctx context.Context, tid string) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) CreateEventStream(ctx context.Context, s *EventStream) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) GetEventStream(ctx context.Context, tid, id string) (*EventStream, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) ListEventStreams(ctx context.Context, tid, after string, take int) ([]EventStream, string, error) {
	return nil, "", ErrEventsUnavailable
}
func (UnimplementedEvents) CountEventStreams(ctx context.Context, tid string) (int, error) {
	return 0, ErrEventsUnavailable
}
func (UnimplementedEvents) UpdateEventStream(ctx context.Context, s *EventStream, version int) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) DeleteEventStream(ctx context.Context, tid, id string) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) LeaseEventStream(ctx context.Context, owner string, now, until time.Time) (*EventStream, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) RecordEventDelivery(ctx context.Context, tid, id, owner string, o DeliveryOutcome) error {
	return ErrEventsUnavailable
}
func (UnimplementedEvents) ListDeliveries(ctx context.Context, tid, streamID string, f DeliveryFilter, after string, take int) ([]EventDelivery, string, error) {
	return nil, "", ErrEventsUnavailable
}
func (UnimplementedEvents) GetDelivery(ctx context.Context, tid, streamID, eventID string) (*EventDelivery, error) {
	return nil, ErrEventsUnavailable
}
func (UnimplementedEvents) QueueRedelivery(ctx context.Context, tid, streamID string, eventIDs []string, f *DeliveryFilter) (int, error) {
	return 0, ErrEventsUnavailable
}
func (UnimplementedEvents) QueuedDeliveries(ctx context.Context, tid, streamID string, take int) ([]EventDelivery, error) {
	return nil, ErrEventsUnavailable
}
