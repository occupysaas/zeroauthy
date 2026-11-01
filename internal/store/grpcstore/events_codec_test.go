package grpcstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func TestEventsCodecCopies(t *testing.T) {
	event := &store.TenantEvent{Body: []byte("body")}
	pbEvent, err := tenantEventToPB(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Body[0] = 'X'
	if string(pbEvent.Body) != "body" {
		t.Fatal("event encoding aliases bytes")
	}
	gotEvent, err := tenantEventFromPB(pbEvent)
	if err != nil {
		t.Fatal(err)
	}
	pbEvent.Body[0] = 'Y'
	if string(gotEvent.Body) != "body" {
		t.Fatal("event decoding aliases bytes")
	}
	stream := &store.EventStream{Subscriptions: []string{"user.created"}, SealedSecret: []byte("secret"), Config: map[string]any{"nested": map[string]any{"value": "original"}}}
	pbStream, err := eventStreamToPB(stream)
	if err != nil {
		t.Fatal(err)
	}
	stream.Subscriptions[0] = "user.updated"
	stream.SealedSecret[0] = 'X'
	stream.Config["nested"].(map[string]any)["value"] = "mutated"
	gotStream, err := eventStreamFromPB(pbStream)
	if err != nil {
		t.Fatal(err)
	}
	if gotStream.Subscriptions[0] != "user.created" || string(gotStream.SealedSecret) != "secret" || gotStream.Config["nested"].(map[string]any)["value"] != "original" {
		t.Fatal("stream encoding aliases input")
	}
	pbStream.Subscriptions.Values[0] = "user.deleted"
	pbStream.SealedSecret[0] = 'Y'
	pbStream.ConfigJson[0] = 'X'
	if gotStream.Subscriptions[0] != "user.created" || string(gotStream.SealedSecret) != "secret" || gotStream.Config["nested"].(map[string]any)["value"] != "original" {
		t.Fatal("stream decoding aliases protocol")
	}
	outcome := &store.DeliveryOutcome{Succeeded: []string{"e"}, Failed: &store.EventDelivery{Attempts: []store.DeliveryAttempt{{ErrorMessage: "timeout"}}}}
	pbOutcome, err := deliveryOutcomeToPB(outcome)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Succeeded[0] = "changed"
	outcome.Failed.Attempts[0].ErrorMessage = "changed"
	gotOutcome, err := deliveryOutcomeFromPB(pbOutcome)
	if err != nil {
		t.Fatal(err)
	}
	if gotOutcome.Succeeded[0] != "e" || gotOutcome.Failed.Attempts[0].ErrorMessage != "timeout" {
		t.Fatal("outcome encoding aliases input")
	}
	pbOutcome.Succeeded.Values[0] = "changed"
	pbOutcome.Failed.Attempts.Values[0].ErrorMessage = "changed"
	if gotOutcome.Succeeded[0] != "e" || gotOutcome.Failed.Attempts[0].ErrorMessage != "timeout" {
		t.Fatal("outcome decoding aliases protocol")
	}
	filter := &store.DeliveryFilter{Statuses: []string{"failed"}, EventTypes: []string{"user.created"}}
	pbFilter, err := deliveryFilterToPB(filter)
	if err != nil {
		t.Fatal(err)
	}
	filter.Statuses[0] = "changed"
	filter.EventTypes[0] = "changed"
	gotFilter, err := deliveryFilterFromPB(pbFilter)
	if err != nil {
		t.Fatal(err)
	}
	pbFilter.Statuses.Values[0] = "changed"
	pbFilter.EventTypes.Values[0] = "changed"
	if gotFilter.Statuses[0] != "failed" || gotFilter.EventTypes[0] != "user.created" {
		t.Fatal("filter aliases across codec")
	}
}
func TestEventsCodecRejectsMalformed(t *testing.T) {
	invalidTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]func() error{
		"eventTimeEncode":  func() error { _, e := tenantEventToPB(&store.TenantEvent{Time: invalidTime}); return e },
		"eventTimeDecode":  func() error { _, e := tenantEventFromPB(&storev1.TenantEventMsg{Time: "invalid"}); return e },
		"streamTimeEncode": func() error { _, e := eventStreamToPB(&store.EventStream{LeaseUntil: invalidTime}); return e },
		"streamTimeDecode": func() error { _, e := eventStreamFromPB(&storev1.EventStreamMsg{CreatedAt: "invalid"}); return e },
		"streamConfigEncode": func() error {
			_, e := eventStreamToPB(&store.EventStream{Config: map[string]any{"bad": make(chan int)}})
			return e
		},
		"streamConfigArray": func() error { _, e := eventStreamFromPB(&storev1.EventStreamMsg{ConfigJson: []byte(`[]`)}); return e },
		"streamConfigTrailing": func() error {
			_, e := eventStreamFromPB(&storev1.EventStreamMsg{ConfigJson: []byte(`{} {}`)})
			return e
		},
		"deliveryTimeEncode": func() error { _, e := eventDeliveryToPB(&store.EventDelivery{EventTime: invalidTime}); return e },
		"deliveryTimeDecode": func() error { _, e := eventDeliveryFromPB(&storev1.EventDeliveryMsg{UpdatedAt: "invalid"}); return e },
		"attemptTimeEncode": func() error {
			_, e := deliveryOutcomeToPB(&store.DeliveryOutcome{Failed: &store.EventDelivery{Attempts: []store.DeliveryAttempt{{Timestamp: invalidTime}}}})
			return e
		},
		"attemptTimeDecode": func() error {
			_, e := deliveryOutcomeFromPB(&storev1.DeliveryOutcomeMsg{Failed: &storev1.EventDeliveryMsg{Attempts: &storev1.DeliveryAttemptsMsg{Values: []*storev1.DeliveryAttemptMsg{{Timestamp: "invalid"}}}}})
			return e
		},
		"attemptNil": func() error {
			_, e := eventDeliveryFromPB(&storev1.EventDeliveryMsg{Attempts: &storev1.DeliveryAttemptsMsg{Values: []*storev1.DeliveryAttemptMsg{nil}}})
			return e
		},
		"filterTimeEncode": func() error { _, e := deliveryFilterToPB(&store.DeliveryFilter{From: invalidTime}); return e },
		"filterTimeDecode": func() error { _, e := deliveryFilterFromPB(&storev1.DeliveryFilterMsg{To: "invalid"}); return e },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
func TestEventsMalformedRequestsDoNotWrite(t *testing.T) {
	ctx := context.Background()
	backing := memory.New()
	defer backing.Close()
	s := NewServer(backing)
	defer s.Close()
	for name, call := range map[string]func(context.Context, *storev1.EventsRequest) (*storev1.EventsResponse, error){"create": s.CreateEventStream, "update": s.UpdateEventStream, "outcome": s.RecordEventDelivery} {
		t.Run(name, func(t *testing.T) {
			r, err := call(ctx, &storev1.EventsRequest{})
			if err != nil || !errors.Is(errFromPB(r.Error), store.ErrInvalid) {
				t.Fatalf("result=%v transport=%v", r, err)
			}
		})
	}
	r, err := s.AppendEvents(ctx, &storev1.EventsRequest{Events: []*storev1.TenantEventMsg{{TenantId: "t", Id: "valid", Time: eventTime(time.Now())}, {TenantId: "t", Id: "invalid", Time: "invalid"}}})
	if err != nil || !errors.Is(errFromPB(r.Error), store.ErrInvalid) {
		t.Fatalf("result=%v transport=%v", r, err)
	}
	if seq, err := backing.Events().LatestEventSeq(ctx, "t"); err != nil || seq != 0 {
		t.Fatalf("partial append: %d %v", seq, err)
	}
}
