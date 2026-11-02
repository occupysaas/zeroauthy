package grpcstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
)

const eventsCapability = 1

var _ store.EventsSupporter = (*Client)(nil)

type clientEvents struct{ c *Client }

func (c *Client) Events() store.Events { return clientEvents{c} }

// Only definitive answers affect the cheap predicate. Operations re-probe so
// transport failures can recover and plugin upgrades/downgrades are observed.
func (c *Client) CheckEventsSupport(ctx context.Context) error {
	v, err := c.rpc.EventsCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("Events capability", capabilityError(err, store.ErrEventsUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < eventsCapability {
			err = store.ErrEventsUnavailable
		}
	}
	if errors.Is(err, store.ErrEventsUnavailable) {
		c.eventsCap.v.Store(2)
	} else if err == nil {
		c.eventsCap.v.Store(1)
	}
	return err
}
func (c *Client) EventsSupported() bool {
	switch c.eventsCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckEventsSupport(ctx) == nil
}
func (s *Server) EventsCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.EventsSupporter); ok {
		if err := c.CheckEventsSupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
		if !c.EventsSupported() {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	// Probe declarations, never repository operations: a held memory transaction
	// owns the backing store lock even while this nontransactional RPC executes.
	switch s.st.Events().(type) {
	case store.UnimplementedEvents, *store.UnimplementedEvents:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: eventsCapability}, nil
}
func eventsCall(c *Client, ctx context.Context, q *storev1.EventsRequest, rpc func(context.Context, *storev1.EventsRequest, ...grpc.CallOption) (*storev1.EventsResponse, error)) (*storev1.EventsResponse, error) {
	if err := c.CheckEventsSupport(ctx); err != nil {
		return nil, err
	}
	q.TxId = c.txID
	v, err := rpc(ctx, q)
	if err != nil {
		err = capabilityError(err, store.ErrEventsUnavailable)
		if errors.Is(err, store.ErrEventsUnavailable) {
			c.eventsCap.v.Store(2)
		}
		return nil, rpcErr("Events", err)
	}
	if err = errFromPB(v.GetError()); err != nil {
		return nil, err
	}
	return v, nil
}
func (s *Server) eventsServe(tx string, fn func(store.Events, *storev1.EventsResponse) error) *storev1.EventsResponse {
	out := &storev1.EventsResponse{}
	out.Error = errToPB(s.with(tx, func(st store.Store) error { return fn(st.Events(), out) }))
	return out
}

func (o clientEvents) AppendEvents(ctx context.Context, events []store.TenantEvent) error {
	es, err := logsEncodeMany(events, tenantEventToPB)
	if err != nil {
		return err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{Events: es}, o.c.rpc.AppendEvents)
	if err != nil {
		return err
	}
	assigned, err := logsDecodeMany(v.Events, tenantEventFromPB)
	if err != nil {
		return err
	}
	if len(assigned) != len(events) {
		return store.ErrInvalid
	}
	for i := range events {
		events[i].Seq = assigned[i].Seq
	}
	return nil
}
func (s *Server) AppendEvents(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		es, err := logsDecodeMany(q.Events, tenantEventFromPB)
		if err != nil {
			return err
		}
		if err = r.AppendEvents(ctx, es); err != nil {
			return err
		}
		out.Events, err = logsEncodeMany(es, tenantEventToPB)
		return err
	}), nil
}

func (o clientEvents) GetEvent(ctx context.Context, tid, id string) (*store.TenantEvent, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: id}, o.c.rpc.GetEvent)
	if err != nil {
		return nil, err
	}
	return tenantEventFromPB(v.Event)
}
func (s *Server) GetEvent(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := r.GetEvent(ctx, q.TenantId, q.Id)
		if err != nil {
			return err
		}
		out.Event, err = tenantEventToPB(v)
		return err
	}), nil
}

func (o clientEvents) EventsAfter(ctx context.Context, tid string, afterSeq int64, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	if err := store.ValidateLogTimes(settled); err != nil {
		return nil, err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Types: eventStringsToPB(types), Take: int64(take), Settled: eventTime(settled), AfterSeq: afterSeq}, o.c.rpc.EventsAfter)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Events, tenantEventFromPB)
}
func (s *Server) EventsAfter(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		var settled time.Time
		if err := logTimesFromPB([]string{q.Settled}, &settled); err != nil {
			return err
		}
		vs, err := r.EventsAfter(ctx, q.TenantId, q.AfterSeq, stringsFromPB(q.Types), int(q.Take), settled)
		if err != nil {
			return err
		}
		out.Events, err = logsEncodeMany(vs, tenantEventToPB)
		return err
	}), nil
}

func (o clientEvents) EventsFromTime(ctx context.Context, tid string, from time.Time, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	if err := store.ValidateLogTimes(from, settled); err != nil {
		return nil, err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Types: eventStringsToPB(types), Take: int64(take), Settled: eventTime(settled), From: eventTime(from)}, o.c.rpc.EventsFromTime)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Events, tenantEventFromPB)
}
func (s *Server) EventsFromTime(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		var settled time.Time
		if err := logTimesFromPB([]string{q.Settled}, &settled); err != nil {
			return err
		}
		var from time.Time
		if err := logTimesFromPB([]string{q.From}, &from); err != nil {
			return err
		}
		vs, err := r.EventsFromTime(ctx, q.TenantId, from, stringsFromPB(q.Types), int(q.Take), settled)
		if err != nil {
			return err
		}
		out.Events, err = logsEncodeMany(vs, tenantEventToPB)
		return err
	}), nil
}

func (o clientEvents) LatestEventSeq(ctx context.Context, tid string) (int64, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid}, o.c.rpc.LatestEventSeq)
	if err != nil {
		return 0, err
	}
	return v.Seq, nil
}
func (s *Server) LatestEventSeq(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		n, err := r.LatestEventSeq(ctx, q.TenantId)
		out.Seq = n
		return err
	}), nil
}

func (o clientEvents) PurgedEventSeq(ctx context.Context, tid string) (int64, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid}, o.c.rpc.PurgedEventSeq)
	if err != nil {
		return 0, err
	}
	return v.Seq, nil
}
func (s *Server) PurgedEventSeq(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		n, err := r.PurgedEventSeq(ctx, q.TenantId)
		out.Seq = n
		return err
	}), nil
}

func (o clientEvents) OldestEventSeq(ctx context.Context, tid string) (int64, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid}, o.c.rpc.OldestEventSeq)
	if err != nil {
		return 0, err
	}
	return v.Seq, nil
}
func (s *Server) OldestEventSeq(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		n, err := r.OldestEventSeq(ctx, q.TenantId)
		out.Seq = n
		return err
	}), nil
}

func (o clientEvents) PurgeEvents(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := store.ValidateLogTimes(before); err != nil {
		return 0, err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{Before: eventTime(before), Limit: int64(limit)}, o.c.rpc.PurgeEvents)
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (s *Server) PurgeEvents(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		var before time.Time
		if err := logTimesFromPB([]string{q.Before}, &before); err != nil {
			return err
		}
		n, err := r.PurgeEvents(ctx, before, int(q.Limit))
		out.Count = int64(n)
		return err
	}), nil
}

func (o clientEvents) DeleteTenantEvents(ctx context.Context, tid string) error {
	_, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid}, o.c.rpc.DeleteTenantEvents)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) DeleteTenantEvents(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		return r.DeleteTenantEvents(ctx, q.TenantId)
	}), nil
}

func (o clientEvents) CreateEventStream(ctx context.Context, in *store.EventStream) error {
	pb, err := eventStreamToPB(in)
	if err != nil {
		return err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{Stream: pb}, o.c.rpc.CreateEventStream)
	if err != nil {
		return err
	}
	assigned, err := eventStreamFromPB(v.Stream)
	if err != nil {
		return err
	}
	if in == nil || assigned == nil {
		return store.ErrInvalid
	}
	in.Version = assigned.Version
	return nil
}
func (s *Server) CreateEventStream(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := eventStreamFromPB(q.Stream)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		if err = r.CreateEventStream(ctx, v); err != nil {
			return err
		}
		out.Stream, err = eventStreamToPB(v)
		return err
	}), nil
}

func (o clientEvents) UpdateEventStream(ctx context.Context, in *store.EventStream, version int) error {
	pb, err := eventStreamToPB(in)
	if err != nil {
		return err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{Stream: pb, Version: int64(version)}, o.c.rpc.UpdateEventStream)
	if err != nil {
		return err
	}
	assigned, err := eventStreamFromPB(v.Stream)
	if err != nil {
		return err
	}
	if in == nil || assigned == nil {
		return store.ErrInvalid
	}
	in.Version = assigned.Version
	return nil
}
func (s *Server) UpdateEventStream(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := eventStreamFromPB(q.Stream)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		if err = r.UpdateEventStream(ctx, v, int(q.Version)); err != nil {
			return err
		}
		out.Stream, err = eventStreamToPB(v)
		return err
	}), nil
}

func (o clientEvents) GetEventStream(ctx context.Context, tid, id string) (*store.EventStream, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: id}, o.c.rpc.GetEventStream)
	if err != nil {
		return nil, err
	}
	return eventStreamFromPB(v.Stream)
}
func (s *Server) GetEventStream(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := r.GetEventStream(ctx, q.TenantId, q.Id)
		if err != nil {
			return err
		}
		out.Stream, err = eventStreamToPB(v)
		return err
	}), nil
}

func (o clientEvents) ListEventStreams(ctx context.Context, tid, after string, take int) ([]store.EventStream, string, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, After: after, Take: int64(take)}, o.c.rpc.ListEventStreams)
	if err != nil {
		return nil, "", err
	}
	vs, err := logsDecodeMany(v.Streams, eventStreamFromPB)
	return vs, v.Next, err
}
func (s *Server) ListEventStreams(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		vs, next, err := r.ListEventStreams(ctx, q.TenantId, q.After, int(q.Take))
		if err != nil {
			return err
		}
		out.Next = next
		out.Streams, err = logsEncodeMany(vs, eventStreamToPB)
		return err
	}), nil
}

func (o clientEvents) CountEventStreams(ctx context.Context, tid string) (int, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid}, o.c.rpc.CountEventStreams)
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (s *Server) CountEventStreams(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		n, err := r.CountEventStreams(ctx, q.TenantId)
		out.Count = int64(n)
		return err
	}), nil
}

func (o clientEvents) DeleteEventStream(ctx context.Context, tid, id string) error {
	_, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: id}, o.c.rpc.DeleteEventStream)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) DeleteEventStream(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		return r.DeleteEventStream(ctx, q.TenantId, q.Id)
	}), nil
}

func (o clientEvents) LeaseEventStream(ctx context.Context, owner string, now, until time.Time) (*store.EventStream, error) {
	if err := store.ValidateLogTimes(now, until); err != nil {
		return nil, err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{Owner: owner, Now: eventTime(now), Until: eventTime(until)}, o.c.rpc.LeaseEventStream)
	if err != nil {
		return nil, err
	}
	return eventStreamFromPB(v.Stream)
}
func (s *Server) LeaseEventStream(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		var now, until time.Time
		if err := logTimesFromPB([]string{q.Now, q.Until}, &now, &until); err != nil {
			return err
		}
		v, err := r.LeaseEventStream(ctx, q.Owner, now, until)
		if err != nil {
			return err
		}
		out.Stream, err = eventStreamToPB(v)
		return err
	}), nil
}

func (o clientEvents) RecordEventDelivery(ctx context.Context, tid, id, owner string, outcome store.DeliveryOutcome) error {
	pb, err := deliveryOutcomeToPB(&outcome)
	if err != nil {
		return err
	}
	_, err = eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: id, Owner: owner, Outcome: pb}, o.c.rpc.RecordEventDelivery)
	if err != nil {
		return err
	}
	return nil
}
func (s *Server) RecordEventDelivery(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := deliveryOutcomeFromPB(q.Outcome)
		if err != nil {
			return err
		}
		if v == nil {
			return store.ErrInvalid
		}
		return r.RecordEventDelivery(ctx, q.TenantId, q.Id, q.Owner, *v)
	}), nil
}

func (o clientEvents) ListDeliveries(ctx context.Context, tid, streamID string, f store.DeliveryFilter, after string, take int) ([]store.EventDelivery, string, error) {
	pb, err := deliveryFilterToPB(&f)
	if err != nil {
		return nil, "", err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: streamID, Filter: pb, After: after, Take: int64(take)}, o.c.rpc.ListDeliveries)
	if err != nil {
		return nil, "", err
	}
	vs, err := logsDecodeMany(v.Deliveries, eventDeliveryFromPB)
	return vs, v.Next, err
}
func (s *Server) ListDeliveries(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		f, err := deliveryFilterFromPB(q.Filter)
		if err != nil {
			return err
		}
		if f == nil {
			f = &store.DeliveryFilter{}
		}
		vs, next, err := r.ListDeliveries(ctx, q.TenantId, q.Id, *f, q.After, int(q.Take))
		if err != nil {
			return err
		}
		out.Next = next
		out.Deliveries, err = logsEncodeMany(vs, eventDeliveryToPB)
		return err
	}), nil
}

func (o clientEvents) GetDelivery(ctx context.Context, tid, streamID, eventID string) (*store.EventDelivery, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: streamID, EventId: eventID}, o.c.rpc.GetDelivery)
	if err != nil {
		return nil, err
	}
	return eventDeliveryFromPB(v.Delivery)
}
func (s *Server) GetDelivery(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		v, err := r.GetDelivery(ctx, q.TenantId, q.Id, q.EventId)
		if err != nil {
			return err
		}
		out.Delivery, err = eventDeliveryToPB(v)
		return err
	}), nil
}

func (o clientEvents) QueueRedelivery(ctx context.Context, tid, streamID string, eventIDs []string, f *store.DeliveryFilter) (int, error) {
	pb, err := deliveryFilterToPB(f)
	if err != nil {
		return 0, err
	}
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: streamID, EventIds: eventStringsToPB(eventIDs), Filter: pb}, o.c.rpc.QueueRedelivery)
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (s *Server) QueueRedelivery(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		f, err := deliveryFilterFromPB(q.Filter)
		if err != nil {
			return err
		}
		n, err := r.QueueRedelivery(ctx, q.TenantId, q.Id, stringsFromPB(q.EventIds), f)
		out.Count = int64(n)
		return err
	}), nil
}

func (o clientEvents) QueuedDeliveries(ctx context.Context, tid, streamID string, take int) ([]store.EventDelivery, error) {
	v, err := eventsCall(o.c, ctx, &storev1.EventsRequest{TenantId: tid, Id: streamID, Take: int64(take)}, o.c.rpc.QueuedDeliveries)
	if err != nil {
		return nil, err
	}
	return logsDecodeMany(v.Deliveries, eventDeliveryFromPB)
}
func (s *Server) QueuedDeliveries(ctx context.Context, q *storev1.EventsRequest) (*storev1.EventsResponse, error) {
	return s.eventsServe(q.TxId, func(r store.Events, out *storev1.EventsResponse) error {
		vs, err := r.QueuedDeliveries(ctx, q.TenantId, q.Id, int(q.Take))
		if err != nil {
			return err
		}
		out.Deliveries, err = logsEncodeMany(vs, eventDeliveryToPB)
		return err
	}), nil
}
