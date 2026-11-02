package memory

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const eventCapacity = 10000

type storedEvent struct {
	event     store.TenantEvent
	committed time.Time
	pending   bool
}
type eventRing struct {
	purged int64
	events []storedEvent
	start  int
}

func (r *eventRing) each(fn func(storedEvent)) {
	if r == nil {
		return
	}
	for i := range len(r.events) {
		fn(r.events[(r.start+i)%len(r.events)])
	}
}
func (r *eventRing) append(e storedEvent) {
	if len(r.events) < eventCapacity {
		r.events = append(r.events, e)
	} else {
		r.purged = max(r.purged, r.events[r.start].event.Seq)
		r.events[r.start] = e
		r.start = (r.start + 1) % eventCapacity
	}
}

type deliveryKey struct{ tenant, stream, event string }
type events struct{ s *Store }

func (s *Store) Events() store.Events                     { return events{s} }
func (s *Store) CheckEventsSupport(context.Context) error { return nil }
func (s *Store) EventsSupported() bool                    { return true }
func cloneEvent(e store.TenantEvent) store.TenantEvent    { e.Body = slices.Clone(e.Body); return e }
func cloneEventStream(s *store.EventStream) *store.EventStream {
	if s == nil {
		return nil
	}
	v := *s
	v.Subscriptions = slices.Clone(s.Subscriptions)
	v.SealedSecret = slices.Clone(s.SealedSecret)
	v.Config = cloneJSON(s.Config)
	return &v
}
func cloneEventDelivery(s *store.EventDelivery) *store.EventDelivery {
	if s == nil {
		return nil
	}
	v := *s
	v.Attempts = slices.Clone(s.Attempts)
	return &v
}
func cloneEventRings(m map[string]*eventRing) map[string]*eventRing {
	out := make(map[string]*eventRing, len(m))
	for k, r := range m {
		v := &eventRing{purged: r.purged, start: r.start, events: make([]storedEvent, len(r.events))}
		for i, e := range r.events {
			v.events[i] = e
			v.events[i].event = cloneEvent(e.event)
		}
		out[k] = v
	}
	return out
}
func (r events) AppendEvents(ctx context.Context, es []store.TenantEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	seen := map[key]bool{}
	for _, e := range es {
		k := key{e.TenantID, e.ID}
		if seen[k] {
			return store.ErrConflict
		}
		seen[k] = true
		duplicate := false
		r.s.tenantEvents[e.TenantID].each(func(v storedEvent) { duplicate = duplicate || v.event.ID == e.ID })
		if duplicate {
			return store.ErrConflict
		}
	}
	now := r.s.now().UTC()
	for i, e := range es {
		r.s.eventSeq++
		e.Seq = r.s.eventSeq
		es[i].Seq = e.Seq
		ring := r.s.tenantEvents[e.TenantID]
		if ring == nil {
			ring = &eventRing{}
			r.s.tenantEvents[e.TenantID] = ring
		}
		stamp := now
		if len(ring.events) > 0 {
			last := ring.events[(ring.start+len(ring.events)-1)%len(ring.events)]
			if last.committed.After(stamp) {
				stamp = last.committed
			}
		}
		if len(ring.events) == eventCapacity && len(r.s.eventDeliveries) > 0 {
			evicted := ring.events[ring.start].event.ID
			r.removeEventDeliveries(e.TenantID, evicted)
		}
		ring.append(storedEvent{event: cloneEvent(e), committed: stamp, pending: r.s.tx})
	}
	return nil
}
func (r events) GetEvent(ctx context.Context, tid, id string) (*store.TenantEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var out *store.TenantEvent
	r.s.tenantEvents[tid].each(func(e storedEvent) {
		if e.event.ID == id {
			v := cloneEvent(e.event)
			out = &v
		}
	})
	if out == nil {
		return nil, store.ErrNotFound
	}
	return out, nil
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
func eventMatches(e store.TenantEvent, types []string) bool {
	return len(types) == 0 || slices.Contains(types, e.Type)
}
func (r events) read(ctx context.Context, tid string, after int64, from time.Time, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.TenantEvent{}
	take = eventTake(take)
	r.s.tenantEvents[tid].each(func(e storedEvent) {
		if len(out) < take && !e.pending && !e.committed.After(settled) && e.event.Seq > after && (from.IsZero() || !e.event.Time.Before(from)) && eventMatches(e.event, types) {
			out = append(out, cloneEvent(e.event))
		}
	})
	return out, nil
}
func (r events) EventsAfter(ctx context.Context, tid string, after int64, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	return r.read(ctx, tid, after, time.Time{}, types, take, settled)
}
func (r events) EventsFromTime(ctx context.Context, tid string, from time.Time, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	return r.read(ctx, tid, 0, from, types, take, settled)
}
func (r events) LatestEventSeq(ctx context.Context, tid string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var seq int64
	r.s.tenantEvents[tid].each(func(e storedEvent) { seq = e.event.Seq })
	return seq, nil
}
func (r events) PurgedEventSeq(ctx context.Context, tid string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	if ring := r.s.tenantEvents[tid]; ring != nil {
		return ring.purged, nil
	}
	return 0, nil
}
func (r events) OldestEventSeq(ctx context.Context, tid string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var seq int64
	r.s.tenantEvents[tid].each(func(e storedEvent) {
		if seq == 0 {
			seq = e.event.Seq
		}
	})
	return seq, nil
}
func (r events) PurgeEvents(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.lock()
	defer r.s.unlock()
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	for tid, ring := range r.s.tenantEvents {
		next := &eventRing{purged: ring.purged}
		ring.each(func(e storedEvent) {
			if n < limit && e.event.Time.Before(before) {
				n++
				next.purged = max(next.purged, e.event.Seq)
				r.removeEventDeliveries(tid, e.event.ID)
			} else {
				next.append(e)
			}
		})
		r.s.tenantEvents[tid] = next
	}
	return n, nil
}

// Caller holds the mutation lock, including the transaction snapshot lock.
// Retention and ring eviction remove extant failures without resetting the
// consecutive failure streak (only a successful delivery resets that streak).
func (r events) removeEventDeliveries(tid, eid string) {
	for k := range r.s.eventDeliveries {
		if k.tenant != tid || k.event != eid {
			continue
		}
		delete(r.s.eventDeliveries, k)
		if s := r.s.eventStreams[key{tid, k.stream}]; s != nil {
			s.TotalFailures = max(0, s.TotalFailures-1)
			s.Version++
			s.UpdatedAt = r.s.now().UTC()
		}
	}
}
func (s *Store) deleteTenantEvents(tid string) {
	delete(s.tenantEvents, tid)
	for k := range s.eventStreams {
		if k.tenant == tid {
			delete(s.eventStreams, k)
		}
	}
	for k := range s.eventDeliveries {
		if k.tenant == tid {
			delete(s.eventDeliveries, k)
		}
	}
}
func (r events) DeleteTenantEvents(ctx context.Context, tid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	r.s.deleteTenantEvents(tid)
	return nil
}
func (r events) CreateEventStream(ctx context.Context, v *store.EventStream) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{v.TenantID, v.ID}
	if r.s.eventStreams[k] != nil {
		return store.ErrConflict
	}
	for _, s := range r.s.eventStreams {
		if s.TenantID == v.TenantID && s.Name == v.Name {
			return store.ErrConflict
		}
	}
	c := cloneEventStream(v)
	c.Version = 1
	r.s.eventStreams[k] = c
	v.Version = c.Version
	return nil
}
func (r events) GetEventStream(ctx context.Context, tid, id string) (*store.EventStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	s := r.s.eventStreams[key{tid, id}]
	if s == nil {
		return nil, store.ErrNotFound
	}
	return cloneEventStream(s), nil
}
func (r events) ListEventStreams(ctx context.Context, tid, after string, take int) ([]store.EventStream, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.EventStream{}
	for k, s := range r.s.eventStreams {
		if k.tenant == tid && k.id > after {
			out = append(out, *cloneEventStream(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	take = eventTake(take)
	next := ""
	if len(out) > take {
		out = out[:take]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}
func (r events) CountEventStreams(ctx context.Context, tid string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	n := 0
	for k := range r.s.eventStreams {
		if k.tenant == tid {
			n++
		}
	}
	return n, nil
}
func (r events) UpdateEventStream(ctx context.Context, v *store.EventStream, version int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{v.TenantID, v.ID}
	old := r.s.eventStreams[k]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Version != version {
		return store.ErrConflict
	}
	for key, s := range r.s.eventStreams {
		if key != k && s.TenantID == v.TenantID && s.Name == v.Name {
			return store.ErrConflict
		}
	}
	c := cloneEventStream(v)
	c.Version = version + 1
	r.s.eventStreams[k] = c
	v.Version = c.Version
	return nil
}
func (r events) DeleteEventStream(ctx context.Context, tid, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	if r.s.eventStreams[k] == nil {
		return store.ErrNotFound
	}
	delete(r.s.eventStreams, k)
	for k := range r.s.eventDeliveries {
		if k.tenant == tid && k.stream == id {
			delete(r.s.eventDeliveries, k)
		}
	}
	return nil
}
func (r events) LeaseEventStream(ctx context.Context, owner string, now, until time.Time) (*store.EventStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || !until.After(now) {
		return nil, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	keys := []key{}
	for k := range r.s.eventStreams {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := r.s.eventStreams[keys[i]], r.s.eventStreams[keys[j]]
		if !left.LeaseUntil.Equal(right.LeaseUntil) {
			return left.LeaseUntil.Before(right.LeaseUntil)
		}
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].id < keys[j].id
	})
	for _, k := range keys {
		s := r.s.eventStreams[k]
		if s.LeaseOwner != owner && s.LeaseOwner != "" && s.LeaseUntil.After(now) {
			continue
		}
		due := false
		for k, d := range r.s.eventDeliveries {
			if k.tenant == s.TenantID && k.stream == s.ID && d.Queued {
				due = true
				break
			}
		}
		if s.Status == "enabled" {
			r.s.tenantEvents[s.TenantID].each(func(e storedEvent) {
				if e.event.Seq > s.Checkpoint {
					due = true
				}
			})
		}
		if !due {
			continue
		}
		// Reuse the persisted expiry as the fair scheduling key. Advance even
		// under an identical clock/request, so equal expiries cannot pin the
		// lexicographically first stream after an initial round of claims.
		leaseUntil := until
		if !leaseUntil.After(s.LeaseUntil) {
			leaseUntil = s.LeaseUntil.Add(time.Nanosecond)
			if leaseUntil.Year() > 9999 {
				return nil, store.ErrInvalid
			}
		}
		s.LeaseOwner = owner
		s.LeaseUntil = leaseUntil
		return cloneEventStream(s), nil
	}
	return nil, store.ErrNotFound
}
func (r events) RecordEventDelivery(ctx context.Context, tid, id, owner string, o store.DeliveryOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s.eventStreams[key{tid, id}]
	if s == nil {
		return store.ErrNotFound
	}
	if s.LeaseOwner != owner || owner == "" || !s.LeaseUntil.After(r.s.now()) {
		return store.ErrPrecondition
	}
	if o.Failed != nil && (o.Failed.TenantID != tid || o.Failed.StreamID != id || o.Failed.Status != "failed") {
		return store.ErrInvalid
	}
	if o.Checkpoint < s.Checkpoint {
		return store.ErrPrecondition
	}
	// Purge/eviction can remove an event after a worker reads it. Resolve all
	// references while holding the mutation lock before touching any outcome
	// state; foreign tenant IDs are indistinguishable from missing events.
	referenced := make(map[string]bool, len(o.Succeeded)+1)
	if o.Failed != nil {
		referenced[o.Failed.EventID] = false
	}
	for _, eid := range o.Succeeded {
		referenced[eid] = false
	}
	if len(referenced) > 0 {
		r.s.tenantEvents[tid].each(func(e storedEvent) {
			if _, ok := referenced[e.event.ID]; ok {
				referenced[e.event.ID] = true
			}
		})
		for _, found := range referenced {
			if !found {
				return store.ErrNotFound
			}
		}
	}
	s.Checkpoint = o.Checkpoint
	s.ConsecutiveFailures = o.ConsecutiveFailures
	s.TotalFailures = o.TotalFailures
	if o.Disable {
		s.Status = "disabled"
	}
	s.UpdatedAt = r.s.now().UTC()
	s.Version++
	if o.Failed != nil {
		d := cloneEventDelivery(o.Failed)
		d.UpdatedAt = s.UpdatedAt
		r.s.eventDeliveries[deliveryKey{tid, id, d.EventID}] = d
	}
	for _, eid := range o.Succeeded {
		delete(r.s.eventDeliveries, deliveryKey{tid, id, eid})
	}
	return nil
}
func deliveryMatches(d *store.EventDelivery, f store.DeliveryFilter) bool {
	return (len(f.Statuses) == 0 || slices.Contains(f.Statuses, d.Status)) && (len(f.EventTypes) == 0 || slices.Contains(f.EventTypes, d.EventType)) && (f.From.IsZero() || !d.EventTime.Before(f.From)) && (f.To.IsZero() || d.EventTime.Before(f.To))
}

// Delivery cursors use event IDs; ordering is stable across record updates.
func (r events) ListDeliveries(ctx context.Context, tid, sid string, f store.DeliveryFilter, after string, take int) ([]store.EventDelivery, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.eventStreams[key{tid, sid}] == nil {
		return nil, "", store.ErrNotFound
	}
	out := []store.EventDelivery{}
	for k, d := range r.s.eventDeliveries {
		if k.tenant == tid && k.stream == sid && k.event > after && deliveryMatches(d, f) {
			out = append(out, *cloneEventDelivery(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	take = eventTake(take)
	next := ""
	if len(out) > take {
		out = out[:take]
		next = out[len(out)-1].EventID
	}
	return out, next, nil
}
func (r events) GetDelivery(ctx context.Context, tid, sid, eid string) (*store.EventDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	d := r.s.eventDeliveries[deliveryKey{tid, sid, eid}]
	if d == nil {
		return nil, store.ErrNotFound
	}
	return cloneEventDelivery(d), nil
}
func (r events) QueueRedelivery(ctx context.Context, tid, sid string, ids []string, f *store.DeliveryFilter) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.eventStreams[key{tid, sid}] == nil {
		return 0, store.ErrNotFound
	}
	selected := map[deliveryKey]*store.EventDelivery{}
	if len(ids) > 0 {
		for _, eid := range ids {
			k := deliveryKey{tid, sid, eid}
			d := r.s.eventDeliveries[k]
			if d == nil || d.Status != "failed" || d.Queued {
				return 0, store.ErrPrecondition
			}
			selected[k] = d
		}
	} else {
		filter := store.DeliveryFilter{}
		if f != nil {
			filter = *f
		}
		for k, d := range r.s.eventDeliveries {
			if k.tenant == tid && k.stream == sid && deliveryMatches(d, filter) {
				if d.Status != "failed" || d.Queued {
					return 0, store.ErrPrecondition
				}
				selected[k] = d
			}
		}
	}
	if len(selected) == 0 {
		return 0, store.ErrPrecondition
	}
	for _, d := range selected {
		d.Queued = true
		d.UpdatedAt = r.s.now().UTC()
	}
	return len(selected), nil
}
func (r events) QueuedDeliveries(ctx context.Context, tid, sid string, take int) ([]store.EventDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.eventStreams[key{tid, sid}] == nil {
		return nil, store.ErrNotFound
	}
	out := []store.EventDelivery{}
	for k, d := range r.s.eventDeliveries {
		if k.tenant == tid && k.stream == sid && d.Queued {
			out = append(out, *cloneEventDelivery(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	if len(out) > eventTake(take) {
		out = out[:eventTake(take)]
	}
	return out, nil
}
