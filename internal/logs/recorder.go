package logs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const batchSize = 100
const batchDelay = 250 * time.Millisecond

type queuedEvent struct {
	event store.LogEvent
	body  map[string]any
}

// AsyncRecorder owns a bounded queue and one batch writer. Run starts the writer;
// Flush also starts it when necessary and permanently closes admission. Flush is
// safe to call concurrently and waits for queued AND in-flight writes. A flush
// deadline cancels storage work; failed writes are counted as dropped, never retried.
type AsyncRecorder struct {
	st      store.Store
	cfg     Config
	log     *slog.Logger
	queue   chan queuedEvent
	stop    chan struct{}
	done    chan struct{}
	notices chan struct{}
	once    sync.Once
	mu      sync.RWMutex
	closing bool
	cancel  context.CancelFunc
	dropped atomic.Uint64
	// err belongs to the batch writer and is read only after done closes.
	// warned and lastWarn belong to the independent warning worker.
	err        error
	warned     bool
	lastWarn   time.Time
	statsKinds map[string]string
}

func NewRecorder(st store.Store, cfg Config, log *slog.Logger) *AsyncRecorder {
	cfg = cfg.defaults()
	if log == nil {
		log = slog.Default()
	}
	r := &AsyncRecorder{st: st, cfg: cfg, log: slog.New(logscrub.Handler(log.Handler())), queue: make(chan queuedEvent, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}), notices: make(chan struct{}, 1), statsKinds: map[string]string{}}
	for _, c := range logrules.Codes() {
		if c.StatsKind != "" {
			r.statsKinds[c.Type] = c.StatsKind
		}
	}
	return r
}
func (r *AsyncRecorder) Dropped() uint64 { return r.dropped.Load() }
func (r *AsyncRecorder) drop(n int) {
	r.dropped.Add(uint64(n))
	select {
	case r.notices <- struct{}{}:
	default:
	}
}

func (r *AsyncRecorder) Record(ctx context.Context, e Event) {
	if e.TenantID == "" {
		r.drop(1)
		return
	}
	if e.Date.IsZero() {
		e.Date = r.cfg.Now()
	}
	e.Date = e.Date.UTC()
	doc := map[string]any{"date": e.Date.Format(time.RFC3339Nano), "type": e.Type}
	fields := map[string]string{"description": e.Description, "client_id": e.ClientID, "client_name": e.ClientName, "connection": e.Connection, "connection_id": e.ConnectionID, "strategy": e.Strategy, "strategy_type": e.StrategyType, "user_id": e.UserID, "user_name": e.UserName, "audience": e.Audience, "scope": e.Scope, "organization_id": e.OrganizationID, "organization_name": e.OrganizationName, "hostname": e.Hostname, "ip": e.IP, "user_agent": e.UserAgent}
	for key, value := range fields {
		if value != "" {
			doc[key] = value
		}
	}

	details := maps.Clone(e.Details)
	if len(e.ExecutionIDs) > 0 {
		if details == nil {
			details = map[string]any{}
		}
		existing, _ := details["actions"].(map[string]any)
		actions := maps.Clone(existing)
		if actions == nil {
			actions = map[string]any{}
		}
		actions["executions"] = e.ExecutionIDs
		details["actions"] = actions
	}
	if len(details) > 0 {
		doc["details"] = details
	}
	// Scrub the completed document, including enrichment. This immutable
	// context-aware scrub masks dynamic names and encoded JSON. No context or
	// caller-owned value survives in the queue.
	safe := logscrub.ScrubValueContext(ctx, doc).(map[string]any)
	body, err := json.Marshal(safe)
	if err != nil {
		r.drop(1)
		return
	}
	str := func(key string) string { s, _ := safe[key].(string); return s }
	event := store.LogEvent{TenantID: e.TenantID, Type: str("type"), Date: e.Date, UserID: str("user_id"), ClientID: str("client_id"), ConnectionID: str("connection_id"), OrganizationID: str("organization_id"), IP: str("ip"), Body: body}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closing {
		r.drop(1)
		return
	}
	select {
	case r.queue <- queuedEvent{event: event, body: safe}:
	default:
		r.drop(1)
	}
}
func (r *AsyncRecorder) start() {
	r.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		r.cancel = cancel
		go r.writeLoop(ctx)
	})
}

// Run blocks until cancellation or a completed Flush. Cancellation performs a
// bounded shutdown flush; callers serving HTTP should cancel after requests drain.
func (r *AsyncRecorder) Run(ctx context.Context) {
	r.start()
	select {
	case <-r.done:
	case <-ctx.Done():
		flush, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.Flush(flush)
	}
}
func (r *AsyncRecorder) Flush(ctx context.Context) error {
	r.start()
	r.mu.Lock()
	if !r.closing {
		r.closing = true
		close(r.stop)
	}
	r.mu.Unlock()
	stopCancel := context.AfterFunc(ctx, r.cancel)
	defer stopCancel()
	select {
	case <-r.done:
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), r.err)
		}
		return r.err
	case <-ctx.Done():
		r.cancel()
		return ctx.Err()
	}
}
func (r *AsyncRecorder) warnDrops() {
	now := r.cfg.Now()
	if r.warned && now.Sub(r.lastWarn) < time.Minute {
		return
	}
	r.warned = true
	r.lastWarn = now
	r.log.Warn("log events dropped", "dropped", r.Dropped())
}
func (r *AsyncRecorder) writeLoop(ctx context.Context) {
	// Overflow warnings must remain responsive while AppendLogs is blocked.
	written := make(chan struct{})
	warned := make(chan struct{})
	go func() { defer close(warned); r.warningLoop(written) }()
	defer func() { close(written); <-warned; close(r.done) }()
	defer r.cancel()
	tick := time.NewTicker(batchDelay)
	defer tick.Stop()
	batch := make([]queuedEvent, 0, batchSize)
	write := func() {
		if len(batch) > 0 {
			r.writeBatch(ctx, batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case e := <-r.queue:
			batch = append(batch, e)
			if len(batch) == batchSize {
				write()
			}
		case <-tick.C:
			write()
		case <-r.stop:
			for {
				select {
				case e := <-r.queue:
					batch = append(batch, e)
					if len(batch) == batchSize {
						write()
					}
				default:
					write()
					return
				}
			}
		}
	}
}
func (r *AsyncRecorder) writeBatch(ctx context.Context, batch []queuedEvent) {
	if ctx.Err() != nil {
		r.failBatch(ctx.Err(), len(batch))
		return
	}
	repo := r.st.Logs()
	unavailable := false
	if probe, ok := r.st.(store.LogsSupporter); ok {
		err := probe.CheckLogsSupport(ctx)
		if errors.Is(err, store.ErrLogsUnavailable) {
			unavailable = true
		} else if err != nil {
			r.failBatch(err, len(batch))
			return
		} else if !probe.LogsSupported() {
			unavailable = true
		}
	}
	names := map[string]string{}
	for i := range batch {
		tid := batch[i].event.TenantID
		name, ok := names[tid]
		if !ok {
			t, err := r.st.Tenants().Get(ctx, tid)
			if err == nil {
				name = t.Name
			}
			names[tid] = name
		}
		if name != "" {
			batch[i].body["tenant_name"] = name
		}
		body, err := json.Marshal(logscrub.ScrubValue(batch[i].body))
		if err != nil {
			r.failBatch(err, len(batch))
			return
		}
		batch[i].event.Body = body
	}
	if unavailable {
		r.fallback(batch)
		return
	}
	events := make([]store.LogEvent, len(batch))
	deltas := map[struct {
		tenant string
		day    time.Time
	}]*store.DailyStatDelta{}
	for i, q := range batch {
		events[i] = q.event
		day := q.event.Date.UTC().Truncate(24 * time.Hour)
		key := struct {
			tenant string
			day    time.Time
		}{q.event.TenantID, day}
		kind := r.statsKinds[q.event.Type]
		if kind == "" {
			continue
		}
		delta := deltas[key]
		if delta == nil {
			delta = &store.DailyStatDelta{TenantID: key.tenant, Day: day}
			deltas[key] = delta
		}
		switch kind {
		case "logins":
			delta.Logins++
		case "signups":
			delta.Signups++
		case "leaked_passwords":
			delta.LeakedPasswords++
		}
	}
	stats := make([]store.DailyStatDelta, 0, len(deltas))
	for _, delta := range deltas {
		stats = append(stats, *delta)
	}
	err := repo.AppendLogs(ctx, events, stats)
	if errors.Is(err, store.ErrLogsUnavailable) {
		r.fallback(batch)
		return
	}
	if err != nil {
		r.failBatch(err, len(batch))
	}
}
func (r *AsyncRecorder) fallback(batch []queuedEvent) {
	for _, q := range batch {
		r.log.Info("tenant log event", "event", json.RawMessage(q.event.Body))
	}
}
func (r *AsyncRecorder) failBatch(err error, n int) {
	if r.err == nil {
		r.err = err
	}
	r.drop(n)
}

func (r *AsyncRecorder) warningLoop(written <-chan struct{}) {
	for {
		select {
		case <-r.notices:
			r.warnDrops()
		case <-written:
			select {
			case <-r.notices:
				r.warnDrops()
			default:
			}
			return
		}
	}
}
