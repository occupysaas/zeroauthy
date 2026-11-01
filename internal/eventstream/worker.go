package eventstream

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ActionRunner is implemented by the durable Actions adapter.
type ActionRunner interface {
	RunEventStream(ctx context.Context, tenantID, actionID string, message []byte) error
}

type Worker struct {
	st     store.Store
	keys   keys.Wrapper
	cfg    events.Config
	client *http.Client
	runner ActionRunner
	owner  string
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
}

func NewWorker(st store.Store, keys keys.Wrapper, cfg events.Config, client *http.Client, runner ActionRunner, log *slog.Logger) *Worker {
	return &Worker{st: st, keys: keys, cfg: cfg, client: webhookClient(cfg, client), runner: runner, owner: secrets.RandomString(32), now: time.Now, sleep: sleep}
}

// Deliver is also used for immediate test events, which never enter the outbox
// or failure repository. The caller supplies a stamped copy of the CloudEvent.
func (w *Worker) Deliver(ctx context.Context, s *store.EventStream, body []byte) []store.DeliveryAttempt {
	out := []store.DeliveryAttempt{}
	private, openErr := OpenSecrets(w.keys, s)
	for _, delay := range retryDelays {
		if ctx.Err() != nil {
			return out
		}
		if delay > 0 {
			if err := w.sleep(ctx, delay); err != nil {
				return out
			}
		}
		if ctx.Err() != nil {
			return out
		}
		start := w.now().UTC()
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message := "connection_error"
		stop := false
		switch {
		case openErr != nil:
		case s.DestType == "webhook":
			message, stop = w.webhook(attemptCtx, s, private, body)
		case s.DestType == "action":
			if w.runner == nil {
				message = "action_error: unavailable"
			} else {
				id, _ := s.Config["action_id"].(string)
				err := w.runner.RunEventStream(attemptCtx, s.TenantID, id, body)
				if err == nil && attemptCtx.Err() == nil {
					message = ""
					stop = true
				} else if attemptCtx.Err() != nil {
					message = transportError(attemptCtx.Err())
				} else {
					masked := logscrub.ScrubValueContext(ctx, err.Error()).(string)
					message = "action_error: " + string([]rune(masked)[:min(len([]rune(masked)), 512)])
				}
			}
		}
		cancel()
		status := "failed"
		if message == "" {
			status = "success"
		}
		out = append(out, store.DeliveryAttempt{Status: status, Timestamp: start, ErrorMessage: message, DurationMS: max(0, float64(w.now().Sub(start))/float64(time.Millisecond))})
		if stop {
			return out
		}
	}
	return out
}

func (w *Worker) Run(ctx context.Context) {
	defer w.client.CloseIdleConnections()
	for ctx.Err() == nil {
		if probe, ok := w.st.(store.EventsSupporter); ok {
			err := probe.CheckEventsSupport(ctx)
			// Negotiated capabilities cannot change during this plugin connection.
			if errors.Is(err, store.ErrEventsUnavailable) || err == nil && !probe.EventsSupported() {
				return
			}
			if err != nil {
				if w.sleep(ctx, time.Second) != nil {
					return
				}
				continue
			}
		}
		if w.runOne(ctx) {
			continue
		}
		if w.sleep(ctx, time.Second) != nil {
			return
		}
	}
}

// One lease iteration sends at most one event. Four bounded attempts and the
// seven seconds of backoff fit in 60s; all reads and recording share an earlier
// deadline. Reacquiring before the next event prevents a 100-event drain from
// silently running beyond its lease.
func (w *Worker) runOne(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	now := w.now().UTC()
	s, err := w.st.Events().LeaseEventStream(ctx, w.owner, now, now.Add(time.Minute))
	if err != nil {
		return false
	}
	remaining := s.LeaseUntil.Sub(w.now()) - 5*time.Second
	if remaining <= 0 {
		return false
	}
	workCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	queued, err := w.st.Events().QueuedDeliveries(workCtx, s.TenantID, s.ID, 100)
	if err != nil {
		return false
	}
	checkpoint := s.Checkpoint
	var event *store.TenantEvent
	if len(queued) > 0 {
		event, err = w.st.Events().GetEvent(workCtx, s.TenantID, queued[0].EventID)
		if err != nil {
			return false
		}
	} else {
		if s.Status != "enabled" {
			return false
		}
		rows, err := w.st.Events().EventsAfter(workCtx, s.TenantID, s.Checkpoint, s.Subscriptions, 100, now.Add(-2*time.Second))
		if err != nil {
			return false
		}
		if len(rows) > 0 {
			event = &rows[0]
			checkpoint = event.Seq
		} else {
			// An unmatched tail still needs a settled checkpoint, or it would lease
			// forever and prevent other streams from making progress.
			rows, err = w.st.Events().EventsAfter(workCtx, s.TenantID, s.Checkpoint, nil, 100, now.Add(-2*time.Second))
			if err != nil || len(rows) == 0 {
				return false
			}
			checkpoint = rows[len(rows)-1].Seq
		}
	}
	// Avoid sending if preprocessing used up the attempt budget or ownership
	// changed. Record repeats this fence inside the mutation transaction.
	current, err := w.st.Events().GetEventStream(workCtx, s.TenantID, s.ID)
	if err != nil || current.Version != s.Version || current.LeaseOwner != w.owner || !current.LeaseUntil.After(w.now()) || workCtx.Err() != nil {
		return false
	}
	var attempts []store.DeliveryAttempt
	if event != nil {
		if s.LeaseUntil.Sub(w.now()) < 52*time.Second {
			return false
		}
		attempts = w.Deliver(workCtx, s, events.Stamp(event.Body, s.ID, false))
		if workCtx.Err() != nil || len(attempts) == 0 {
			return false
		}
	}
	err = w.st.WithTx(workCtx, func(tx store.Store) error {
		// This is the existing SQL tenant row lock. Hold it before reading counters
		// and records, so purge, management updates and recording cannot race them.
		if _, err := tx.Tenants().Get(workCtx, s.TenantID); err != nil {
			return err
		}
		fresh, err := tx.Events().GetEventStream(workCtx, s.TenantID, s.ID)
		if err != nil {
			return err
		}
		if fresh.Version != s.Version || fresh.LeaseOwner != w.owner || !fresh.LeaseUntil.After(w.now()) {
			return store.ErrPrecondition
		}
		total, err := failureCount(workCtx, tx.Events(), s.TenantID, s.ID)
		if err != nil {
			return err
		}
		outcome := store.DeliveryOutcome{Checkpoint: checkpoint, ConsecutiveFailures: fresh.ConsecutiveFailures, TotalFailures: total}
		if event != nil {
			_, existing := tx.Events().GetDelivery(workCtx, s.TenantID, s.ID, event.ID)
			if existing != nil && !errors.Is(existing, store.ErrNotFound) {
				return existing
			}
			if attempts[len(attempts)-1].Status == "success" {
				outcome.Succeeded = []string{event.ID}
				outcome.ConsecutiveFailures = 0
				if existing == nil {
					outcome.TotalFailures--
				}
			} else {
				outcome.ConsecutiveFailures++
				if errors.Is(existing, store.ErrNotFound) {
					outcome.TotalFailures++
				}
				outcome.Failed = &store.EventDelivery{TenantID: s.TenantID, StreamID: s.ID, EventID: event.ID, EventType: event.Type, Status: "failed", Attempts: attempts, EventTime: event.Time}
			}
		}
		outcome.Disable = outcome.ConsecutiveFailures >= 500 || outcome.TotalFailures >= 5000
		return tx.Events().RecordEventDelivery(workCtx, s.TenantID, s.ID, w.owner, outcome)
	})
	return err == nil
}

func failureCount(ctx context.Context, repo store.Events, tid, sid string) (int, error) {
	total := 0
	after := ""
	for {
		rows, next, err := repo.ListDeliveries(ctx, tid, sid, store.DeliveryFilter{Statuses: []string{"failed"}}, after, 100)
		if err != nil {
			return 0, err
		}
		total += len(rows)
		if next == "" {
			return total, nil
		}
		after = next
	}
}
