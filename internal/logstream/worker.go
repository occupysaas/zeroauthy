package logstream

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Item is the frozen envelope common to HTTP and vendor adapters.
type Item struct {
	LogID string          `json:"log_id"`
	Data  json.RawMessage `json:"data"`
}
type Sink interface {
	Send(context.Context, *store.LogStream, map[string]any, []Item) error
}
type Worker struct {
	st         store.Store
	keys       keys.Wrapper
	now        func() time.Time
	sink       Sink
	categories map[string]string
}

func NewWorker(st store.Store, keys keys.Wrapper, cfg logs.Config, client *http.Client, log *slog.Logger) *Worker {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	categories := map[string]string{}
	for _, code := range logrules.Codes() {
		categories[code.Type] = code.Category
	}
	return &Worker{st: st, keys: keys, now: now, sink: newHTTPSink(cfg.Streams, client), categories: categories}
}

// Run follows the application lifetime. Old plugins retry their unavailable
// capability in the normal idle loop; missing Logs support never fails startup.
func (w *Worker) Run(ctx context.Context) {
	if sink, ok := w.sink.(*httpSink); ok {
		defer sink.client.CloseIdleConnections()
	}
	for ctx.Err() == nil {
		if w.runOne(ctx) {
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
func (w *Worker) runOne(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	now := w.now().UTC()
	repo := w.st.Logs()
	// A process ID cannot fence an old acquisition after this worker reacquires.
	owner := secrets.RandomString(32)
	s, err := repo.LeaseLogStream(ctx, owner, now, now.Add(60*time.Second))
	if err != nil {
		return false
	}
	events, err := repo.LogsAfter(ctx, s.TenantID, s.Checkpoint, nil, 100, now.Add(-2*time.Second))
	checkpoint := s.Checkpoint
	items := make([]Item, 0, len(events))
	if err == nil {
		for _, e := range events {
			checkpoint = e.Seq
			if !s.StartFrom.IsZero() && e.Date.Before(s.StartFrom) {
				continue
			}
			if !w.matches(s, e.Type) {
				continue
			}
			data, e2 := outgoing(ctx, e.Body, s.PII)
			if e2 != nil {
				err = e2
				break
			}
			items = append(items, Item{LogID: e.ID, Data: data})
		}
	}
	if err == nil && len(items) > 0 {
		var private map[string]any
		private, err = OpenSecrets(w.keys, s)
		if err == nil {
			deliveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = w.sink.Send(deliveryCtx, s, private, items)
			cancel()
		}
	}
	// Shutdown between a successful send and persistence intentionally leaves
	// the checkpoint behind. An expired lease redelivers this batch on restart.
	if ctx.Err() != nil {
		return true
	}
	done := w.now().UTC()
	d := store.LogStreamDelivery{Checkpoint: checkpoint, Status: "active", NextAt: done, LastSuccessAt: s.LastSuccessAt}
	if err != nil {
		d.Checkpoint = s.Checkpoint
		d.Failures = s.Failures + 1
		d.FailingSince = s.FailingSince
		if d.FailingSince.IsZero() {
			d.FailingSince = done
		}
		d.LastErrorClass = errorClass(err)
		delay := time.Second
		for n := 1; n < d.Failures && delay < 5*time.Minute; n++ {
			delay *= 2
		}
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		d.NextAt = done.Add(delay)
		if done.Sub(d.FailingSince) >= 24*time.Hour {
			d.Status = "suspended"
		}
	} else if len(events) == 0 {
		d.NextAt = done.Add(time.Second)
	} else if len(items) > 0 {
		d.LastSuccessAt = done
	}
	// Store atomically checks token, expiry and active status; an admin update
	// invalidates the lease. No stale result may overwrite a newer checkpoint.
	_ = repo.RecordDelivery(ctx, s.TenantID, s.ID, owner, d)
	return true
}
func (w *Worker) matches(s *store.LogStream, typ string) bool {
	if len(s.Filters) == 0 {
		return true
	}
	category := w.categories[typ]
	if category == "" {
		category = "other"
	}
	for _, f := range s.Filters {
		if f.Type == "category" && f.Name == category {
			return true
		}
	}
	return false
}
