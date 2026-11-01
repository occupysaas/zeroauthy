package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// actionRunner submits durable snapshots. Queue workers alone execute Node;
// delivery workers observe committed terminal outcomes, including across hosts.
type actionRunner struct{ engine *actions.Engine }

func NewActionRunner(e *actions.Engine) ActionRunner { return &actionRunner{engine: e} }

func (r *actionRunner) RunEventStream(ctx context.Context, tid, id string, message []byte) error {
	attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	attemptDeadline, _ := attemptCtx.Deadline()
	// Reserve cancellation I/O inside the same delivery deadline. Short caller
	// budgets reserve proportionally less; a normal attempt reserves 100ms.
	reserve := min(100*time.Millisecond, max(0, time.Until(attemptDeadline)/10))
	ctx, stopWait := context.WithDeadline(attemptCtx, attemptDeadline.Add(-reserve))
	defer stopWait()
	a := r.engine.Store.Actions()
	// Probe additive methods before enqueue: old plugins retain ordinary Actions
	// compatibility and refuse this destination without leaving an orphan job.
	if _, err := a.GetJob(ctx, tid, "event-stream-capability-probe"); !errors.Is(err, store.ErrNotFound) {
		return errors.New("Actions job observation unavailable")
	}
	if err := a.CancelJob(ctx, tid, "event-stream-capability-probe"); !errors.Is(err, store.ErrNotFound) {
		return errors.New("Actions job cancellation unavailable")
	}
	deadline, _ := ctx.Deadline()
	j, err := r.engine.EnqueueEventStream(ctx, tid, id, json.RawMessage(message), deadline)
	if err != nil {
		return errors.New("Actions event stream enqueue failed")
	}
	completed := false
	defer func() {
		if !completed {
			cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), minTime(time.Now().Add(reserve), attemptDeadline))
			defer stop()
			_ = a.CancelJob(cleanup, tid, j.ID)
		}
	}()
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		state, err := a.GetJob(ctx, tid, j.ID)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("Actions job result unavailable")
		}
		if state.Status != "pending" {
			completed = true
			if state.Status == "done" {
				return nil
			}
			if len(state.ExecutionIDs) > 0 {
				ex, err := a.GetExecution(ctx, tid, state.ExecutionIDs[len(state.ExecutionIDs)-1])
				if err == nil {
					for _, result := range ex.Results {
						if result.ErrorID == "timeout" {
							return context.DeadlineExceeded
						}
						if result.ErrorID != "" {
							return errors.New(result.ErrorMsg)
						}
					}
				}
			}
			return errors.New("Actions event stream execution failed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
