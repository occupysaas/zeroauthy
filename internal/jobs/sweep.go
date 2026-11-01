package jobs

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SweepExpired drains bounded atomic cleanup batches. It must be called on a
// committed store, outside WithTx: a returned write report is recorded only
// after its transaction succeeds. Older repositories clean up once and omit
// events whose outcomes they cannot report.
func SweepExpired(ctx context.Context, st store.Jobs, before time.Time) (int, error) {
	writer, ok := st.(store.JobsOutcomeWriter)
	if !ok {
		return st.DeleteExpired(ctx, before)
	}
	total := 0
	for {
		n, outcomes, more, err := writer.DeleteExpiredResult(ctx, before, store.JobSweepBatch)
		if err != nil {
			return total, err
		}
		total += n
		for _, outcome := range outcomes {
			if outcome.Type == store.JobUsersImport && outcome.Status == store.JobFailed {
				logs.RecordEvent(ctx, logs.RecorderFromContext(ctx), logs.Event{TenantID: outcome.TenantID, Type: "fui", Date: outcome.UpdatedAt, Details: map[string]any{"job_id": outcome.ID}})
			}
		}
		if !more {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}
