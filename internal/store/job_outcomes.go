package store

import (
	"context"
	"time"
)

// JobOutcome contains only the metadata of an actual terminal write. Input,
// params, error bodies, connection configuration and status details are excluded.
type JobOutcome struct {
	TenantID, ID string
	Type         JobType
	Status       JobStatus
	UpdatedAt    time.Time
}

const JobSweepBatch = 100

// JobsOutcomeWriter optionally reports the failures made by expiry cleanup.
// A call atomically fails at most limit jobs (1..JobSweepBatch), clears expired
// records and their children, and reports only changed rows. More requests
// another batch. Outcomes from a failed call are empty; inside WithTx they are
// provisional until the caller commits. Callers must emit only after commit.
// Old plugins retain DeleteExpired semantics without guessing outcomes.
type JobsOutcomeWriter interface {
	DeleteExpiredResult(ctx context.Context, before time.Time, limit int) (deleted int, outcomes []JobOutcome, more bool, err error)
}
