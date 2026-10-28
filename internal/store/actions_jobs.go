package store

import "time"

// ActionJob is a durable sealed event and its immutable runtime pins.
type ActionJob struct {
	TenantID, ID, Trigger, Status            string
	Sealed                                   []byte
	Attempts                                 int
	NextAt, LeaseUntil, CreatedAt, UpdatedAt time.Time
	ExecutionIDs, ModuleVersionIDs           []string
}
