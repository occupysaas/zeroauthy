package store

import "time"

// TenantEvent is an immutable CloudEvent before destination-specific stamping.
// The events store assigns Seq when appending it in the mutation transaction.
type TenantEvent struct {
	TenantID, ID, Type string
	Seq                int64
	Time               time.Time
	Body               []byte
}
