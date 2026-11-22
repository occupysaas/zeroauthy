package dsig

import "time"

// Clock supplies the current time to signature validation. A nil *Clock uses
// the system clock.
//
// zeroauthy modification: upstream wraps github.com/jonboulle/clockwork; this
// copy keeps only Now so no module is added (D-0130).
type Clock struct {
	now func() time.Time
}

// Now returns the clock's current time.
func (c *Clock) Now() time.Time {
	if c == nil || c.now == nil {
		return time.Now()
	}
	return c.now()
}

// NewRealClock returns a clock reading the system time.
func NewRealClock() *Clock { return &Clock{now: time.Now} }

// NewFakeClockAt returns a clock fixed at t.
func NewFakeClockAt(t time.Time) *Clock { return &Clock{now: func() time.Time { return t }} }

// NewClock returns a clock reading now.
func NewClock(now func() time.Time) *Clock { return &Clock{now: now} }
