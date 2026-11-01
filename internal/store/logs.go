package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrLogsUnavailable means the driver has not negotiated the Logs v1 capability.
var ErrLogsUnavailable = errors.New("store: logs repository unavailable")

// LogsSupporter is an optional read-only probe for the Logs v1 capability.
type LogsSupporter interface {
	CheckLogsSupport(context.Context) error
	LogsSupported() bool
}

// FormatLogID formats a store-assigned positive sequence as a sortable ID.
func FormatLogID(seq int64) string { return fmt.Sprintf("%056d", seq) }

// ParseLogID accepts only the canonical 56-digit positive int64 representation.
func ParseLogID(id string) (int64, error) {
	if len(id) != 56 || strings.Trim(id, "0123456789") != "" {
		return 0, ErrNotFound
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrNotFound
	}
	return n, nil
}

type LogEvent struct {
	TenantID, ID, Type                                 string
	Seq                                                int64
	Date                                               time.Time
	UserID, ClientID, ConnectionID, OrganizationID, IP string
	Body                                               []byte
}
type DailyStatDelta struct {
	TenantID                         string
	Day                              time.Time
	Logins, Signups, LeakedPasswords int
}
type DailyStat struct {
	Day                              time.Time
	Logins, Signups, LeakedPasswords int
	CreatedAt, UpdatedAt             time.Time
}
type LogPage struct {
	Page, PerPage            int
	Ascending, IncludeTotals bool
}

// LogQuery is the storage-owned Lucene subset AST. A nil or empty root matches
// all events. Binary and/or nodes have Left and Right; not has only Left.
// Leaves use eq (exact text), sw (trailing wildcard) or range (date or fixed-width log ID bounds).
// Empty range endpoints mean unbounded. Bare text leaves use an empty Field.
// Date values use RFC3339Nano. Field names are frozen by internal/logrules.
type LogQuery struct {
	Op, Field, Value, Upper        string
	Left, Right                    *LogQuery
	LowerExclusive, UpperExclusive bool
}

type LogStreamFilter struct{ Type, Name string }
type LogStreamPII struct {
	LogFields         []string
	Method, Algorithm string
}
type LogStream struct {
	TenantID, ID, Name, Type, Status string
	// Sink accepts JSON-serializable values; drivers may normalize typed values
	// to their JSON representation. Create/update reject invalid JSON as ErrInvalid.
	Sink          map[string]any
	SealedSecrets []byte
	Filters       []LogStreamFilter
	IsPriority    bool
	PII           *LogStreamPII
	// StartFrom is create-only. Reads for public API consumers omit this field.
	StartFrom                                       time.Time
	Checkpoint                                      int64
	LeaseOwner                                      string
	LeaseUntil, NextAt, FailingSince, LastSuccessAt time.Time
	Failures                                        int
	LastErrorClass                                  string
	Version                                         int
	CreatedAt, UpdatedAt                            time.Time
}
type LogStreamDelivery struct {
	Checkpoint                          int64
	Status                              string
	NextAt, FailingSince, LastSuccessAt time.Time
	Failures                            int
	LastErrorClass                      string
}

// Logs stores immutable scrubbed events, stream delivery state and daily stats.
// All returns and inputs are deeply copied. AppendLogs atomically assigns IDs
// and sequences and adds stat deltas. Checkpoint reads sort by sequence and
// exclude events committed after settled; page reads sort Date then Seq.
// SearchLogs defaults PerPage=50; pages must stay inside the first 1000 results.
// LatestLogs returns the newest take sequences in ascending sequence order.
// Updates retain create-only StartFrom and delivery state, invalidate any lease,
// and increment Version; stale admin versions return ErrConflict. Resuming from
// paused/suspended resets NextAt to now and clears failure backoff state. Delivery
// requires an unexpired lease held by owner (a unique acquisition token), else
// ErrPrecondition. Delivery clears its lease and never changes admin Version.
// Create defaults Checkpoint immediately before the earliest retained sequence
// with Date>=StartFrom; absent such an event (or StartFrom), it starts at latest.
type Logs interface {
	AppendLogs(context.Context, []LogEvent, []DailyStatDelta) error
	GetLog(context.Context, string, string) (*LogEvent, error)
	SearchLogs(context.Context, string, *LogQuery, LogPage) ([]LogEvent, int, error)
	LogsAfter(context.Context, string, int64, *LogQuery, int, time.Time) ([]LogEvent, error)
	LatestLogs(context.Context, string, *LogQuery, int, time.Time) ([]LogEvent, error)
	PurgeLogs(context.Context, time.Time, int) (int, error)
	DeleteTenantLogs(context.Context, string) error
	CreateLogStream(context.Context, *LogStream) error
	GetLogStream(context.Context, string, string) (*LogStream, error)
	ListLogStreams(context.Context, string) ([]LogStream, error)
	UpdateLogStream(context.Context, *LogStream, int) error
	DeleteLogStream(context.Context, string, string) error
	LeaseLogStream(context.Context, string, time.Time, time.Time) (*LogStream, error)
	RecordDelivery(context.Context, string, string, string, LogStreamDelivery) error
	DailyStats(context.Context, string, time.Time, time.Time) ([]DailyStat, error)
	ActiveUsers(context.Context, string, time.Time) (int, error)
}

// UnimplementedLogs lets older drivers fail closed until Logs v1 is available.
type UnimplementedLogs struct{}

func (UnimplementedLogs) AppendLogs(context.Context, []LogEvent, []DailyStatDelta) error {
	return ErrLogsUnavailable
}
func (UnimplementedLogs) GetLog(context.Context, string, string) (*LogEvent, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) SearchLogs(context.Context, string, *LogQuery, LogPage) ([]LogEvent, int, error) {
	return nil, 0, ErrLogsUnavailable
}
func (UnimplementedLogs) LogsAfter(context.Context, string, int64, *LogQuery, int, time.Time) ([]LogEvent, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) LatestLogs(context.Context, string, *LogQuery, int, time.Time) ([]LogEvent, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) PurgeLogs(context.Context, time.Time, int) (int, error) {
	return 0, ErrLogsUnavailable
}
func (UnimplementedLogs) DeleteTenantLogs(context.Context, string) error { return ErrLogsUnavailable }
func (UnimplementedLogs) CreateLogStream(context.Context, *LogStream) error {
	return ErrLogsUnavailable
}
func (UnimplementedLogs) GetLogStream(context.Context, string, string) (*LogStream, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) ListLogStreams(context.Context, string) ([]LogStream, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) UpdateLogStream(context.Context, *LogStream, int) error {
	return ErrLogsUnavailable
}
func (UnimplementedLogs) DeleteLogStream(context.Context, string, string) error {
	return ErrLogsUnavailable
}
func (UnimplementedLogs) LeaseLogStream(context.Context, string, time.Time, time.Time) (*LogStream, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) RecordDelivery(context.Context, string, string, string, LogStreamDelivery) error {
	return ErrLogsUnavailable
}
func (UnimplementedLogs) DailyStats(context.Context, string, time.Time, time.Time) ([]DailyStat, error) {
	return nil, ErrLogsUnavailable
}
func (UnimplementedLogs) ActiveUsers(context.Context, string, time.Time) (int, error) {
	return 0, ErrLogsUnavailable
}

// LogTimeLayout is the sortable full-range UTC timestamp encoding for SQL Logs.
const LogTimeLayout = "2006-01-02T15:04:05.000000000Z"

// ValidateLogTimes keeps all drivers within the full RFC3339 UTC year range.
// Conversion to UTC happens before validation because an offset near a year
// boundary can otherwise produce an unrepresentable stored timestamp.
func ValidateLogTimes(times ...time.Time) error {
	for _, t := range times {
		if year := t.UTC().Year(); year < 0 || year > 9999 {
			return ErrInvalid
		}
	}
	return nil
}
