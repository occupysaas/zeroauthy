package sqlstore

import (
	"database/sql"
	"encoding/json"
	"time"
)

// micros encodes t as microseconds since the Unix epoch; the zero time is 0.
func micros(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

// fromMicros decodes micros; 0 is the zero time, anything else is UTC.
func fromMicros(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

// nullMicros encodes an optional time: nil becomes SQL NULL.
func nullMicros(t *time.Time) any {
	if t == nil {
		return nil
	}
	return micros(*t)
}

func fromNullMicros(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMicros(v.Int64)
	return &t
}

// toJSON encodes v as JSON text; nil slices and maps become "null".
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fromJSON decodes JSON text into v; "" and "null" leave v at its zero value.
func fromJSON(s string, v any) error {
	if s == "" || s == "null" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}
