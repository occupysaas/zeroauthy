package sqlstore

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"reflect"
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

// nullBool encodes an optional bool: nil becomes SQL NULL.
func nullBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func fromNullBool(v sql.NullBool) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Bool
	return &b
}

// toJSON encodes v as JSON text; nil slices and maps become "null".
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fromJSON decodes JSON text into v; "" and "null" set *v to its zero value.
func fromJSON(s string, v any) error {
	if s == "" || s == "null" {
		reflect.ValueOf(v).Elem().SetZero()
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}

// jsonColumn reads and writes nullable JSON settings. Passing the field's
// address preserves the distinction between a missing and an empty object.
type jsonColumn struct{ field any }

func (j jsonColumn) Scan(src any) error {
	var raw sql.NullString
	if err := raw.Scan(src); err != nil {
		return err
	}
	return fromJSON(raw.String, j.field)
}

func (j jsonColumn) Value() (driver.Value, error) {
	return toJSON(j.field)
}
