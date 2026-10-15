package sqlstore

import (
	"database/sql"
	"reflect"
	"testing"
	"time"
)

func TestMicrosRoundTrip(t *testing.T) {
	cases := map[string]time.Time{
		"utc":   time.Date(2026, 10, 14, 12, 30, 45, 123456000, time.UTC),
		"zone":  time.Date(2026, 10, 14, 12, 30, 45, 0, time.FixedZone("x", 3*3600)),
		"nanos": time.Date(2026, 10, 14, 12, 30, 45, 123456789, time.UTC),
	}
	for name, in := range cases {
		got := fromMicros(micros(in))
		want := in.Truncate(time.Microsecond).UTC()
		if !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
}

func TestMicrosZero(t *testing.T) {
	if micros(time.Time{}) != 0 || !fromMicros(0).IsZero() {
		t.Error("zero time must map to 0 and back")
	}
}

func TestNullMicros(t *testing.T) {
	if nullMicros(nil) != nil {
		t.Error("nullMicros(nil) must be nil")
	}
	if fromNullMicros(sql.NullInt64{}) != nil {
		t.Error("invalid NullInt64 must decode to nil")
	}
	now := time.UnixMicro(1_700_000_000_123_456).UTC()
	if v := nullMicros(&now); v != int64(1_700_000_000_123_456) {
		t.Errorf("nullMicros = %v", v)
	}
	if got := fromNullMicros(sql.NullInt64{Int64: 1_700_000_000_123_456, Valid: true}); got == nil || !got.Equal(now) {
		t.Errorf("fromNullMicros = %v", got)
	}
}

func TestJSON(t *testing.T) {
	var ns []string
	s, err := toJSON(ns)
	if err != nil || s != "null" {
		t.Fatalf("nil slice: %q %v", s, err)
	}
	back := []string{"stale"}
	if err := fromJSON(s, &back); err != nil {
		t.Fatal(err)
	}
	// "null" decodes to the zero value only when v starts zero; json.Unmarshal
	// of null into a slice sets it nil, but fromJSON skips it, so use a fresh var.
	var fresh []string
	if err := fromJSON(s, &fresh); err != nil || fresh != nil {
		t.Fatalf("nil slice round trip: %#v %v", fresh, err)
	}

	var nm map[string]string
	s, _ = toJSON(nm)
	var freshM map[string]string
	if err := fromJSON(s, &freshM); err != nil || s != "null" || freshM != nil {
		t.Fatalf("nil map round trip: %q %#v %v", s, freshM, err)
	}

	in := map[string]any{"a": []any{"x"}}
	s, _ = toJSON(in)
	var out map[string]any
	if err := fromJSON(s, &out); err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("map round trip: %#v %v", out, err)
	}
	if err := fromJSON("", &out); err != nil {
		t.Fatal(err)
	}
}
