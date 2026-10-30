package logsearch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestValidateQueryBounds(t *testing.T) {
	leaf := func() *store.LogQuery { return &store.LogQuery{Op: "eq", Field: "type", Value: "s"} }
	q := leaf()
	for range 5 {
		q = &store.LogQuery{Op: "or", Left: q, Right: leaf()}
	}
	for name, q := range map[string]*store.LogQuery{
		"six predicates":  q,
		"unknown field":   {Op: "eq", Field: "password", Value: "x"},
		"missing operand": {Op: "and", Left: leaf()},
		"not has right":   {Op: "not", Left: leaf(), Right: leaf()},
		"large":           {Op: "eq", Field: "type", Value: strings.Repeat("x", 1001)},
		"bad range":       {Op: "range", Field: "date", Value: "yesterday"},
		"string range":    {Op: "range", Field: "type", Value: "a", Upper: "z"},
		"unknown op":      {Op: "regex", Field: "type", Value: "s"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(q); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("Validate()=%v want ErrInvalid", err)
			}
		})
	}
	cyclic := &store.LogQuery{Op: "not"}
	cyclic.Left = cyclic
	if err := Validate(cyclic); !errors.Is(err, store.ErrInvalid) {
		t.Fatal("cycle accepted")
	}
}

func TestMatchLogQueries(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	event := store.LogEvent{ID: store.FormatLogID(1), Type: "s", Date: at, UserID: "auth0|u", IP: "192.0.2.1", Body: []byte(`{"description":"login completed","user_name":"Alice","hostname":"issuer.test"}`)}
	for name, tc := range map[string]struct {
		q    *store.LogQuery
		want bool
	}{
		"all": {nil, true}, "empty": {&store.LogQuery{}, true},
		"column":           {&store.LogQuery{Op: "eq", Field: "user_id", Value: "auth0|u"}, true},
		"body prefix":      {&store.LogQuery{Op: "sw", Field: "description", Value: "login"}, true},
		"bare":             {&store.LogQuery{Op: "eq", Value: "Alice"}, true},
		"nonbare hostname": {&store.LogQuery{Op: "eq", Value: "issuer.test"}, false},
		"date equal":       {&store.LogQuery{Op: "eq", Field: "date", Value: at.Format(time.RFC3339)}, true},
		"inclusive":        {&store.LogQuery{Op: "range", Field: "date", Value: at.Format(time.RFC3339), Upper: at.Format(time.RFC3339)}, true},
		"exclusive lower":  {&store.LogQuery{Op: "range", Field: "date", Value: at.Format(time.RFC3339), LowerExclusive: true}, false},
		"exclusive upper":  {&store.LogQuery{Op: "range", Field: "date", Upper: at.Format(time.RFC3339), UpperExclusive: true}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(tc.q); err != nil {
				t.Fatal(err)
			}
			if got := Match(tc.q, event); got != tc.want {
				t.Fatalf("Match()=%v want %v", got, tc.want)
			}
		})
	}
}
