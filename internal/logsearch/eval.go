// Package logsearch evaluates the storage-owned bounded log query language.
package logsearch

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Validate rejects malformed ASTs, including cycles through the depth limit.
// The parser and SQL compiler share these same bounds and field inventory.
func Validate(q *store.LogQuery) error {
	predicates, size := 0, 0
	var walk func(*store.LogQuery, int) bool
	walk = func(n *store.LogQuery, depth int) bool {
		if n == nil {
			return depth == 1
		}
		size += utf8.RuneCountInString(n.Field + n.Value + n.Upper)
		if depth > 16 || size > 1000 || !utf8.ValidString(n.Field+n.Value+n.Upper) || strings.ContainsRune(n.Field+n.Value+n.Upper, 0) {
			return false
		}
		branch := n.Field == "" && n.Value == "" && n.Upper == "" && !n.LowerExclusive && !n.UpperExclusive
		switch n.Op {
		case "":
			return depth == 1 && branch && n.Left == nil && n.Right == nil
		case "and", "or":
			return branch && n.Left != nil && n.Right != nil && walk(n.Left, depth+1) && walk(n.Right, depth+1)
		case "not":
			return branch && n.Left != nil && n.Right == nil && walk(n.Left, depth+1)
		}
		predicates++
		if predicates > 5 || n.Left != nil || n.Right != nil {
			return false
		}
		field, found := logrules.Field{}, false
		for _, f := range logrules.Fields() {
			if f.Name == n.Field {
				field = f
				found = true
				break
			}
		}
		if !found && n.Field != "" {
			return false
		}
		if n.Op == "range" {
			if field.Type != "date" {
				return false
			}
			for _, s := range []string{n.Value, n.Upper} {
				if s != "" {
					if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
						return false
					}
				}
			}
			return true
		}
		if n.Op != "eq" && n.Op != "sw" || n.Upper != "" || n.LowerExclusive || n.UpperExclusive {
			return false
		}
		if field.Type == "date" {
			_, err := time.Parse(time.RFC3339Nano, n.Value)
			return n.Op == "eq" && err == nil
		}
		return n.Value != ""
	}
	if !walk(q, 1) {
		return store.ErrInvalid
	}
	return nil
}

// Match evaluates a valid query. Unknown or malformed leaf operations fail closed;
// callers accepting external ASTs must Validate once before evaluating a batch.
func Match(q *store.LogQuery, e store.LogEvent) bool {
	if q == nil || q.Op == "" {
		return true
	}
	switch q.Op {
	case "and":
		return q.Left != nil && q.Right != nil && Match(q.Left, e) && Match(q.Right, e)
	case "or":
		return q.Left != nil && q.Right != nil && (Match(q.Left, e) || Match(q.Right, e))
	case "not":
		return q.Left != nil && q.Right == nil && !Match(q.Left, e)
	case "range":
		if q.Field != "date" {
			return false
		}
		if q.Value != "" {
			v, err := time.Parse(time.RFC3339Nano, q.Value)
			if err != nil || e.Date.Before(v) || q.LowerExclusive && e.Date.Equal(v) {
				return false
			}
		}
		if q.Upper != "" {
			v, err := time.Parse(time.RFC3339Nano, q.Upper)
			if err != nil || e.Date.After(v) || q.UpperExclusive && e.Date.Equal(v) {
				return false
			}
		}
		return true
	case "eq", "sw":
		if q.Field == "date" {
			v, err := time.Parse(time.RFC3339Nano, q.Value)
			return err == nil && q.Op == "eq" && e.Date.Equal(v)
		}
		matches := func(v string) bool {
			if q.Op == "sw" {
				return strings.HasPrefix(v, q.Value)
			}
			return v == q.Value
		}
		var body map[string]any
		_ = json.Unmarshal(e.Body, &body)
		value := func(field string) string {
			switch field {
			case "log_id":
				return e.ID
			case "type":
				return e.Type
			case "user_id":
				return e.UserID
			case "client_id":
				return e.ClientID
			case "connection_id":
				return e.ConnectionID
			case "organization_id":
				return e.OrganizationID
			case "ip":
				return e.IP
			}
			v, _ := body[field].(string)
			return v
		}
		for _, f := range logrules.Fields() {
			if f.Name == q.Field || q.Field == "" && f.Bare {
				if matches(value(f.Name)) {
					return true
				}
			}
		}
	}
	return false
}
