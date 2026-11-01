package logsearch

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SQL compiles validated inventory fields and binds every query value.
// JSON fields use the SQL store's ASCII-hex projection, avoiding dialect JSON
// Unicode/numeric restrictions while preserving Go string equality and prefixes.
// Predicates are two-valued so NOT also includes missing JSON fields.
func SQL(q *store.LogQuery, dialect string) (string, []any, error) {
	if Validate(q) != nil || dialect != "sqlite" && dialect != "postgres" && dialect != "mysql" {
		return "", nil, store.ErrInvalid
	}
	var args []any
	bind := func(v any) string { args = append(args, v); return "?" }
	expr := func(f logrules.Field) string {
		v := f.Column
		if f.Storage == "json-string" {
			key := f.Name
			switch dialect {
			case "postgres":
				v = "(searchable_body::jsonb ->> '" + key + "')"
			case "mysql":
				v = "json_unquote(json_extract(searchable_body,'$." + key + "'))"
			default:
				v = "json_extract(searchable_body,'$." + key + "')"
			}
			v = "COALESCE(" + v + ",'')"
		}
		switch dialect {
		case "postgres":
			return v + ` COLLATE "C"`
		case "mysql":
			return "CAST(" + v + " AS BINARY)"
		default:
			return v + " COLLATE BINARY"
		}
	}
	var walk func(*store.LogQuery) string
	walk = func(n *store.LogQuery) string {
		if n == nil || n.Op == "" {
			return "1=1"
		}
		switch n.Op {
		case "and", "or":
			return "(" + walk(n.Left) + " " + strings.ToUpper(n.Op) + " " + walk(n.Right) + ")"
		case "not":
			return "(NOT (" + walk(n.Left) + "))"
		}
		if n.Field == "date" {
			timestamp := func(v string) string {
				t, _ := time.Parse(time.RFC3339Nano, v)
				return bind(t.UTC().Format(store.LogTimeLayout))
			}
			if n.Op == "eq" {
				return "date=" + timestamp(n.Value)
			}
			var terms []string
			if n.Value != "" {
				op := ">="
				if n.LowerExclusive {
					op = ">"
				}
				terms = append(terms, "date"+op+timestamp(n.Value))
			}
			if n.Upper != "" {
				op := "<="
				if n.UpperExclusive {
					op = "<"
				}
				terms = append(terms, "date"+op+timestamp(n.Upper))
			}
			if len(terms) == 0 {
				return "1=1"
			}
			return "(" + strings.Join(terms, " AND ") + ")"
		}
		var terms []string
		for _, f := range logrules.Fields() {
			if f.Name != n.Field && !(n.Field == "" && f.Bare) {
				continue
			}
			v := expr(f)
			value := n.Value
			if f.Storage == "json-string" {
				value = hex.EncodeToString([]byte(value))
			}
			if n.Op == "range" {
				if n.Value != "" {
					op := ">="
					if n.LowerExclusive {
						op = ">"
					}
					terms = append(terms, v+op+bind(n.Value))
				}
				if n.Upper != "" {
					op := "<="
					if n.UpperExclusive {
						op = "<"
					}
					terms = append(terms, v+op+bind(n.Upper))
				}
				if len(terms) == 0 {
					return "1=1"
				}
				return "(" + strings.Join(terms, " AND ") + ")"
			}
			if n.Op == "eq" {
				terms = append(terms, v+"="+bind(value))
				continue
			}
			pattern := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value) + "%"
			term := v + " LIKE " + bind(pattern) + " ESCAPE '!'"
			if dialect == "sqlite" {
				term = "(" + term + " AND substr(" + v + ",1,length(" + bind(value) + "))=" + bind(value) + ")"
			}
			terms = append(terms, term)
		}
		return "(" + strings.Join(terms, " OR ") + ")"
	}
	where := walk(q)
	return where, args, nil
}
