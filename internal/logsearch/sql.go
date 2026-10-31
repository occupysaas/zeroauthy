package logsearch

import (
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SQL compiles validated inventory fields and binds every query value.
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
			key := strings.TrimPrefix(f.Column, "body.")
			switch dialect {
			case "postgres":
				doc := "COALESCE(NULLIF(convert_from(body,'UTF8'),''),'{}')::jsonb"
				v = "(CASE WHEN jsonb_typeof(" + doc + " -> '" + key + "')='string' THEN " + doc + " ->> '" + key + "' END)"
			case "mysql":
				doc := "COALESCE(NULLIF(CONVERT(body USING utf8mb4),''),'{}')"
				v = "(CASE WHEN json_type(json_extract(" + doc + ",'$." + key + "'))='STRING' THEN json_unquote(json_extract(" + doc + ",'$." + key + "')) END)"
			default:
				doc := "COALESCE(NULLIF(CAST(body AS TEXT),''),'{}')"
				v = "(CASE WHEN json_type(" + doc + ",'$." + key + "')='text' THEN json_extract(" + doc + ",'$." + key + "') END)"
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
			if n.Op == "eq" {
				terms = append(terms, v+"="+bind(n.Value))
				continue
			}
			pattern := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(n.Value) + "%"
			term := v + " LIKE " + bind(pattern) + " ESCAPE '!'"
			if dialect == "sqlite" {
				term = "(" + term + " AND substr(" + v + ",1,length(" + bind(n.Value) + "))=" + bind(n.Value) + ")"
			}
			terms = append(terms, term)
		}
		return "(" + strings.Join(terms, " OR ") + ")"
	}
	where := walk(q)
	return where, args, nil
}
