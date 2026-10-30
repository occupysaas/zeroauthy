package orgsearch

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SQL returns a parameterized predicate for the SQL store's supported dialects.
// Column names come only from the validated AST. Metadata paths and all values
// remain bound arguments, including quotes, wildcard characters and backslashes.
func SQL(q store.OrganizationQuery, dialect string) (string, []any, error) {
	if Validate(q) != nil || dialect != "sqlite" && dialect != "postgres" && dialect != "mysql" {
		return "", nil, store.ErrInvalid
	}
	var args []any
	bind := func(v any) string { args = append(args, v); return "?" }
	var walk func(store.OrganizationQuery) string
	walk = func(n store.OrganizationQuery) string {
		if n.Op == "" {
			return "1=1"
		}
		if n.Op == "and" || n.Op == "or" {
			return "(" + walk(*n.Left) + " " + strings.ToUpper(n.Op) + " " + walk(*n.Right) + ")"
		}
		expr := func() string {
			f := n.Field
			if strings.HasPrefix(f, "metadata.") {
				key := f[9:]
				switch dialect {
				case "postgres":
					f = "(metadata::jsonb ->> " + bind(key) + ")"
				default:
					path, _ := json.Marshal(key)
					f = "json_extract(metadata," + bind("$."+string(path)) + ")"
					if dialect == "mysql" {
						f = "json_unquote(" + f + ")"
					}
				}
			}
			if n.Field != "created_at" {
				switch dialect {
				case "postgres":
					f += " COLLATE \"C\""
				case "mysql":
					f = "CAST(" + f + " AS BINARY)"
				default:
					f += " COLLATE BINARY"
				}
			}
			return f
		}
		val := func(v string) any {
			if n.Field == "created_at" {
				t, _ := time.Parse(time.RFC3339Nano, v)
				return t.UnixMicro()
			}
			return v
		}
		if n.Op == "pr" {
			return expr() + " IS NOT NULL"
		}
		if n.Field == "created_at" {
			temporal := func(op, v string) string {
				t, _ := time.Parse(time.RFC3339Nano, v)
				micro := t.UnixMicro()
				fraction := t.Nanosecond()%1000 != 0
				if fraction {
					switch op {
					case "=":
						return "0=1"
					case "<>":
						return "1=1"
					case ">=", "<":
						micro++
					}
				}
				return expr() + op + bind(micro)
			}
			if n.Op == "range" {
				var terms []string
				if n.Value != "" {
					op := ">="
					if n.LowerExclusive {
						op = ">"
					}
					terms = append(terms, temporal(op, n.Value))
				}
				if n.Upper != "" {
					op := "<="
					if n.UpperExclusive {
						op = "<"
					}
					terms = append(terms, temporal(op, n.Upper))
				}
				if len(terms) == 0 {
					return "1=1"
				}
				return "(" + strings.Join(terms, " AND ") + ")"
			}
			return temporal(map[string]string{"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[n.Op], n.Value)
		}

		switch n.Op {
		case "eq", "ne", "gt", "ge", "lt", "le":
			op := map[string]string{"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[n.Op]
			return expr() + " " + op + " " + bind(val(n.Value))
		case "range":
			var terms []string
			if n.Value != "" {
				op := ">="
				if n.LowerExclusive {
					op = ">"
				}
				terms = append(terms, expr()+op+bind(val(n.Value)))
			}
			if n.Upper != "" {
				op := "<="
				if n.UpperExclusive {
					op = "<"
				}
				terms = append(terms, expr()+op+bind(val(n.Upper)))
			}
			if len(terms) == 0 {
				return "1=1"
			}
			return "(" + strings.Join(terms, " AND ") + ")"
		default:
			pattern := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(n.Value)
			switch n.Op {
			case "sw":
				pattern += "%"
			case "ew":
				pattern = "%" + pattern
			case "co":
				pattern = "%" + pattern + "%"
			}
			like := expr() + " LIKE " + bind(pattern) + " ESCAPE '!'"
			// SQLite LIKE always folds ASCII; an exact substring check restores the
			// same case-sensitive semantics as byte comparisons and the other drivers.
			if dialect == "sqlite" {
				var exact string
				switch n.Op {
				case "co":
					exact = "instr(" + expr() + "," + bind(n.Value) + ")>0"
				case "sw":
					exact = "substr(" + expr() + ",1,length(" + bind(n.Value) + "))=" + bind(n.Value)
				case "ew":
					exact = "substr(" + expr() + ",-length(" + bind(n.Value) + "))=" + bind(n.Value)
				}
				like = "(" + like + " AND " + exact + ")"
			}
			return like
		}
	}
	s := walk(q)
	return s, args, nil
}
