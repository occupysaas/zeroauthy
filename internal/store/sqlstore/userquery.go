package sqlstore

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"
	"strconv"
	"strings"

	"modernc.org/sqlite"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// za_lower is SQLite's case fold for user search. SQLite's own lower() folds
// ASCII only; this one is Go's strings.ToLower, as the memory store uses, so
// "Émilie" matches "émilie" on every driver.
func init() {
	sqlite.MustRegisterDeterministicScalarFunction("za_lower", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		switch v := args[0].(type) {
		case string:
			return strings.ToLower(v), nil
		case []byte:
			return strings.ToLower(string(v)), nil
		}
		return args[0], nil
	})
}

// identityKeys are the JSON keys of store.Identity in the identities column.
var identityKeys = map[string]string{"connection": "Connection", "provider": "Provider", "user_id": "UserID"}

// queryBuilder translates a store.UserQuery into a WHERE condition over the
// users table, with the semantics documented on store.UserQuery. Every leaf
// is wrapped so it is strictly true or false, never NULL, which keeps NOT a
// plain negation. Values are always bound as arguments.
type queryBuilder struct {
	d    dialect
	args []any
}

func (b *queryBuilder) arg(v any) string {
	b.args = append(b.args, v)
	return "?"
}

func (b *queryBuilder) lower(expr string) string {
	if b.d.name == "sqlite" {
		return "za_lower(" + expr + ")"
	}
	return "LOWER(" + expr + ")"
}

// leaf wraps a condition that may be NULL into a strict boolean.
func leaf(cond string) string { return "(CASE WHEN " + cond + " THEN 1 ELSE 0 END = 1)" }

const never = "(1 = 0)"

func (b *queryBuilder) build(q *store.UserQuery) (string, error) {
	switch q.Op {
	case store.QueryAll:
		return "(1 = 1)", nil
	case store.QueryAnd, store.QueryOr:
		sep := " AND "
		if q.Op == store.QueryOr {
			sep = " OR "
		}
		parts := make([]string, 0, len(q.Kids))
		for _, k := range q.Kids {
			p, err := b.build(k)
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		}
		return "(" + strings.Join(parts, sep) + ")", nil
	case store.QueryNot:
		p, err := b.build(q.Kids[0])
		if err != nil {
			return "", err
		}
		return "(NOT " + p + ")", nil
	}
	f, err := store.ParseUserField(q.Field)
	if err != nil {
		return "", err
	}
	switch f.Class {
	case store.FieldIdentity:
		return b.identity(q, f)
	case store.FieldMetadata:
		return b.metadata(q, f)
	}
	col := "users." + f.Name
	switch f.Kind {
	case store.KindString:
		switch q.Op {
		case store.QueryExists:
			return leaf(col + " <> ''"), nil
		case store.QueryRange:
			if f.Name != "user_id" {
				return "", fmt.Errorf("sqlstore: range is not supported on %q", q.Field)
			}
			expr := b.lower(col) + b.d.byteOrder
			var conds []string
			if q.Lo != nil {
				op := " > "
				if q.LoIncl {
					op = " >= "
				}
				conds = append(conds, expr+op+b.arg(strings.ToLower(*q.Lo)))
			}
			if q.Hi != nil {
				op := " < "
				if q.HiIncl {
					op = " <= "
				}
				conds = append(conds, expr+op+b.arg(strings.ToLower(*q.Hi)))
			}
			if len(conds) == 0 {
				conds = append(conds, col+" <> ''")
			}
			return leaf(strings.Join(conds, " AND ")), nil
		case store.QueryWildcard:
			return leaf(col + " <> '' AND " + b.lower(col) + " LIKE " + b.arg(likePattern(q.Value)) + " ESCAPE '!'"), nil
		}
		if q.Value == "" {
			return never, nil
		}
		return leaf(b.lower(col) + " = " + b.arg(strings.ToLower(q.Value))), nil
	case store.KindBool:
		if q.Op == store.QueryExists {
			return "(1 = 1)", nil
		}
		return leaf(col + " = " + b.arg(q.Value == "true")), nil
	}
	if q.Op == store.QueryExists {
		if f.Name == "last_login" {
			return leaf(col + " IS NOT NULL"), nil
		}
		return "(1 = 1)", nil
	}
	lo, hi, err := q.IntBounds()
	if err != nil {
		return "", err
	}
	if lo > hi {
		return never, nil
	}
	// On PostgreSQL the cast binds the bounds as BIGINT; logins_count is an
	// INTEGER column, and a bound may not fit.
	expr := col
	if b.d.name == "postgres" {
		expr = "CAST(" + col + " AS BIGINT)"
	}
	var conds []string
	if lo != math.MinInt64 {
		conds = append(conds, expr+" >= "+b.arg(lo))
	}
	if hi != math.MaxInt64 {
		conds = append(conds, expr+" <= "+b.arg(hi))
	}
	if len(conds) == 0 {
		conds = append(conds, col+" IS NOT NULL")
	}
	return leaf(strings.Join(conds, " AND ")), nil
}

// likePattern turns a glob into a LIKE pattern with '!' as the escape
// character, so %, _ and ! in the pieces are literal.
func likePattern(glob string) string {
	esc := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")
	pieces := store.GlobPieces(glob)
	for i, p := range pieces {
		pieces[i] = esc.Replace(strings.ToLower(p))
	}
	return strings.Join(pieces, "%")
}

func (b *queryBuilder) identity(q *store.UserQuery, f store.UserField) (string, error) {
	key := identityKeys[f.Name]
	var elem, from string
	switch b.d.name {
	case "sqlite":
		elem = "json_extract(i.value, '$." + key + "')"
		from = "json_each(users.identities) AS i"
	case "postgres":
		elem = "(i.v ->> '" + key + "')"
		from = "jsonb_array_elements(CASE WHEN jsonb_typeof(CAST(users.identities AS jsonb)) = 'array' " +
			"THEN CAST(users.identities AS jsonb) ELSE CAST('[]' AS jsonb) END) AS i(v)"
	default:
		elem = "i.v"
		from = "JSON_TABLE(CASE WHEN JSON_TYPE(users.identities) = 'ARRAY' THEN users.identities ELSE '[]' END, " +
			"'$[*]' COLUMNS (v VARCHAR(1024) PATH '$." + key + "')) AS i"
	}
	var cond string
	if q.Op == store.QueryExists {
		cond = "COALESCE(" + elem + ", '') <> ''"
	} else {
		if q.Value == "" {
			return never, nil
		}
		l := b.lower(elem)
		if b.d.name == "mysql" {
			l += " COLLATE utf8mb4_0900_bin" // JSON_TABLE columns default to an accent-insensitive collation
		}
		cond = l + " = " + b.arg(strings.ToLower(q.Value))
	}
	return leaf("EXISTS (SELECT 1 FROM " + from + " WHERE " + cond + ")"), nil
}

// metadata translates a term or exists on app_metadata/user_metadata. A
// term matches a scalar of the same JSON type and value, or an element of
// an array at the path.
func (b *queryBuilder) metadata(q *store.UserQuery, f store.UserField) (string, error) {
	col := "users." + f.Name
	var lit string
	if q.Op == store.QueryTerm {
		var err error
		if lit, err = q.MetadataJSON(); err != nil {
			return "", err
		}
	}
	switch b.d.name {
	case "sqlite":
		path := jsonPath(f.Path)
		if q.Op == store.QueryExists {
			return leaf("json_type(" + col + ", " + b.arg(path) + ") <> 'null'"), nil
		}
		var typ string
		var val any
		switch q.Kind {
		case store.KindString:
			typ, val = "m.type = 'text'", q.Value
		case store.KindBool:
			typ = "m.type = 'false'"
			if q.Value == "true" {
				typ = "m.type = 'true'"
			}
		default:
			n, _ := store.ParseQueryNumber(q.Value)
			typ, val = "m.type IN ('integer', 'real')", n
		}
		// Arguments bind in the order the calls appear, left to right.
		cond := "json_type(" + col + ", " + b.arg(path) + ") <> 'object' AND EXISTS (SELECT 1 FROM json_each(" + col + ", " +
			b.arg(path) + ") AS m WHERE " + typ
		if val != nil {
			cond += " AND m.atom = " + b.arg(val)
		}
		return leaf(cond + ")"), nil
	case "postgres":
		x := func() string {
			e := "CAST(" + col + " AS jsonb)"
			for _, k := range f.Path {
				e += " -> CAST(" + b.arg(k) + " AS text)"
			}
			return "(" + e + ")"
		}
		if q.Op == store.QueryExists {
			return leaf("jsonb_typeof(" + x() + ") <> 'null'"), nil
		}
		return leaf("EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(" + x() + ") = 'array' THEN " + x() +
			" ELSE jsonb_build_array(" + x() + ") END) AS m(v) WHERE m.v = CAST(" + b.arg(lit) + " AS jsonb))"), nil
	}
	x := func() string { return "JSON_EXTRACT(" + col + ", " + b.arg(jsonPath(f.Path)) + ")" }
	if q.Op == store.QueryExists {
		return leaf("JSON_TYPE(" + x() + ") <> 'NULL'"), nil
	}
	return leaf("CASE WHEN JSON_TYPE(" + x() + ") = 'ARRAY' THEN CAST(" + b.arg(lit) + " AS JSON) MEMBER OF (" + x() +
		") ELSE " + x() + " = CAST(" + b.arg(lit) + " AS JSON) END"), nil
}

// jsonPath is a SQLite/MySQL JSON path with every key quoted. Keys never
// hold '"' or '\' (store.ParseUserField refuses them).
func jsonPath(keys []string) string {
	var sb strings.Builder
	sb.WriteString("$")
	for _, k := range keys {
		sb.WriteString(`."` + k + `"`)
	}
	return sb.String()
}

// orderBy is the ORDER BY clause for s, ties on user_id in byte order.
func (b *queryBuilder) orderBy(s store.UserSort) string {
	s = s.Effective()
	dir := " ASC"
	if s.Desc {
		dir = " DESC"
	}
	col := "users." + s.Field
	f, _ := store.ParseUserField(s.Field)
	var keys []string
	switch {
	case f.Kind == store.KindString:
		keys = []string{b.lower(col) + b.d.byteOrder + dir}
	case s.Field == "last_login":
		keys = []string{"CASE WHEN " + col + " IS NULL THEN 0 ELSE 1 END" + dir, col + dir}
	default:
		keys = []string{col + dir}
	}
	keys = append(keys, "users.user_id"+b.d.byteOrder+" ASC")
	return " ORDER BY " + strings.Join(keys, ", ")
}

func (r users) List(ctx context.Context, tenantID string, q *store.UserQuery, s store.UserSort, p store.Page) ([]*store.User, int, error) {
	if err := q.Validate(); err != nil {
		return nil, 0, err
	}
	if err := s.Validate(); err != nil {
		return nil, 0, err
	}
	b := &queryBuilder{d: r.s.d}
	where := "users.tenant_id = " + b.arg(tenantID)
	if q != nil {
		cond, err := b.build(q)
		if err != nil {
			return nil, 0, err
		}
		where += " AND " + cond
	}
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM users WHERE `+where, b.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("sqlstore: count users: %w", err)
	}
	// Offset and limit are integers built here, never caller text.
	limit, offset := int64(p.Limit), int64(max(p.Offset, 0))
	if limit <= 0 {
		limit = math.MaxInt64
	}
	sqlText := `SELECT ` + userCols + ` FROM users WHERE ` + where + b.orderBy(s) +
		` LIMIT ` + strconv.FormatInt(limit, 10) + ` OFFSET ` + strconv.FormatInt(offset, 10)
	rows, err := r.s.query(ctx, sqlText, b.args...)
	if err != nil {
		return nil, 0, fmt.Errorf("sqlstore: list users: %w", err)
	}
	defer rows.Close()
	var out []*store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}
