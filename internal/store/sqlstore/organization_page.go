package sqlstore

import (
	"context"
	"database/sql/driver"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"modernc.org/sqlite"
)

func init() {
	// SQLite's built-in lower only handles ASCII. Legacy list collation is Go's
	// Unicode lowercasing on every driver, with punctuation removed for names.
	sqlite.MustRegisterDeterministicScalarFunction("za_org_lower", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		if args[0] == nil {
			return nil, nil
		}
		switch v := args[0].(type) {
		case string:
			return strings.ToLower(v), nil
		case []byte:
			return strings.ToLower(string(v)), nil
		}
		return "", nil
	})
}
func (r organizations) pageOrgs(ctx context.Context, p store.OrgPage, scope, where string, args ...any) (store.OrgResult[store.Organization], error) {
	out := store.OrgResult[store.Organization]{Items: []store.Organization{}}
	field, desc, err := orgrules.ParseSort(p.Sort)
	if err != nil {
		return out, store.ErrInvalid
	}
	mode, err := orgrules.NormalizePage(&p)
	if err != nil {
		return out, store.ErrInvalid
	}
	if field == "" {
		field = "name"
		if mode == orgrules.Checkpoint {
			field = "created_at"
		}
	}
	expression := field
	if field != "created_at" {
		col := field
		if r.s.d.name == "mysql" {
			col = "CAST(" + col + " AS CHAR CHARACTER SET utf8mb4)"
		}
		lower := "lower"
		if r.s.d.name == "sqlite" {
			lower = "za_org_lower"
		}
		expression = lower + "(" + col + ")"
		if field == "name" {
			expression = "replace(replace(" + expression + ",'-',''),'_','')"
		}
		expression += r.s.d.byteOrder
	}
	order, cmp := " ASC", ">"
	if desc {
		order, cmp = " DESC", "<"
	}
	query := `SELECT ` + orgCols + ` FROM organizations WHERE ` + where
	if mode == orgrules.Offset {
		if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE `+where, args...).Scan(&out.Total); err != nil {
			return out, err
		}
	} else if p.From != "" {
		c, e := orgrules.DecodeCursor(p.From, scope, p.Sort)
		if e != nil {
			return out, store.ErrInvalid
		}
		var key any = c.Key
		if field == "created_at" {
			n, e := strconv.ParseInt(c.Key, 10, 64)
			if e != nil {
				return out, store.ErrInvalid
			}
			key = n / 1000
		}
		query += ` AND (` + expression + cmp + `? OR (` + expression + `=? AND id` + r.s.d.byteOrder + cmp + `?))`
		args = append(args, key, key, c.ID)
	}
	query += ` ORDER BY ` + expression + order + `, id` + r.s.d.byteOrder + order
	if mode == orgrules.Offset {
		query += ` LIMIT ` + strconv.Itoa(p.PerPage) + ` OFFSET ` + strconv.Itoa(p.Page*p.PerPage)
	} else {
		query += ` LIMIT ` + strconv.Itoa(p.Take+1)
	}
	rows, e := r.queryOrgs(ctx, query, args...)
	if e != nil {
		return out, e
	}
	if mode == orgrules.Checkpoint && len(rows) > p.Take {
		rows = rows[:p.Take]
		last := rows[len(rows)-1]
		key := ""
		switch field {
		case "name":
			key = strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(last.Name))
		case "display_name":
			key = strings.ToLower(last.DisplayName)
		default:
			key = fmtOrgTime(last.CreatedAt)
		}
		out.Next = orgrules.EncodeCursor(orgrules.Cursor{Scope: scope, Sort: p.Sort, Key: key, ID: last.ID})
	}
	for _, o := range rows {
		out.Items = append(out.Items, *o)
	}
	return out, nil
}
func fmtOrgTime(t time.Time) string {
	s := strconv.FormatInt(t.UnixNano(), 10)
	if len(s) < 20 {
		s = strings.Repeat("0", 20-len(s)) + s
	}
	return s
}

// clientSummaries performs one bounded query for all rows on an organization page.
func (r organizations) clientSummaries(ctx context.Context, tid, client string, items []store.Organization) error {
	if len(items) == 0 {
		return nil
	}
	args := []any{tid, client}
	marks := make([]string, len(items))
	byID := map[string]int{}
	for i, o := range items {
		items[i].ClientAssociationLoaded = true
		args = append(args, o.ID)
		marks[i] = "?"
		byID[o.ID] = i
	}
	rows, err := r.s.query(ctx, `SELECT organization_id,use_for_member_access FROM organization_clients WHERE tenant_id=? AND client_id=? AND organization_id IN (`+strings.Join(marks, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var use bool
		if err = rows.Scan(&id, &use); err != nil {
			return err
		}
		i := byID[id]
		items[i].ClientAssociation = &store.OrganizationClient{TenantID: tid, OrganizationID: id, ClientID: client, UseForMemberAccess: use}
	}
	return rows.Err()
}

// connectionSummaries batches the page's live connection names and strategies.
func (r organizations) connectionSummaries(ctx context.Context, tid string, items []store.OrganizationConnection) error {
	if len(items) == 0 {
		return nil
	}
	args := []any{tid}
	marks := make([]string, len(items))
	byID := map[string]int{}
	for i, o := range items {
		args = append(args, o.ConnectionID)
		marks[i] = "?"
		byID[o.ConnectionID] = i
	}
	rows, err := r.s.query(ctx, `SELECT id,name,strategy FROM connections WHERE tenant_id=? AND id IN (`+strings.Join(marks, ",")+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, strategy string
		if err = rows.Scan(&id, &name, &strategy); err != nil {
			return err
		}
		i := byID[id]
		items[i].SummaryName = name
		items[i].SummaryStrategy = strategy
	}
	return rows.Err()
}
