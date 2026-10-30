package orgsearch

import (
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func Match(q store.OrganizationQuery, o store.Organization) bool {
	switch q.Op {
	case "":
		return true
	case "and":
		return Match(*q.Left, o) && Match(*q.Right, o)
	case "or":
		return Match(*q.Left, o) || Match(*q.Right, o)
	}
	var v string
	exists := true
	switch q.Field {
	case "id":
		v = o.ID
	case "name":
		v = o.Name
	case "display_name":
		v = o.DisplayName
	case "created_at":
		v = o.CreatedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	default:
		v, exists = o.Metadata[strings.TrimPrefix(q.Field, "metadata.")]
	}
	if q.Op == "pr" {
		return exists
	}
	if !exists {
		return false
	}
	cmp := func(b string) int {
		if q.Field == "created_at" {
			a, _ := time.Parse(time.RFC3339Nano, v)
			t, _ := time.Parse(time.RFC3339Nano, b)
			return a.Compare(t)
		}
		return strings.Compare(v, b)
	}
	switch q.Op {
	case "eq":
		return cmp(q.Value) == 0
	case "ne":
		return cmp(q.Value) != 0
	case "sw":
		return strings.HasPrefix(v, q.Value)
	case "ew":
		return strings.HasSuffix(v, q.Value)
	case "co":
		return strings.Contains(v, q.Value)
	case "gt":
		return cmp(q.Value) > 0
	case "ge":
		return cmp(q.Value) >= 0
	case "lt":
		return cmp(q.Value) < 0
	case "le":
		return cmp(q.Value) <= 0
	case "range":
		return (q.Value == "" || cmp(q.Value) > 0 || !q.LowerExclusive && cmp(q.Value) == 0) && (q.Upper == "" || cmp(q.Upper) < 0 || !q.UpperExclusive && cmp(q.Upper) == 0)
	}
	return false
}
