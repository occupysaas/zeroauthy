// Package usersearch parses Auth0's v3 user search syntax (the q parameter)
// and sort strings into the store's query tree. The rewrites it applies are
// logged as D-0043.
package usersearch

import (
	"regexp"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Error is a search or sort error carrying Auth0's message text. The handler
// answers it with 400. Code is empty for search errors (Auth0 sends no
// errorCode for them) and "invalid_query_string" for sort errors.
type Error struct {
	Message string
	Code    string
}

func (e *Error) Error() string { return e.Message }

// CodeInvalidQueryString is the Code of a sort error.
const CodeInvalidQueryString = "invalid_query_string"

// FieldInfo describes a searchable field.
type FieldInfo struct {
	Kind     store.ValueKind // root and identity fields; metadata takes the literal's kind
	Sortable bool
	// Prefix marks app_metadata and user_metadata, which are searched as
	// <name>.<key path>.
	Prefix bool
}

// Fields maps each searchable field to its description. Metadata appears as
// the two prefixes.
var Fields = buildFields()

func buildFields() map[string]FieldInfo {
	m := map[string]FieldInfo{}
	for _, name := range []string{
		"user_id", "email", "email_verified", "name", "given_name", "family_name", "nickname",
		"username", "phone_number", "phone_verified", "blocked", "created_at", "updated_at",
		"last_login", "logins_count", "last_ip",
	} {
		f, err := store.ParseUserField(name)
		if err != nil {
			panic(err)
		}
		m[name] = FieldInfo{Kind: f.Kind, Sortable: true}
	}
	for _, name := range []string{"identities.connection", "identities.provider", "identities.user_id"} {
		m[name] = FieldInfo{Kind: store.KindString}
	}
	m["app_metadata"] = FieldInfo{Prefix: true}
	m["user_metadata"] = FieldInfo{Prefix: true}
	return m
}

var sortPattern = regexp.MustCompile(`^(([a-zA-Z0-9_\.]+))\:(1|-1)$`)

// ParseSort parses a sort string "field:1" or "field:-1". An unknown field
// or a metadata field is ignored, as Auth0 does: the zero UserSort (the
// default order) is returned. An empty s is no sort.
func ParseSort(s string) (store.UserSort, error) {
	if s == "" {
		return store.UserSort{}, nil
	}
	m := sortPattern.FindStringSubmatch(s)
	if m == nil {
		return store.UserSort{}, &Error{
			Code: CodeInvalidQueryString,
			Message: `Query validation error: 'String does not match pattern ^(([a-zA-Z0-9_\\.]+))\:(1|-1)$: ` + s +
				`' on property sort (Field to sort by. Use <code>field:order</code> where order is <code>1</code> for ascending and <code>-1</code> for descending. e.g. <code>created_at:1</code>).`,
		}
	}
	if fi, ok := Fields[m[1]]; !ok || !fi.Sortable {
		return store.UserSort{}, nil
	}
	return store.UserSort{Field: m[1], Desc: m[3] == "-1"}, nil
}
