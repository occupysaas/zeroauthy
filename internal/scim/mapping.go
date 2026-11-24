package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// DefaultMapping is the mapping of a new SCIM configuration (LR37c-6): the
// RFC 7643 core attributes of the user profile, and the enterprise
// department in app_metadata. Auth0 shows its default only in its
// Dashboard.
func DefaultMapping() []store.SCIMMapping {
	return []store.SCIMMapping{
		{Auth0: "email", SCIM: "emails[primary eq true].value"},
		{Auth0: "name", SCIM: "displayName"},
		{Auth0: "given_name", SCIM: "name.givenName"},
		{Auth0: "family_name", SCIM: "name.familyName"},
		{Auth0: "nickname", SCIM: "userName"},
		{Auth0: "app_metadata.department", SCIM: EnterpriseUser + ":department"},
	}
}

// DefaultUserIDAttribute is the SCIM attribute that names the user: its
// value is the identity subject a later login presents (Okta and OpenID
// IdPs send it as externalId).
const DefaultUserIDAttribute = "externalId"

// rootFields are the Auth0 root profile fields a mapping may write.
var rootFields = map[string]bool{"email": true, "email_verified": true, "name": true, "given_name": true, "family_name": true,
	"nickname": true, "picture": true, "username": true}

// reserved SCIM attributes that cannot be mapped (Auth0: id and meta;
// password is unusable; active is the inverse of blocked).
var reserved = map[string]bool{"id": true, "meta": true, "password": true, "active": true, "schemas": true, "groups": true}

// entry is one parsed mapping item.
type entry struct {
	auth0 string
	meta  string   // "app_metadata" or "user_metadata"; "" for a root field
	keys  []string // metadata key path
	path  Path
}

// Mapping is a validated SCIM configuration mapping.
type Mapping []entry

// ParseMapping validates a mapping: known Auth0 fields, valid SCIM paths
// outside the reserved attributes, one-to-one.
func ParseMapping(items []store.SCIMMapping) (Mapping, error) {
	if len(items) > 100 {
		return nil, errors.New("mapping has more than 100 entries")
	}
	var out Mapping
	seenA, seenS := map[string]bool{}, map[string]bool{}
	for _, it := range items {
		e := entry{auth0: it.Auth0}
		switch {
		case rootFields[it.Auth0]:
		case strings.HasPrefix(it.Auth0, "app_metadata.") || strings.HasPrefix(it.Auth0, "user_metadata."):
			e.meta, _, _ = strings.Cut(it.Auth0, ".")
			e.keys = strings.Split(strings.TrimPrefix(it.Auth0, e.meta+"."), ".")
			for _, k := range e.keys {
				if k == "" || len(k) > 64 {
					return nil, fmt.Errorf("mapping: invalid Auth0 attribute %q", it.Auth0)
				}
			}
		default:
			return nil, fmt.Errorf("mapping: %q is not a mappable Auth0 attribute", it.Auth0)
		}
		p, err := ParsePath(it.SCIM)
		if err != nil {
			return nil, fmt.Errorf("mapping: invalid SCIM attribute %q", it.SCIM)
		}
		if p.URN == "" && reserved[strings.ToLower(p.Attr)] {
			return nil, fmt.Errorf("mapping: SCIM attribute %q cannot be mapped", it.SCIM)
		}
		if p.Filter != nil && p.Sub == "" {
			return nil, fmt.Errorf("mapping: a filtered SCIM attribute needs a sub-attribute: %q", it.SCIM)
		}
		e.path = p
		ka, ks := strings.ToLower(it.Auth0), strings.ToLower(p.String())
		if seenA[ka] || seenS[ks] {
			return nil, fmt.Errorf("mapping: %q is mapped twice", it.SCIM)
		}
		seenA[ka], seenS[ks] = true, true
		out = append(out, e)
	}
	return out, nil
}

// lookup finds a key case-insensitively (SCIM attribute names are).
func lookup(m map[string]any, k string) (any, bool) {
	if v, ok := m[k]; ok {
		return v, true
	}
	for key, v := range m {
		if strings.EqualFold(key, k) {
			return v, true
		}
	}
	return nil, false
}

func equalValue(a, b any) bool {
	if as, ok := a.(string); ok {
		if bs, ok := b.(string); ok {
			return strings.EqualFold(as, bs)
		}
	}
	if ab, ok := a.(bool); ok {
		if bs, ok := b.(string); ok { // Entra sends "True"/"False"
			return strings.EqualFold(bs, fmt.Sprint(ab))
		}
	}
	return a == b
}

// container returns the object holding p's attribute.
func container(res map[string]any, p Path, create bool) map[string]any {
	if p.URN == "" {
		return res
	}
	v, _ := lookup(res, p.URN)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if !create {
		return nil
	}
	m := map[string]any{}
	res[p.URN] = m
	return m
}

// Get reads p from a resource; missing means absent. A filter matches the
// first element whose sub-attribute equals the value; with none, a lone
// element is taken for "primary eq true".
func Get(res map[string]any, p Path) (any, bool) {
	c := container(res, p, false)
	if c == nil {
		return nil, false
	}
	v, ok := lookup(c, p.Attr)
	if !ok || v == nil {
		return nil, false
	}
	if p.Filter != nil {
		list, ok := v.([]any)
		if !ok {
			return nil, false
		}
		var hit map[string]any
		for _, el := range list {
			m, ok := el.(map[string]any)
			if !ok {
				continue
			}
			if fv, ok := lookup(m, p.Filter.Path); ok && equalValue(p.Filter.Value, fv) {
				hit = m
				break
			}
		}
		if hit == nil && strings.EqualFold(p.Filter.Path, "primary") && p.Filter.Value == true && len(list) == 1 {
			hit, _ = list[0].(map[string]any)
		}
		if hit == nil {
			return nil, false
		}
		v, ok = lookup(hit, p.Sub)
		return v, ok && v != nil
	}
	if p.Sub != "" {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = lookup(m, p.Sub)
		return v, ok && v != nil
	}
	return v, true
}

// Set writes v at p, creating containers and filtered elements.
func Set(res map[string]any, p Path, v any) {
	c := container(res, p, true)
	switch {
	case p.Filter != nil:
		list, _ := c[p.Attr].([]any)
		for _, el := range list {
			if m, ok := el.(map[string]any); ok {
				if fv, ok := lookup(m, p.Filter.Path); ok && equalValue(p.Filter.Value, fv) {
					m[p.Sub] = v
					return
				}
			}
		}
		c[p.Attr] = append(list, map[string]any{p.Filter.Path: p.Filter.Value, p.Sub: v})
	case p.Sub != "":
		m, ok := c[p.Attr].(map[string]any)
		if !ok {
			m = map[string]any{}
			c[p.Attr] = m
		}
		m[p.Sub] = v
	default:
		c[p.Attr] = v
	}
}

func rootValue(u *store.User, f string) any {
	switch f {
	case "email":
		return u.Email
	case "email_verified":
		return u.EmailVerified
	case "name":
		return u.Name
	case "given_name":
		return u.GivenName
	case "family_name":
		return u.FamilyName
	case "nickname":
		return u.Nickname
	case "picture":
		return u.Picture
	case "username":
		return u.Username
	}
	return nil
}

func metaMap(u *store.User, which string) *map[string]any {
	if which == "app_metadata" {
		return &u.AppMetadata
	}
	return &u.UserMetadata
}

func metaGet(m map[string]any, keys []string) (any, bool) {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[k]; !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

func metaSet(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	if v == nil {
		delete(m, keys[len(keys)-1])
		return
	}
	m[keys[len(keys)-1]] = v
}

// Render writes the mapped profile fields into a new resource object.
func (m Mapping) Render(u *store.User) map[string]any {
	res := map[string]any{}
	for _, e := range m {
		var v any
		var ok bool
		if e.meta == "" {
			v = rootValue(u, e.auth0)
			ok = v != "" && v != nil && !(e.auth0 == "email_verified" && v == false)
		} else {
			v, ok = metaGet(*metaMap(u, e.meta), e.keys)
		}
		if ok {
			Set(res, e.path, v)
		}
	}
	return res
}

// Apply sets every mapped field of u from res; an absent attribute clears
// its field. Root values are checked as provider profile fields and
// metadata with the Management API's limits.
func (m Mapping) Apply(res map[string]any, u *store.User) error {
	root := map[string]any{"user_id": "scim"}
	for _, e := range m {
		v, ok := Get(res, e.path)
		if e.meta != "" {
			mm := metaMap(u, e.meta)
			if *mm == nil {
				*mm = map[string]any{}
			}
			if !ok {
				v = nil
			}
			metaSet(*mm, e.keys, v)
			continue
		}
		if ok {
			root[e.auth0] = v
		}
	}
	raw, _ := json.Marshal(root)
	p, err := federation.NormalizeProfile(raw)
	if err != nil {
		return err
	}
	for _, e := range m {
		if e.meta != "" {
			continue
		}
		str := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		switch e.auth0 {
		case "email":
			if next := str(p.Email); next != u.Email {
				u.Email, u.EmailVerified = next, false
			}
		case "email_verified":
			u.EmailVerified = p.EmailVerified != nil && *p.EmailVerified
		case "name":
			u.Name = str(p.Name)
		case "given_name":
			u.GivenName = str(p.GivenName)
		case "family_name":
			u.FamilyName = str(p.FamilyName)
		case "nickname":
			u.Nickname = str(p.Nickname)
		case "picture":
			u.Picture = str(p.Picture)
		case "username":
			u.Username = strings.ToLower(str(p.Username))
		}
	}
	for _, which := range []string{"app_metadata", "user_metadata"} {
		if mm := *metaMap(u, which); mm != nil {
			if err := userrules.CheckMetadata(which, mm); err != nil {
				return err
			}
		}
	}
	return nil
}

// Find returns the mapping entry for a SCIM attribute path, ignoring any
// value filter (filters name attributes by base and sub-attribute).
func (m Mapping) Find(p Path) (entry, bool) {
	for _, e := range m {
		if strings.EqualFold(e.path.URN, p.URN) && strings.EqualFold(e.path.Attr, p.Attr) && strings.EqualFold(e.path.Sub, p.Sub) {
			return e, true
		}
	}
	return entry{}, false
}
