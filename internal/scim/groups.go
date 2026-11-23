package scim

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const base58 = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

// NewGroupID is grp_ and 20 base58 characters (Auth0's format: 14–22).
func NewGroupID() string {
	b := make([]byte, 20)
	n := big.NewInt(int64(len(base58)))
	for i := range b {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic(err)
		}
		b[i] = base58[v.Int64()]
	}
	return "grp_" + string(b)
}

// ValidGroupName is Auth0's group name rule: 1–128 printable ASCII.
func ValidGroupName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// groupInput is a parsed Group resource.
type groupInput struct {
	name, externalID string
	members          []string
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// readGroup parses a Group resource; members must be users of the
// connection (Auth0 supports only user members).
func (h *Handler) readGroup(r *http.Request, c *call, tx store.Store, res map[string]any) (groupInput, error) {
	var in groupInput
	name, _ := lookup(res, "displayName")
	s, ok := name.(string)
	if !ok || !ValidGroupName(s) {
		return in, errorf(http.StatusBadRequest, "invalidValue", "displayName must be 1 to 128 printable ASCII characters.")
	}
	in.name = s
	if v, ok := lookup(res, "externalId"); ok && v != nil {
		ext, isStr := v.(string)
		if !isStr || len(ext) > 256 {
			return in, errorf(http.StatusBadRequest, "invalidValue", "externalId must be a string of at most 256 characters.")
		}
		in.externalID = ext
	}
	v, _ := lookup(res, "members")
	list, ok := v.([]any)
	if v != nil && !ok {
		return in, errorf(http.StatusBadRequest, "invalidValue", "members must be an array.")
	}
	seen := map[string]bool{}
	for _, el := range list {
		m, _ := el.(map[string]any)
		if t, ok := lookup(m, "type"); ok && t != nil && !strings.EqualFold(asString(t), "User") {
			return in, errorf(http.StatusBadRequest, "invalidValue", "Only user members are supported.")
		}
		id, ok := valueKey(el)
		if !ok || id == "" {
			return in, errorf(http.StatusBadRequest, "invalidValue", "Each member needs a value.")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		u, err := tx.Users().Get(r.Context(), c.tenant.ID, id)
		if errors.Is(err, store.ErrNotFound) || err == nil && c.subjectOf(u) == "" {
			return in, errorf(http.StatusBadRequest, "invalidValue", "Members must be users of this connection.")
		}
		if err != nil {
			return in, err
		}
		in.members = append(in.members, id)
	}
	return in, nil
}

func (c *call) groupResource(g *store.Group, members []store.GroupMember, withMembers bool) map[string]any {
	res := map[string]any{"schemas": []string{CoreGroup}, "id": g.ID, "displayName": g.Name,
		"meta": meta("Group", c.base()+"/Groups/"+g.ID, g.CreatedAt, g.UpdatedAt)}
	if g.ExternalID != "" {
		res["externalId"] = g.ExternalID
	}
	if withMembers {
		list := []any{}
		for _, m := range members {
			list = append(list, map[string]any{"value": m.UserID, "type": "User", "$ref": c.base() + "/Users/" + m.UserID})
		}
		res["members"] = list
	}
	return res
}

func excludesMembers(r *http.Request) bool {
	for _, a := range strings.Split(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), "members") {
			return true
		}
	}
	return false
}

func (h *Handler) loadGroup(r *http.Request, c *call, tx store.Store) (*store.Group, error) {
	g, err := tx.Directory().GetGroup(r.Context(), c.tenant.ID, chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && g.ConnectionID != c.conn.ID {
		return nil, errNotFound
	}
	return g, err
}

func (h *Handler) groupMembers(r *http.Request, c *call, g *store.Group) ([]store.GroupMember, error) {
	ms, _, err := h.Store.Directory().ListGroupMembers(r.Context(), c.tenant.ID, g.ID, store.Page{})
	return ms, err
}

func (h *Handler) writeGroup(w http.ResponseWriter, r *http.Request, c *call, status int, g *store.Group) error {
	with := !excludesMembers(r)
	var ms []store.GroupMember
	if with {
		var err error
		if ms, err = h.groupMembers(r, c, g); err != nil {
			return err
		}
	}
	writeJSON(w, status, c.groupResource(g, ms, with))
	return nil
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, c *call) error {
	g, err := h.loadGroup(r, c, h.Store)
	if err != nil {
		return err
	}
	return h.writeGroup(w, r, c, http.StatusOK, g)
}

// groupFilter translates eq filters on displayName, externalId or id
// (joined with and).
func groupFilter(f *Filter, out *store.GroupFilter) error {
	unsupported := errorf(http.StatusBadRequest, "invalidFilter", "Groups support eq on displayName, externalId or id.")
	if f.Op == OpAnd {
		if err := groupFilter(f.Left, out); err != nil {
			return err
		}
		return groupFilter(f.Right, out)
	}
	p := f.Attr()
	v, ok := f.Value.(string)
	if f.Op != OpEq || !ok || p.URN != "" || p.Sub != "" || p.Filter != nil {
		return unsupported
	}
	switch strings.ToLower(p.Attr) {
	case "displayname":
		out.Name = v
	case "externalid":
		out.ExternalID = v
	case "id":
		out.IDs = []string{v}
	default:
		return unsupported
	}
	return nil
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, c *call) error {
	start, count, err := page(r)
	if err != nil {
		return err
	}
	f := store.GroupFilter{ConnectionID: c.conn.ID}
	if raw := r.URL.Query().Get("filter"); raw != "" {
		flt, err := ParseFilter(raw)
		if err != nil {
			return errorf(http.StatusBadRequest, "invalidFilter", "The filter is not valid or uses an unsupported operator.")
		}
		if err := groupFilter(flt, &f); err != nil {
			return err
		}
	}
	limit := count
	if limit == 0 {
		limit = 1
	}
	groups, total, err := h.Store.Directory().ListGroups(r.Context(), c.tenant.ID, f, store.Page{Offset: start - 1, Limit: limit})
	if err != nil {
		return err
	}
	with := !excludesMembers(r)
	var out []any
	if count > 0 {
		for _, g := range groups {
			var ms []store.GroupMember
			if with {
				if ms, err = h.groupMembers(r, c, g); err != nil {
					return err
				}
			}
			out = append(out, c.groupResource(g, ms, with))
		}
	}
	writeJSON(w, http.StatusOK, listResponse(total, start, out))
	return nil
}

var errGroupName = errorf(http.StatusConflict, "uniqueness", "A group with this displayName already exists on the connection.")

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, c *call) error {
	var res map[string]any
	if err := readBody(r, &res); err != nil {
		return err
	}
	now := h.now()
	g := &store.Group{TenantID: c.tenant.ID, ID: NewGroupID(), ConnectionID: c.conn.ID, CreatedAt: now, UpdatedAt: now}
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		in, err := h.readGroup(r, c, tx, res)
		if err != nil {
			return err
		}
		g.Name, g.ExternalID = in.name, in.externalID
		if err := tx.Directory().CreateGroup(r.Context(), g); err != nil {
			return err
		}
		if len(in.members) == 0 {
			return nil
		}
		return tx.Directory().UpdateGroupMembers(r.Context(), c.tenant.ID, g.ID, in.members, nil, true, now)
	})
	if errors.Is(err, store.ErrConflict) {
		return errGroupName
	}
	if err != nil {
		return err
	}
	w.Header().Set("Location", c.base()+"/Groups/"+g.ID)
	return h.writeGroup(w, r, c, http.StatusCreated, g)
}

// replaceGroupWith rewrites a group from the resource build returns.
func (h *Handler) replaceGroupWith(w http.ResponseWriter, r *http.Request, c *call, build func(tx store.Store, g *store.Group) (map[string]any, error)) error {
	var out *store.Group
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		g, err := h.loadGroup(r, c, tx)
		if err != nil {
			return err
		}
		res, err := build(tx, g)
		if err != nil {
			return err
		}
		in, err := h.readGroup(r, c, tx, res)
		if err != nil {
			return err
		}
		g.Name, g.ExternalID, g.UpdatedAt = in.name, in.externalID, h.now()
		if err := tx.Directory().UpdateGroup(r.Context(), g); err != nil {
			return err
		}
		if err := tx.Directory().UpdateGroupMembers(r.Context(), c.tenant.ID, g.ID, in.members, nil, true, h.now()); err != nil {
			return err
		}
		out = g
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return errGroupName
	}
	if err != nil {
		return err
	}
	return h.writeGroup(w, r, c, http.StatusOK, out)
}

func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request, c *call) error {
	var res map[string]any
	if err := readBody(r, &res); err != nil {
		return err
	}
	return h.replaceGroupWith(w, r, c, func(store.Store, *store.Group) (map[string]any, error) { return res, nil })
}

func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, c *call) error {
	var p PatchRequest
	if err := readBody(r, &p); err != nil {
		return err
	}
	return h.replaceGroupWith(w, r, c, func(tx store.Store, g *store.Group) (map[string]any, error) {
		ms, _, err := tx.Directory().ListGroupMembers(r.Context(), c.tenant.ID, g.ID, store.Page{})
		if err != nil {
			return nil, err
		}
		res := c.groupResource(g, ms, true)
		if err := ApplyPatch(res, p.Operations); err != nil {
			return nil, errorf(http.StatusBadRequest, "invalidPath", "The patch operations are not valid.")
		}
		return res, nil
	})
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, c *call) error {
	g, err := h.loadGroup(r, c, h.Store)
	if err != nil {
		return err
	}
	if err := h.Store.Directory().DeleteGroup(r.Context(), c.tenant.ID, g.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Discovery endpoints (RFC 7644 §4) need a token of the connection, so
// they do not reveal which connections have SCIM.
func (h *Handler) discovery(fn func(w http.ResponseWriter, c *call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := h.authorize(r, "")
		if err != nil {
			h.fail(w, r, err)
			return
		}
		fn(w, c)
	}
}

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	h.discovery(func(w http.ResponseWriter, c *call) {
		writeJSON(w, http.StatusOK, map[string]any{
			"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"documentationUri": "https://auth0.com/docs/authenticate/protocols/scim/configure-inbound-scim",
			"patch":            map[string]any{"supported": true},
			"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":           map[string]any{"supported": true, "maxResults": 100},
			"changePassword":   map[string]any{"supported": false},
			"sort":             map[string]any{"supported": false},
			"etag":             map[string]any{"supported": false},
			"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token",
				"description": "A SCIM token of this connection.", "primary": true}},
			"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": c.base() + "/ServiceProviderConfig"},
		})
	})(w, r)
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	h.discovery(func(w http.ResponseWriter, c *call) {
		rt := func(id, endpoint, schema string, ext []any) map[string]any {
			m := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": id, "name": id, "endpoint": endpoint, "schema": schema,
				"meta": map[string]any{"resourceType": "ResourceType", "location": c.base() + "/ResourceTypes/" + id}}
			if ext != nil {
				m["schemaExtensions"] = ext
			}
			return m
		}
		writeJSON(w, http.StatusOK, listResponse(2, 1, []any{
			rt("User", "/Users", CoreUser, []any{map[string]any{"schema": EnterpriseUser, "required": false}}),
			rt("Group", "/Groups", CoreGroup, nil),
		}))
	})(w, r)
}

func schemaAttr(name, typ string, multi bool, extra map[string]any) map[string]any {
	m := map[string]any{"name": name, "type": typ, "multiValued": multi, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	h.discovery(func(w http.ResponseWriter, c *call) {
		sub := func(names ...string) []any {
			var out []any
			for _, n := range names {
				out = append(out, schemaAttr(n, "string", false, nil))
			}
			return out
		}
		schema := func(id, name string, attrs []any) map[string]any {
			return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": id, "name": name, "attributes": attrs,
				"meta": map[string]any{"resourceType": "Schema", "location": c.base() + "/Schemas/" + id}}
		}
		user := []any{
			schemaAttr("userName", "string", false, map[string]any{"uniqueness": "server"}),
			schemaAttr("name", "complex", false, map[string]any{"subAttributes": sub("formatted", "familyName", "givenName", "middleName")}),
			schemaAttr("displayName", "string", false, nil), schemaAttr("nickName", "string", false, nil), schemaAttr("title", "string", false, nil),
			schemaAttr("active", "boolean", false, nil),
			schemaAttr("emails", "complex", true, map[string]any{"subAttributes": append(sub("value", "type"), schemaAttr("primary", "boolean", false, nil))}),
			schemaAttr("phoneNumbers", "complex", true, map[string]any{"subAttributes": sub("value", "type")}),
		}
		group := []any{
			schemaAttr("displayName", "string", false, map[string]any{"required": true, "uniqueness": "server"}),
			schemaAttr("members", "complex", true, map[string]any{"subAttributes": sub("value", "type", "display")}),
		}
		enterprise := []any{schemaAttr("employeeNumber", "string", false, nil), schemaAttr("costCenter", "string", false, nil),
			schemaAttr("organization", "string", false, nil), schemaAttr("division", "string", false, nil), schemaAttr("department", "string", false, nil),
			schemaAttr("manager", "complex", false, map[string]any{"subAttributes": sub("value", "displayName")})}
		writeJSON(w, http.StatusOK, listResponse(3, 1, []any{schema(CoreUser, "User", user), schema(CoreGroup, "Group", group), schema(EnterpriseUser, "EnterpriseUser", enterprise)}))
	})(w, r)
}
