package myorg

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// maxListedRoles is the OpenAPI's bound on roles shown per member.
const maxListedRoles = 10

func memberView(u *store.User) map[string]any {
	out := map[string]any{"user_id": u.UserID, "created_at": timeString(u.CreatedAt), "updated_at": timeString(u.UpdatedAt)}
	for k, v := range map[string]string{"email": u.Email, "name": u.Name, "nickname": u.Nickname, "given_name": u.GivenName, "family_name": u.FamilyName, "phone_number": u.PhoneNumber} {
		if v != "" {
			out[k] = v
		}
	}
	if u.LastLogin != nil {
		out["last_login"] = timeString(*u.LastLogin)
	}
	return out
}

// memberRoles are up to limit of uid's roles in c's organization.
func (h *Handlers) memberRoles(ctx context.Context, c *Caller, uid string, p store.OrgPage) ([]map[string]any, string, error) {
	res, err := h.Store.Organizations().MemberRoles(ctx, c.TenantID, c.Org.ID, uid, p)
	if err != nil {
		return nil, "", err
	}
	out := []map[string]any{}
	for _, id := range res.Items {
		role, err := h.Store.RBAC().GetRole(ctx, c.TenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		out = append(out, roleView(role))
	}
	return out, res.Next, nil
}

func roleView(r *store.Role) map[string]any {
	out := map[string]any{"id": r.ID, "name": r.Name}
	if r.Description != "" {
		out["description"] = r.Description
	}
	return out
}

// withRoles reports whether members carry roles: the token has
// read:my_org:member_roles and the fields filter keeps roles.
func withRoles(c *Caller, f fieldFilter) bool {
	return c.Has("read:my_org:member_roles") && f.keep("roles")
}

func (h *Handlers) member(ctx context.Context, c *Caller, uid string, f fieldFilter) (map[string]any, error) {
	u, err := h.Store.Users().Get(ctx, c.TenantID, uid)
	if err != nil {
		return nil, err
	}
	m := memberView(u)
	if withRoles(c, f) {
		roles, _, err := h.memberRoles(ctx, c, uid, store.OrgPage{Take: maxListedRoles})
		if err != nil {
			return nil, err
		}
		m["roles"] = roles
	}
	return f.apply(m), nil
}

func (h *Handlers) listMembers(w http.ResponseWriter, r *http.Request, c *Caller) {
	p, prob := page(r)
	if prob == nil {
		var f fieldFilter
		if f, prob = fieldsOf(r); prob == nil {
			h.membersPage(w, r, c, p, f)
			return
		}
	}
	writeProblem(w, r, prob)
}

// totalCap bounds include_totals counts (the OpenAPI's 1000).
const totalCap = 1000

func (h *Handlers) membersPage(w http.ResponseWriter, r *http.Request, c *Caller, p store.OrgPage, f fieldFilter) {
	ctx := r.Context()
	res, err := h.Store.Organizations().Members(ctx, c.TenantID, c.Org.ID, store.OrgPage{From: p.From, Take: p.Take})
	if errors.Is(err, store.ErrInvalid) {
		writeProblem(w, r, invalidQuery("from", "from is not a valid cursor."))
		return
	}
	if err != nil {
		h.fail(w, r, "list members", err)
		return
	}
	members := []any{}
	for _, uid := range res.Items {
		m, err := h.member(ctx, c, uid, f)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			h.fail(w, r, "load a member", err)
			return
		}
		members = append(members, m)
	}
	out := map[string]any{"members": members}
	if res.Next != "" {
		out["next"] = res.Next
	}
	if p.IncludeTotals {
		total, capped, err := h.countMembers(ctx, c)
		if err != nil {
			h.fail(w, r, "count members", err)
			return
		}
		out["total"], out["total_is_capped"] = total, capped
	}
	writeJSON(w, r, http.StatusOK, out)
}

// countMembers counts up to totalCap members.
func (h *Handlers) countMembers(ctx context.Context, c *Caller) (int, bool, error) {
	n, from := 0, ""
	for {
		res, err := h.Store.Organizations().Members(ctx, c.TenantID, c.Org.ID, store.OrgPage{From: from, Take: 100})
		if err != nil {
			return 0, false, err
		}
		n += len(res.Items)
		if n >= totalCap {
			return totalCap, true, nil
		}
		if res.Next == "" {
			return n, false, nil
		}
		from = res.Next
	}
}

// requireMember answers 404 unless uid is a member of c's organization.
func (h *Handlers) requireMember(ctx context.Context, c *Caller, uid string) error {
	ok, err := h.Store.Organizations().IsMember(ctx, c.TenantID, c.Org.ID, uid)
	if err != nil {
		return err
	}
	if !ok {
		return notFound("The member does not exist in this organization.")
	}
	return nil
}

func (h *Handlers) getMember(w http.ResponseWriter, r *http.Request, c *Caller) {
	uid := chi.URLParam(r, "user_id")
	f, prob := fieldsOf(r)
	if prob != nil {
		writeProblem(w, r, prob)
		return
	}
	if err := h.requireMember(r.Context(), c, uid); err != nil {
		h.fail(w, r, "get a member", err)
		return
	}
	m, err := h.member(r.Context(), c, uid, f)
	if err != nil {
		h.fail(w, r, "get a member", err)
		return
	}
	writeJSON(w, r, http.StatusOK, m)
}

// deleteMemberships removes one member (the user stays; roles stay, as the
// Management API's member removal, D-0055). The organization's last
// administrator cannot be removed (LR42b-8).
func (h *Handlers) deleteMemberships(w http.ResponseWriter, r *http.Request, c *Caller) {
	var b struct {
		Members []string `json:"members"`
	}
	if p := decode(r, &b); p != nil {
		writeProblem(w, r, p)
		return
	}
	if len(b.Members) != 1 || b.Members[0] == "" || len(b.Members[0]) > 1024 {
		writeProblem(w, r, badRequest("invalid_body", "members must name exactly one user.", ValidationError{Detail: "exactly one", Field: "members", Source: "body"}))
		return
	}
	uid := b.Members[0]
	ctx := r.Context()
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if err := h.withStore(tx).requireMember(ctx, c, uid); err != nil {
			return err
		}
		if err := h.withStore(tx).guardLastAdmin(ctx, c, uid, nil); err != nil {
			return err
		}
		return tx.Organizations().RemoveMembers(ctx, c.TenantID, c.Org.ID, []string{uid})
	})
	if err != nil {
		h.event(r, c, "my_organization_api_member_failed")
		h.fail(w, r, "delete a membership", err)
		return
	}
	h.event(r, c, "my_organization_api_member_succeeded")
	w.Header().Set("x-correlation-id", correlationID(r))
	w.WriteHeader(http.StatusNoContent)
}

// withStore is h on another store view (a transaction).
func (h *Handlers) withStore(st store.Store) *Handlers {
	c := *h
	c.Store = st
	return &c
}
