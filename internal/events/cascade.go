package events

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Cascades bypass repository decorators inside a driver. Snapshot only the
// affected observable edges in the business transaction, then emit after the
// driver confirms the mutation. Dormant roles of nonmembers are not enumerable.
type cascadeEvent struct {
	tid, typ string
	object   any
}

func (s *capture) emitCascades(ctx context.Context, events []cascadeEvent) error {
	for _, e := range events {
		if err := s.emit(ctx, e.tid, e.typ, e.object, nil); err != nil {
			return err
		}
	}
	return nil
}
func memberObject(o *store.Organization, uid string) map[string]any {
	return map[string]any{"organization": orgRef(o), "user": map[string]any{"user_id": uid}}
}
func (s *capture) memberRemoval(ctx context.Context, o *store.Organization, uid string) ([]cascadeEvent, error) {
	out := []cascadeEvent{}
	for cursor := ""; ; {
		page, err := s.Store.Organizations().MemberRoles(ctx, o.TenantID, o.ID, uid, store.OrgPage{From: cursor, Take: 100})
		if err != nil {
			return nil, err
		}
		for _, id := range page.Items {
			role, err := s.Store.RBAC().GetRole(ctx, o.TenantID, id)
			if err != nil {
				return nil, err
			}
			out = append(out, cascadeEvent{tid: o.TenantID, typ: "organization.member.role.deleted", object: map[string]any{"organization": map[string]any{"id": o.ID}, "user": map[string]any{"user_id": uid}, "role": map[string]any{"id": id, "name": role.Name}}})
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	return append(out, cascadeEvent{tid: o.TenantID, typ: "organization.member.deleted", object: memberObject(o, uid)}), nil
}
func (s *capture) userRemoval(ctx context.Context, u *store.User) ([]cascadeEvent, error) {
	out := []cascadeEvent{}
	for cursor := ""; ; {
		page, err := s.Store.Organizations().UserOrganizations(ctx, u.TenantID, u.UserID, store.OrgPage{From: cursor, Take: 100})
		if errors.Is(err, store.ErrOrganizationsUnavailable) {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, o := range page.Items {
			edges, err := s.memberRemoval(ctx, &o, u.UserID)
			if err != nil {
				return nil, err
			}
			out = append(out, edges...)
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	return append(out, cascadeEvent{tid: u.TenantID, typ: "user.deleted", object: u}), nil
}
func (s *capture) organizationRemoval(ctx context.Context, o *store.Organization) ([]cascadeEvent, error) {
	out := []cascadeEvent{}
	for cursor := ""; ; {
		page, err := s.Store.Organizations().Members(ctx, o.TenantID, o.ID, store.OrgPage{From: cursor, Take: 100})
		if err != nil {
			return nil, err
		}
		for _, uid := range page.Items {
			edges, err := s.memberRemoval(ctx, o, uid)
			if err != nil {
				return nil, err
			}
			out = append(out, edges...)
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	for cursor := ""; ; {
		page, err := s.Store.Organizations().Connections(ctx, o.TenantID, o.ID, store.OrgPage{From: cursor, Take: 100})
		if err != nil {
			return nil, err
		}
		for _, c := range page.Items {
			out = append(out, cascadeEvent{tid: o.TenantID, typ: "organization.connection.removed", object: orgConnection(o, c)})
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	return out, nil
}
func (s *capture) connectionRemoval(ctx context.Context, c *store.Connection) ([]cascadeEvent, []*store.User, error) {
	out := []cascadeEvent{}
	changed := []*store.User{}
	conns, err := s.Store.Organizations().ConnectionsByConnection(ctx, c.TenantID, c.ID)
	if err != nil && !errors.Is(err, store.ErrOrganizationsUnavailable) {
		return nil, nil, err
	}
	for _, link := range conns {
		o, err := s.Store.Organizations().Get(ctx, c.TenantID, link.OrganizationID)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, cascadeEvent{tid: c.TenantID, typ: "organization.connection.removed", object: orgConnection(o, link)})
	}
	for offset := 0; ; {
		page, total, err := s.Store.Users().List(ctx, c.TenantID, nil, store.UserSort{}, store.Page{Offset: offset, Limit: 100})
		if err != nil {
			return nil, nil, err
		}
		for _, candidate := range page {
			del, strip := candidate.ConnectionDeleteEffect(c.Name)
			if !del && !strip {
				continue
			}
			u, err := s.Store.Users().GetForUpdate(ctx, c.TenantID, candidate.UserID)
			if err != nil {
				return nil, nil, err
			}
			del, strip = u.ConnectionDeleteEffect(c.Name)
			if del {
				edges, err := s.userRemoval(ctx, u)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, edges...)
			} else if strip {
				changed = append(changed, u)
			}
		}
		offset += len(page)
		if len(page) == 0 || offset >= total {
			break
		}
	}
	return out, changed, nil
}
