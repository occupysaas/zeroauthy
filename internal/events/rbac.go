package events

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type rbac struct {
	store.RBAC
	s *capture
}

func (s *capture) RBAC() store.RBAC { return rbac{RBAC: s.Store.RBAC(), s: s} }

// DeleteRole removes organization assignments inside the driver as well as
// the role. Capture only active member edges visible before that atomic delete.
func (r rbac) DeleteRole(ctx context.Context, tid, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if s.pending == nil {
			return s.Store.RBAC().DeleteRole(ctx, tid, id)
		}
		role, err := s.Store.RBAC().GetRole(ctx, tid, id)
		if err != nil {
			return err
		}
		edges := []cascadeEvent{}
		for cursor := ""; ; {
			orgs, err := s.Store.Organizations().List(ctx, tid, store.OrgPage{From: cursor, Take: 100})
			if errors.Is(err, store.ErrOrganizationsUnavailable) {
				break
			}
			if err != nil {
				return err
			}
			for _, org := range orgs.Items {
				for memberCursor := ""; ; {
					members, err := s.Store.Organizations().RoleMembers(ctx, tid, org.ID, id, store.OrgPage{From: memberCursor, Take: 100})
					if err != nil {
						return err
					}
					for _, uid := range members.Items {
						edges = append(edges, cascadeEvent{tid: tid, typ: "organization.member.role.deleted", object: map[string]any{"organization": map[string]any{"id": org.ID}, "user": map[string]any{"user_id": uid}, "role": map[string]any{"id": role.ID, "name": role.Name}}})
					}
					if members.Next == "" {
						break
					}
					memberCursor = members.Next
				}
			}
			if orgs.Next == "" {
				break
			}
			cursor = orgs.Next
		}
		if err := s.Store.RBAC().DeleteRole(ctx, tid, id); err != nil {
			return err
		}
		return s.emitCascades(ctx, edges)
	})
}
