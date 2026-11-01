package events

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pendingEvent struct {
	ctx          context.Context
	typ, tid, id string
	event        *store.TenantEvent
	previous     *store.User
}
type capture struct {
	store.Store
	cfg     Config
	pending *[]pendingEvent
}

// Wrap records catalog mutations in their business transaction. Capability
// checks remain delegated so older plugins continue serving other features.
func Wrap(st store.Store, cfg Config) store.Store {
	if _, ok := st.(*capture); ok {
		return st
	}
	return &capture{Store: st, cfg: cfg}
}

// Unwrap exposes the underlying store to lifecycle and diagnostic helpers.
func (s *capture) Unwrap() store.Store {
	if s == nil {
		return nil
	}
	return s.Store
}

func (s *capture) available(ctx context.Context) (bool, error) {
	if p, ok := s.Store.(store.EventsSupporter); ok {
		err := p.CheckEventsSupport(ctx)
		if errors.Is(err, store.ErrEventsUnavailable) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return p.EventsSupported(), nil
	}
	_, err := s.Store.Events().LatestEventSeq(ctx, "")
	if errors.Is(err, store.ErrEventsUnavailable) {
		return false, nil
	}
	return err == nil, err
}
func (s *capture) WithTx(ctx context.Context, fn func(store.Store) error) error {
	if s.pending != nil {
		original := append([]pendingEvent(nil), (*s.pending)...)
		committed := false
		defer func() {
			if !committed {
				*s.pending = original
			}
		}()
		err := s.Store.WithTx(ctx, func(tx store.Store) error { return fn(&capture{Store: tx, cfg: s.cfg, pending: s.pending}) })
		committed = err == nil
		return err
	}
	enabled, err := s.available(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return s.Store.WithTx(ctx, fn)
	}
	return s.Store.WithTx(ctx, func(tx store.Store) error {
		p := []pendingEvent{}
		view := &capture{Store: tx, cfg: s.cfg, pending: &p}
		if err := fn(view); err != nil {
			return err
		}
		out := make([]store.TenantEvent, 0, len(p))
		for _, v := range p {
			if v.event != nil {
				out = append(out, *v.event)
				continue
			}
			u, err := tx.Users().Get(ctx, v.tid, v.id)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			tenant, err := tx.Tenants().Get(ctx, v.tid)
			if err != nil {
				return err
			}
			e, err := Build(v.ctx, tenant, v.typ, u, v.previous, time.Now())
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		if len(out) == 0 {
			return nil
		}
		return tx.Events().AppendEvents(ctx, out)
	})
}
func (s *capture) mutate(ctx context.Context, fn func(*capture) error) error {
	if s.pending != nil {
		return fn(s)
	}
	enabled, err := s.available(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return fn(&capture{Store: s.Store, cfg: s.cfg})
	}
	return s.WithTx(ctx, func(tx store.Store) error { return fn(tx.(*capture)) })
}
func (s *capture) emit(ctx context.Context, tid, typ string, object, prior any) error {
	if s.pending == nil {
		return nil
	}
	tenant, err := s.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return err
	}
	e, err := Build(ctx, tenant, typ, object, prior, time.Now())
	if errors.Is(err, ErrNotEmitted) {
		return nil
	}
	if err != nil {
		return err
	}
	*s.pending = append(*s.pending, pendingEvent{ctx: ctx, typ: typ, tid: tid, event: &e})
	return nil
}
func (s *capture) userUpdated(ctx context.Context, prior *store.User) {
	if s.pending == nil {
		return
	}
	for _, p := range *s.pending {
		if p.typ == "user.updated" && p.tid == prior.TenantID && p.id == prior.UserID {
			return
		}
	}
	*s.pending = append(*s.pending, pendingEvent{ctx: ctx, typ: "user.updated", tid: prior.TenantID, id: prior.UserID, previous: prior})
}
func (s *capture) Users() store.Users { return users{Users: s.Store.Users(), s: s} }
func (s *capture) Connections() store.Connections {
	return connections{Connections: s.Store.Connections(), s: s}
}
func (s *capture) Organizations() store.Organizations {
	return organizations{Organizations: s.Store.Organizations(), s: s}
}
func (s *capture) Federation() store.Federation {
	return federation{Federation: s.Store.Federation(), s: s}
}

type users struct {
	store.Users
	s *capture
}

func (r users) Create(ctx context.Context, u *store.User) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if err := s.Store.Users().Create(ctx, u); err != nil {
			return err
		}
		stored, err := s.Store.Users().Get(ctx, u.TenantID, u.UserID)
		if err != nil {
			return err
		}
		return s.emit(ctx, u.TenantID, "user.created", stored, nil)
	})
}
func (r users) update(ctx context.Context, tid, id string, fn func(store.Users) error) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if s.pending == nil {
			return fn(s.Store.Users())
		}
		before, err := s.Store.Users().GetForUpdate(ctx, tid, id)
		if err != nil {
			return err
		}
		if err := fn(s.Store.Users()); err != nil {
			return err
		}
		s.userUpdated(ctx, before)
		return nil
	})
}
func (r users) Update(ctx context.Context, u *store.User) error {
	return r.update(ctx, u.TenantID, u.UserID, func(repo store.Users) error { return repo.Update(ctx, u) })
}
func (r users) SetPasswordHash(ctx context.Context, tid, id, conn, hash string, at time.Time) error {
	return r.update(ctx, tid, id, func(repo store.Users) error { return repo.SetPasswordHash(ctx, tid, id, conn, hash, at) })
}
func (r users) SetPasswordHashIfEmpty(ctx context.Context, tid, id, conn, hash string, at time.Time) error {
	return r.update(ctx, tid, id, func(repo store.Users) error { return repo.SetPasswordHashIfEmpty(ctx, tid, id, conn, hash, at) })
}
func (r users) Delete(ctx context.Context, tid, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		before, err := s.Store.Users().GetForUpdate(ctx, tid, id)
		if err != nil {
			return err
		}
		if s.pending == nil {
			return s.Store.Users().Delete(ctx, tid, id)
		}
		cascades, err := s.userRemoval(ctx, before)
		if err != nil {
			return err
		}
		if err := s.Store.Users().Delete(ctx, tid, id); err != nil {
			return err
		}
		return s.emitCascades(ctx, cascades)
	})
}

type connections struct {
	store.Connections
	s *capture
}

func (r connections) Create(ctx context.Context, c *store.Connection) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if err := s.Store.Connections().Create(ctx, c); err != nil {
			return err
		}
		return s.emit(ctx, c.TenantID, "connection.created", c, nil)
	})
}
func (r connections) Update(ctx context.Context, c *store.Connection) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Connections().Get(ctx, c.TenantID, c.ID)
		if err != nil {
			return err
		}
		if err := s.Store.Connections().Update(ctx, c); err != nil {
			return err
		}
		current, err := s.Store.Connections().Get(ctx, c.TenantID, c.ID)
		if err != nil {
			return err
		}
		return s.emit(ctx, c.TenantID, "connection.updated", current, prior)
	})
}
func (r connections) Delete(ctx context.Context, tid, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Connections().Get(ctx, tid, id)
		if err != nil {
			return err
		}
		if s.pending == nil {
			return s.Store.Connections().Delete(ctx, tid, id)
		}
		cascades, changed, err := s.connectionRemoval(ctx, prior)
		if err != nil {
			return err
		}
		if err := s.Store.Connections().Delete(ctx, tid, id); err != nil {
			return err
		}
		if err := s.emitCascades(ctx, cascades); err != nil {
			return err
		}
		for _, u := range changed {
			s.userUpdated(ctx, u)
		}
		return s.emit(ctx, tid, "connection.deleted", prior, nil)
	})
}

type organizations struct {
	store.Organizations
	s *capture
}

func (r organizations) Create(ctx context.Context, o *store.Organization, conns []store.OrganizationConnection) error {
	return r.s.mutate(ctx, func(s *capture) error {
		if err := s.Store.Organizations().Create(ctx, o, conns); err != nil {
			return err
		}
		if err := s.emit(ctx, o.TenantID, "organization.created", o, nil); err != nil {
			return err
		}
		for _, c := range conns {
			current, err := s.Store.Organizations().GetConnection(ctx, o.TenantID, o.ID, c.ConnectionID)
			if err != nil {
				return err
			}
			if err := s.emit(ctx, o.TenantID, "organization.connection.added", orgConnection(o, *current), nil); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r organizations) Update(ctx context.Context, o *store.Organization) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Organizations().Get(ctx, o.TenantID, o.ID)
		if err != nil {
			return err
		}
		if err := s.Store.Organizations().Update(ctx, o); err != nil {
			return err
		}
		return s.emit(ctx, o.TenantID, "organization.updated", o, prior)
	})
}
func (r organizations) Delete(ctx context.Context, tid, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Organizations().Get(ctx, tid, id)
		if err != nil {
			return err
		}
		if s.pending == nil {
			return s.Store.Organizations().Delete(ctx, tid, id)
		}
		cascades, err := s.organizationRemoval(ctx, prior)
		if err != nil {
			return err
		}
		if err := s.Store.Organizations().Delete(ctx, tid, id); err != nil {
			return err
		}
		if err := s.emitCascades(ctx, cascades); err != nil {
			return err
		}
		return s.emit(ctx, tid, "organization.deleted", prior, nil)
	})
}
func orgRef(o *store.Organization) map[string]any { return map[string]any{"id": o.ID, "name": o.Name} }
func orgConnection(o *store.Organization, c store.OrganizationConnection) map[string]any {
	return map[string]any{"organization": orgRef(o), "connection": map[string]any{"id": c.ConnectionID}, "assign_membership_on_login": c.AssignMembershipOnLogin, "show_as_button": c.ShowAsButton, "is_signup_enabled": c.IsSignupEnabled, "is_enabled": c.IsEnabled || !c.IsEnabledSet, "organization_access_level": c.OrganizationAccessLevel, "organization_member_access_level": c.OrganizationMemberAccessLevel}
}
func (r organizations) PutConnection(ctx context.Context, c store.OrganizationConnection, create bool) error {
	return r.s.mutate(ctx, func(s *capture) error {
		o, err := s.Store.Organizations().Get(ctx, c.TenantID, c.OrganizationID)
		if err != nil {
			return err
		}
		typ := "organization.connection.added"
		var prior any
		if !create {
			p, err := s.Store.Organizations().GetConnection(ctx, c.TenantID, c.OrganizationID, c.ConnectionID)
			if err != nil {
				return err
			}
			prior = orgConnection(o, *p)
			typ = "organization.connection.updated"
		}
		if err := s.Store.Organizations().PutConnection(ctx, c, create); err != nil {
			return err
		}
		current, err := s.Store.Organizations().GetConnection(ctx, c.TenantID, c.OrganizationID, c.ConnectionID)
		if err != nil {
			return err
		}
		return s.emit(ctx, c.TenantID, typ, orgConnection(o, *current), prior)
	})
}
func (r organizations) DeleteConnection(ctx context.Context, tid, oid, cid string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Organizations().GetConnection(ctx, tid, oid, cid)
		if errors.Is(err, store.ErrNotFound) {
			return s.Store.Organizations().DeleteConnection(ctx, tid, oid, cid)
		}
		if err != nil {
			return err
		}
		o, err := s.Store.Organizations().Get(ctx, tid, oid)
		if err != nil {
			return err
		}
		if err := s.Store.Organizations().DeleteConnection(ctx, tid, oid, cid); err != nil {
			return err
		}
		return s.emit(ctx, tid, "organization.connection.removed", orgConnection(o, *prior), nil)
	})
}
func (r organizations) AddMembers(ctx context.Context, tid, oid string, ids []string) error {
	_, err := r.AddMembersResult(ctx, tid, oid, ids)
	return err
}
func (r organizations) AddMembersResult(ctx context.Context, tid, oid string, ids []string) ([]string, error) {
	var added []string
	err := r.s.mutate(ctx, func(s *capture) error {
		if s.pending == nil {
			var err error
			added, err = store.AddMembersResult(ctx, s.Store.Organizations(), tid, oid, ids)
			return err
		}
		o, err := s.Store.Organizations().Get(ctx, tid, oid)
		if err != nil {
			return err
		}
		repo := s.Store.Organizations()
		if writer, ok := repo.(store.OrganizationMembershipWriter); ok {
			added, err = writer.AddMembersResult(ctx, tid, oid, ids)
		} else {
			seen := map[string]bool{}
			for _, id := range ids {
				present, e := repo.IsMember(ctx, tid, oid, id)
				if e != nil {
					return e
				}
				if !present && !seen[id] {
					added = append(added, id)
					seen[id] = true
				}
			}
			err = repo.AddMembers(ctx, tid, oid, ids)
		}
		if err != nil {
			return err
		}
		for _, id := range added {
			if err := s.emit(ctx, tid, "organization.member.added", map[string]any{"organization": orgRef(o), "user": map[string]any{"user_id": id}}, nil); err != nil {
				return err
			}
		}
		return nil
	})
	return added, err
}
func (r organizations) RemoveMembers(ctx context.Context, tid, oid string, ids []string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		o, err := s.Store.Organizations().Get(ctx, tid, oid)
		if err != nil {
			return err
		}
		removed := map[string]bool{}
		for _, id := range ids {
			present, e := s.Store.Organizations().IsMember(ctx, tid, oid, id)
			if e != nil {
				return e
			}
			if present {
				removed[id] = true
			}
		}
		if err := s.Store.Organizations().RemoveMembers(ctx, tid, oid, ids); err != nil {
			return err
		}
		for id := range removed {
			if err := s.emit(ctx, tid, "organization.member.deleted", map[string]any{"organization": orgRef(o), "user": map[string]any{"user_id": id}}, nil); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r organizations) ChangeMemberRoles(ctx context.Context, tid, oid, uid string, add bool, ids []string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		prior, err := s.Store.Organizations().MemberRoles(ctx, tid, oid, uid, store.OrgPage{})
		if err != nil {
			return err
		}
		had := map[string]bool{}
		for _, id := range prior.Items {
			had[id] = true
		}
		if err := s.Store.Organizations().ChangeMemberRoles(ctx, tid, oid, uid, add, ids); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] || had[id] == add {
				continue
			}
			seen[id] = true
			role, err := s.Store.RBAC().GetRole(ctx, tid, id)
			if err != nil {
				return err
			}
			typ := "organization.member.role.deleted"
			if add {
				typ = "organization.member.role.assigned"
			}
			if err := s.emit(ctx, tid, typ, map[string]any{"organization": map[string]any{"id": oid}, "user": map[string]any{"user_id": uid}, "role": map[string]any{"id": id, "name": role.Name}}, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

type federation struct {
	store.Federation
	s *capture
}

func (r federation) PutIdentity(ctx context.Context, k store.FederatedIdentityKey, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		return users{s: s}.update(ctx, k.TenantID, id, func(_ store.Users) error { return s.Store.Federation().PutIdentity(ctx, k, id) })
	})
}
func (r federation) DeleteIdentity(ctx context.Context, k store.FederatedIdentityKey, id string) error {
	return r.s.mutate(ctx, func(s *capture) error {
		return users{s: s}.update(ctx, k.TenantID, id, func(_ store.Users) error { return s.Store.Federation().DeleteIdentity(ctx, k, id) })
	})
}

// Tenant deletion purges the outbox, including provisional events buffered in
// this transaction. It must never create fresh delete events for the tenant.
func (s *capture) Tenants() store.Tenants { return tenants{Tenants: s.Store.Tenants(), s: s} }

type tenants struct {
	store.Tenants
	s *capture
}

func (r tenants) Delete(ctx context.Context, id string) error {
	if err := r.s.Store.Tenants().Delete(ctx, id); err != nil {
		return err
	}
	if r.s.pending != nil {
		kept := make([]pendingEvent, 0, len(*r.s.pending))
		for _, p := range *r.s.pending {
			if p.tid != id {
				kept = append(kept, p)
			}
		}
		*r.s.pending = kept
	}
	return nil
}
