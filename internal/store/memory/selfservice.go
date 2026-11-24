package memory

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// selfServiceState is Plan 37c Phase B state (scim.v1 version 2).
type selfServiceState struct {
	profiles map[key]*store.SelfServiceProfile // key{tenant, profile id}
	texts    map[textKey]json.RawMessage
	tickets  map[key]*store.SSOTicket         // key{tenant, ticket id}
	conns    map[key]*store.ConnectionProfile // key{tenant, connection profile id}
}

type textKey struct{ tenant, profile, language, page string }

func newSelfServiceState() *selfServiceState {
	return &selfServiceState{profiles: map[key]*store.SelfServiceProfile{}, texts: map[textKey]json.RawMessage{},
		tickets: map[key]*store.SSOTicket{}, conns: map[key]*store.ConnectionProfile{}}
}

func (d *selfServiceState) clone() *selfServiceState {
	out := newSelfServiceState()
	for k, v := range d.profiles {
		out.profiles[k] = v.Clone()
	}
	for k, v := range d.texts {
		out.texts[k] = slices.Clone(v)
	}
	for k, v := range d.tickets {
		out.tickets[k] = v.Clone()
	}
	for k, v := range d.conns {
		out.conns[k] = v.Clone()
	}
	return out
}

func (d *selfServiceState) dropTenant(tid string) {
	for k := range d.profiles {
		if k.tenant == tid {
			delete(d.profiles, k)
		}
	}
	for k := range d.texts {
		if k.tenant == tid {
			delete(d.texts, k)
		}
	}
	for k := range d.tickets {
		if k.tenant == tid {
			delete(d.tickets, k)
		}
	}
	for k := range d.conns {
		if k.tenant == tid {
			delete(d.conns, k)
		}
	}
}

type selfService struct{ s *Store }

func (s *Store) SelfService() store.SelfService { return selfService{s} }
func (s *Store) SelfServiceSupported() bool     { return true }

func (r selfService) CreateProfile(_ context.Context, p *store.SelfServiceProfile) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	if _, ok := st.profiles[key{p.TenantID, p.ID}]; ok {
		return store.ErrConflict
	}
	for k, v := range st.profiles {
		if k.tenant == p.TenantID && v.Name == p.Name {
			return store.ErrConflict
		}
	}
	st.profiles[key{p.TenantID, p.ID}] = p.Clone()
	return nil
}

func (r selfService) GetProfile(_ context.Context, tid, id string) (*store.SelfServiceProfile, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	p, ok := r.s.selfService.profiles[key{tid, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p.Clone(), nil
}

func (r selfService) UpdateProfile(_ context.Context, p *store.SelfServiceProfile) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	cur, ok := st.profiles[key{p.TenantID, p.ID}]
	if !ok {
		return store.ErrNotFound
	}
	for k, v := range st.profiles {
		if k.tenant == p.TenantID && k.id != p.ID && v.Name == p.Name {
			return store.ErrConflict
		}
	}
	next := p.Clone()
	next.CreatedAt = cur.CreatedAt
	st.profiles[key{p.TenantID, p.ID}] = next
	return nil
}

func (r selfService) DeleteProfile(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	if _, ok := st.profiles[key{tid, id}]; !ok {
		return store.ErrNotFound
	}
	delete(st.profiles, key{tid, id})
	for k := range st.texts {
		if k.tenant == tid && k.profile == id {
			delete(st.texts, k)
		}
	}
	for k, t := range st.tickets {
		if k.tenant == tid && t.ProfileID == id {
			delete(st.tickets, k)
		}
	}
	return nil
}

func byCreated[T any](all []T, at func(T) (time.Time, string)) {
	slices.SortFunc(all, func(a, b T) int {
		ta, ia := at(a)
		tb, ib := at(b)
		return cmp.Or(ta.Compare(tb), strings.Compare(ia, ib))
	})
}

func (r selfService) ListProfiles(_ context.Context, tid string, p store.Page) ([]*store.SelfServiceProfile, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.SelfServiceProfile
	for k, v := range r.s.selfService.profiles {
		if k.tenant == tid {
			all = append(all, v.Clone())
		}
	}
	byCreated(all, func(v *store.SelfServiceProfile) (time.Time, string) { return v.CreatedAt, v.ID })
	return dirPage(all, p), len(all), nil
}

func (r selfService) GetCustomText(_ context.Context, tid, pid, lang, page string) (json.RawMessage, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if _, ok := r.s.selfService.profiles[key{tid, pid}]; !ok {
		return nil, store.ErrNotFound
	}
	return slices.Clone(r.s.selfService.texts[textKey{tid, pid, lang, page}]), nil
}

func (r selfService) SetCustomText(_ context.Context, tid, pid, lang, page string, text json.RawMessage) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.selfService.profiles[key{tid, pid}]; !ok {
		return store.ErrNotFound
	}
	r.s.selfService.texts[textKey{tid, pid, lang, page}] = slices.Clone(text)
	return nil
}

func (r selfService) CreateTicket(_ context.Context, t *store.SSOTicket) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	if _, ok := st.profiles[key{t.TenantID, t.ProfileID}]; !ok {
		return store.ErrNotFound
	}
	if _, ok := st.tickets[key{t.TenantID, t.ID}]; ok {
		return store.ErrConflict
	}
	for k, v := range st.tickets {
		if k.tenant == t.TenantID && v.Hash == t.Hash {
			return store.ErrConflict
		}
	}
	st.tickets[key{t.TenantID, t.ID}] = t.Clone()
	return nil
}

func (r selfService) GetTicketByHash(_ context.Context, tid, hash string) (*store.SSOTicket, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, v := range r.s.selfService.tickets {
		if k.tenant == tid && v.Hash == hash {
			return v.Clone(), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r selfService) RevokeTicket(_ context.Context, tid, pid, id string, now time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.s.selfService.tickets[key{tid, id}]
	if !ok || t.ProfileID != pid {
		return store.ErrNotFound
	}
	if t.RevokedAt == nil {
		t.RevokedAt = &now
	}
	return nil
}

func (r selfService) UseTicket(_ context.Context, tid, id string, now time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.s.selfService.tickets[key{tid, id}]
	if !ok {
		return store.ErrNotFound
	}
	if !t.Usable(now) {
		return store.ErrPrecondition
	}
	t.UsedAt = &now
	return nil
}

func (r selfService) BindTicketConnection(_ context.Context, tid, id, conn string) error {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.s.selfService.tickets[key{tid, id}]
	if !ok {
		return store.ErrNotFound
	}
	switch t.ConnectionID {
	case "":
		t.ConnectionID = conn
	case conn:
	default:
		return store.ErrPrecondition
	}
	return nil
}

func (r selfService) CreateConnectionProfile(_ context.Context, p *store.ConnectionProfile) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	if _, ok := st.conns[key{p.TenantID, p.ID}]; ok {
		return store.ErrConflict
	}
	for k, v := range st.conns {
		if k.tenant == p.TenantID && v.Name == p.Name {
			return store.ErrConflict
		}
	}
	st.conns[key{p.TenantID, p.ID}] = p.Clone()
	return nil
}

func (r selfService) GetConnectionProfile(_ context.Context, tid, id string) (*store.ConnectionProfile, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	p, ok := r.s.selfService.conns[key{tid, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p.Clone(), nil
}

func (r selfService) UpdateConnectionProfile(_ context.Context, p *store.ConnectionProfile) error {
	r.s.lock()
	defer r.s.unlock()
	st := r.s.selfService
	cur, ok := st.conns[key{p.TenantID, p.ID}]
	if !ok {
		return store.ErrNotFound
	}
	for k, v := range st.conns {
		if k.tenant == p.TenantID && k.id != p.ID && v.Name == p.Name {
			return store.ErrConflict
		}
	}
	next := p.Clone()
	next.CreatedAt = cur.CreatedAt
	st.conns[key{p.TenantID, p.ID}] = next
	return nil
}

func (r selfService) DeleteConnectionProfile(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.selfService.conns[key{tid, id}]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.selfService.conns, key{tid, id})
	return nil
}

func (r selfService) ListConnectionProfiles(_ context.Context, tid string, p store.Page) ([]*store.ConnectionProfile, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.ConnectionProfile
	for k, v := range r.s.selfService.conns {
		if k.tenant == tid {
			all = append(all, v.Clone())
		}
	}
	byCreated(all, func(v *store.ConnectionProfile) (time.Time, string) { return v.CreatedAt, v.ID })
	return dirPage(all, p), len(all), nil
}
