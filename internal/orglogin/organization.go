// Package orglogin holds organization policy shared by hosted login,
// federation and authorization continuations. Every write uses fresh store data.
package orglogin

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Context struct {
	Org         *store.Organization
	Connections map[string]store.OrganizationConnection
}

var ErrNotMember = errors.New("organization: connection or membership is not eligible")

func Load(ctx context.Context, st store.Store, tid string, params map[string]string) (Context, error) {
	if params[store.TxnParamOrgMode] != "fixed" {
		return Context{}, nil
	}
	id := params[store.TxnParamOrgID]
	if id == "" {
		return Context{}, ErrNotMember
	}
	org, err := st.Organizations().Get(ctx, tid, id)
	if err != nil {
		return Context{}, err
	}
	links, err := st.Organizations().Connections(ctx, tid, id, store.OrgPage{PerPage: 100})
	if err != nil {
		return Context{}, err
	}
	oc := Context{Org: org, Connections: map[string]store.OrganizationConnection{}}
	for _, c := range links.Items {
		oc.Connections[c.ConnectionID] = c
	}
	return oc, nil
}
func EligibleConnections(conns []*store.Connection, oc Context) []*store.Connection {
	if oc.Org == nil {
		return conns
	}
	var out []*store.Connection
	for _, c := range conns {
		if _, ok := oc.Connections[c.ID]; ok && c.TenantID == oc.Org.TenantID {
			out = append(out, c)
		}
	}
	return out
}

// EnsureMembership must run inside the caller's user/session transaction. The
// page snapshot never authorizes a write; connection flags are reloaded here.
func EnsureMembership(ctx context.Context, tx store.Store, oc Context, userID, connectionID string) error {
	if oc.Org == nil {
		return nil
	}
	tid, id := oc.Org.TenantID, oc.Org.ID
	link, err := tx.Organizations().GetConnection(ctx, tid, id, connectionID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotMember
	}
	if err != nil {
		return err
	}
	member, err := tx.Organizations().IsMember(ctx, tid, id, userID)
	if err != nil {
		return err
	}
	if member {
		return nil
	}
	if !link.AssignMembershipOnLogin {
		return ErrNotMember
	}
	return tx.Organizations().AddMembers(ctx, tid, id, []string{userID})
}

// PickerChoices considers all connection links before limiting the display;
// therefore 21+ matching organizations can never look like a unique choice.
func PickerChoices(ctx context.Context, st store.Store, tid, userID, connectionID string) (orgs []store.Organization, auto *store.Organization, err error) {
	links, err := st.Organizations().ConnectionsByConnection(ctx, tid, connectionID)
	if err != nil {
		return nil, nil, err
	}
	var candidates []store.Organization
	for _, link := range links {
		member, e := st.Organizations().IsMember(ctx, tid, link.OrganizationID, userID)
		if e != nil {
			return nil, nil, e
		}
		if !member && !link.AssignMembershipOnLogin {
			continue
		}
		org, e := st.Organizations().Get(ctx, tid, link.OrganizationID)
		if e != nil {
			return nil, nil, e
		}
		if member {
			orgs = append(orgs, *org)
		} else {
			candidates = append(candidates, *org)
		}
	}
	slices.SortFunc(orgs, func(a, b store.Organization) int {
		if n := strings.Compare(a.DisplayName, b.DisplayName); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(orgs) == 1 {
		return orgs, &orgs[0], nil
	}
	if len(orgs) == 0 && len(candidates) == 1 {
		return nil, &candidates[0], nil
	}
	if len(orgs) > 20 {
		orgs = orgs[:20]
	}
	return orgs, nil, nil
}
