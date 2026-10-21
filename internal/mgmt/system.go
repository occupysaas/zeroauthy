package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// DefaultConnection is the database connection a new tenant gets, under
// Auth0's default name.
const DefaultConnection = "Username-Password-Authentication"

const maxFriendlyName = 255

var (
	errTenantNotFound   = &Error{Status: http.StatusNotFound, Code: "inexistent_tenant", Message: "The tenant does not exist"}
	errOperatorNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_operator", Message: "The operator does not exist"}
	errSystemTenant     = &Error{Status: http.StatusForbidden, Code: "operation_not_supported", Message: "The system tenant is managed by zeroauthy"}

	errLastOperatorRemove = &Error{Status: http.StatusConflict, Code: "last_operator", Message: "The last operator cannot be removed"}
	errLastOperatorBlock  = &Error{Status: http.StatusConflict, Code: "last_operator", Message: "The last operator cannot be blocked"}
	errLastOperatorLink   = &Error{Status: http.StatusConflict, Code: "last_operator", Message: "The last operator cannot be linked as a secondary account"}
)

// lastOperator reports whether userID is the only operator of the reserved
// system tenant tn. The Users API on the system tenant reaches operators
// too, so it refuses what would leave no operator to sign in: deleting,
// blocking or linking away the last one (the system API's DeleteOperator
// refuses the same).
func lastOperator(ctx context.Context, st store.Store, tn *store.Tenant, userID string) (bool, error) {
	if !tn.Reserved {
		return false, nil
	}
	if _, err := st.Operators().Get(ctx, tn.ID, userID); errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	ops, err := st.Operators().List(ctx, tn.ID)
	if err != nil {
		return false, err
	}
	return len(ops) <= 1, nil
}

func conflict(format string, args ...any) *Error {
	return &Error{Status: http.StatusConflict, Code: "conflict", Message: fmt.Sprintf(format, args...)}
}

// tenantView is t as the system API reports it.
func (h *Handlers) tenantView(t *store.Tenant) mgmtapi.SystemTenant {
	id := tenant.ManagementAPIIdentifier(t, h.BaseDomain)
	host := strings.TrimSuffix(strings.TrimPrefix(id, "https://"), "/api/v2/")
	if t.Reserved && len(t.Domains) > 0 {
		host = t.Domains[0] // the canonical system host, the operator-token issuer
	}
	domains := slices.Clone(t.Domains)
	if domains == nil {
		domains = []string{}
	}
	return mgmtapi.SystemTenant{
		Name: t.Name, FriendlyName: t.FriendlyName, Domains: domains,
		Host: host, ManagementApiIdentifier: id,
		Seeded: t.Seeded, Reserved: t.Reserved, CreatedAt: t.CreatedAt.UTC(),
	}
}

// GetTenants lists every tenant by name.
func (h *Handlers) GetTenants(w http.ResponseWriter, r *http.Request) {
	all, err := h.Store.Tenants().List(r.Context())
	if err != nil {
		Fail(w, internalError(h, r, "list tenants", err))
		return
	}
	out := make([]mgmtapi.SystemTenant, len(all))
	for i, t := range all {
		out[i] = h.tenantView(t)
	}
	writeJSON(w, http.StatusOK, out)
}

// tenantBody is a decoded TenantCreate or TenantUpdate.
type tenantBody struct {
	Name         *string   `json:"name"`
	FriendlyName *string   `json:"friendly_name"`
	Domains      *[]string `json:"domains"`
}

func decodeTenantBody(r *http.Request, create bool) (tenantBody, error) {
	var b tenantBody
	body, err := decodeObject(r)
	if err != nil {
		return b, err
	}
	for k := range body {
		if k != "friendly_name" && k != "domains" && (k != "name" || !create) {
			return b, badBody("unknown property %q", k)
		}
	}
	raw, _ := json.Marshal(body)
	if err := decodeStrict(raw, &b); err != nil {
		return b, badBody("%v", err)
	}
	if b.FriendlyName != nil && len(*b.FriendlyName) > maxFriendlyName {
		return b, badBody("friendly_name must be at most %d characters", maxFriendlyName)
	}
	return b, nil
}

// domains normalizes and checks a tenant's domains.
func (h *Handlers) domains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	sysHost := tenant.NormalizeHost(h.SystemHost)
	for _, d := range in {
		nd := tenant.NormalizeHost(d)
		switch {
		case !tenant.ValidDomain(nd):
			return nil, badBody("domains: %q is not a host", d)
		case slices.Contains(out, nd):
			return nil, badBody("domains: %q is listed twice", d)
		case sysHost != "" && nd == sysHost:
			return nil, badBody("domains: %q is the system host, reserved for zeroauthy's own tenant", d)
		}
		out = append(out, nd)
	}
	if len(out) == 0 && h.BaseDomain == "" {
		return nil, badBody("domains: a tenant needs at least one domain when the server has no base domain")
	}
	return out, nil
}

// CreateTenant creates a tenant with signing keys, the default database
// connection and its Management API (design §4.3).
func (h *Handlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	b, err := decodeTenantBody(r, true)
	if err != nil {
		Fail(w, err)
		return
	}
	switch {
	case b.Name == nil:
		Fail(w, badBody("Missing required property: name"))
		return
	case *b.Name == tenant.SystemName:
		Fail(w, badBody("name %q is reserved for zeroauthy's own tenant", tenant.SystemName))
		return
	case !tenant.ValidName(*b.Name):
		Fail(w, badBody("name must be a DNS label: lower-case letters, digits and hyphens, at most 63 characters"))
		return
	}
	var domains []string
	if b.Domains != nil {
		domains = *b.Domains
	}
	if domains, err = h.domains(domains); err != nil {
		Fail(w, err)
		return
	}
	now := h.now()
	var out *store.Tenant
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := tx.Tenants().GetByName(r.Context(), *b.Name); err == nil {
			return conflict("a tenant named %q exists", *b.Name)
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		tn, err := tenantsetup.UpsertTenant(r.Context(), tx, *b.Name, now, func(t *store.Tenant) error {
			t.Domains, t.Origin = domains, store.OriginAPI
			if b.FriendlyName != nil {
				t.FriendlyName = *b.FriendlyName
			}
			t.DefaultDirectory = DefaultConnection
			return nil
		})
		if errors.Is(err, store.ErrConflict) {
			return conflict("a domain is already used by another tenant")
		}
		if err != nil {
			return err
		}
		if err := tenantsetup.SigningKeys(r.Context(), tx, h.Wrapper, tn.ID); err != nil {
			return err
		}
		if err := tenantsetup.UpsertConnection(r.Context(), tx, tn.ID, DefaultConnection, now, func(c *store.Connection) error {
			c.Strategy = store.StrategyDatabase
			return nil
		}); err != nil {
			return err
		}
		if _, err := tenantsetup.ManagementAPI(r.Context(), tx, tn, h.BaseDomain, now); err != nil {
			return err
		}
		out = tn
		return nil
	})
	if err != nil {
		h.failTx(w, r, "create tenant", err)
		return
	}
	h.audit(r, "create tenant", "name", out.Name)
	writeJSON(w, http.StatusCreated, h.tenantView(out))
}

// failTx writes an *Error from a transaction as itself and anything else
// as a logged 500.
func (h *Handlers) failTx(w http.ResponseWriter, r *http.Request, what string, err error) {
	var e *Error
	if errors.As(err, &e) {
		Fail(w, e)
		return
	}
	Fail(w, internalError(h, r, what, err))
}

// UpdateTenant changes a tenant's friendly name or domains.
func (h *Handlers) UpdateTenant(w http.ResponseWriter, r *http.Request, name string) {
	b, err := decodeTenantBody(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	var out *store.Tenant
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		t, err := tx.Tenants().GetByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			return errTenantNotFound
		}
		if err != nil {
			return err
		}
		if t.Reserved {
			return errSystemTenant
		}
		if b.FriendlyName != nil {
			t.FriendlyName = *b.FriendlyName
		}
		if b.Domains != nil {
			if t.Domains, err = h.domains(*b.Domains); err != nil {
				return err
			}
		}
		if err := tx.Tenants().Update(r.Context(), t); errors.Is(err, store.ErrConflict) {
			return conflict("a domain is already used by another tenant")
		} else if err != nil {
			return err
		}
		// Without a base domain the identifier follows the first domain.
		if _, err := tenantsetup.ManagementAPI(r.Context(), tx, t, h.BaseDomain, h.now()); err != nil {
			return err
		}
		out = t
		return nil
	})
	if err != nil {
		h.failTx(w, r, "update tenant", err)
		return
	}
	h.audit(r, "update tenant", "name", name)
	writeJSON(w, http.StatusOK, h.tenantView(out))
}

// DeleteTenant deletes a tenant and all of its data; confirm must repeat
// the name.
func (h *Handlers) DeleteTenant(w http.ResponseWriter, r *http.Request, name string, p mgmtapi.DeleteTenantParams) {
	if p.Confirm != name {
		Fail(w, badQuery("Query validation error: confirm must repeat the tenant's name"))
		return
	}
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		t, err := tx.Tenants().GetByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			return errTenantNotFound
		}
		if err != nil {
			return err
		}
		if t.Reserved {
			return errSystemTenant
		}
		return tx.Tenants().Delete(r.Context(), t.ID)
	})
	if err != nil {
		h.failTx(w, r, "delete tenant", err)
		return
	}
	h.audit(r, "delete tenant", "name", name)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) operatorView(r *http.Request, sysID string, o *store.Operator) (mgmtapi.Operator, error) {
	email := ""
	u, err := h.Store.Users().Get(r.Context(), sysID, o.UserID)
	switch {
	case err == nil:
		email = u.Email
	case !errors.Is(err, store.ErrNotFound):
		return mgmtapi.Operator{}, err
	}
	tenants := slices.Clone(o.Tenants)
	if tenants == nil {
		tenants = []string{}
	}
	return mgmtapi.Operator{UserId: o.UserID, Email: email, Tenants: tenants, CreatedAt: o.CreatedAt.UTC()}, nil
}

// GetOperators lists the operators.
func (h *Handlers) GetOperators(w http.ResponseWriter, r *http.Request) {
	sys := resolved(r)
	ops, err := h.Store.Operators().List(r.Context(), sys.ID)
	if err != nil {
		Fail(w, internalError(h, r, "list operators", err))
		return
	}
	out := make([]mgmtapi.Operator, 0, len(ops))
	for _, o := range ops {
		v, err := h.operatorView(r, sys.ID, o)
		if err != nil {
			Fail(w, internalError(h, r, "list operators", err))
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateOperator invites an operator and returns the setup link.
func (h *Handlers) CreateOperator(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var b struct {
		Email string `json:"email"`
	}
	raw, _ := json.Marshal(body)
	if err := decodeStrict(raw, &b); err != nil {
		Fail(w, badBody("%v", err))
		return
	}
	email := identity.NormalizeLogin(strings.TrimSpace(b.Email))
	if identity.CheckEmail(email) != nil {
		Fail(w, badBody("email must be an email address"))
		return
	}
	link, err := system.CreateOperator(r.Context(), h.Store, email)
	if err != nil {
		Fail(w, internalError(h, r, "create operator", err))
		return
	}
	sys := resolved(r)
	u, err := h.Store.Users().FindByLogin(r.Context(), sys.ID, system.OperatorsConnection, email)
	if err != nil {
		Fail(w, internalError(h, r, "create operator", err))
		return
	}
	op, err := h.Store.Operators().Get(r.Context(), sys.ID, u.UserID)
	if err != nil {
		Fail(w, internalError(h, r, "create operator", err))
		return
	}
	v, err := h.operatorView(r, sys.ID, op)
	if err != nil {
		Fail(w, internalError(h, r, "create operator", err))
		return
	}
	h.audit(r, "invite operator", "user_id", u.UserID)
	writeJSON(w, http.StatusCreated, mgmtapi.OperatorInvite{UserId: v.UserId, Email: v.Email, Tenants: v.Tenants, CreatedAt: v.CreatedAt, SetupUrl: link})
}

// DeleteOperator removes an operator and ends their sessions and refresh
// tokens; the user stays. The last operator stays.
func (h *Handlers) DeleteOperator(w http.ResponseWriter, r *http.Request, id string) {
	sys := resolved(r)
	now := h.now()
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		// Bump the user first: it locks the user, so a grant minting for
		// the operator runs wholly before this (and its tokens are revoked
		// below) or after it (and its version check refuses it).
		if _, err := tx.Users().BumpVersion(r.Context(), sys.ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := tx.Operators().Get(r.Context(), sys.ID, id); errors.Is(err, store.ErrNotFound) {
			return errOperatorNotFound
		} else if err != nil {
			return err
		}
		ops, err := tx.Operators().List(r.Context(), sys.ID)
		if err != nil {
			return err
		}
		if len(ops) <= 1 {
			return errLastOperatorRemove
		}
		if err := tx.Operators().Delete(r.Context(), sys.ID, id); err != nil {
			return err
		}
		if _, err := tx.RefreshTokens().RevokeByUser(r.Context(), sys.ID, id, now); err != nil {
			return err
		}
		_, err = tx.Sessions().DeleteByUser(r.Context(), sys.ID, id)
		return err
	})
	if err != nil {
		h.failTx(w, r, "delete operator", err)
		return
	}
	h.audit(r, "remove operator", "user_id", id)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
