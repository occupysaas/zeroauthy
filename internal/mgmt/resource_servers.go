package mgmt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// resourceServerIDBytes makes IDs of 24 hexadecimal characters, the shape of
// Auth0's (A1).
const resourceServerIDBytes = 12

var errResourceServerNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_resource_server", Message: "The resource server does not exist"}

// GetResourceServers lists the tenant's APIs in creation order, the system
// API first (A7).
func (h *Handlers) GetResourceServers(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetResourceServersParams) {
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	q := r.URL.Query()
	if q.Has("from") || q.Has("take") {
		Fail(w, badQuery("Query validation error: checkpoint pagination (from, take) is not supported"))
		return
	}
	identifiers := q["identifiers"]
	all, err := h.Store.ResourceServers().List(r.Context(), resolved(r).ID)
	if err != nil {
		Fail(w, internalError(h, r, "list resource servers", err))
		return
	}
	// The store orders by creation; the system API goes first whenever it
	// was created.
	slices.SortStableFunc(all, func(a, b *store.ResourceServer) int {
		switch {
		case a.IsSystem && !b.IsSystem:
			return -1
		case !a.IsSystem && b.IsSystem:
			return 1
		}
		return 0
	})
	out := make([]map[string]any, 0, len(all))
	for _, rs := range all {
		if len(identifiers) > 0 && !slices.Contains(identifiers, rs.Identifier) {
			continue
		}
		out = append(out, ProjectKeeping(resourceServerView(rs), fields, include, nil))
	}
	WriteList(w, "resource_servers", out, page, perPage, totals)
}

// GetResourceServer returns one API, by ID or by identifier (D-0041).
func (h *Handlers) GetResourceServer(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetResourceServerParams) {
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	rs, err := h.Store.ResourceServers().Get(r.Context(), tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		rs, err = h.Store.ResourceServers().GetByIdentifier(r.Context(), tn.ID, id)
	}
	if errors.Is(err, store.ErrNotFound) {
		// auth0-cli escapes the identifier and its HTTP client escapes the
		// path again, so the server sees it still percent-encoded once.
		if once, uerr := url.PathUnescape(id); uerr == nil && once != id {
			rs, err = h.Store.ResourceServers().GetByIdentifier(r.Context(), tn.ID, once)
		}
	}
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errResourceServerNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get resource server", err))
		return
	}
	writeJSON(w, http.StatusOK, ProjectKeeping(resourceServerView(rs), fields, include, nil))
}

// CreateResourceServer creates an API (D-0041). Its identifier is fixed
// from then on.
func (h *Handlers) CreateResourceServer(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, ok := body["identifier"]; !ok {
		Fail(w, badBody("Missing required property: identifier"))
		return
	}
	spec := apirules.Spec{TokenLifetime: apirules.DefaultTokenLifetime, TokenLifetimeForWeb: apirules.DefaultTokenLifetimeForWeb}
	if _, err := readResourceServerBody(body, &spec, true); err != nil {
		Fail(w, err)
		return
	}
	if err := normalizeResourceServer(&spec); err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	if err := apirules.Reserved(spec.Identifier, tenant.ManagementAPIIdentifier(tn, h.BaseDomain)); err != nil {
		Fail(w, &Error{Status: http.StatusBadRequest, Code: "reserved_identifier", Message: err.Error()})
		return
	}
	rs := &store.ResourceServer{
		TenantID: tn.ID, ID: secrets.RandomHex(resourceServerIDBytes), Identifier: spec.Identifier,
		CreatedAt: h.now(), Origin: store.OriginAPI,
	}
	apirules.Apply(rs, &spec)
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := tx.ResourceServers().GetByIdentifier(r.Context(), tn.ID, rs.Identifier); err == nil {
			return errResourceServerConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		err := tx.ResourceServers().Create(r.Context(), rs)
		if errors.Is(err, store.ErrConflict) {
			return errResourceServerConflict
		}
		return err
	})
	if err != nil {
		h.failTx(w, r, "create resource server", err)
		return
	}
	h.audit(r, "create resource server", "identifier", rs.Identifier, "id", rs.ID)
	writeJSON(w, http.StatusCreated, resourceServerView(rs))
}

var errResourceServerConflict = &Error{Status: http.StatusConflict, Code: "resource_server_conflict", Message: "A resource server with this identifier already exists"}

// UpdateResourceServer changes the settings the body names. scopes replaces
// the list, and a scope that goes is removed from the client grants that
// carry it (A5).
func (h *Handlers) UpdateResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	var out *store.ResourceServer
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		rs, err := tx.ResourceServers().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errResourceServerNotFound
		}
		if err != nil {
			return err
		}
		spec := apirules.FromResourceServer(rs)
		in, err := readResourceServerBody(body, &spec, false)
		if err != nil {
			return err
		}
		if err := normalizeResourceServer(&spec); err != nil {
			return err
		}
		if rs.IsSystem {
			if err := checkSystemUpdate(tn, rs, &spec, in); err != nil {
				return err
			}
		}
		removed := removedScopes(rs.Scopes, spec.Scopes)
		apirules.Apply(rs, &spec)
		if err := tx.ResourceServers().Update(r.Context(), rs); err != nil {
			return err
		}
		if len(removed) > 0 {
			if err := removeGrantScopes(r.Context(), tx, tn.ID, rs.Identifier, removed, h.now().UTC()); err != nil {
				return err
			}
		}
		out = rs
		return nil
	})
	if err != nil {
		h.failTx(w, r, "update resource server", err)
		return
	}
	h.audit(r, "update resource server", "id", id)
	writeJSON(w, http.StatusOK, resourceServerView(out))
}

// DeleteResourceServer deletes an API with its client grants and user
// grants, and ends its refresh tokens (the store cascades). When the API is the tenant's
// default audience, the tenant has none afterwards (D-0041). Access tokens
// already issued stay valid until they expire. An unknown ID is 204 too (A6).
func (h *Handlers) DeleteResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	tn := resolved(r)
	deleted, clearedDefault := false, false
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		rs, err := tx.ResourceServers().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if rs.IsSystem {
			return &Error{Status: http.StatusBadRequest, Code: "delete_system_resource_server", Message: "A system resource server cannot be deleted"}
		}
		if t, err := tx.Tenants().Get(r.Context(), tn.ID); err == nil && t.DefaultAudience == rs.Identifier {
			clearedDefault = true
		}
		if err := tx.ResourceServers().Delete(r.Context(), tn.ID, rs.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		deleted = true
		return nil
	})
	if err != nil {
		h.failTx(w, r, "delete resource server", err)
		return
	}
	if deleted {
		h.audit(r, "delete resource server", "id", id)
		if clearedDefault {
			h.log().InfoContext(r.Context(), "cleared the tenant default audience with its API", "tenant", tn.ID, "id", id)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// removeGrantScopes takes the removed scopes out of every client grant for
// audience, and from every user grant (consent) for it, so nothing names a
// scope its API no longer defines (Plan 14 review focus 3). The grants stay,
// even with no scope left.
func removeGrantScopes(ctx context.Context, st store.Store, tenantID, audience string, removed []string, now time.Time) error {
	grants, _, err := st.ClientGrants().List(ctx, tenantID, store.ClientGrantFilter{Audience: audience}, store.Page{})
	if err != nil {
		return err
	}
	for _, g := range grants {
		kept := slices.DeleteFunc(slices.Clone(g.Scopes), func(s string) bool { return slices.Contains(removed, s) })
		if len(kept) == len(g.Scopes) {
			continue
		}
		g.Scopes = kept
		if err := st.ClientGrants().Update(ctx, g); err != nil {
			return err
		}
	}
	consents, err := st.UserGrants().ListByAudience(ctx, tenantID, audience)
	if err != nil {
		return err
	}
	for _, g := range consents {
		kept := slices.DeleteFunc(slices.Clone(g.Scopes), func(s string) bool { return slices.Contains(removed, s) })
		if len(kept) == len(g.Scopes) {
			continue
		}
		g.Scopes = kept
		g.UpdatedAt = now
		if _, err := st.UserGrants().Upsert(ctx, g); err != nil {
			return err
		}
	}
	return nil
}

// removedScopes lists the values in before that after no longer has.
func removedScopes(before, after []store.Scope) []string {
	var out []string
	for _, s := range before {
		if !slices.ContainsFunc(after, func(a store.Scope) bool { return a.Value == s.Value }) {
			out = append(out, s.Value)
		}
	}
	return out
}

// checkSystemUpdate refuses the changes a system API cannot take (A4):
// a name, other scopes, and the settings zeroauthy depends on. Naming one
// of those with its current value is accepted, since auth0-deploy-cli sends
// back what it read.
//   - A tenant's Management API keeps its scopes and its user policy (a
//     tenant user must never get a token for it).
//   - The system tenant's urn:zeroauthy:management also keeps offline
//     access (the console refreshes with it), skipped consent and both
//     policies (machine clients must never get operator tokens).
func checkSystemUpdate(tn *store.Tenant, rs *store.ResourceServer, spec *apirules.Spec, in resourceServerBody) error {
	if spec.EnforcePolicies || spec.TokenDialect != "access_token" {
		return badBody("RBAC settings cannot change for system APIs")
	}
	if in.name {
		return badBody("name: a system API cannot be renamed")
	}
	if !slices.Equal(rs.Scopes, spec.Scopes) {
		return badBody("scopes: the scopes of a system API cannot change")
	}
	sta := rs.SubjectTypeAuthorization
	if spec.SubjectTypeAuthorization.User != sta.User {
		return badBody("subject_type_authorization.user.policy: cannot change for a system API")
	}
	if !tn.Reserved {
		return nil
	}
	switch {
	case spec.AllowOfflineAccess != rs.AllowOfflineAccess:
		return badBody("allow_offline_access: cannot change for this system API")
	case *spec.SkipConsentForVerifiableFirstPartyClients != rs.SkipConsentForVerifiableFirstPartyClients:
		return badBody("skip_consent_for_verifiable_first_party_clients: cannot change for this system API")
	case spec.SubjectTypeAuthorization.Client != sta.Client:
		return badBody("subject_type_authorization.client.policy: cannot change for this system API")
	}
	return nil
}

func normalizeResourceServer(s *apirules.Spec) error {
	if errs := apirules.Normalize(s); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return badBody("%s", strings.Join(msgs, "; "))
	}
	return nil
}

// resourceServerView is rs in Auth0's shape: name, scopes and is_system are
// absent when empty (A1).
func resourceServerView(rs *store.ResourceServer) mgmtapi.ResourceServer {
	v := mgmtapi.ResourceServer{
		Id: rs.ID, Identifier: rs.Identifier,
		SigningAlg:         mgmtapi.ResourceServerSigningAlgRS256,
		TokenLifetime:      cmp.Or(rs.TokenLifetime, apirules.DefaultTokenLifetime),
		AllowOfflineAccess: rs.AllowOfflineAccess,
		SkipConsentForVerifiableFirstPartyClients: rs.SkipConsentForVerifiableFirstPartyClients,
		TokenLifetimeForWeb:                       cmp.Or(rs.TokenLifetimeForWeb, apirules.DefaultTokenLifetimeForWeb),
		EnforcePolicies:                           rs.EnforcePolicies,
		TokenDialect:                              mgmtapi.ResourceServerTokenDialect(cmp.Or(rs.TokenDialect, "access_token")),
	}
	user, client := rs.SubjectTypeAuthorization.User, rs.SubjectTypeAuthorization.Client
	if user == "" {
		user = store.PolicyAllowAll
	}
	if client == "" {
		client = store.PolicyRequireClientGrant
	}
	v.SubjectTypeAuthorization.User.Policy = mgmtapi.ResourceServerSubjectTypeAuthorizationUserPolicy(user)
	v.SubjectTypeAuthorization.Client.Policy = mgmtapi.ResourceServerSubjectTypeAuthorizationClientPolicy(client)
	if rs.Name != "" {
		name := rs.Name
		v.Name = &name
	}
	if rs.IsSystem {
		t := true
		v.IsSystem = &t
	}
	if len(rs.Scopes) > 0 {
		scopes := make([]mgmtapi.ResourceServerScope, len(rs.Scopes))
		for i, s := range rs.Scopes {
			desc := s.Description
			scopes[i] = mgmtapi.ResourceServerScope{Value: s.Value, Description: &desc}
		}
		v.Scopes = &scopes
	}
	return v
}

// resourceServerBody is what readResourceServerBody learned beyond the Spec.
type resourceServerBody struct {
	name bool
}

// readResourceServerBody applies body's fields to s, in name order so that
// the first error reported is stable. identifier is accepted on create only;
// on update it, id and is_system are unknown properties (A3).
func readResourceServerBody(body map[string]json.RawMessage, s *apirules.Spec, create bool) (resourceServerBody, error) {
	var out resourceServerBody
	for _, k := range slices.Sorted(maps.Keys(body)) {
		raw := body[k]
		var err error
		switch k {
		case "identifier":
			if !create {
				return out, badBody("unknown property %q", k)
			}
			err = decodeString(raw, &s.Identifier)
		case "name":
			err, out.name = decodeString(raw, &s.Name), true
			if err == nil && s.Name == "" {
				err = fmt.Errorf("must be 1 to %d characters", apirules.MaxName)
			}
		case "scopes":
			err = readResourceServerScopes(raw, s)
		case "signing_alg":
			var alg string
			if err = decodeString(raw, &alg); err == nil && alg != apirules.SigningAlg {
				err = fmt.Errorf("%q is not supported (%s only)", alg, apirules.SigningAlg)
			}
		case "signing_secret":
			err = errors.New("is not supported (zeroauthy signs access tokens with RS256 only)")
		case "token_lifetime":
			err = decodeLifetime(raw, &s.TokenLifetime)
		case "token_lifetime_for_web":
			err = decodeLifetime(raw, &s.TokenLifetimeForWeb)
			s.CheckWebLifetime = true
		case "allow_offline_access":
			err = decodeStrict(raw, &s.AllowOfflineAccess)
		case "skip_consent_for_verifiable_first_party_clients":
			var v bool
			err = decodeStrict(raw, &v)
			s.SkipConsentForVerifiableFirstPartyClients = &v
		case "subject_type_authorization":
			err = readSubjectTypeAuthorization(raw, &s.SubjectTypeAuthorization)
		case "enforce_policies":
			err = decodeStrict(raw, &s.EnforcePolicies)
		case "token_dialect":
			err = decodeString(raw, &s.TokenDialect)
		case "consent_policy", "proof_of_possession", "token_encryption":
			if !isNull(raw) {
				err = errors.New("is not supported; only null is accepted")
			}
		case "authorization_details":
			var v []json.RawMessage
			if !isNull(raw) && (json.Unmarshal(raw, &v) != nil || len(v) > 0) {
				err = errors.New("is not supported; only null or an empty list is accepted")
			}
		default:
			return out, badBody("unknown property %q", k)
		}
		if err != nil {
			return out, badBody("%s: %v", k, err)
		}
	}
	return out, nil
}

// decodeLifetime reads a token lifetime: an integer from 1 to
// apirules.MaxTokenLifetime (Normalize treats zero as "the default", so an
// explicit zero is refused here).
func decodeLifetime(raw json.RawMessage, dst *int) error {
	var n int
	if isNull(raw) || json.Unmarshal(raw, &n) != nil {
		return errors.New("must be an integer")
	}
	if n < 1 || n > apirules.MaxTokenLifetime {
		return fmt.Errorf("must be 1 to %d seconds", apirules.MaxTokenLifetime)
	}
	*dst = n
	return nil
}

// readResourceServerScopes replaces s.Scopes with the list in raw.
func readResourceServerScopes(raw json.RawMessage, s *apirules.Spec) error {
	var in []struct {
		Value       *string `json:"value"`
		Description string  `json:"description"`
	}
	if err := decodeStrict(raw, &in); err != nil {
		return err
	}
	scopes := make([]store.Scope, len(in))
	for i, sc := range in {
		if sc.Value == nil {
			return errors.New("every scope needs a value")
		}
		scopes[i] = store.Scope{Value: *sc.Value, Description: sc.Description}
	}
	s.Scopes = scopes
	return nil
}

// readSubjectTypeAuthorization merges the policies in raw into sta: a
// subject type that is not named keeps its policy.
func readSubjectTypeAuthorization(raw json.RawMessage, sta *store.SubjectTypeAuthorization) error {
	type policy struct {
		Policy *string `json:"policy"`
	}
	var in struct {
		User   *policy `json:"user"`
		Client *policy `json:"client"`
	}
	if err := decodeStrict(raw, &in); err != nil {
		return err
	}
	if in.User != nil && in.User.Policy != nil {
		sta.User = *in.User.Policy
	}
	if in.Client != nil && in.Client.Policy != nil {
		sta.Client = *in.Client.Policy
	}
	return nil
}
