package mgmt

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/apirules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// clientGrantIDLength is the number of letters and digits after "cgr_" in
// the ID of a grant created through the API (A8).
const clientGrantIDLength = 16

// Checkpoint paging (A9): take is 1 to maxTake, defaulting to
// DefaultPerPage.
const maxTake = 100

// maxClientIDFilter bounds a client_id filter. zeroauthy client IDs are
// whatever the seed names (the API makes 32 letters and digits), so the
// filter refuses only what cannot be an ID: empty, very long, or holding
// whitespace or control characters.
const maxClientIDFilter = 255

// clientGrantID is the form of a grant ID. The seed's older grants have 24
// characters after "cgr_", so any length up to the bound is accepted.
var clientGrantID = regexp.MustCompile(`^cgr_[A-Za-z0-9]{1,64}$`)

var (
	errClientGrantNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_client_grant", Message: "The client grant does not exist"}
	errClientGrantConflict = &Error{Status: http.StatusConflict, Code: "client_grant_conflict", Message: "A client grant for this client, audience and subject type already exists"}
	errBadGrantID          = &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the client grant ID is malformed"}
)

// noCode is a 400 without an errorCode, as Auth0 answers a bad checkpoint
// cursor and a subject_type filter on its own (A9).
func noCode(message string) *Error {
	return &Error{Status: http.StatusBadRequest, Message: "Query validation error: " + message}
}

// GetClientGrants lists the tenant's client grants in ID order, by offset or
// by checkpoint (A9).
func (h *Handlers) GetClientGrants(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetClientGrantsParams) {
	q := r.URL.Query()
	checkpoint := q.Has("take") || q.Has("from")
	f := store.ClientGrantFilter{ClientID: q.Get("client_id"), Audience: q.Get("audience"), SubjectType: q.Get("subject_type")}
	if q.Has("client_id") && !validClientIDFilter(f.ClientID) {
		Fail(w, badQuery("Query validation error: client_id is malformed"))
		return
	}
	if q.Has("subject_type") && f.SubjectType != store.SubjectTypeClient && f.SubjectType != store.SubjectTypeUser {
		Fail(w, badQuery("Query validation error: subject_type must be client or user"))
		return
	}
	if f.SubjectType != "" && f.ClientID == "" && f.Audience == "" {
		Fail(w, noCode("subject_type needs client_id or audience"))
		return
	}
	tn := resolved(r)
	if checkpoint {
		h.checkpointClientGrants(w, r, tn.ID, f)
		return
	}
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	got, total, err := h.Store.ClientGrants().List(r.Context(), tn.ID, f, store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		Fail(w, internalError(h, r, "list client grants", err))
		return
	}
	out := clientGrantViews(got)
	if !totals {
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client_grants": out, "start": page * perPage, "limit": perPage, "total": total})
}

// checkpointClientGrants answers one page after the cursor in from. It asks
// for one grant more than take to know whether another page follows. The
// cursor names the last grant returned, and the next page lists the grants
// whose ID sorts after it, so a grant added or deleted meanwhile neither
// repeats nor skips another. The cursor carries no tenant: the listing is
// always of the caller's tenant, so a cursor cannot reach another's data.
func (h *Handlers) checkpointClientGrants(w http.ResponseWriter, r *http.Request, tenantID string, f store.ClientGrantFilter) {
	q := r.URL.Query()
	take := DefaultPerPage
	if v := q.Get("take"); q.Has("take") {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTake {
			Fail(w, badQuery("Query validation error: take must be an integer from 1 to %d", maxTake))
			return
		}
		take = n
	}
	if from := q.Get("from"); from != "" {
		id, ok := decodeGrantCursor(from)
		if !ok {
			Fail(w, noCode("from is not a valid checkpoint"))
			return
		}
		f.AfterID = id
	}
	got, _, err := h.Store.ClientGrants().List(r.Context(), tenantID, f, store.Page{Limit: take + 1})
	if err != nil {
		Fail(w, internalError(h, r, "list client grants", err))
		return
	}
	out := map[string]any{}
	if len(got) > take {
		got = got[:take]
		out["next"] = encodeGrantCursor(got[take-1].ID)
	}
	out["client_grants"] = clientGrantViews(got)
	writeJSON(w, http.StatusOK, out)
}

const cursorPrefix = "v1:"

func encodeGrantCursor(lastID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + lastID))
}

func decodeGrantCursor(from string) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(from)
	id, ok := strings.CutPrefix(string(b), cursorPrefix)
	if err != nil || !ok || !clientGrantID.MatchString(id) {
		return "", false
	}
	return id, true
}

func validClientIDFilter(id string) bool {
	if id == "" || len(id) > maxClientIDFilter {
		return false
	}
	return !strings.ContainsFunc(id, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// GetClientGrant returns one client grant.
func (h *Handlers) GetClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	if !clientGrantID.MatchString(id) {
		Fail(w, errBadGrantID)
		return
	}
	g, err := findClientGrant(r, h.Store, resolved(r).ID, id)
	if err != nil {
		h.failTx(w, r, "get client grant", err)
		return
	}
	writeJSON(w, http.StatusOK, clientGrantView(g))
}

// findClientGrant returns the tenant's grant with the ID.
func findClientGrant(r *http.Request, st store.Store, tenantID, id string) (*store.ClientGrant, error) {
	got, _, err := st.ClientGrants().List(r.Context(), tenantID, store.ClientGrantFilter{ID: id}, store.Page{Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(got) == 0 {
		return nil, errClientGrantNotFound
	}
	return got[0], nil
}

// grantBody is what a create or update body says.
type grantBody struct {
	clientID, audience string
	subjectType        string
	scopes             []string
	scopeSet           bool
	allowAll           bool
	allowAllSet        bool
}

// readClientGrantBody reads body in name order so that the first error
// reported is stable. client_id, audience and subject_type are accepted on
// create only; on update they are unknown properties (A10).
func readClientGrantBody(body map[string]json.RawMessage, create bool) (grantBody, error) {
	var out grantBody
	for _, k := range slices.Sorted(maps.Keys(body)) {
		raw := body[k]
		var err error
		switch k {
		case "client_id", "audience", "subject_type":
			if !create {
				return out, badBody("unknown property %q", k)
			}
			switch k {
			case "client_id":
				err = decodeString(raw, &out.clientID)
			case "audience":
				err = decodeString(raw, &out.audience)
			default:
				if err = decodeString(raw, &out.subjectType); err == nil && out.subjectType != store.SubjectTypeClient && out.subjectType != store.SubjectTypeUser {
					err = errors.New("must be client or user")
				}
			}
		case "scope":
			if isNull(raw) {
				err = errors.New("must be a list of strings")
			} else {
				err = decodeStrings(raw, &out.scopes)
			}
			out.scopeSet = true
		case "allow_all_scopes":
			err = decodeStrict(raw, &out.allowAll)
			out.allowAllSet = true
		// zeroauthy has no organizations or rich authorization requests
		// (D-0041): only the inert values are accepted, and none is stored.
		case "organization_usage":
			var v string
			if !isNull(raw) && (decodeString(raw, &v) != nil || v != "deny") {
				err = errors.New("zeroauthy has no organizations; only deny is supported")
			}
		case "allow_any_organization":
			var v bool
			if !isNull(raw) && (decodeStrict(raw, &v) != nil || v) {
				err = errors.New("zeroauthy has no organizations; only false is supported")
			}
		case "authorization_details_types":
			var v []json.RawMessage
			if !isNull(raw) && (json.Unmarshal(raw, &v) != nil || len(v) > 0) {
				err = errors.New("is not supported; only null or an empty list is accepted")
			}
		case "default_for":
			if !isNull(raw) {
				err = errors.New("is not supported; only null is accepted")
			}
		default:
			return out, badBody("unknown property %q", k)
		}
		if err != nil {
			return out, badBody("%s: %v", k, err)
		}
	}
	out.scopes = apirules.DedupeScopes(out.scopes)
	if out.allowAll && len(out.scopes) > 0 {
		return out, badBody("allow_all_scopes: cannot be true together with scope")
	}
	return out, nil
}

// CreateClientGrant creates a grant of scopes on an API to an application
// (A8, D-0041).
func (h *Handlers) CreateClientGrant(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	in, err := readClientGrantBody(body, true)
	if err != nil {
		Fail(w, err)
		return
	}
	switch {
	case in.clientID == "":
		Fail(w, badBody("Missing required property: client_id"))
		return
	case in.audience == "":
		Fail(w, badBody("Missing required property: audience"))
		return
	case !in.scopeSet && !in.allowAll:
		Fail(w, badBody("Missing required property: scope or allow_all_scopes"))
		return
	}
	if in.subjectType == "" {
		in.subjectType = store.SubjectTypeClient
	}
	tn := resolved(r)
	own := tenant.ManagementAPIIdentifier(tn, h.BaseDomain)
	if err := checkGrantAudience(in.audience); err != nil {
		Fail(w, err)
		return
	}
	g := &store.ClientGrant{
		TenantID: tn.ID, ID: "cgr_" + secrets.RandomString(clientGrantIDLength),
		ClientID: in.clientID, Audience: in.audience, SubjectType: in.subjectType,
		CreatedAt: h.now(), Origin: store.OriginAPI,
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		ctx := r.Context()
		if _, err := tx.Clients().Get(ctx, tn.ID, in.clientID); errors.Is(err, store.ErrNotFound) {
			return errClientNotFound
		} else if err != nil {
			return err
		}
		rs, err := tx.ResourceServers().GetByIdentifier(ctx, tn.ID, in.audience)
		if errors.Is(err, store.ErrNotFound) && in.audience == own {
			// The tenant's Management API is created with its first token;
			// an operator may grant it before then.
			rs, err = tenantsetup.ManagementAPI(ctx, tx, tn, h.BaseDomain, h.now())
		}
		if errors.Is(err, store.ErrNotFound) && apirules.IsManagementAPIIdentifier(in.audience) {
			// No API of this tenant has the identifier of a Management API
			// (Plan 14 review focus 1): it is another tenant's, which a
			// token of this tenant cannot reach.
			return badBody("audience: only this tenant's Management API (%s) can be granted", own)
		}
		if errors.Is(err, store.ErrNotFound) {
			return errResourceServerNotFound
		}
		if err != nil {
			return err
		}
		g.AllowAllScopes, g.Scopes = in.allowAll, in.scopes
		if err := checkGrant(g, rs, in.audience == own); err != nil {
			return err
		}
		if _, err := tx.ClientGrants().Find(ctx, tn.ID, g.ClientID, g.Audience, g.SubjectType); err == nil {
			return errClientGrantConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.ClientGrants().Create(ctx, g); errors.Is(err, store.ErrConflict) {
			return errClientGrantConflict
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		h.failTx(w, r, "create client grant", err)
		return
	}
	h.audit(r, "create client grant", "id", g.ID, "client_id", g.ClientID, "audience", g.Audience)
	writeJSON(w, http.StatusCreated, clientGrantView(g))
}

// checkGrantAudience refuses the audience no application may be granted:
// the system tenant's operator API. Another tenant's Management API is
// refused where the API is looked up (see CreateClientGrant), since the
// tenant may define an ordinary API whose identifier has that form.
func checkGrantAudience(audience string) error {
	if audience == tenant.OperatorAudience {
		return badBody("audience: %s is for console operators and cannot be granted to applications", audience)
	}
	return nil
}

// checkGrant validates g against its API with the rules the seed shares
// (apirules.CheckGrant). Scopes are checked against what the API defines
// now; a grant with AllowAllScopes keeps none and covers whatever the API
// defines when a token is issued, for the Management API its own scopes.
func checkGrant(g *store.ClientGrant, rs *store.ResourceServer, mgmt bool) error {
	defined := func(s string) bool {
		return slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == s })
	}
	errs := apirules.CheckGrant(g.SubjectType, mgmt, g.Scopes, defined)
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return badBody("%s", strings.Join(msgs, "; "))
}

// UpdateClientGrant changes a grant's scopes (A10). The scopes are checked
// against the API as on create; the organization fields are accepted when
// inert and not stored.
func (h *Handlers) UpdateClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	if !clientGrantID.MatchString(id) {
		Fail(w, errBadGrantID)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if len(body) == 0 {
		Fail(w, badBody("at least one property is required"))
		return
	}
	in, err := readClientGrantBody(body, false)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	own := tenant.ManagementAPIIdentifier(tn, h.BaseDomain)
	var out *store.ClientGrant
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		g, err := findClientGrant(r, tx, tn.ID, id)
		if err != nil {
			return err
		}
		if !in.scopeSet && !in.allowAllSet {
			out = g // only inert organization fields: nothing to change
			return nil
		}
		rs, err := tx.ResourceServers().GetByIdentifier(r.Context(), tn.ID, g.Audience)
		if errors.Is(err, store.ErrNotFound) {
			return errResourceServerNotFound
		}
		if err != nil {
			return err
		}
		next := *g
		switch {
		case in.allowAll:
			next.AllowAllScopes, next.Scopes = true, nil
		case in.scopeSet:
			next.AllowAllScopes, next.Scopes = false, in.scopes
		default: // allow_all_scopes false alone
			next.AllowAllScopes = false
		}
		if err := checkGrant(&next, rs, g.Audience == own); err != nil {
			return err
		}
		if err := tx.ClientGrants().Update(r.Context(), &next); err != nil {
			return err
		}
		out = &next
		return nil
	})
	if err != nil {
		h.failTx(w, r, "update client grant", err)
		return
	}
	h.audit(r, "update client grant", "id", id)
	writeJSON(w, http.StatusOK, clientGrantView(out))
}

// DeleteClientGrant deletes a grant. An unknown ID in the right format is
// 204 too (A10).
func (h *Handlers) DeleteClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	if !clientGrantID.MatchString(id) {
		Fail(w, errBadGrantID)
		return
	}
	err := h.Store.ClientGrants().Delete(r.Context(), resolved(r).ID, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		Fail(w, internalError(h, r, "delete client grant", err))
		return
	}
	if err == nil {
		h.audit(r, "delete client grant", "id", id)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// clientGrantView is g in Auth0's shape: allow_all_scopes replaces scope
// (A8).
func clientGrantView(g *store.ClientGrant) mgmtapi.ClientGrant {
	v := mgmtapi.ClientGrant{
		Id: g.ID, ClientId: g.ClientID, Audience: g.Audience,
		SubjectType: mgmtapi.ClientGrantSubjectType(cmp.Or(g.SubjectType, store.SubjectTypeClient)),
	}
	if g.AllowAllScopes {
		t := true
		v.AllowAllScopes = &t
		return v
	}
	scope := slices.Clone(g.Scopes)
	if scope == nil {
		scope = []string{}
	}
	v.Scope = &scope
	return v
}

func clientGrantViews(gs []*store.ClientGrant) []mgmtapi.ClientGrant {
	out := make([]mgmtapi.ClientGrant, len(gs))
	for i, g := range gs {
		out[i] = clientGrantView(g)
	}
	return out
}
