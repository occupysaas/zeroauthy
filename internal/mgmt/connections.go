package mgmt

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// connectionIDLength is the number of letters and digits after "con_" in the
// ID of a connection created through the API (D-0042).
const connectionIDLength = 16

// defaultConnectionsPerPage is the offset page size of the connection list
// (D-0042: 100, not the 50 of the other lists).
const defaultConnectionsPerPage = 100

// connectionID is the form of a connection ID. The seed's connections have
// their own lengths, so any length up to the bound is accepted.
var connectionID = regexp.MustCompile(`^con_[A-Za-z0-9]{1,64}$`)

var (
	errConnectionNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_connection", Message: "The connection does not exist"}
	errConnectionConflict = &Error{Status: http.StatusConflict, Code: "connection_conflict", Message: "A connection with this name already exists"}
	errBadConnectionID    = &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the connection ID is malformed"}
	// errNoSuchClient is the 400 Auth0 answers when a connection names an
	// application that does not exist (the application endpoints answer 404).
	errNoSuchClient = &Error{Status: http.StatusBadRequest, Code: "inexistent_client", Message: "The client does not exist"}
)

// alwaysConnectionFields are kept by every projection (D-0042).
var alwaysConnectionFields = []string{"id", "is_domain_connection"}

// settingsKeys are the top-level properties a connection takes on create and
// update. name, strategy and enabled_clients are for create only.
var settingsKeys = []string{"options", "is_domain_connection", "display_name", "realms", "metadata", "show_as_button", "connected_accounts", "authentication"}

// GetConnections lists the tenant's connections by name, by offset or by
// checkpoint (D-0042).
func (h *Handlers) GetConnections(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetConnectionsParams) {
	q := r.URL.Query()
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	f := store.ConnectionFilter{Name: q.Get("name"), Strategies: q["strategy"]}
	tn := resolved(r)
	if q.Has("take") || q.Has("from") {
		h.checkpointConnections(w, r, tn.ID, f, fields, include)
		return
	}
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if q.Get("per_page") == "" {
		perPage = defaultConnectionsPerPage
	}
	got, total, err := h.Store.Connections().List(r.Context(), tn.ID, f, store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		Fail(w, internalError(h, r, "list connections", err))
		return
	}
	out, err := h.connectionViews(got, fields, include)
	if err != nil {
		Fail(w, internalError(h, r, "list connections", err))
		return
	}
	if !totals {
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out, "start": page * perPage, "limit": perPage, "total": total})
}

// checkpointConnections answers one page after the cursor in from. The
// cursor holds the sort key (lower-case name, ID) of the last connection
// returned and the next page lists those that sort after it, so a connection
// added or deleted meanwhile, the cursor's own included, neither repeats nor
// skips another. It names no tenant: the listing is always of the caller's.
func (h *Handlers) checkpointConnections(w http.ResponseWriter, r *http.Request, tenantID string, f store.ConnectionFilter, fields []string, include bool) {
	q := r.URL.Query()
	take, err := takeParam(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var after *connectionCursor
	if from := q.Get("from"); from != "" {
		if after = decodeConnectionCursor(from); after == nil {
			Fail(w, badQuery("Query validation error: from is not a valid checkpoint"))
			return
		}
	}
	all, _, err := h.Store.Connections().List(r.Context(), tenantID, f, store.Page{})
	if err != nil {
		Fail(w, internalError(h, r, "list connections", err))
		return
	}
	if after != nil {
		all = slices.DeleteFunc(all, func(c *store.Connection) bool {
			return cmp.Or(strings.Compare(strings.ToLower(c.Name), after.Name), strings.Compare(c.ID, after.ID)) <= 0
		})
	}
	out := map[string]any{}
	if len(all) > take {
		all = all[:take]
		last := all[take-1]
		out["next"] = encodeConnectionCursor(connectionCursor{Name: strings.ToLower(last.Name), ID: last.ID})
	}
	views, err := h.connectionViews(all, fields, include)
	if err != nil {
		Fail(w, internalError(h, r, "list connections", err))
		return
	}
	out["connections"] = views
	writeJSON(w, http.StatusOK, out)
}

// takeParam reads the checkpoint page size: 1 to maxTake, DefaultPerPage
// when absent.
func takeParam(r *http.Request) (int, error) {
	q := r.URL.Query()
	if !q.Has("take") {
		return DefaultPerPage, nil
	}
	n, err := strconv.Atoi(q.Get("take"))
	if err != nil || n < 1 || n > maxTake {
		return 0, badQuery("Query validation error: take must be an integer from 1 to %d", maxTake)
	}
	return n, nil
}

type connectionCursor struct {
	Name string `json:"n"`
	ID   string `json:"i"`
}

const maxCursorName = 1024

func encodeConnectionCursor(c connectionCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + string(b)))
}

func decodeConnectionCursor(from string) *connectionCursor {
	b, err := base64.RawURLEncoding.DecodeString(from)
	raw, ok := strings.CutPrefix(string(b), cursorPrefix)
	if err != nil || !ok {
		return nil
	}
	var c connectionCursor
	if json.Unmarshal([]byte(raw), &c) != nil || !connectionID.MatchString(c.ID) || len(c.Name) > maxCursorName {
		return nil
	}
	return &c
}

// GetConnection returns one connection, without enabled_clients.
func (h *Handlers) GetConnection(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetConnectionParams) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	c, err := h.Store.Connections().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get connection", err))
		return
	}
	views, err := h.connectionViews([]*store.Connection{c}, fields, include)
	if err != nil {
		Fail(w, internalError(h, r, "get connection", err))
		return
	}
	writeJSON(w, http.StatusOK, views[0])
}

// connectionViews renders connections in Auth0's shape, projected by fields.
func (h *Handlers) connectionViews(cs []*store.Connection, fields []string, include bool) ([]map[string]any, error) {
	out := make([]map[string]any, len(cs))
	for i, c := range cs {
		v, err := h.connectionView(c, false)
		if err != nil {
			return nil, err
		}
		out[i] = ProjectKeeping(v, fields, include, alwaysConnectionFields)
	}
	return out, nil
}

// connectionView is c in Auth0's shape. options.configuration holds one
// opaque blob per stored value, never the plaintext. enabled_clients is
// included for create only.
func (h *Handlers) connectionView(c *store.Connection, withClients bool) (map[string]any, error) {
	spec := connrules.FromConnection(c)
	if len(c.ConfigurationSealed) > 0 {
		cfg, err := keys.OpenConnectionConfig(h.Wrapper, c.TenantID, c.ID, c.ConfigurationSealed)
		if err != nil {
			return nil, err
		}
		blobs := make(map[string]*string, len(cfg))
		for k, v := range cfg {
			blob, err := keys.SealConfigValue(h.Wrapper, c.TenantID, c.ID, k, v)
			if err != nil {
				return nil, err
			}
			blobs[k] = &blob
		}
		spec.Options.Configuration = blobs
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["id"] = c.ID
	if !withClients {
		delete(m, "enabled_clients")
	}
	return m, nil
}

// readConnectionBody reads a create or update body into a Spec. The keys it
// names are returned, since a PATCH changes only those. name, strategy and
// enabled_clients are unknown properties on update (D-0042).
func readConnectionBody(body map[string]json.RawMessage, create bool) (*connrules.Spec, map[string]bool, error) {
	allowed := settingsKeys
	if create {
		allowed = append([]string{"name", "strategy", "enabled_clients"}, settingsKeys...)
	}
	set := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(body)) {
		if !slices.Contains(allowed, k) {
			return nil, nil, badBody("unknown property %q", k)
		}
		set[k] = true
	}
	if raw, ok := body["options"]; ok && !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, nil, badBody("options: must be an object")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, nil, badBody("the body must be a JSON object")
	}
	var spec connrules.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, badBody("a property has the wrong type: %v", cleanJSONError(err))
	}
	if spec.EnabledClients != nil {
		var ids []string
		for _, id := range spec.EnabledClients {
			if !validClientIDFilter(id) {
				return nil, nil, badBody("enabled_clients: %q is not a client ID", id)
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		spec.EnabledClients = ids
	}
	return &spec, set, nil
}

// cleanJSONError drops Go type names from a decoding error.
func cleanJSONError(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		field := te.Field
		if field == "" {
			field = "value"
		}
		return fmt.Sprintf("%s must be a JSON %s", field, jsonKind(te.Type.Kind().String()))
	}
	return "malformed JSON"
}

func jsonKind(goKind string) string {
	switch goKind {
	case "string":
		return "string"
	case "bool":
		return "boolean"
	case "map", "struct":
		return "object"
	case "slice":
		return "array"
	}
	return "number"
}

// resolveConfiguration turns the configuration a body names into the
// plaintext map to seal. A value that is a blob this API returned for the
// key keeps the stored secret; any other string is new plaintext; null
// removes the key. A blob that does not open for this connection and key, or
// is not the key's current value (stale, or another key's), is refused:
// storing a ciphertext as a secret would be a silent mistake.
func (h *Handlers) resolveConfiguration(tenantID, id string, in map[string]*string, current map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(in)) {
		v := in[k]
		if v == nil {
			continue
		}
		if !keys.IsConfigValueBlob(*v) {
			out[k] = *v
			continue
		}
		plain, err := keys.OpenConfigValue(h.Wrapper, tenantID, id, k, *v)
		cur, has := current[k]
		if err != nil || !has || plain != cur {
			return nil, badBody("options.configuration.%s: not the encrypted value this API returned for the key; send the new value in plain text", k)
		}
		out[k] = cur
	}
	return out, nil
}

// currentConfiguration opens c's stored configuration.
func (h *Handlers) currentConfiguration(c *store.Connection) (map[string]string, error) {
	if len(c.ConfigurationSealed) == 0 {
		return map[string]string{}, nil
	}
	return keys.OpenConnectionConfig(h.Wrapper, c.TenantID, c.ID, c.ConfigurationSealed)
}

// setPlainConfiguration replaces the spec's configuration with plain, so the
// limits are checked on the real values (a blob is longer than its value).
func setPlainConfiguration(s *connrules.Spec, plain map[string]string) {
	if len(plain) == 0 {
		s.Options.Configuration = nil
		return
	}
	cfg := make(map[string]*string, len(plain))
	for k, v := range plain {
		cfg[k] = &v
	}
	s.Options.Configuration = cfg
}

func normalizeConnection(s *connrules.Spec) error {
	if s.Federated() {
		// Plan 24 Task 4 seals provider credentials before writes; until
		// then federated strategies stay unavailable through the API.
		return badBody("strategy %q is not supported", s.Strategy)
	}
	errs := connrules.NormalizeAPI(s)
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return badBody("%s", strings.Join(msgs, "; "))
}

// checkClientsExist refuses an application the tenant does not have, another
// tenant's included (the lookup is tenant-scoped).
func checkClientsExist(r *http.Request, st store.Store, tenantID string, ids []string) error {
	for _, id := range ids {
		if _, err := st.Clients().Get(r.Context(), tenantID, id); errors.Is(err, store.ErrNotFound) {
			return errNoSuchClient
		} else if err != nil {
			return err
		}
	}
	return nil
}

// CreateConnection creates a database connection (D-0042).
func (h *Handlers) CreateConnection(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	spec, _, err := readConnectionBody(body, true)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	c := &store.Connection{
		TenantID: tn.ID, ID: "con_" + secrets.RandomString(connectionIDLength),
		CreatedAt: h.now(), Origin: store.OriginAPI,
	}
	plain, err := h.resolveConfiguration(tn.ID, c.ID, spec.Options.Configuration, nil)
	if err != nil {
		Fail(w, err)
		return
	}
	setPlainConfiguration(spec, plain)
	connrules.CreateDefaults(spec)
	if err := normalizeConnection(spec); err != nil {
		Fail(w, err)
		return
	}
	connrules.Apply(spec, c)
	if c.ConfigurationSealed, err = h.sealConfiguration(c, plain); err != nil {
		Fail(w, internalError(h, r, "seal connection configuration", err))
		return
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if err := checkClientsExist(r, tx, tn.ID, c.EnabledClients); err != nil {
			return err
		}
		if err := tx.Connections().Create(r.Context(), c); errors.Is(err, store.ErrConflict) {
			return errConnectionConflict
		} else {
			return err
		}
	})
	if err != nil {
		h.failTx(w, r, "create connection", err)
		return
	}
	view, err := h.connectionView(c, true)
	if err != nil {
		Fail(w, internalError(h, r, "create connection", err))
		return
	}
	h.audit(r, "create connection", "id", c.ID, "name", c.Name)
	writeJSON(w, http.StatusCreated, view)
}

func (h *Handlers) sealConfiguration(c *store.Connection, plain map[string]string) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	if h.Wrapper == nil {
		return nil, errors.New("no master key wrapper to seal the configuration")
	}
	return keys.SealConnectionConfig(h.Wrapper, c.TenantID, c.ID, plain)
}

// UpdateConnection changes a connection. options, when sent, replaces the
// stored options whole; the other properties change only when named
// (D-0042, C3).
func (h *Handlers) UpdateConnection(w http.ResponseWriter, r *http.Request, id string) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
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
	patch, set, err := readConnectionBody(body, false)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	var out *store.Connection
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		c, err := tx.Connections().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errConnectionNotFound
		}
		if err != nil {
			return err
		}
		spec := connrules.FromConnection(c)
		if set["is_domain_connection"] {
			spec.IsDomainConnection = patch.IsDomainConnection
		}
		if set["display_name"] {
			spec.DisplayName = patch.DisplayName
		}
		if set["realms"] {
			spec.Realms = patch.Realms
		}
		if set["metadata"] {
			spec.Metadata = patch.Metadata
		}
		if set["show_as_button"] {
			spec.ShowAsButton = patch.ShowAsButton
		}
		if set["connected_accounts"] {
			spec.ConnectedAccounts = patch.ConnectedAccounts
		}
		if set["authentication"] {
			spec.Authentication = patch.Authentication
		}
		var plain map[string]string
		if set["options"] {
			current, err := h.currentConfiguration(c)
			if err != nil {
				return err
			}
			if plain, err = h.resolveConfiguration(tn.ID, id, patch.Options.Configuration, current); err != nil {
				return err
			}
			spec.Options = patch.Options
			setPlainConfiguration(spec, plain)
		}
		if err := normalizeConnection(spec); err != nil {
			return err
		}
		next := *c
		connrules.Apply(spec, &next)
		if set["options"] {
			if next.ConfigurationSealed, err = h.sealConfiguration(&next, plain); err != nil {
				return err
			}
		}
		if err := tx.Connections().Update(r.Context(), &next); err != nil {
			return err
		}
		out = &next
		return nil
	})
	if err != nil {
		h.failTx(w, r, "update connection", err)
		return
	}
	view, err := h.connectionView(out, false)
	if err != nil {
		Fail(w, internalError(h, r, "update connection", err))
		return
	}
	h.audit(r, "update connection", "id", id)
	writeJSON(w, http.StatusOK, view)
}

// DeleteConnection deletes a connection with its users (the store cascades),
// and clears the tenant's default_directory when it names it. A connection
// already deleted answers 204 (D-0042).
func (h *Handlers) DeleteConnection(w http.ResponseWriter, r *http.Request, id string) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	err := h.Store.Connections().Delete(r.Context(), resolved(r).ID, id)
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, store.ErrNotFound):
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		Fail(w, internalError(h, r, "delete connection", err))
	default:
		h.audit(r, "delete connection", "id", id)
		writeJSON(w, http.StatusAccepted, map[string]any{"deleted_at": h.now().Format(time.RFC3339)})
	}
}

// GetConnectionClients lists the applications enabled on a connection in
// client ID order, by checkpoint.
func (h *Handlers) GetConnectionClients(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetConnectionClientsParams) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	take, err := takeParam(r)
	if err != nil {
		Fail(w, err)
		return
	}
	after, hasAfter := "", false
	if from := r.URL.Query().Get("from"); from != "" {
		b, err := base64.RawURLEncoding.DecodeString(from)
		after, hasAfter = strings.CutPrefix(string(b), cursorPrefix)
		if err != nil || !hasAfter || !validClientIDFilter(after) {
			Fail(w, badQuery("Query validation error: from is not a valid checkpoint"))
			return
		}
	}
	c, err := h.Store.Connections().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get connection clients", err))
		return
	}
	ids := slices.Sorted(slices.Values(c.EnabledClients))
	if hasAfter {
		ids = slices.DeleteFunc(ids, func(s string) bool { return s <= after })
	}
	out := map[string]any{}
	if len(ids) > take {
		ids = ids[:take]
		out["next"] = base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + ids[take-1]))
	}
	list := make([]map[string]string, len(ids))
	for i, id := range ids {
		list[i] = map[string]string{"client_id": id}
	}
	out["clients"] = list
	writeJSON(w, http.StatusOK, out)
}

// clientStatus is one entry of a PATCH /connections/{id}/clients body.
type clientStatus struct {
	clientID string
	enabled  bool
}

func readClientStatuses(r *http.Request) ([]clientStatus, error) {
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, badBody("the body is too large or unreadable")
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, badBody("the body must be an array of {client_id, status}")
	}
	if len(entries) == 0 {
		return nil, badBody("at least one {client_id, status} is required")
	}
	out := make([]clientStatus, len(entries))
	for i, e := range entries {
		for k := range e {
			if k != "client_id" && k != "status" {
				return nil, badBody("entry %d: unknown property %q", i, k)
			}
		}
		var id string
		if err := decodeString(e["client_id"], &id); err != nil || !validClientIDFilter(id) {
			return nil, badBody("entry %d: client_id must be a client ID", i)
		}
		var status bool
		if raw, ok := e["status"]; !ok || decodeStrict(raw, &status) != nil {
			return nil, badBody("entry %d: status must be true or false", i)
		}
		out[i] = clientStatus{id, status}
	}
	return out, nil
}

// UpdateConnectionClients enables or disables applications on a connection.
// Nothing changes when any entry names an application the tenant lacks.
func (h *Handlers) UpdateConnectionClients(w http.ResponseWriter, r *http.Request, id string) {
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	entries, err := readClientStatuses(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		c, err := tx.Connections().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errConnectionNotFound
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := checkClientsExist(r, tx, tn.ID, []string{e.clientID}); err != nil {
				return err
			}
			has := slices.Contains(c.EnabledClients, e.clientID)
			switch {
			case e.enabled && !has:
				c.EnabledClients = append(c.EnabledClients, e.clientID)
			case !e.enabled && has:
				c.EnabledClients = slices.DeleteFunc(c.EnabledClients, func(s string) bool { return s == e.clientID })
			}
		}
		return tx.Connections().Update(r.Context(), c)
	})
	if err != nil {
		h.failTx(w, r, "update connection clients", err)
		return
	}
	h.audit(r, "update connection clients", "id", id, "entries", len(entries))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
