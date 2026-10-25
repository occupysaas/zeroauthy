package mgmt

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Client secret lengths (M3, M4): generated secrets have 64 characters,
// supplied ones at least 48.
const (
	generatedSecretLength = 64
	minSecretLength       = 48
	maxSecretLength       = 1024
	clientIDLength        = 32
	maxNameLength         = 255
	maxBodyBytes          = 1 << 20
)

// Handlers serves the Management API and the system API.
type Handlers struct {
	Protection *protection.Service
	// BreachCheckerAvailable reports an actually constructed server-side checker.
	BreachCheckerAvailable bool

	Store store.Store
	// Wrapper seals and opens client secrets (D-0038).
	Wrapper keys.Wrapper
	// BaseDomain is server.base_domain, and SystemHost the system tenant's
	// canonical host, which no other tenant may claim.
	BaseDomain string
	SystemHost string
	Log        *slog.Logger
	Now        func() time.Time
	// Scripts runs custom database scripts for the system API's script
	// try; nil answers 503.
	Scripts *customdb.Client
	// Verification sends verification emails for /users; nil logs and
	// sends nothing.
	Verification VerificationSender
	// Notify wakes the job workers after a job is stored; nil does
	// nothing (the workers poll).
	Notify func()
	// Export signs and checks export download links; nil gives completed
	// exports no location and refuses every download.
	Export *ExportLink
	// TrustProxyHeaders makes the download log read the client address from
	// the proxy headers.
	TrustProxyHeaders bool
	// Keys verifies link_with ID tokens (POST /users/{id}/identities).
	Keys *keys.Manager

	tryOnce     sync.Once
	tryThrottle *identity.Throttle
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// audit logs a Management API write with its actor (design §6).
func (h *Handlers) audit(r *http.Request, action string, args ...any) {
	c, _ := CallerFrom(r.Context())
	res, _ := tenant.FromContext(r.Context())
	actor := c.ClientID
	if c.Kind == Operator {
		actor = c.UserID
	}
	tn := ""
	if res.Tenant != nil {
		tn = res.Tenant.Name
	}
	h.log().InfoContext(r.Context(), "management API: "+action, append([]any{"tenant", tn, "actor", actor}, args...)...)
}

func badBody(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Payload validation error: " + fmt.Sprintf(format, args...)}
}

func internalError(h *Handlers, r *http.Request, what string, err error) *Error {
	h.log().ErrorContext(r.Context(), "management API: "+what, "err", err)
	return &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Internal error"}
}

var errClientNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_client", Message: "The client does not exist"}

// protectedClient refuses changes to the console's own client, without
// which no operator could sign in.
func protectedClient(t *store.Tenant, clientID string) error {
	if t.Reserved && clientID == system.ConsoleClientID {
		return &Error{Status: http.StatusForbidden, Code: "operation_not_supported", Message: "The console's client is managed by zeroauthy"}
	}
	return nil
}

func resolved(r *http.Request) *store.Tenant {
	res, _ := tenant.FromContext(r.Context())
	return res.Tenant
}

// GetClients lists the tenant's applications in creation order (M6).
func (h *Handlers) GetClients(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetClientsParams) {
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
	var types []string
	for _, t := range strings.Split(q.Get("app_type"), ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if !slices.Contains(clientrules.AppTypes, t) {
			Fail(w, badQuery("Query validation error: app_type %q must be one of %v", t, clientrules.AppTypes))
			return
		}
		types = append(types, t)
	}
	var firstParty *bool
	if q.Get("is_first_party") != "" {
		v, err := boolParam(r, "is_first_party", true)
		if err != nil {
			Fail(w, err)
			return
		}
		firstParty = &v
	}
	tn := resolved(r)
	// The store filters, orders and pages; Page already bounds both numbers.
	got, total, err := h.Store.Clients().List(r.Context(), tn.ID,
		store.ClientFilter{AppTypes: types, IsFirstParty: firstParty},
		store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		Fail(w, internalError(h, r, "list clients", err))
		return
	}
	reveal := callerHas(r, "read:client_keys")
	out := make([]map[string]any, 0, len(got))
	for _, c := range got {
		out = append(out, Project(h.clientView(r.Context(), tn, c, reveal), fields, include))
	}
	WritePage(w, "clients", out, page, perPage, total, totals)
}

// GetClient returns one application.
func (h *Handlers) GetClient(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetClientParams) {
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	c, err := h.Store.Clients().Get(r.Context(), tn.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errClientNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "get client", err))
		return
	}
	writeJSON(w, http.StatusOK, Project(h.clientView(r.Context(), tn, c, callerHas(r, "read:client_keys")), fields, include))
}

// CreateClient creates an application. The API applies its own defaults;
// the console sends per-type defaults (D-0039).
func (h *Handlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, ok := body["client_id"]; ok {
		// Auth0 refuses a caller-supplied client ID (M10).
		Fail(w, &Error{Status: http.StatusForbidden, Code: "operation_not_supported", Message: "client_id cannot be set; it is generated"})
		return
	}
	if _, ok := body["name"]; !ok {
		Fail(w, badBody("Missing required property: name"))
		return
	}
	spec := clientrules.Spec{AppType: string(store.AppTypeRegularWeb)}
	in, err := readClientBody(body, &spec)
	if err != nil {
		Fail(w, err)
		return
	}
	if !in.grantTypesSet {
		method := spec.TokenEndpointAuthMethod
		if method == "" {
			method = clientrules.DefaultAuthMethod(spec.AppType)
		}
		spec.GrantTypes = clientrules.DefaultGrantTypes(method)
	}
	tn := resolved(r)
	if err := normalize(&spec, tn); err != nil {
		Fail(w, err)
		return
	}
	now := h.now()
	c := &store.Client{TenantID: tn.ID, ClientID: secrets.RandomString(clientIDLength), CreatedAt: now, Origin: store.OriginAPI}
	clientrules.Apply(c, &spec)
	if err := h.setSecret(c, in.secret, in.secretSet, now); err != nil {
		Fail(w, err)
		return
	}
	if err := h.Store.Clients().Create(r.Context(), c); err != nil {
		Fail(w, internalError(h, r, "create client", err))
		return
	}
	h.audit(r, "create client", "client_id", c.ClientID)
	writeJSON(w, http.StatusCreated, h.clientView(r.Context(), tn, c, callerHas(r, "read:client_keys")))
}

// UpdateClient changes the fields the body names.
func (h *Handlers) UpdateClient(w http.ResponseWriter, r *http.Request, id string) {
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	// update:clients for settings, update:client_keys for the secret (M3).
	_, hasSecret := body["client_secret"]
	if hasSecret && !callerHas(r, "update:client_keys") {
		Fail(w, &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "Insufficient scope, expected: update:client_keys"})
		return
	}
	if (len(body) > 1 || !hasSecret) && !callerHas(r, "update:clients") {
		Fail(w, &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "Insufficient scope, expected: update:clients"})
		return
	}
	if raw, ok := body["client_id"]; ok {
		var v string
		if json.Unmarshal(raw, &v) != nil || v != id {
			Fail(w, badBody("client_id cannot change"))
			return
		}
		delete(body, "client_id")
	}
	tn := resolved(r)
	if err := protectedClient(tn, id); err != nil {
		Fail(w, err)
		return
	}
	var out *store.Client
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		c, err := tx.Clients().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errClientNotFound
		}
		if err != nil {
			return err
		}
		spec := clientrules.FromClient(c)
		in, err := readClientBody(body, &spec)
		if err != nil {
			return err
		}
		// M8: party and security mode are fixed at creation.
		if in.firstPartySet && *spec.IsFirstParty != c.IsFirstParty {
			return badBody("is_first_party cannot change after creation")
		}
		if in.securityModeSet && spec.ThirdPartySecurityMode != c.ThirdPartySecurityMode {
			return badBody("third_party_security_mode cannot change after creation")
		}
		if err := normalize(&spec, tn); err != nil {
			return err
		}
		if err := clientrules.CheckImmutable(c, &spec); err != nil {
			return badBody("%v", err)
		}
		clientrules.Apply(c, &spec)
		if err := h.setSecret(c, in.secret, in.secretSet, h.now()); err != nil {
			return err
		}
		out = c
		return tx.Clients().Update(r.Context(), c)
	})
	if err != nil {
		h.failTx(w, r, "update client", err)
		return
	}
	h.audit(r, "update client", "client_id", id)
	writeJSON(w, http.StatusOK, h.clientView(r.Context(), tn, out, callerHas(r, "read:client_keys")))
}

// DeleteClient deletes an application with its grants and refresh tokens,
// and removes it from every connection. An unknown ID is 204 too (M9).
func (h *Handlers) DeleteClient(w http.ResponseWriter, r *http.Request, id string) {
	tn := resolved(r)
	if err := protectedClient(tn, id); err != nil {
		Fail(w, err)
		return
	}
	deleted := false
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		err := tx.Clients().Delete(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		deleted = true
		conns, _, err := tx.Connections().List(r.Context(), tn.ID, store.ConnectionFilter{}, store.Page{})
		if err != nil {
			return err
		}
		for _, c := range conns {
			if !slices.Contains(c.EnabledClients, id) {
				continue
			}
			c.EnabledClients = slices.DeleteFunc(c.EnabledClients, func(s string) bool { return s == id })
			if err := tx.Connections().Update(r.Context(), c); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		Fail(w, internalError(h, r, "delete client", err))
		return
	}
	if deleted {
		h.audit(r, "delete client", "client_id", id)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// RotateClientSecret replaces the secret; the old one stops working at
// once (M4). The response carries the new secret.
func (h *Handlers) RotateClientSecret(w http.ResponseWriter, r *http.Request, id string) {
	tn := resolved(r)
	if err := protectedClient(tn, id); err != nil {
		Fail(w, err)
		return
	}
	var out *store.Client
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		c, err := tx.Clients().Get(r.Context(), tn.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return errClientNotFound
		}
		if err != nil {
			return err
		}
		if c.TokenEndpointAuthMethod == store.AuthMethodNone {
			return badBody("public applications (token_endpoint_auth_method none) have no secret")
		}
		c.Secrets = nil
		if err := h.setSecret(c, "", false, h.now()); err != nil {
			return err
		}
		out = c
		return tx.Clients().Update(r.Context(), c)
	})
	if err != nil {
		h.failTx(w, r, "rotate client secret", err)
		return
	}
	h.audit(r, "rotate client secret", "client_id", id)
	writeJSON(w, http.StatusOK, h.clientView(r.Context(), tn, out, true))
}

// setSecret makes c's secrets match its auth method: none for a public
// client; for a confidential one the supplied secret, or a generated one
// when it has none.
func (h *Handlers) setSecret(c *store.Client, secret string, supplied bool, now time.Time) error {
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		if supplied && secret != "" {
			return badBody("public applications (token_endpoint_auth_method none) cannot have a client_secret")
		}
		c.Secrets = nil
		return nil
	}
	if !supplied {
		if len(c.Secrets) > 0 {
			return nil
		}
		secret = secrets.RandomString(generatedSecretLength)
	}
	sealed, err := keys.SealClientSecret(h.Wrapper, c.TenantID, c.ClientID, secret)
	if err != nil {
		return err
	}
	c.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: now}}
	return nil
}

func normalize(s *clientrules.Spec, tn *store.Tenant) error {
	if errs := clientrules.Normalize(s, tn.PushedAuthorizationRequestsSupported); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return badBody("%s", strings.Join(msgs, "; "))
	}
	return nil
}

func callerHas(r *http.Request, scope string) bool {
	c, ok := CallerFrom(r.Context())
	return ok && c.Has(scope)
}

// clientView is c in Auth0's shape; the secret only with reveal and when it
// can be opened (a legacy hash cannot, D-0038).
func (h *Handlers) clientView(ctx context.Context, tn *store.Tenant, c *store.Client, reveal bool) mgmtapi.Client {
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return slices.Clone(s)
	}
	idTTL := c.IDTokenLifetime
	if idTTL == 0 {
		idTTL = clientrules.DefaultIDTTL
	}
	alg := mgmtapi.JwtConfigurationAlgRS256
	secretEncoded := false
	spec := clientrules.FromClient(c)
	rotation := mgmtapi.RefreshTokenSettingsRotationType(spec.RefreshToken.RotationType)
	expiration := mgmtapi.RefreshTokenSettingsExpirationType(spec.RefreshToken.ExpirationType)
	lifetime := cmp.Or(c.RefreshToken.TokenLifetime, defaultRefreshLifetime)
	idle := cmp.Or(c.RefreshToken.IdleTokenLifetime, defaultRefreshIdleLifetime)
	infinite := !c.RefreshToken.Expiring
	leeway := c.RefreshToken.Leeway
	created := c.CreatedAt.UTC()
	v := mgmtapi.Client{
		Tenant: tn.Name, ClientId: c.ClientID, Name: c.Name,
		AppType: mgmtapi.AppType(c.AppType), IsFirstParty: c.IsFirstParty,
		OidcConformant: true,
		Callbacks:      nonNil(c.Callbacks), AllowedLogoutUrls: nonNil(c.AllowedLogoutURLs),
		WebOrigins: nonNil(c.WebOrigins), AllowedOrigins: nonNil(c.AllowedOrigins),
		GrantTypes:              nonNil(c.GrantTypes),
		TokenEndpointAuthMethod: mgmtapi.TokenEndpointAuthMethod(c.TokenEndpointAuthMethod),
		JwtConfiguration:        mgmtapi.JwtConfiguration{Alg: &alg, LifetimeInSeconds: &idTTL, SecretEncoded: &secretEncoded},
		RefreshToken: mgmtapi.RefreshTokenSettings{
			RotationType: &rotation, ExpirationType: &expiration, Leeway: &leeway,
			TokenLifetime: &lifetime, IdleTokenLifetime: &idle,
			InfiniteTokenLifetime: &infinite, InfiniteIdleTokenLifetime: &infinite,
		},
		RequirePushedAuthorizationRequests: c.RequirePushedAuthorizationRequests,
		CreatedAt:                          &created,
	}
	if c.ThirdPartySecurityMode != "" {
		m := mgmtapi.ClientThirdPartySecurityMode(c.ThirdPartySecurityMode)
		v.ThirdPartySecurityMode = &m
	}
	if c.RedirectionPolicy != "" {
		p := mgmtapi.ClientRedirectionPolicy(c.RedirectionPolicy)
		v.RedirectionPolicy = &p
	}
	if p := c.SkipNonVerifiableCallbackURIConfirmationPrompt; p != nil {
		b := *p
		v.SkipNonVerifiableCallbackUriConfirmationPrompt = &b
	}
	if reveal {
		if s := h.openSecret(ctx, c); s != "" {
			v.ClientSecret = &s
		}
	}
	return v
}

// The refresh-token lifetimes zeroauthy applies when a client sets none.
const (
	defaultRefreshLifetime     = 31557600
	defaultRefreshIdleLifetime = 2592000
)

// openSecret returns the newest unexpired sealed secret, or "".
func (h *Handlers) openSecret(ctx context.Context, c *store.Client) string {
	now := h.now()
	for i := len(c.Secrets) - 1; i >= 0; i-- {
		s := c.Secrets[i]
		if s.Sealed == nil || (s.ExpiresAt != nil && !s.ExpiresAt.After(now)) {
			continue
		}
		plain, err := keys.OpenClientSecret(h.Wrapper, c.TenantID, c.ClientID, s.Sealed)
		if err != nil {
			h.log().ErrorContext(ctx, "management API: open client secret", "client_id", c.ClientID, "err", err)
			return ""
		}
		return plain
	}
	return ""
}

// decodeObject reads a JSON object body.
func decodeObject(r *http.Request) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, badBody("the body is too large or unreadable")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil || body == nil {
		return nil, badBody("the body must be a JSON object")
	}
	return body, nil
}

// ignoredClientFields are fields Auth0's tools send that zeroauthy accepts
// and ignores (D-0039).
var ignoredClientFields = []string{
	"description", "logo_uri", "client_metadata", "sso", "sso_disabled",
	"cross_origin_authentication", "cross_origin_auth", "cross_origin_loc",
	"custom_login_page_on", "custom_login_page", "initiate_login_uri",
	"native_social_login", "mobile", "organization_usage", "organization_require_behavior",
	"is_token_endpoint_ip_header_trusted", "allowed_clients", "created_at", "updated_at",
}

// clientBody is what readClientBody learned beyond the Spec.
type clientBody struct {
	secret          string
	secretSet       bool
	grantTypesSet   bool
	firstPartySet   bool
	securityModeSet bool
}

// readClientBody applies body's fields to s, in name order so that the
// first error reported is stable.
func readClientBody(body map[string]json.RawMessage, s *clientrules.Spec) (clientBody, error) {
	var out clientBody
	for _, k := range slices.Sorted(maps.Keys(body)) {
		raw := body[k]
		var err error
		switch k {
		case "name":
			err = decodeString(raw, &s.Name)
			if err == nil && (s.Name == "" || len(s.Name) > maxNameLength) {
				err = fmt.Errorf("must be 1 to %d characters", maxNameLength)
			}
		case "app_type":
			err = decodeString(raw, &s.AppType)
		case "token_endpoint_auth_method":
			// null selects the default for the type.
			s.TokenEndpointAuthMethod = ""
			if !isNull(raw) {
				err = decodeString(raw, &s.TokenEndpointAuthMethod)
			}
		case "grant_types":
			err, out.grantTypesSet = decodeStrings(raw, &s.GrantTypes), true
		case "callbacks":
			err = decodeStrings(raw, &s.Callbacks)
		case "allowed_logout_urls":
			err = decodeStrings(raw, &s.AllowedLogoutURLs)
		case "web_origins":
			err = decodeStrings(raw, &s.WebOrigins)
		case "allowed_origins":
			err = decodeStrings(raw, &s.AllowedOrigins)
		case "is_first_party":
			var v bool
			err = decodeStrict(raw, &v)
			s.IsFirstParty, out.firstPartySet = &v, true
		case "third_party_security_mode":
			err, out.securityModeSet = decodeString(raw, &s.ThirdPartySecurityMode), true
		case "redirection_policy":
			err = decodeString(raw, &s.RedirectionPolicy)
		case "require_pushed_authorization_requests":
			err = decodeStrict(raw, &s.RequirePushedAuthorizationRequests)
		case "skip_non_verifiable_callback_uri_confirmation_prompt":
			s.SkipNonVerifiableCallbackURIConfirmationPrompt = nil
			if !isNull(raw) {
				var v bool
				err = decodeStrict(raw, &v)
				s.SkipNonVerifiableCallbackURIConfirmationPrompt = &v
			}
		case "oidc_conformant":
			var v bool
			if err = decodeStrict(raw, &v); err == nil && !v {
				err = errors.New("zeroauthy applications are always OIDC-conformant")
			}
		case "client_secret":
			err = decodeString(raw, &out.secret)
			out.secretSet = true
			if err == nil && (len(out.secret) < minSecretLength || len(out.secret) > maxSecretLength) {
				err = fmt.Errorf("must be %d to %d characters", minSecretLength, maxSecretLength)
			}
		case "jwt_configuration":
			err = readJWTConfiguration(raw, s)
		case "refresh_token":
			err = readRefreshToken(raw, &s.RefreshToken)
		default:
			if slices.Contains(ignoredClientFields, k) {
				continue
			}
			return out, badBody("unknown property %q", k)
		}
		if err != nil {
			return out, badBody("%s: %v", k, err)
		}
	}
	return out, nil
}

func readJWTConfiguration(raw json.RawMessage, s *clientrules.Spec) error {
	var v struct {
		Alg               *string `json:"alg"`
		LifetimeInSeconds *int    `json:"lifetime_in_seconds"`
		SecretEncoded     *bool   `json:"secret_encoded"`
	}
	if err := decodeStrict(raw, &v); err != nil {
		return err
	}
	if v.Alg != nil && *v.Alg != "RS256" {
		return fmt.Errorf("alg %q is not supported (RS256 only)", *v.Alg)
	}
	if v.LifetimeInSeconds != nil {
		s.IDTokenLifetime = *v.LifetimeInSeconds
	}
	return nil
}

// readRefreshToken merges the given members into rt. infinite_token_lifetime
// sets the expiration type when expiration_type is absent.
func readRefreshToken(raw json.RawMessage, rt *clientrules.RefreshToken) error {
	var v struct {
		RotationType              *string `json:"rotation_type"`
		ExpirationType            *string `json:"expiration_type"`
		Leeway                    *int    `json:"leeway"`
		TokenLifetime             *int    `json:"token_lifetime"`
		IdleTokenLifetime         *int    `json:"idle_token_lifetime"`
		InfiniteTokenLifetime     *bool   `json:"infinite_token_lifetime"`
		InfiniteIdleTokenLifetime *bool   `json:"infinite_idle_token_lifetime"`
	}
	if err := decodeStrict(raw, &v); err != nil {
		return err
	}
	if v.RotationType != nil {
		rt.RotationType = *v.RotationType
	}
	switch {
	case v.ExpirationType != nil:
		rt.ExpirationType = *v.ExpirationType
	case v.InfiniteTokenLifetime != nil && *v.InfiniteTokenLifetime:
		rt.ExpirationType = clientrules.NonExpiring
	case v.InfiniteTokenLifetime != nil:
		rt.ExpirationType = clientrules.Expiring
	}
	if v.Leeway != nil {
		rt.Leeway = *v.Leeway
	}
	if v.TokenLifetime != nil {
		rt.TokenLifetime = *v.TokenLifetime
	}
	if v.IdleTokenLifetime != nil {
		rt.IdleTokenLifetime = *v.IdleTokenLifetime
	}
	return nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

func decodeString(raw json.RawMessage, dst *string) error {
	if isNull(raw) {
		return errors.New("must be a string")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return errors.New("must be a string")
	}
	return nil
}

// decodeStrings reads a list of strings; null is the empty list.
func decodeStrings(raw json.RawMessage, dst *[]string) error {
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return errors.New("must be a list of strings")
	}
	*dst = v
	return nil
}

// decodeStrict reads raw into dst, refusing null and unknown members.
func decodeStrict(raw json.RawMessage, dst any) error {
	if isNull(raw) {
		return errors.New("must not be null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var unknown string
		if _, after, ok := strings.Cut(err.Error(), "unknown field "); ok {
			unknown = after
		}
		if unknown != "" {
			return fmt.Errorf("unknown property %s", unknown)
		}
		return errors.New("has the wrong type")
	}
	return nil
}
