package selfservice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Path is the assistant's route on tenant hosts.
const Path = "/self-service/connections-flow"

// cookieName holds the ticket token while the assistant runs: HttpOnly,
// Secure, SameSite=Strict, scoped to /self-service, no longer than the
// ticket lives. The token leaves the URL after the first request.
const cookieName = "za_self_service"

const maxForm = 256 << 10

// Writes is the Management API surface the assistant writes through
// (*mgmt.Handlers).
type Writes interface {
	AssistantCreateConnection(ctx context.Context, tn *store.Tenant, host string, body map[string]any) (mgmt.AssistantResult, error)
	AssistantGetConnection(ctx context.Context, tn *store.Tenant, host, id string) (mgmt.AssistantResult, error)
	AssistantUpdateConnection(ctx context.Context, tn *store.Tenant, host, id string, body map[string]any) (mgmt.AssistantResult, error)
	AssistantEnableOrganization(ctx context.Context, tn *store.Tenant, host, orgID string, body map[string]any) (mgmt.AssistantResult, error)
	AssistantCreateSCIM(ctx context.Context, tn *store.Tenant, host, connID string, token map[string]any) (mgmt.AssistantResult, error)
}

// Handler serves the assistant.
type Handler struct {
	Store  store.Store
	Writes Writes
	Now    func() time.Time
	Log    *slog.Logger
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

//go:embed templates/assistant.html
var templateFS embed.FS

var page = template.Must(template.New("assistant.html").Funcs(template.FuncMap{"sanitize": sanitize}).ParseFS(templateFS, "templates/assistant.html"))

// ticketDoc is the part of a ticket request the assistant uses.
type ticketDoc struct {
	ConnectionID     string `json:"connection_id"`
	ConnectionConfig *struct {
		Name               string             `json:"name"`
		DisplayName        string             `json:"display_name"`
		IsDomainConnection *bool              `json:"is_domain_connection"`
		ShowAsButton       *bool              `json:"show_as_button"`
		Metadata           map[string]*string `json:"metadata"`
		Options            *struct {
			IconURL      *string        `json:"icon_url"`
			DomainAlias  []string       `json:"domain_aliases"`
			IdPInitiated map[string]any `json:"idpinitiated"`
		} `json:"options"`
	} `json:"connection_config"`
	EnabledClients       []string `json:"enabled_clients"`
	EnabledOrganizations []struct {
		OrganizationID          string `json:"organization_id"`
		AssignMembershipOnLogin *bool  `json:"assign_membership_on_login"`
		ShowAsButton            *bool  `json:"show_as_button"`
	} `json:"enabled_organizations"`
	DomainAliasesConfig *struct {
		DomainVerification string   `json:"domain_verification"`
		PendingDomains     []string `json:"pending_domains"`
	} `json:"domain_aliases_config"`
	ProvisioningConfig *struct {
		Scopes        []string `json:"scopes"`
		TokenLifetime *int64   `json:"token_lifetime"`
	} `json:"provisioning_config"`
	EnabledFeatures *struct {
		SSO                *bool `json:"sso"`
		DomainVerification *bool `json:"domain_verification"`
		Provisioning       *bool `json:"provisioning"`
	} `json:"enabled_features"`
}

// profileDoc is the part of a profile the assistant uses.
type profileDoc struct {
	Branding struct {
		LogoURL string `json:"logo_url"`
		Colors  struct {
			Primary string `json:"primary"`
		} `json:"colors"`
	} `json:"branding"`
	AllowedStrategies []string `json:"allowed_strategies"`
	UserAttributes    []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		IsOptional  bool   `json:"is_optional"`
	} `json:"user_attributes"`
}

// configurable are the strategies the assistant can configure (Q7).
var configurable = []string{"samlp", "oidc", "okta", "waad", "adfs"}

// session is one request's view of the ticket.
type session struct {
	tenant  *store.Tenant
	host    string
	token   string
	ticket  *store.SSOTicket
	doc     ticketDoc
	profile *store.SelfServiceProfile
	pdoc    profileDoc
	text    map[string]string
	conn    *store.Connection // the ticket's connection, once it exists
}

// PDocLogo is the profile's https logo, if any.
func (s *session) PDocLogo() string {
	if strings.HasPrefix(s.pdoc.Branding.LogoURL, "https://") {
		return s.pdoc.Branding.LogoURL
	}
	return ""
}

// Intro is the custom text introduction (sanitized by the template).
func (s *session) Intro() string { return s.text["introduction"] }

// Attributes are the profile's user attributes to map.
func (s *session) Attributes() any { return s.pdoc.UserAttributes }

// CanSSO and CanSCIM expose the feature checks to the template.
func (s *session) CanSSO() bool  { return s.canSSO() }
func (s *session) CanSCIM() bool { return s.canSCIM() }

// edit reports a ticket for an existing connection.
func (s *session) edit() bool { return s.doc.ConnectionID != "" }

func featureOn(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// canSSO: a create ticket always configures SSO; an edit ticket unless
// enabled_features.sso is false.
func (s *session) canSSO() bool {
	if !s.edit() || s.doc.EnabledFeatures == nil {
		return true
	}
	return featureOn(s.doc.EnabledFeatures.SSO, true)
}

// domains are the domains the customer may choose: only the ticket's
// pending_domains, when domain verification is not "none". The customer
// cannot claim any other domain (home realm discovery routes by them).
func (s *session) domains() []string {
	c := s.doc.DomainAliasesConfig
	if c == nil || c.DomainVerification == "none" || len(c.PendingDomains) == 0 {
		return nil
	}
	if s.edit() && (s.doc.EnabledFeatures == nil || !featureOn(s.doc.EnabledFeatures.DomainVerification, false)) {
		return nil
	}
	return c.PendingDomains
}

// canSCIM: the ticket asks for provisioning and the connection accepts
// SCIM.
func (s *session) canSCIM() bool {
	if s.doc.ProvisioningConfig == nil || s.conn == nil || !slices.Contains(scim.Strategies, s.conn.Strategy) {
		return false
	}
	if s.edit() && (s.doc.EnabledFeatures == nil || !featureOn(s.doc.EnabledFeatures.Provisioning, false)) {
		return false
	}
	return true
}

// strategies the customer may choose: the profile's list (or every
// configurable one), within what zeroauthy configures.
func (s *session) strategies() []string {
	if s.conn != nil {
		return []string{s.conn.Strategy}
	}
	if len(s.pdoc.AllowedStrategies) == 0 {
		return configurable
	}
	var out []string
	for _, st := range s.pdoc.AllowedStrategies {
		if slices.Contains(configurable, st) {
			out = append(out, st)
		}
	}
	return out
}

// csrf is derived from the ticket token, which only the cookie holder has.
func (s *session) csrf() string {
	m := hmac.New(sha256.New, []byte(s.token))
	m.Write([]byte("zeroauthy self-service csrf"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

var errTicket = errors.New("selfservice: no usable ticket")

// load resolves the ticket from the cookie (or token) and everything the
// page needs.
func (h *Handler) load(r *http.Request, token string) (*session, error) {
	res, ok := tenant.FromContext(r.Context())
	if !ok || token == "" || len(token) > 256 || !store.SelfServiceAvailable(h.Store) {
		return nil, errTicket
	}
	ctx := r.Context()
	ss := h.Store.SelfService()
	t, err := ss.GetTicketByHash(ctx, res.Tenant.ID, scim.HashToken(token))
	if err != nil || !t.Usable(h.now()) {
		return nil, errTicket
	}
	s := &session{tenant: res.Tenant, host: res.Host, token: token, ticket: t}
	if err := json.Unmarshal(t.Doc, &s.doc); err != nil {
		return nil, err
	}
	if s.profile, err = ss.GetProfile(ctx, res.Tenant.ID, t.ProfileID); err != nil {
		return nil, errTicket
	}
	_ = json.Unmarshal(s.profile.Doc, &s.pdoc)
	if raw, err := ss.GetCustomText(ctx, res.Tenant.ID, t.ProfileID, "en", "get-started"); err == nil && raw != nil {
		_ = json.Unmarshal(raw, &s.text)
	}
	if t.ConnectionID != "" {
		c, err := h.Store.Connections().Get(ctx, res.Tenant.ID, t.ConnectionID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		s.conn = c
	}
	return s, nil
}

// view is the template's data.
type view struct {
	S                *session
	CSRF             string
	Error, Notice    string
	Strategies       []string
	Strategy         string
	Callback, ACS    string
	EntityID         string
	SCIMEndpoint     string
	SCIMToken        string
	TestURL          string
	Domains          []string
	Done             bool
	PrimaryColor     template.CSS
	ConnectionName   string
	ConnectionExists bool
}

var hexColor = func(c string) bool {
	if len(c) != 4 && len(c) != 7 || c[0] != '#' {
		return false
	}
	for _, ch := range c[1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", ch) {
			return false
		}
	}
	return true
}

func (h *Handler) render(w http.ResponseWriter, s *session, v view, status int) {
	v.S = s
	if s != nil {
		v.CSRF = s.csrf()
		v.Strategies = s.strategies()
		v.Domains = s.domains()
		v.ConnectionExists = s.conn != nil
		if s.conn != nil {
			v.ConnectionName = s.conn.Name
			v.Strategy = s.conn.Strategy
		} else if s.doc.ConnectionConfig != nil {
			v.ConnectionName = s.doc.ConnectionConfig.Name
		}
		v.Callback = "https://" + s.host + "/login/callback"
		v.ACS = v.Callback + "?connection=" + url.QueryEscape(v.ConnectionName)
		v.EntityID = "urn:auth0:" + s.tenant.Name + ":" + v.ConnectionName
		if s.conn != nil {
			v.SCIMEndpoint = "https://" + s.host + "/scim/v2/connections/" + s.conn.ID
		}
		if c := s.pdoc.Branding.Colors.Primary; hexColor(c) {
			v.PrimaryColor = template.CSS(c) // #nosec G203 -- validated #rgb or #rrggbb
		}
		if s.conn != nil && len(s.doc.EnabledClients) > 0 {
			v.TestURL = h.testURL(s)
		}
	}
	if v.PrimaryColor == "" {
		v.PrimaryColor = "#1f2328"
	}
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := page.Execute(w, v); err != nil {
		h.log().Error("self-service assistant render", "error", err)
	}
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
}

// testURL starts a login through the ticket's first application with the
// new connection (LR37c ruling: an ordinary login; there is no
// side-effect-free test mode).
func (h *Handler) testURL(s *session) string {
	c, err := h.Store.Clients().Get(context.Background(), s.tenant.ID, s.doc.EnabledClients[0])
	if err != nil || len(c.Callbacks) == 0 {
		return ""
	}
	// A discarded S256 challenge makes the request valid for public
	// applications too; the application cannot redeem the code.
	verifier := secrets.RandomString(43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {c.ClientID}, "response_type": {"code"}, "redirect_uri": {c.Callbacks[0]}, "scope": {"openid profile email"},
		"connection": {s.conn.Name}, "prompt": {"login"}, "state": {secrets.RandomString(16)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	return "https://" + s.host + "/authorize?" + q.Encode()
}

func (h *Handler) invalid(w http.ResponseWriter) {
	h.render(w, nil, view{Error: "This link is invalid, was revoked or has expired. Ask the administrator who sent it for a new one."}, http.StatusNotFound)
}

// ServeHTTP routes GET and POST of the assistant.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.get(w, r)
	case http.MethodPost:
		h.post(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if token := r.URL.Query().Get("ticket"); token != "" {
		s, err := h.load(r, token)
		if err != nil {
			h.invalid(w)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/self-service", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
			Expires: s.ticket.ExpiresAt})
		securityHeaders(w)
		http.Redirect(w, r, Path, http.StatusSeeOther)
		return
	}
	s, err := h.fromCookie(r)
	if err != nil {
		h.invalid(w)
		return
	}
	h.render(w, s, view{}, http.StatusOK)
}

func (h *Handler) fromCookie(r *http.Request) (*session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, errTicket
	}
	return h.load(r, c.Value)
}

// sameOrigin refuses a POST whose Origin (when sent) is another site.
func sameOrigin(r *http.Request, host string) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == "https://"+host
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request) {
	s, err := h.fromCookie(r)
	if err != nil {
		h.invalid(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil || !sameOrigin(r, s.host) || !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(s.csrf())) {
		h.render(w, s, view{Error: "The form expired. Reload the page and try again."}, http.StatusForbidden)
		return
	}
	switch r.PostForm.Get("action") {
	case "configure":
		h.configure(w, r, s)
	case "scim":
		h.setupSCIM(w, r, s)
	case "finish":
		h.finish(w, r, s)
	default:
		h.render(w, s, view{Error: "Unknown action."}, http.StatusBadRequest)
	}
}

// field returns a trimmed form value, at most 64 KiB.
func field(r *http.Request, name string) string {
	v := strings.TrimSpace(r.PostForm.Get(name))
	if len(v) > 64<<10 {
		return ""
	}
	return v
}

// options builds the connection options for strategy from the form. Only
// these fields can come from the customer; everything else is fixed by the
// ticket.
func options(r *http.Request, strategy string) (map[string]any, string) {
	o := map[string]any{}
	set := func(k, form string) {
		if v := field(r, form); v != "" {
			o[k] = v
		}
	}
	switch strategy {
	case "samlp":
		if v := field(r, "metadata_url"); v != "" {
			o["metadataUrl"] = v
		} else {
			set("signInEndpoint", "sign_in_url")
			set("signingCert", "signing_cert")
			if o["signInEndpoint"] == nil || o["signingCert"] == nil {
				return nil, "Enter the metadata URL, or the sign-in URL and the signing certificate."
			}
		}
	case "oidc":
		set("discovery_url", "discovery_url")
		set("client_id", "client_id")
		set("client_secret", "client_secret")
		if o["discovery_url"] == nil || o["client_id"] == nil {
			return nil, "Enter the discovery URL and the client ID."
		}
		o["scope"] = "openid profile email"
		if o["client_secret"] != nil {
			o["type"] = "back_channel"
		} else {
			o["type"] = "front_channel"
		}
	case "okta":
		set("domain", "okta_domain")
		set("client_id", "client_id")
		set("client_secret", "client_secret")
		if o["domain"] == nil || o["client_id"] == nil || o["client_secret"] == nil {
			return nil, "Enter the Okta domain, the client ID and the client secret."
		}
		o["scope"] = "openid profile email"
	case "waad":
		// One directory only: the customer's. useCommonEndpoint would admit
		// every organizational directory.
		set("tenant_domain", "tenant_domain")
		set("client_id", "client_id")
		set("client_secret", "client_secret")
		if o["tenant_domain"] == nil || o["client_id"] == nil || o["client_secret"] == nil {
			return nil, "Enter the directory (tenant) domain or ID, the client ID and the client secret."
		}
	case "adfs":
		if v := field(r, "adfs_server"); v != "" {
			o["adfs_server"] = v
		} else if v := field(r, "fed_metadata_xml"); v != "" {
			o["fedMetadataXml"] = v
		} else {
			return nil, "Enter the ADFS server or paste its federation metadata."
		}
	default:
		return nil, "Choose an identity provider."
	}
	return o, ""
}

// chosenDomains are the submitted domains, each one of the allowed list.
func chosenDomains(r *http.Request, allowed []string) []string {
	var out []string
	for _, d := range r.PostForm["domains"] {
		if slices.Contains(allowed, d) && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func (h *Handler) configure(w http.ResponseWriter, r *http.Request, s *session) {
	ctx := r.Context()
	if !s.canSSO() {
		h.render(w, s, view{Error: "This link does not allow changing the sign-in configuration."}, http.StatusForbidden)
		return
	}
	strategy := field(r, "strategy")
	if !slices.Contains(s.strategies(), strategy) {
		h.render(w, s, view{Error: "This identity provider is not available."}, http.StatusBadRequest)
		return
	}
	o, problem := options(r, strategy)
	if problem != "" {
		h.render(w, s, view{Error: problem}, http.StatusBadRequest)
		return
	}
	if allowed := s.domains(); allowed != nil {
		if ds := chosenDomains(r, allowed); len(ds) > 0 {
			o["domain_aliases"] = ds
		}
	}
	if s.conn != nil {
		// The ticket's one connection: merge into its options as the
		// Management API shows them.
		got, err := h.Writes.AssistantGetConnection(ctx, s.tenant, s.host, s.conn.ID)
		var shown struct {
			Options map[string]any `json:"options"`
		}
		if err != nil || !got.OK() || json.Unmarshal(got.Body, &shown) != nil {
			h.render(w, s, view{Error: writeProblem(got, err)}, http.StatusInternalServerError)
			return
		}
		cur := shown.Options
		if cur == nil {
			cur = map[string]any{}
		}
		for k, v := range o {
			cur[k] = v
		}
		if strategy == "samlp" {
			if _, ok := o["metadataUrl"]; ok {
				delete(cur, "signInEndpoint")
				delete(cur, "signingCert")
			} else {
				delete(cur, "metadataUrl")
			}
		}
		res, err := h.Writes.AssistantUpdateConnection(ctx, s.tenant, s.host, s.conn.ID, map[string]any{"options": cur})
		if err != nil || !res.OK() {
			h.render(w, s, view{Error: writeProblem(res, err)}, http.StatusBadRequest)
			return
		}
		h.reload(w, r, s, "Saved. Test the sign-in, then finish.")
		return
	}
	cfg := s.doc.ConnectionConfig
	if cfg == nil {
		h.render(w, s, view{Error: "This link names no connection."}, http.StatusBadRequest)
		return
	}
	if cfg.Options != nil {
		if cfg.Options.IconURL != nil {
			o["icon_url"] = *cfg.Options.IconURL
		}
		if cfg.Options.IdPInitiated != nil && strategy == "samlp" {
			o["idpinitiated"] = cfg.Options.IdPInitiated
		}
	}
	body := map[string]any{"name": cfg.Name, "strategy": strategy, "options": o, "enabled_clients": nonNil(s.doc.EnabledClients)}
	if cfg.DisplayName != "" {
		body["display_name"] = cfg.DisplayName
	}
	if cfg.IsDomainConnection != nil {
		body["is_domain_connection"] = *cfg.IsDomainConnection
	}
	if cfg.ShowAsButton != nil {
		body["show_as_button"] = *cfg.ShowAsButton
	}
	if len(cfg.Metadata) > 0 {
		body["metadata"] = cfg.Metadata
	}
	res, err := h.Writes.AssistantCreateConnection(ctx, s.tenant, s.host, body)
	if err != nil || !res.OK() {
		h.render(w, s, view{Error: writeProblem(res, err)}, http.StatusBadRequest)
		return
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(res.Body, &created) != nil || created.ID == "" {
		h.render(w, s, view{Error: "The connection could not be created."}, http.StatusInternalServerError)
		return
	}
	if err := h.Store.SelfService().BindTicketConnection(ctx, s.tenant.ID, s.ticket.ID, created.ID); err != nil {
		h.log().Error("self-service assistant bind", "ticket", s.ticket.ID, "error", err)
		h.render(w, s, view{Error: "The connection was created but could not be recorded for this link."}, http.StatusInternalServerError)
		return
	}
	for _, org := range s.doc.EnabledOrganizations {
		b := map[string]any{"connection_id": created.ID}
		if org.AssignMembershipOnLogin != nil {
			b["assign_membership_on_login"] = *org.AssignMembershipOnLogin
		}
		if org.ShowAsButton != nil {
			b["show_as_button"] = *org.ShowAsButton
		}
		if res, err := h.Writes.AssistantEnableOrganization(ctx, s.tenant, s.host, org.OrganizationID, b); err != nil || !res.OK() {
			h.log().Warn("self-service assistant organization", "organization", org.OrganizationID, "status", res.Status)
		}
	}
	h.reload(w, r, s, "The connection is created. Test the sign-in, then finish.")
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func writeProblem(res mgmt.AssistantResult, err error) string {
	if err == nil && res.Message() != "" {
		return "The identity provider settings were not accepted: " + res.Message()
	}
	return "The settings could not be saved. Try again."
}

// reload re-reads the session after a write and renders the page.
func (h *Handler) reload(w http.ResponseWriter, r *http.Request, s *session, notice string) {
	next, err := h.load(r, s.token)
	if err != nil {
		h.invalid(w)
		return
	}
	h.render(w, next, view{Notice: notice}, http.StatusOK)
}

func (h *Handler) setupSCIM(w http.ResponseWriter, r *http.Request, s *session) {
	if !s.canSCIM() {
		h.render(w, s, view{Error: "This link does not include provisioning."}, http.StatusForbidden)
		return
	}
	tok := map[string]any{}
	if len(s.doc.ProvisioningConfig.Scopes) > 0 {
		tok["scopes"] = s.doc.ProvisioningConfig.Scopes
	}
	if s.doc.ProvisioningConfig.TokenLifetime != nil {
		tok["token_lifetime"] = *s.doc.ProvisioningConfig.TokenLifetime
	}
	res, err := h.Writes.AssistantCreateSCIM(r.Context(), s.tenant, s.host, s.conn.ID, tok)
	var created struct {
		Token string `json:"token"`
	}
	if err != nil || !res.OK() || json.Unmarshal(res.Body, &created) != nil || created.Token == "" {
		h.render(w, s, view{Error: writeProblem(res, err)}, http.StatusBadRequest)
		return
	}
	h.render(w, s, view{Notice: "Copy the SCIM token now; it is shown only once.", SCIMToken: created.Token}, http.StatusOK)
}

func (h *Handler) finish(w http.ResponseWriter, r *http.Request, s *session) {
	if s.conn == nil {
		h.render(w, s, view{Error: "Configure the connection first."}, http.StatusBadRequest)
		return
	}
	if err := h.Store.SelfService().UseTicket(r.Context(), s.tenant.ID, s.ticket.ID, h.now()); err != nil {
		h.invalid(w)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/self-service", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	h.render(w, s, view{Done: true}, http.StatusOK)
}
