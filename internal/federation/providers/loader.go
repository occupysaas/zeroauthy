// Package providers holds the Plan 39b social provider descriptors: one
// embedded JSON file per strategy giving its fixed endpoints, client
// authentication, PKCE use, scope table, profile map and email rule (D-0180).
// It is a leaf package: option rules (federation/rules) and the generic
// provider (federation) read it. Strict decoding plus validate is the schema.
package providers

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

//go:embed *.json
var files embed.FS

// Hook names a provider quirk implemented in Go by the federation package.
const (
	HookFacebook   = "facebook"   // appsecret_proof on Graph calls
	HookLinkedIn   = "linkedin"   // strategy_version 1 and 2 refused at login
	HookSalesforce = "salesforce" // profile from the token response identity URL
	HookShopify    = "shopify"    // per-shop endpoints from login_hint
	HookLine       = "line"       // email from the ID token via the verify endpoint
	HookTwitter    = "twitter"    // protocol oauth1 or oauth2
)

var hooks = []string{HookFacebook, HookLinkedIn, HookSalesforce, HookShopify, HookLine, HookTwitter}

// Hooks returns every hook name a descriptor may use.
func Hooks() []string { return slices.Clone(hooks) }

// Client authentication methods and PKCE modes.
const (
	AuthPost  = "client_secret_post"
	AuthBasic = "client_secret_basic"
	// AuthQuery sends client_id and client_secret as token-request query
	// parameters (Untappd, Baidu; Plan 39d).
	AuthQuery = "client_secret_query"
	PKCES256  = "S256"
	PKCENone  = "none"
)

// Email verification rules (LR39b-4).
const (
	EmailAlways = "always" // verified whenever the provider returns an email
	EmailNever  = "never"
	EmailField  = "field" // the boolean at Path
)

// Template placeholders allowed in endpoint URLs.
const (
	ShopPlaceholder      = "{shop}"
	CommunityPlaceholder = "{community_base_url}"
	// BaseURLPlaceholder is a regional base URL chosen from BaseURLHosts
	// (Exact, Plan 39d).
	BaseURLPlaceholder = "{base_url}"
	// TokenPrefix marks a profile path read from the token response.
	TokenPrefix = "token:"
)

// Protocols.
const ProtocolOAuth1 = "oauth1"

// Retired marks a strategy whose provider retired its sign-in API: stored,
// refused at sign-in (Plan 39d LR39d-3).
type Retired struct {
	Date   string `json:"date"`
	Reason string `json:"reason"`
	Source string `json:"source"`
}

// OAuth1Endpoints are an OAuth 1.0a descriptor's fixed endpoints.
type OAuth1Endpoints struct {
	RequestTokenURL  string `json:"request_token_url"`
	AccessTokenURL   string `json:"access_token_url"`
	AuthorizationURL string `json:"authorization_url"`
	// EmptySecret accepts an empty oauth_token_secret (Evernote).
	EmptySecret bool `json:"empty_secret,omitempty"`
}

// Descriptor is one social strategy.
type Descriptor struct {
	Strategy          string            `json:"strategy"`
	DisplayName       string            `json:"display_name"`
	Source            []string          `json:"source"`
	AuthorizationURL  string            `json:"authorization_url"`
	TokenURL          string            `json:"token_url"`
	ProfileURL        string            `json:"profile_url"`
	ProfileMethod     string            `json:"profile_method,omitempty"` // GET (default) or POST
	ProfileAuth       string            `json:"profile_auth,omitempty"`   // bearer (default) or header:<Name>
	EmailURL          string            `json:"email_url,omitempty"`      // optional second GET; email paths apply to it
	VerifyURL         string            `json:"verify_url,omitempty"`     // hook-specific extra endpoint (LINE)
	TokenAuth         string            `json:"token_auth,omitempty"`
	PKCE              string            `json:"pkce,omitempty"`
	TokenMethod       string            `json:"token_method,omitempty"`        // POST (default) or GET
	TokenResponsePath string            `json:"token_response_path,omitempty"` // Lookup path of the token object
	TokenAccept       string            `json:"token_accept,omitempty"`        // Accept header of the token request
	ProfileAccept     string            `json:"profile_accept,omitempty"`      // Accept header of profile calls
	RedirectParam     string            `json:"redirect_param,omitempty"`      // default redirect_uri
	AuthorizeParams   map[string]string `json:"authorize_params,omitempty"`
	TokenParams       map[string]string `json:"token_params,omitempty"`
	ProfileParams     map[string]string `json:"profile_params,omitempty"`
	Retired           *Retired          `json:"retired,omitempty"`
	FreeScope         bool              `json:"free_scope,omitempty"`
	BaseURLHosts      []string          `json:"base_url_hosts,omitempty"`
	Protocol          string            `json:"protocol,omitempty"`
	OAuth1            *OAuth1Endpoints  `json:"oauth1,omitempty"`
	ScopeSeparator    string            `json:"scope_separator,omitempty"` // " " (default) or ","
	BaseScopes        []string          `json:"base_scopes"`
	Flags             []Flag            `json:"flags"`
	StoredOnly        []string          `json:"stored_only,omitempty"`
	FreeformScopes    bool              `json:"freeform_scopes"`
	TokenTypeOptional bool              `json:"token_type_optional,omitempty"`
	Profile           ProfileMap        `json:"profile"`
	EmailVerified     EmailRule         `json:"email_verified"`
	Hook              string            `json:"hook,omitempty"`
}

// Flag maps one boolean connection option to the scopes it adds.
type Flag struct {
	Option  string   `json:"option"`
	Scopes  []string `json:"scopes"`
	Default bool     `json:"default,omitempty"`
}

// ProfileMap gives Lookup paths from the provider profile to the normalized
// profile. Email paths read the email_url response when the descriptor has
// one.
type ProfileMap struct {
	UserID       string   `json:"user_id"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
	GivenName    string   `json:"given_name,omitempty"`
	FamilyName   string   `json:"family_name,omitempty"`
	Nickname     string   `json:"nickname,omitempty"`
	Username     string   `json:"username,omitempty"`
	Picture      string   `json:"picture,omitempty"`
	ProviderData []string `json:"provider_data,omitempty"`
}

// EmailRule decides email_verified.
type EmailRule struct {
	Rule string `json:"rule"`
	Path string `json:"path,omitempty"`
}

var (
	registry   = map[string]*Descriptor{}
	strategies []string
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	optionRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	scopeRE    = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	headerRE   = regexp.MustCompile(`^header:[A-Za-z][A-Za-z0-9-]{0,63}$`)
	queryRE    = regexp.MustCompile(`^query:[A-Za-z][A-Za-z0-9_]{0,63}$`)
	schemeRE   = regexp.MustCompile(`^scheme:[A-Za-z][A-Za-z0-9-]{0,31}$`)
	paramKeyRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	paramValRE = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	dateRE     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	tokenVarRE = regexp.MustCompile(`\{token\.([^}]*)\}`)
	tokenVarOK = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	indexRE    = regexp.MustCompile(`^(.+)\[(\d{1,3})\]$`)
)

// reservedParams are protocol parameters a descriptor may neither rename
// to nor fix.
var reservedParams = []string{"client_id", "client_secret", "redirect_uri", "response_type", "code", "state", "scope",
	"code_challenge", "code_challenge_method", "code_verifier", "grant_type", "access_token", "nonce", "login_hint"}

func init() {
	entries, err := files.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		b, err := files.ReadFile(e.Name())
		if err != nil {
			panic(err)
		}
		d, err := Parse(b)
		if err != nil {
			panic(fmt.Sprintf("providers: %s: %v", e.Name(), err))
		}
		if e.Name() != d.Strategy+".json" {
			panic(fmt.Sprintf("providers: %s declares strategy %q", e.Name(), d.Strategy))
		}
		registry[d.Strategy] = d
		strategies = append(strategies, d.Strategy)
	}
	sort.Strings(strategies)
}

// Parse decodes one descriptor strictly and validates it.
func Parse(b []byte) (*Descriptor, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d Descriptor
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Strategies lists every descriptor strategy, sorted.
func Strategies() []string { return slices.Clone(strategies) }

// Is reports whether strategy has a descriptor.
func Is(strategy string) bool { _, ok := registry[strategy]; return ok }

// Get returns a copy of strategy's descriptor.
func Get(strategy string) (*Descriptor, bool) {
	d, ok := registry[strategy]
	if !ok {
		return nil, false
	}
	return d.clone(), true
}

// All returns copies of every descriptor, sorted by strategy.
func All() []*Descriptor {
	out := make([]*Descriptor, 0, len(strategies))
	for _, s := range strategies {
		out = append(out, registry[s].clone())
	}
	return out
}

func (d *Descriptor) clone() *Descriptor {
	c := *d
	c.Source = slices.Clone(d.Source)
	c.BaseScopes = slices.Clone(d.BaseScopes)
	c.StoredOnly = slices.Clone(d.StoredOnly)
	c.Profile.ProviderData = slices.Clone(d.Profile.ProviderData)
	c.AuthorizeParams, c.TokenParams, c.ProfileParams = maps.Clone(d.AuthorizeParams), maps.Clone(d.TokenParams), maps.Clone(d.ProfileParams)
	c.BaseURLHosts = slices.Clone(d.BaseURLHosts)
	if d.Retired != nil {
		r := *d.Retired
		c.Retired = &r
	}
	if d.OAuth1 != nil {
		o := *d.OAuth1
		c.OAuth1 = &o
	}
	c.Flags = make([]Flag, len(d.Flags))
	for i, f := range d.Flags {
		c.Flags[i] = Flag{Option: f.Option, Scopes: slices.Clone(f.Scopes), Default: f.Default}
	}
	return &c
}

// Flag returns the flag for option.
func (d *Descriptor) Flag(option string) (Flag, bool) {
	for _, f := range d.Flags {
		if f.Option == option {
			return f, true
		}
	}
	return Flag{}, false
}

// EffectiveScopes is the base scopes, then each enabled flag's scopes, then
// extra (freeform) scopes, deduplicated in order (LR39b-3). enabled receives
// each flag's option and default.
func (d *Descriptor) EffectiveScopes(enabled func(option string, def bool) bool, extra []string) []string {
	out := []string{}
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, s := range d.BaseScopes {
		add(s)
	}
	for _, f := range d.Flags {
		if enabled(f.Option, f.Default) {
			for _, s := range f.Scopes {
				add(s)
			}
		}
	}
	for _, s := range extra {
		add(s)
	}
	return out
}

// Separator is the scope separator sent upstream.
func (d *Descriptor) Separator() string {
	if d.ScopeSeparator == "" {
		return " "
	}
	return d.ScopeSeparator
}

func (d *Descriptor) validate() error {
	if !nameRE.MatchString(d.Strategy) {
		return fmt.Errorf("strategy %q is invalid", d.Strategy)
	}
	if strings.TrimSpace(d.DisplayName) == "" || len(d.DisplayName) > 64 {
		return fmt.Errorf("display_name is invalid")
	}
	if len(d.Source) == 0 {
		return fmt.Errorf("source is required")
	}
	for _, s := range d.Source {
		if err := checkURL(s, false); err != nil {
			return fmt.Errorf("source %q: %w", s, err)
		}
	}
	if err := d.validateTier2(); err != nil {
		return err
	}
	if d.Protocol == ProtocolOAuth1 {
		return d.validateProfileAndRest()
	}
	for name, u := range map[string]string{"authorization_url": d.AuthorizationURL, "token_url": d.TokenURL, "profile_url": d.ProfileURL} {
		if err := checkURL(u, true); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if strings.HasPrefix(u, BaseURLPlaceholder) != (len(d.BaseURLHosts) > 0) {
			return fmt.Errorf("%s: %s must start the endpoints exactly when base_url_hosts is set", name, BaseURLPlaceholder)
		}
	}
	for name, u := range map[string]string{"email_url": d.EmailURL, "verify_url": d.VerifyURL} {
		if u != "" {
			if err := checkURL(u, true); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	switch d.ProfileMethod {
	case "", "GET", "POST":
	default:
		return fmt.Errorf("profile_method %q is invalid", d.ProfileMethod)
	}
	if d.ProfileAuth != "" && d.ProfileAuth != "bearer" && !headerRE.MatchString(d.ProfileAuth) && !queryRE.MatchString(d.ProfileAuth) && !schemeRE.MatchString(d.ProfileAuth) {
		return fmt.Errorf("profile_auth %q is invalid", d.ProfileAuth)
	}
	if d.TokenAuth != AuthPost && d.TokenAuth != AuthBasic && d.TokenAuth != AuthQuery {
		return fmt.Errorf("token_auth %q is invalid", d.TokenAuth)
	}
	if d.PKCE != PKCES256 && d.PKCE != PKCENone {
		return fmt.Errorf("pkce %q is invalid", d.PKCE)
	}
	return d.validateProfileAndRest()
}

// validateProfileAndRest checks scopes, flags, the profile map, the email
// rule and the hook.
func (d *Descriptor) validateProfileAndRest() error {
	if d.ScopeSeparator != "" && d.ScopeSeparator != " " && d.ScopeSeparator != "," {
		return fmt.Errorf("scope_separator %q is invalid", d.ScopeSeparator)
	}
	for _, s := range d.BaseScopes {
		if !scopeRE.MatchString(s) || strings.Contains(s, ",") {
			return fmt.Errorf("base scope %q is invalid", s)
		}
	}
	options := map[string]bool{}
	for _, f := range d.Flags {
		if !optionRE.MatchString(f.Option) || options[f.Option] {
			return fmt.Errorf("flag %q is invalid or duplicated", f.Option)
		}
		options[f.Option] = true
		if len(f.Scopes) == 0 {
			return fmt.Errorf("flag %q has no scopes", f.Option)
		}
		for _, s := range f.Scopes {
			if !scopeRE.MatchString(s) || strings.Contains(s, ",") {
				return fmt.Errorf("flag %q scope %q is invalid", f.Option, s)
			}
		}
	}
	for _, o := range d.StoredOnly {
		if !optionRE.MatchString(o) || options[o] {
			return fmt.Errorf("stored_only %q is invalid or also a flag", o)
		}
	}
	if d.Profile.UserID == "" {
		return fmt.Errorf("profile.user_id is required")
	}
	switch d.EmailVerified.Rule {
	case EmailNever:
	case EmailAlways:
		if d.Profile.Email == "" {
			return fmt.Errorf("email_verified always needs profile.email")
		}
	case EmailField:
		if d.EmailVerified.Path == "" || d.Profile.Email == "" {
			return fmt.Errorf("email_verified field needs a path and profile.email")
		}
	default:
		return fmt.Errorf("email_verified rule %q is invalid", d.EmailVerified.Rule)
	}
	if d.Hook != "" && !slices.Contains(hooks, d.Hook) {
		return fmt.Errorf("hook %q is unknown", d.Hook)
	}
	return nil
}

// validateTier2 checks the Plan 39d keys.
func (d *Descriptor) validateTier2() error {
	switch d.TokenMethod {
	case "", "POST", "GET":
	default:
		return fmt.Errorf("token_method %q is invalid", d.TokenMethod)
	}
	for name, v := range map[string]string{"token_accept": d.TokenAccept, "profile_accept": d.ProfileAccept} {
		if v != "" && !paramValRE.MatchString(v) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if d.TokenResponsePath != "" && !validPath(d.TokenResponsePath) {
		return fmt.Errorf("token_response_path is invalid")
	}
	if d.RedirectParam != "" && (!paramKeyRE.MatchString(d.RedirectParam) || slices.Contains(reservedParams, d.RedirectParam)) {
		return fmt.Errorf("redirect_param %q is invalid or reserved", d.RedirectParam)
	}
	for name, m := range map[string]map[string]string{"authorize_params": d.AuthorizeParams, "token_params": d.TokenParams, "profile_params": d.ProfileParams} {
		for k, v := range m {
			if !paramKeyRE.MatchString(k) || !paramValRE.MatchString(v) || slices.Contains(reservedParams, k) {
				return fmt.Errorf("%s.%s is invalid or reserved", name, k)
			}
		}
	}
	for _, m := range tokenVarRE.FindAllStringSubmatch(d.ProfileURL, -1) {
		if !tokenVarOK.MatchString(m[1]) {
			return fmt.Errorf("profile_url token variable %q is invalid", m[1])
		}
	}
	if i := strings.Index(d.ProfileURL, "{token."); i >= 0 {
		rest := d.ProfileURL[strings.Index(d.ProfileURL, "://")+3:]
		if slash := strings.Index(rest, "/"); slash < 0 || strings.Contains(rest[:slash], "{") {
			return fmt.Errorf("profile_url token variables may appear only after the host")
		}
	}
	if r := d.Retired; r != nil {
		if !dateRE.MatchString(r.Date) || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 200 || checkURL(r.Source, false) != nil {
			return fmt.Errorf("retired needs a YYYY-MM-DD date, a reason and an https source")
		}
	}
	if d.FreeScope && (len(d.Flags) > 0 || d.FreeformScopes) {
		return fmt.Errorf("free_scope excludes flags and freeform_scopes")
	}
	for _, h := range d.BaseURLHosts {
		if !hostRE.MatchString(h) {
			return fmt.Errorf("base_url_hosts entry %q is not a host name", h)
		}
	}
	switch d.Protocol {
	case "":
		if d.OAuth1 != nil {
			return fmt.Errorf("oauth1 needs protocol oauth1")
		}
	case ProtocolOAuth1:
		o := d.OAuth1
		if o == nil || d.AuthorizationURL != "" || d.TokenURL != "" || d.ProfileURL != "" || d.TokenAuth != "" || d.PKCE != "" || len(d.Flags) > 0 || len(d.BaseScopes) > 0 || d.FreeScope {
			return fmt.Errorf("an oauth1 descriptor has only the oauth1 endpoints")
		}
		for name, u := range map[string]string{"request_token_url": o.RequestTokenURL, "access_token_url": o.AccessTokenURL, "authorization_url": o.AuthorizationURL} {
			if err := checkURL(u, true); err != nil {
				return fmt.Errorf("oauth1.%s: %w", name, err)
			}
		}
	default:
		return fmt.Errorf("protocol %q is invalid", d.Protocol)
	}
	for _, p := range []string{d.Profile.UserID, d.Profile.Email, d.Profile.Name, d.Profile.GivenName, d.Profile.FamilyName, d.Profile.Nickname, d.Profile.Username, d.Profile.Picture, d.EmailVerified.Path} {
		if p != "" && !validPath(strings.TrimPrefix(p, TokenPrefix)) {
			return fmt.Errorf("profile path %q is invalid", p)
		}
	}
	return nil
}

// validPath reports whether path is Lookup syntax: dot-separated names, each
// optionally followed by [?field] or [N].
func validPath(path string) bool {
	if path == "" {
		return false
	}
	for _, seg := range strings.Split(path, ".") {
		name := seg
		if i := strings.Index(seg, "["); i >= 0 {
			name = seg[:i]
			inner, ok := strings.CutSuffix(seg[i+1:], "]")
			if !ok || strings.ContainsAny(inner, "[]") {
				return false
			}
			if f, isFilter := strings.CutPrefix(inner, "?"); isFilter {
				if f == "" {
					return false
				}
			} else if len(inner) == 0 || len(inner) > 3 || strings.Trim(inner, "0123456789") != "" {
				return false
			}
		}
		if name == "" || strings.ContainsAny(name, " ?") {
			return false
		}
	}
	return true
}

// checkURL requires https without userinfo; endpoints also without a
// fragment, and they may start with a template placeholder. Sources may link
// a document anchor.
func checkURL(raw string, endpoint bool) error {
	if endpoint {
		for _, p := range []string{CommunityPlaceholder, BaseURLPlaceholder} {
			if rest, ok := strings.CutPrefix(raw, p); ok {
				if !strings.HasPrefix(rest, "/") {
					return fmt.Errorf("placeholder must be followed by a path")
				}
				return nil
			}
		}
		raw = strings.Replace(raw, ShopPlaceholder, "shop.example", 1)
		raw = tokenVarRE.ReplaceAllString(raw, "v")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (endpoint && u.Fragment != "") {
		return fmt.Errorf("must be an https URL without userinfo (or fragment, for endpoints)")
	}
	return nil
}

// Lookup reads path from a decoded JSON document. Segments are separated by
// dots; a segment "name[?field]" selects the first element of the array name
// whose field is boolean true.
func Lookup(doc any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		name, filter := seg, ""
		index := -1
		if m := indexRE.FindStringSubmatch(seg); m != nil && !strings.Contains(seg, "[?") {
			name = m[1]
			fmt.Sscanf(m[2], "%d", &index)
		} else if i := strings.Index(seg, "[?"); i >= 0 {
			if !strings.HasSuffix(seg, "]") {
				return nil, false
			}
			name, filter = seg[:i], seg[i+2:len(seg)-1]
			if filter == "" {
				return nil, false
			}
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[name]; !ok {
			return nil, false
		}
		if index >= 0 {
			list, ok := cur.([]any)
			if !ok || index >= len(list) {
				return nil, false
			}
			cur = list[index]
		}
		if filter != "" {
			list, ok := cur.([]any)
			if !ok {
				return nil, false
			}
			found := false
			for _, e := range list {
				if em, ok := e.(map[string]any); ok && em[filter] == true {
					cur, found = em, true
					break
				}
			}
			if !found {
				return nil, false
			}
		}
	}
	return cur, true
}
