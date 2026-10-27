// Package connrules holds the rules every database connection must follow,
// whoever writes it: the seed, the Management API and, through the API, the
// console. Spec is a connection in Auth0's wire shape; Normalize and
// NormalizeAPI fill in the defaults and validate; Apply copies a Spec into a
// store.Connection and FromConnection reads one back.
//
// Two entry points apply two sets of defaults (D-0042):
//   - Normalize is for the seed. Defaults stay the seed's: a connection that
//     names no minimum password length keeps zeroauthy's long-standing 8,
//     fields the seed does not name are left alone by Apply, and the seed's
//     own limits hold (a minimum length up to identity.MaxPasswordBytes,
//     set_user_root_attributes on any custom database).
//   - NormalizeAPI is for the Management API and the console: Auth0's create
//     defaults for password_options, brute_force_protection, realms and
//     validation, and Auth0's limits (minimum length 1-72, the root
//     attributes rule, the connection name pattern). CreateDefaults adds the
//     options Auth0 fills in only when it creates a connection; the API
//     calls it before NormalizeAPI on POST, not on PATCH.
//
// Fields that are pointers or maps mean "not named" when nil: Apply leaves
// the stored value alone. NormalizeAPI fills them all, so an API write
// replaces the whole connection, as Auth0's PATCH replaces options.
package connrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Limits that are not Auth0's: custom database scripts and configuration.
const (
	maxScriptBytes   = 102400 // D-0022: smaller than Auth0's, kept
	maxConfigKeys    = 64
	maxConfigValueBy = 4096
	maxNameLength    = 128
	maxMetadataKeys  = 10
	maxMetadataValue = 255
)

// RootAttributesNeverOnLogin is Auth0's third value of
// set_user_root_attributes. store has constants for the other two.
const RootAttributesNeverOnLogin = "never_on_login"

var (
	// namePattern is Auth0's connection name format (D-0042).
	namePattern = regexp.MustCompile(`^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$`)
	configKey   = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
)

// Precedence identifiers.
var precedenceValues = []string{"email", "username", "phone_number"}

// ExtraSchema lists the options zeroauthy stores without interpreting, with
// the JSON type each must have: "object", "array", "boolean", "number" or
// "string". They live in Options.Extra beside the unknown keys, which are
// stored untouched and not checked (Auth0 accepts them as sent).
var ExtraSchema = map[string]string{
	"authentication_methods":               "object",
	"passkey_options":                      "object",
	"attributes":                           "object",
	"precedence":                           "array",
	"mfa":                                  "object",
	"disable_self_service_change_password": "boolean",
	"non_persistent_attrs":                 "array",
	"strategy_version":                     "number",
}

// topKey is the key of Connection.Extra that holds the top-level properties
// zeroauthy stores without interpreting (display_name, show_as_button,
// metadata, realms beyond the default, connected_accounts, authentication).
// It is reserved: an option of that name is refused. The store has no column
// for them, so they ride in Extra, beside the options, and FromConnection
// splits them out again.
const topKey = "zeroauthy:connection"

// Spec is a connection in Auth0's terms. Its JSON form is Auth0's request
// and response body; the caller's decoder should refuse unknown properties
// (Options keeps unknown option keys itself).
type Spec struct {
	Name     string  `json:"name,omitempty" yaml:"-"`
	Strategy string  `json:"strategy,omitempty" yaml:"-"`
	Options  Options `json:"options" yaml:"-"`

	EnabledClients     []string `json:"enabled_clients" yaml:"-"`
	IsDomainConnection bool     `json:"is_domain_connection" yaml:"-"`

	// The properties below are stored, not enforced (D-0042). Nil or empty
	// means not named.
	DisplayName       string            `json:"display_name,omitempty" yaml:"-"`
	Realms            []string          `json:"realms,omitempty" yaml:"-"`
	Metadata          map[string]string `json:"metadata,omitempty" yaml:"-"`
	ShowAsButton      *bool             `json:"show_as_button,omitempty" yaml:"-"`
	ConnectedAccounts map[string]any    `json:"connected_accounts,omitempty" yaml:"-"`
	Authentication    map[string]any    `json:"authentication,omitempty" yaml:"-"`

	// Federated strategies only, never part of the wire form. Apply leaves
	// the sealed secret and revision alone (their writers own them);
	// FromConnection fills all three. FederationIssuer is the issuer pinned
	// at the first successful discovery and is immutable once set.
	FederationSecretsSealed []byte `json:"-" yaml:"-"`
	FederationRevision      int64  `json:"-" yaml:"-"`
	FederationIssuer        string `json:"-" yaml:"-"`
}

// Federated reports whether s uses a federated strategy (Plan 24).
func (s *Spec) Federated() bool { return rules.IsFederated(s.Strategy) }

// FederationInput is s in the form the shared federated rules validate.
func (s *Spec) FederationInput() rules.Input {
	return rules.Input{
		Strategy: s.Strategy, Name: s.Name, Options: s.Options.Extra,
		RootAttributes: s.Options.SetUserRootAttributes, Authentication: s.Authentication,
		HasSealedSecret: len(s.FederationSecretsSealed) > 0,
	}
}

// Options is a connection's options. Known keys are typed; Extra holds the
// rest, untouched.
type Options struct {
	// PasswordOptions is the current password model. The legacy fields
	// below are the old one; Normalize maps them onto PasswordOptions and
	// clears them. Naming both is an error.
	PasswordOptions        *PasswordOptions  `json:"password_options,omitempty"`
	PasswordPolicy         string            `json:"passwordPolicy,omitempty"`
	PasswordComplexity     *LegacyComplexity `json:"password_complexity_options,omitempty"`
	PasswordHistory        *LegacyHistory    `json:"password_history,omitempty"`
	PasswordDictionary     *LegacyDictionary `json:"password_dictionary,omitempty"`
	PasswordNoPersonalInfo *LegacyEnable     `json:"password_no_personal_info,omitempty"`

	BruteForceProtection *bool       `json:"brute_force_protection,omitempty"`
	DisableSignup        bool        `json:"disable_signup"`
	RequiresUsername     bool        `json:"requires_username"`
	Validation           *Validation `json:"validation,omitempty"`

	EnabledDatabaseCustomization bool              `json:"enabledDatabaseCustomization"`
	ImportMode                   bool              `json:"import_mode"`
	CustomScripts                map[string]string `json:"customScripts,omitempty"`
	// Configuration is plaintext here; null values are allowed. FromConnection
	// never fills it: the stored form is sealed, and the caller that seals
	// and unseals it owns the wire form.
	Configuration         map[string]*string `json:"configuration,omitempty"`
	SetUserRootAttributes string             `json:"set_user_root_attributes,omitempty"`

	// Extra holds every other key: the known ones of ExtraSchema and the
	// unknown ones. Nil means not named.
	Extra map[string]any `json:"-"`
}

// Validation is options.validation.
type Validation struct {
	Username *UsernameValidation `json:"username,omitempty"`
}

// UsernameValidation bounds usernames.
type UsernameValidation struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// typedOptionKeys are the JSON names Options types, so decoding can leave
// them out of Extra.
var typedOptionKeys = func() map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(Options{})
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}()

// isTypedKey reports whether k is a typed option key in any letter case.
func isTypedKey(k string) bool {
	for t := range typedOptionKeys {
		if strings.EqualFold(t, k) {
			return true
		}
	}
	return false
}

type plainOptions Options

// UnmarshalJSON decodes the typed keys and collects the others into Extra.
func (o *Options) UnmarshalJSON(data []byte) error {
	// Keys are case-sensitive, as Auth0's JSON is: only the exact spelling of
	// a typed key is typed. Any other spelling of one goes to Extra, where
	// normalizeExtra refuses it, so nothing is stored twice or in plaintext.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	typedOnly := map[string]json.RawMessage{}
	for k, raw := range all {
		if typedOptionKeys[k] {
			typedOnly[k] = raw
		}
	}
	filtered, err := json.Marshal(typedOnly)
	if err != nil {
		return err
	}
	var p plainOptions
	dec0 := json.NewDecoder(bytes.NewReader(filtered))
	if err := dec0.Decode(&p); err != nil {
		return err
	}
	p.Extra = map[string]any{}
	for k, raw := range all {
		if typedOptionKeys[k] {
			continue
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&v); err != nil {
			return err
		}
		p.Extra[k] = v
	}
	*o = Options(p)
	return nil
}

// MarshalJSON encodes the typed keys and Extra together.
func (o Options) MarshalJSON() ([]byte, error) {
	typed, err := json.Marshal(plainOptions(o))
	if err != nil {
		return nil, err
	}
	if len(o.Extra) == 0 {
		return typed, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(typed, &m); err != nil {
		return nil, err
	}
	for k, v := range o.Extra {
		if isTypedKey(k) {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = raw
	}
	return json.Marshal(m)
}

// CreateDefaults fills the options and properties Auth0 sets only when it
// creates a connection and that zeroauthy stores without enforcing
// (D-0042, observations/management-connections.md C1): strategy_version,
// mfa, authentication_methods (password on, passkeys off), passkey_options,
// authentication and connected_accounts. Keys already named are kept.
func CreateDefaults(s *Spec) {
	if s.Options.Extra == nil {
		s.Options.Extra = map[string]any{}
	}
	if s.Federated() {
		// Database defaults (mfa, passwords, passkeys) stay off federated
		// connections; only the shared purpose objects apply.
		if s.Authentication == nil {
			s.Authentication = map[string]any{"active": true}
		}
		if s.ConnectedAccounts == nil {
			s.ConnectedAccounts = map[string]any{"active": false}
		}
		return
	}
	e := s.Options.Extra
	setDefault := func(k string, v any) {
		if _, ok := e[k]; !ok {
			e[k] = v
		}
	}
	setDefault("strategy_version", float64(2))
	setDefault("mfa", map[string]any{"active": true, "return_enroll_settings": true})
	setDefault("authentication_methods", map[string]any{
		"password": map[string]any{"enabled": true, "api_behavior": "required", "signup_behavior": "allow"},
		"passkey":  map[string]any{"enabled": false},
	})
	setDefault("passkey_options", map[string]any{
		"challenge_ui": "both", "progressive_enrollment_enabled": true, "local_enrollment_enabled": true,
	})
	if s.Authentication == nil {
		s.Authentication = map[string]any{"active": true}
	}
	if s.ConnectedAccounts == nil {
		s.ConnectedAccounts = map[string]any{"active": false}
	}
}

// Normalize fills in s's seed defaults and checks it. It returns every
// problem, each phrased without the connection's name. The checks that span
// connections (clients, duplicates, the default directory) are the caller's.
func Normalize(s *Spec) []error { return normalize(s, false) }

// NormalizeAPI is Normalize with Auth0's create defaults and limits, for
// the Management API and the console.
func NormalizeAPI(s *Spec) []error { return normalize(s, true) }

func normalize(s *Spec, api bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch {
	case s.Name == "":
		fail("name is required")
	case api && len(s.Name) > maxNameLength:
		fail("name must be at most %d characters", maxNameLength)
	case api && !namePattern.MatchString(s.Name):
		fail("name %q must be letters and digits, with single hyphens between them", s.Name)
	}
	if s.Strategy == "" && !api {
		s.Strategy = store.StrategyDatabase
	}
	if s.Strategy != store.StrategyDatabase && !s.Federated() {
		fail("strategy %q is not supported (only %q, %q, %q or %q)", s.Strategy,
			store.StrategyDatabase, rules.Google, rules.OAuth2, rules.OIDC)
	}
	for _, r := range s.Realms {
		if r == "" {
			fail("realms must not contain an empty name")
		}
	}
	if api && s.Realms == nil {
		s.Realms = []string{s.Name}
	}
	if len(s.Metadata) > maxMetadataKeys {
		fail("metadata has %d properties, at most %d allowed", len(s.Metadata), maxMetadataKeys)
	}
	for _, k := range slices.Sorted(maps.Keys(s.Metadata)) {
		if len(s.Metadata[k]) > maxMetadataValue {
			fail("metadata value for %q is longer than %d characters", k, maxMetadataValue)
		}
	}

	o := &s.Options
	if s.Federated() {
		errs = append(errs, normalizeFederated(s)...)
		if api && o.Extra == nil {
			o.Extra = map[string]any{}
		}
		return errs
	}
	errs = append(errs, normalizePasswords(o, api)...)

	if api && o.BruteForceProtection == nil {
		t := true
		o.BruteForceProtection = &t
	}
	if api && o.Validation == nil {
		o.Validation = &Validation{}
	}
	if o.Validation != nil && o.Validation.Username != nil {
		u := o.Validation.Username
		switch {
		case u.Min < 1:
			fail("validation.username.min must be at least 1")
		case u.Max > 128:
			fail("validation.username.max must be at most 128")
		case u.Min >= u.Max:
			fail("validation.username.min must be less than max")
		}
	}

	errs = append(errs, normalizeExtra(o)...)
	errs = append(errs, normalizeCustomDB(o, api)...)

	if api && o.Extra == nil {
		o.Extra = map[string]any{}
	}
	return errs
}

// normalizeFederated checks a federated connection: no database options, the
// shared Extra rules, then the strategy's own rules.
func normalizeFederated(s *Spec) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	o := &s.Options
	if o.PasswordOptions != nil || o.PasswordPolicy != "" || o.PasswordComplexity != nil ||
		o.PasswordHistory != nil || o.PasswordDictionary != nil || o.PasswordNoPersonalInfo != nil ||
		o.BruteForceProtection != nil || o.Validation != nil || o.RequiresUsername ||
		o.EnabledDatabaseCustomization || o.ImportMode || len(o.CustomScripts) > 0 || len(o.Configuration) > 0 {
		fail("database options are not supported on strategy %q", s.Strategy)
	}
	for _, k := range slices.Sorted(maps.Keys(ExtraSchema)) {
		if _, ok := o.Extra[k]; ok {
			fail("option %q is not supported on strategy %q", k, s.Strategy)
		}
	}
	errs = append(errs, normalizeExtra(o)...)
	_, ruleErrs := rules.Parse(s.FederationInput())
	return append(errs, ruleErrs...)
}

func normalizeExtra(o *Options) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if _, reserved := o.Extra[topKey]; reserved {
		fail("option %q is reserved", topKey)
	}
	for _, k := range slices.Sorted(maps.Keys(o.Extra)) {
		if isTypedKey(k) {
			fail("option %q is a named option; spell it exactly, in lower case as documented", k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(ExtraSchema)) {
		v, ok := o.Extra[k]
		if !ok {
			continue
		}
		if got := jsonType(v); got != ExtraSchema[k] {
			fail("%s must be a JSON %s, not %s", k, ExtraSchema[k], got)
		}
	}
	if list, ok := o.Extra["precedence"].([]any); ok {
		var seen []string
		bad := false
		for _, p := range list {
			name, isStr := p.(string)
			if !isStr || !slices.Contains(precedenceValues, name) || slices.Contains(seen, name) {
				bad = true
				break
			}
			seen = append(seen, name)
		}
		if bad || len(seen) < 3 {
			fail("precedence must list at least 3 of %v, each once", precedenceValues)
		}
	}
	if list, ok := o.Extra["non_persistent_attrs"].([]any); ok {
		for _, p := range list {
			if _, isStr := p.(string); !isStr {
				fail("non_persistent_attrs must be a list of strings")
				break
			}
		}
	}
	return errs
}

// jsonType names v's JSON type; the Go number kinds all read as "number".
func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any, []string:
		return "array"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64, float32, int, int64, int32, json.Number:
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

func normalizeCustomDB(o *Options, api bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	switch o.SetUserRootAttributes {
	case "", store.RootAttributesOnEachLogin, store.RootAttributesOnFirstLogin, RootAttributesNeverOnLogin:
		// Auth0 allows the attribute only on a custom database that keeps
		// users in the external store. The seed always allowed it on any
		// custom database, and keeps doing so.
		if api && o.SetUserRootAttributes != "" && (!o.EnabledDatabaseCustomization || o.ImportMode) {
			fail("set_user_root_attributes needs a custom database that uses the external store (enabledDatabaseCustomization without import_mode)")
		}
	default:
		fail("set_user_root_attributes %q must be %s, %s or %s", o.SetUserRootAttributes,
			store.RootAttributesOnEachLogin, store.RootAttributesOnFirstLogin, RootAttributesNeverOnLogin)
	}
	if !o.EnabledDatabaseCustomization {
		if len(o.CustomScripts) > 0 || len(o.Configuration) > 0 || o.ImportMode {
			fail("customScripts, configuration and import_mode require enabledDatabaseCustomization")
		}
		return errs
	}
	for _, name := range slices.Sorted(maps.Keys(o.CustomScripts)) {
		if !slices.Contains(store.ScriptNames, name) {
			fail("unknown customScripts key %q", name)
			continue
		}
		if len(o.CustomScripts[name]) > maxScriptBytes {
			fail("customScripts.%s is larger than %d bytes", name, maxScriptBytes)
		}
	}
	if strings.TrimSpace(o.CustomScripts[store.ScriptLogin]) == "" {
		fail("enabledDatabaseCustomization requires a login script")
	}
	if len(o.Configuration) > maxConfigKeys {
		fail("configuration has %d keys, at most %d allowed", len(o.Configuration), maxConfigKeys)
	}
	for _, k := range slices.Sorted(maps.Keys(o.Configuration)) {
		if !configKey.MatchString(k) {
			fail("configuration key %q must be 1-128 characters of A-Za-z0-9_", k)
		}
		if v := o.Configuration[k]; v != nil && len(*v) > maxConfigValueBy {
			fail("configuration value for %q is larger than %d bytes", k, maxConfigValueBy)
		}
	}
	return errs
}

// Apply copies a normalized s into c. It leaves the identity (tenant, ID,
// creation time, origin) and the sealed configuration alone. Fields s does
// not name (nil pointers and maps) leave c's value alone.
func Apply(s *Spec, c *store.Connection) {
	c.Name, c.Strategy = s.Name, s.Strategy
	c.IsDomainConnection = s.IsDomainConnection
	c.EnabledClients = nilIfEmpty(s.EnabledClients)
	o := &s.Options
	c.DisableSignup, c.RequiresUsername = o.DisableSignup, o.RequiresUsername
	if o.BruteForceProtection != nil {
		c.BruteForceProtection = *o.BruteForceProtection
	}
	if v := o.Validation; v != nil {
		c.UsernameMin, c.UsernameMax = 0, 0
		if v.Username != nil {
			c.UsernameMin, c.UsernameMax = v.Username.Min, v.Username.Max
		}
	}
	applyPasswords(o.PasswordOptions, &c.PasswordOptions)
	c.EnabledDatabaseCustomization, c.ImportMode = o.EnabledDatabaseCustomization, o.ImportMode
	c.SetUserRootAttributes = o.SetUserRootAttributes
	c.CustomScripts = maps.Clone(o.CustomScripts)
	if o.Extra != nil {
		extra := cloneMap(o.Extra)
		if top := s.topLevel(); len(top) > 0 {
			extra[topKey] = top
		}
		c.Extra = nil
		if len(extra) > 0 {
			c.Extra = extra
		}
	}
}

// topLevel returns the stored-not-enforced top-level properties as a JSON
// object, leaving out what is at its default (realms equal to [name]).
func (s *Spec) topLevel() map[string]any {
	top := map[string]any{}
	if s.DisplayName != "" {
		top["display_name"] = s.DisplayName
	}
	if s.ShowAsButton != nil {
		top["show_as_button"] = *s.ShowAsButton
	}
	if len(s.Metadata) > 0 {
		m := map[string]any{}
		for k, v := range s.Metadata {
			m[k] = v
		}
		top["metadata"] = m
	}
	if len(s.Realms) > 0 && !slices.Equal(s.Realms, []string{s.Name}) {
		r := make([]any, len(s.Realms))
		for i, v := range s.Realms {
			r[i] = v
		}
		top["realms"] = r
	}
	if s.ConnectedAccounts != nil {
		top["connected_accounts"] = cloneMap(s.ConnectedAccounts)
	}
	if s.Authentication != nil {
		top["authentication"] = cloneMap(s.Authentication)
	}
	if s.FederationIssuer != "" {
		top["federation_issuer"] = s.FederationIssuer
	}
	return top
}

// FromConnection returns c's settings as a Spec in Auth0's terms, the
// starting point of an update. Configuration is not included (it is sealed).
// A connection with the seed's require_character_classes of 1 or 2
// (Complexity.MinCharacterClasses) has no equivalent in Auth0's model: its
// character_types are those stored, and the value is kept on the Spec's
// complexity, out of the JSON form.
func FromConnection(c *store.Connection) *Spec {
	bf := c.BruteForceProtection
	s := &Spec{
		Name: c.Name, Strategy: c.Strategy,
		FederationSecretsSealed: slices.Clone(c.FederationSecretsSealed),
		FederationRevision:      c.FederationRevision,
		EnabledClients:          orEmpty(c.EnabledClients),
		IsDomainConnection:      c.IsDomainConnection,
		Realms:                  []string{c.Name},
		Options: Options{
			PasswordOptions:      fromPasswords(&c.PasswordOptions),
			BruteForceProtection: &bf,
			DisableSignup:        c.DisableSignup, RequiresUsername: c.RequiresUsername,
			Validation:                   &Validation{},
			EnabledDatabaseCustomization: c.EnabledDatabaseCustomization, ImportMode: c.ImportMode,
			CustomScripts:         maps.Clone(c.CustomScripts),
			SetUserRootAttributes: c.SetUserRootAttributes,
			Extra:                 cloneMap(c.Extra),
		},
	}
	if c.UsernameMin != 0 || c.UsernameMax != 0 {
		s.Options.Validation.Username = &UsernameValidation{Min: c.UsernameMin, Max: c.UsernameMax}
	}
	if s.Options.Extra == nil {
		s.Options.Extra = map[string]any{}
	}
	if top, ok := s.Options.Extra[topKey].(map[string]any); ok {
		delete(s.Options.Extra, topKey)
		s.DisplayName, _ = top["display_name"].(string)
		if v, ok := top["show_as_button"].(bool); ok {
			s.ShowAsButton = &v
		}
		if m, ok := top["metadata"].(map[string]any); ok {
			s.Metadata = map[string]string{}
			for k, v := range m {
				s.Metadata[k], _ = v.(string)
			}
		}
		if r := stringList(top["realms"]); len(r) > 0 {
			s.Realms = r
		}
		s.ConnectedAccounts, _ = top["connected_accounts"].(map[string]any)
		s.Authentication, _ = top["authentication"].(map[string]any)
		s.FederationIssuer, _ = top["federation_issuer"].(string)
	}
	if s.Federated() {
		// Database options have no meaning on federated connections.
		s.Options.PasswordOptions, s.Options.BruteForceProtection, s.Options.Validation = nil, nil, nil
	}
	return s
}

// KeepFederationIssuer carries prev's pinned issuer into next when the
// writer's Spec did not name one (the seed never does), so a re-apply never
// unpins it.
func KeepFederationIssuer(prev, next *store.Connection) {
	top, _ := prev.Extra[topKey].(map[string]any)
	issuer, _ := top["federation_issuer"].(string)
	if issuer == "" {
		return
	}
	if next.Extra == nil {
		next.Extra = map[string]any{}
	}
	nt, _ := next.Extra[topKey].(map[string]any)
	if nt == nil {
		nt = map[string]any{}
		next.Extra[topKey] = nt
	}
	if _, ok := nt["federation_issuer"]; !ok {
		nt["federation_issuer"] = issuer
	}
}

func stringList(v any) []string {
	switch l := v.(type) {
	case []string:
		return slices.Clone(l)
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// nilIfEmpty clones s, returning nil for an empty list, which is how the
// store keeps one.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Clone(s)
}

// cloneMap deep-copies a JSON-shaped object.
func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneAny(v)
	}
	return out
}

func cloneAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneAny(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return v
}

// maxPasswordLength is the longest minimum password length each mode takes.
func maxMinLength(api bool) int {
	if api {
		return 72
	}
	return identity.MaxPasswordBytes
}
