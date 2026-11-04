package connrules

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Passwordless strategies (Plan 34). Their option contract is the frozen
// phonerules schema: validated here, defaults merged from it.
const (
	StrategyEmail = "email"
	StrategySMS   = "sms"
)

// Keys of the sealed passwordless secrets in Connection.ConfigurationSealed.
// They never appear in the wire form (P17).
const (
	SecretTwilioToken   = "twilio_token"
	SecretGatewaySecret = "gateway_secret"
)

// Passwordless reports whether s uses an email or SMS passwordless strategy.
func (s *Spec) Passwordless() bool { return IsPasswordless(s.Strategy) }

// IsPasswordless reports whether strategy is "email" or "sms".
func IsPasswordless(strategy string) bool {
	return strategy == StrategyEmail || strategy == StrategySMS
}

type passwordlessContract struct {
	schema   *jsonschema.Schema
	defaults map[string]any
}

var passwordlessContracts = sync.OnceValue(func() map[string]passwordlessContract {
	out := map[string]passwordlessContract{}
	for _, strategy := range []string{StrategyEmail, StrategySMS} {
		c := phonerules.ConnectionOptions(strategy)
		compiler := jsonschema.NewCompiler()
		res := "urn:zeroauthy:connection:" + strategy
		if err := compiler.AddResource(res, c.Options); err != nil {
			panic("connrules: " + err.Error())
		}
		schema, err := compiler.Compile(res)
		if err != nil {
			panic("connrules: " + err.Error())
		}
		out[strategy] = passwordlessContract{schema: schema, defaults: c.Defaults}
	}
	return out
})

// EmailOptions are the email strategy's message options.
type EmailOptions struct {
	From    string `json:"from"`
	Subject string `json:"subject"`
	Syntax  string `json:"syntax"`
	Body    string `json:"body"`
}

// GatewayAuthentication signs the sms_gateway request as a JWT.
type GatewayAuthentication struct {
	Audience            string `json:"audience"`
	Method              string `json:"method"`
	Secret              string `json:"secret"`
	SecretBase64Encoded bool   `json:"secret_base64_encoded"`
	Subject             string `json:"subject"`
}

// SMSOptions are the sms strategy's message and provider options.
type SMSOptions struct {
	From                string                 `json:"from"`
	Syntax              string                 `json:"syntax"`
	Template            string                 `json:"template"`
	Provider            string                 `json:"provider"`
	TwilioSID           string                 `json:"twilio_sid"`
	TwilioToken         string                 `json:"-"`
	MessagingServiceSID string                 `json:"messaging_service_sid"`
	GatewayURL          string                 `json:"gateway_url"`
	GatewayAuth         *GatewayAuthentication `json:"gateway_authentication"`
	ForwardReqInfo      bool                   `json:"forward_req_info"`
}

// PasswordlessOptions is a passwordless connection's options with the
// contract's defaults applied.
type PasswordlessOptions struct {
	Strategy string
	Email    *EmailOptions
	SMS      *SMSOptions
	TOTP     struct{ Length, TimeStep int }
	// DisableSignup refuses to create users on first sign-in.
	DisableSignup bool
	BruteForce    bool
	// AuthParams are defaults merged into magic links (email).
	AuthParams map[string]string
}

// PasswordlessOf reads the options of a stored email or sms connection.
// open unseals ConfigurationSealed into the credential map; with a nil open
// the credentials stay empty.
func PasswordlessOf(conn store.Connection, open func(sealed []byte) (map[string]string, error)) (*PasswordlessOptions, error) {
	if !IsPasswordless(conn.Strategy) {
		return nil, fmt.Errorf("connection strategy %q is not passwordless", conn.Strategy)
	}
	spec := FromConnection(&conn)
	m := passwordlessInput(spec)
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var w struct {
		Email *EmailOptions `json:"email"`
		TOTP  struct {
			Length   int `json:"length"`
			TimeStep int `json:"time_step"`
		} `json:"totp"`
		DisableSignup bool `json:"disable_signup"`
		BruteForce    bool `json:"brute_force_protection"`
		SMSOptions
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("stored passwordless options: %w", err)
	}
	out := &PasswordlessOptions{Strategy: conn.Strategy, DisableSignup: w.DisableSignup, BruteForce: w.BruteForce}
	out.TOTP.Length, out.TOTP.TimeStep = w.TOTP.Length, w.TOTP.TimeStep
	out.AuthParams = parseAuthParams(m["authParams"])
	switch conn.Strategy {
	case StrategyEmail:
		out.Email = w.Email
	case StrategySMS:
		sms := w.SMSOptions
		if open != nil && len(conn.ConfigurationSealed) > 0 {
			secrets, err := open(conn.ConfigurationSealed)
			if err != nil {
				return nil, fmt.Errorf("open passwordless credentials: %w", err)
			}
			sms.TwilioToken = secrets[SecretTwilioToken]
			if sms.GatewayAuth != nil {
				sms.GatewayAuth.Secret = secrets[SecretGatewaySecret]
			}
		}
		out.SMS = &sms
	}
	return out, nil
}

// parseAuthParams reads authParams, stored as a query string or an object of
// strings, into a map.
func parseAuthParams(v any) map[string]string {
	out := map[string]string{}
	switch p := v.(type) {
	case string:
		q, _ := url.ParseQuery(p)
		for k := range q {
			out[k] = q.Get(k)
		}
	case map[string]any:
		for k, e := range p {
			if s, ok := e.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// passwordlessInput is the option object the contract's schema validates:
// the stored options with the contract's defaults filled in.
func passwordlessInput(s *Spec) map[string]any {
	m := cloneMap(s.Options.Extra)
	if m == nil {
		m = map[string]any{}
	}
	delete(m, topKey)
	m["disable_signup"] = s.Options.DisableSignup
	if s.Options.BruteForceProtection != nil {
		m["brute_force_protection"] = *s.Options.BruteForceProtection
	}
	mergeDefaults(m, cloneMap(passwordlessContracts()[s.Strategy].defaults))
	if _, ok := m["name"]; !ok {
		m["name"] = s.Name
	}
	return m
}

// mergeDefaults sets the keys of defaults m lacks, recursing into objects.
func mergeDefaults(m, defaults map[string]any) {
	for k, d := range defaults {
		cur, ok := m[k]
		if !ok {
			m[k] = d
			continue
		}
		cm, curObj := cur.(map[string]any)
		dm, defObj := d.(map[string]any)
		if curObj && defObj {
			mergeDefaults(cm, dm)
		}
	}
}

// passwordlessDefaults stores the contract's defaults on a created
// connection, as Auth0 shows them on a GET.
func passwordlessDefaults(s *Spec) {
	m := passwordlessInput(s)
	if s.Options.BruteForceProtection == nil {
		t := true
		s.Options.BruteForceProtection = &t
	}
	delete(m, "disable_signup")
	delete(m, "brute_force_protection")
	maps.Copy(s.Options.Extra, m)
	if s.Authentication == nil {
		s.Authentication = map[string]any{"active": true}
	}
	if s.ConnectedAccounts == nil {
		s.ConnectedAccounts = map[string]any{"active": false}
	}
}

// normalizePasswordless checks an email or sms connection: its name, no
// database options, then the frozen option schema and the gateway URL.
func normalizePasswordless(s *Spec) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	o := &s.Options
	if s.Name != s.Strategy && s.Name != "" {
		fail("a %q connection must be named %q", s.Strategy, s.Strategy)
	}
	if o.PasswordOptions != nil || o.PasswordPolicy != "" || o.PasswordComplexity != nil ||
		o.PasswordHistory != nil || o.PasswordDictionary != nil || o.PasswordNoPersonalInfo != nil ||
		o.Validation != nil || o.RequiresUsername || o.EnabledDatabaseCustomization || o.ImportMode ||
		len(o.CustomScripts) > 0 || len(o.Configuration) > 0 || o.SetUserRootAttributes != "" {
		fail("database options are not supported on strategy %q", s.Strategy)
	}
	for _, k := range slices.Sorted(maps.Keys(ExtraSchema)) {
		if _, ok := o.Extra[k]; ok && k != "non_persistent_attrs" {
			fail("option %q is not supported on strategy %q", k, s.Strategy)
		}
	}
	errs = append(errs, normalizeExtra(o)...)

	in := passwordlessInput(s)
	// authParams is a query string or an object of strings; the frozen
	// schema types the string form.
	if ap, ok := in["authParams"]; ok {
		if obj, isObj := ap.(map[string]any); isObj {
			for _, k := range slices.Sorted(maps.Keys(obj)) {
				if _, isStr := obj[k].(string); !isStr {
					fail("authParams.%s must be a string", k)
				}
			}
			in["authParams"] = "x"
		}
	}
	// A PATCH that leaves gateway_authentication.secret out keeps the stored one.
	if ga, ok := in["gateway_authentication"].(map[string]any); ok && s.StoredSecrets[SecretGatewaySecret] {
		if _, named := ga["secret"]; !named {
			ga["secret"] = "x"
		}
	}
	// A null twilio_token clears the sealed token (MergePasswordlessSecrets);
	// the schema only types the string form.
	if v, ok := in[SecretTwilioToken]; ok && v == nil {
		delete(in, SecretTwilioToken)
	}
	if err := passwordlessContracts()[s.Strategy].schema.Validate(in); err != nil {
		errs = append(errs, schemaErrors(err)...)
	}
	if s.Strategy == StrategySMS {
		errs = append(errs, checkSMSGateway(in)...)
	}
	return errs
}

// schemaErrors turns a validation failure into one error per violation,
// naming the option and never echoing a credential's value.
func schemaErrors(err error) []error {
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []error{fmt.Errorf("options: %v", err)}
	}
	var out []error
	for _, line := range strings.Split(ve.Error(), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		loc, msg, found := strings.Cut(line, ": ")
		if !found || !strings.HasPrefix(loc, "at '") {
			continue
		}
		path := strings.Trim(strings.TrimPrefix(loc, "at "), "'")
		path = "options" + strings.ReplaceAll(path, "/", ".")
		if strings.Contains(path, "twilio_token") || strings.HasSuffix(path, ".secret") {
			msg = "is invalid"
		}
		out = append(out, fmt.Errorf("%s: %s", path, msg))
	}
	if len(out) == 0 {
		out = append(out, fmt.Errorf("options do not match the %s connection schema", ve.InstanceLocation))
	}
	return out
}

// checkSMSGateway applies the checks the schema cannot express: an
// sms_gateway needs its URL, and the URL must not name a local or private
// host. The dial-time check against resolved addresses is the sender's.
func checkSMSGateway(in map[string]any) []error {
	var errs []error
	raw, has := in["gateway_url"].(string)
	if provider, _ := in["provider"].(string); provider == "sms_gateway" && !has {
		errs = append(errs, fmt.Errorf("options.gateway_url is required for provider sms_gateway"))
	}
	if !has {
		return errs
	}
	if err := checkGatewayURL(raw); err != nil {
		errs = append(errs, fmt.Errorf("options.gateway_url: %v", err))
	}
	return errs
}

func checkGatewayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("must be an https URL")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain credentials")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".local") {
		return fmt.Errorf("must not name a local host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
			return fmt.Errorf("must not name a private or loopback address")
		}
	}
	return nil
}

// MergePasswordlessSecrets removes the credentials from s's options (they
// are sealed, never stored in Extra) and returns the credential map to seal:
// the ones s names, plus the ones in current that s leaves alone. A null
// twilio_token or gateway_authentication clears the credential.
func MergePasswordlessSecrets(s *Spec, current map[string]string) map[string]string {
	out := map[string]string{}
	if s.Strategy != StrategySMS {
		return out
	}
	e := s.Options.Extra
	if tok, named := e[SecretTwilioToken]; named {
		if v, ok := tok.(string); ok {
			out[SecretTwilioToken] = v
		}
		delete(e, SecretTwilioToken)
	} else if v, ok := current[SecretTwilioToken]; ok {
		out[SecretTwilioToken] = v
	}
	if ga, ok := e["gateway_authentication"].(map[string]any); ok {
		if v, named := ga["secret"].(string); named {
			out[SecretGatewaySecret] = v
		} else if v, ok := current[SecretGatewaySecret]; ok {
			out[SecretGatewaySecret] = v
		}
		delete(ga, "secret")
	}
	return out
}
