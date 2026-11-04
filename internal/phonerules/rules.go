// Package phonerules freezes the Plan 34 passwordless and phone wire contract.
// It contains no delivery, storage or login runtime; see D-0060 for local
// rulings and the P1–Pn gaps.
package phonerules

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// RouteSchema uses a distinct name because Go shares one namespace between
// functions and types; Route keeps the planned lookup function name (as
// mfarules does).
type RouteSchema struct {
	Operation  string            `json:"operation"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Source     string            `json:"source"`
	Sources    []string          `json:"sources"`
	Scopes     []string          `json:"scopes"`
	ScopeMode  string            `json:"scope_mode"`
	Parameters []map[string]any  `json:"parameters"`
	Body       map[string]any    `json:"body"`
	Success    int               `json:"success"`
	Response   map[string]any    `json:"response"`
	Errors     map[string]string `json:"errors"`
	Semantics  string            `json:"semantics"`
}

// Schema is a passwordless connection's options contract.
type Schema struct {
	Strategy              string         `json:"strategy"`
	Source                string         `json:"source"`
	Name                  string         `json:"name"`
	Options               map[string]any `json:"options"`
	Sealed                []string       `json:"sealed"`
	Defaults              map[string]any `json:"defaults"`
	ConsolidatedOverrides []string       `json:"consolidated_overrides"`
	TemplateVariables     []string       `json:"template_variables"`
}

type Body struct {
	Text  string `json:"text"`
	Voice string `json:"voice"`
}

type Content struct {
	From   string `json:"from"`
	Syntax string `json:"syntax"`
	Body   Body   `json:"body"`
}

type TemplateType struct {
	Type      string   `json:"type"`
	Default   Content  `json:"default"`
	Variables []string `json:"variables"`
}

type Provider struct {
	Name            string   `json:"name"`
	Extension       bool     `json:"extension"`
	DeliveryMethods []string `json:"delivery_methods"`
}

// ProviderSchema records the configuration and credential fields of a provider.
type ProviderSchema struct {
	Name          string   `json:"name"`
	Source        string   `json:"source"`
	Configuration []string `json:"configuration"`
	Required      []string `json:"required"`
	Credentials   []string `json:"credentials"`
	Working       string   `json:"working"`
	Wire          string   `json:"wire"`
}

// RoutingRule selects the sender and template for one delivery purpose.
// GuardianProvider applies to mfa only; ConnectionProvider to passwordless only.
type RoutingRule struct {
	Purpose            string `json:"purpose"`
	Consolidated       bool   `json:"consolidated"`
	GuardianProvider   string `json:"guardian_provider"`
	ConnectionProvider string `json:"connection_provider"`
	Sender             string `json:"sender"`
	Template           string `json:"template"`
	Failure            string `json:"failure"`
	Source             string `json:"source"`
}

type Trigger struct {
	ID          string   `json:"id"`
	Handler     string   `json:"handler"`
	Version     string   `json:"version"`
	Blocking    bool     `json:"blocking"`
	Event       []string `json:"event"`
	API         []string `json:"api"`
	Retries     int      `json:"retries"`
	MaxBindings int      `json:"max_bindings"`
	Source      string   `json:"source"`
}

// MaskRule replaces every character except the last Visible with Char.
type MaskRule struct {
	Visible int      `json:"visible"`
	Char    string   `json:"char"`
	Source  string   `json:"source"`
	Applies []string `json:"applies"`
	Note    string   `json:"note"`
}

type LimitSchema struct {
	OTPLengthDefault              int `json:"otp_length_default"`
	OTPLengthMin                  int `json:"otp_length_min"`
	OTPLengthMax                  int `json:"otp_length_max"`
	OTPLifetimeDefaultSeconds     int `json:"otp_lifetime_default_seconds"`
	OTPLifetimeMinSeconds         int `json:"otp_lifetime_min_seconds"`
	OTPAttempts                   int `json:"otp_attempts"`
	LinkLifetimeDefaultSeconds    int `json:"link_lifetime_default_seconds"`
	LinkTokenBytes                int `json:"link_token_bytes"`
	StartIDHexLength              int `json:"start_id_hex_length"`
	StartPerIPPerHour             int `json:"start_per_ip_per_hour"`
	IdentifierSendsPerHour        int `json:"identifier_sends_per_hour"`
	PhoneSendsPerUserPerHour      int `json:"phone_sends_per_user_per_hour"`
	VoiceNewRequestsPerHour       int `json:"voice_new_requests_per_hour"`
	SignupOTPLifetimeSeconds      int `json:"signup_otp_lifetime_seconds"`
	SignupOTPSendsPerHour         int `json:"signup_otp_sends_per_hour"`
	MFACodeLengthDefault          int `json:"mfa_code_length_default"`
	MFACodeLengthMin              int `json:"mfa_code_length_min"`
	MFACodeLengthMax              int `json:"mfa_code_length_max"`
	MFACodeLifetimeDefaultSeconds int `json:"mfa_code_lifetime_default_seconds"`
	MFACodeLifetimeMinSeconds     int `json:"mfa_code_lifetime_min_seconds"`
	MFACodeLifetimeMaxSeconds     int `json:"mfa_code_lifetime_max_seconds"`
	GatewayTimeoutSeconds         int `json:"gateway_timeout_seconds"`
	GatewayJWTSeconds             int `json:"gateway_jwt_seconds"`
	CustomProviderRetries         int `json:"custom_provider_retries"`
	NotificationReasonMax         int `json:"notification_reason_max"`
	BackoffImmediate              int `json:"backoff_immediate"`
	BackoffMinSeconds             int `json:"backoff_min_seconds"`
	BackoffMaxSeconds             int `json:"backoff_max_seconds"`
	BackoffJitterPercent          int `json:"backoff_jitter_percent"`
	BackoffResetSeconds           int `json:"backoff_reset_seconds"`
	TemplateBodyMax               int `json:"template_body_max"`
	PhoneNumberMax                int `json:"phone_number_max"`
	PhoneDigitsMin                int `json:"phone_digits_min"`
	PhoneDigitsMax                int `json:"phone_digits_max"`
}

type Contract struct {
	Version           int                 `json:"version"`
	ReviewedAt        string              `json:"reviewed_at"`
	Decision          string              `json:"decision"`
	Evidence          map[string]string   `json:"evidence"`
	Routes            []RouteSchema       `json:"routes"`
	Connections       []Schema            `json:"connections"`
	Providers         []Provider          `json:"providers"`
	ProviderSchemas   []ProviderSchema    `json:"provider_schemas"`
	Templates         []TemplateType      `json:"templates"`
	GuardianTemplates map[string]any      `json:"guardian_templates"`
	Routing           []RoutingRule       `json:"routing"`
	Screens           map[string][]string `json:"screens"`
	Hosted            map[string]string   `json:"hosted"`
	Triggers          []Trigger           `json:"triggers"`
	Masking           MaskRule            `json:"masking"`
	Limits            LimitSchema         `json:"limits"`
	LogCodes          map[string]string   `json:"log_codes"`
	TenantSettings    map[string]string   `json:"tenant_settings"`
	EmailTemplates    map[string]string   `json:"email_templates"`
	Identity          map[string]string   `json:"identity"`
	Gateway           map[string]any      `json:"gateway"`
	ProtectionBackoff map[string]string   `json:"protection_backoff"`
	Discovery         map[string]string   `json:"discovery"`
	Rulings           []string            `json:"rulings"`
	Gaps              []string            `json:"gaps"`
	GapNotes          map[string]string   `json:"gap_notes"`
}

//go:embed inventory.json
var inventoryJSON []byte

// Limits are the frozen numeric rules (documented or D-0060 local rulings).
var Limits = Inventory().Limits

var masking = Inventory().Masking

// Inventory returns a deep independent snapshot of the frozen contract.
func Inventory() Contract {
	var c Contract
	if err := json.Unmarshal(inventoryJSON, &c); err != nil {
		panic("phonerules: invalid inventory: " + err.Error())
	}
	return c
}

// Route looks up an operation ID or a "METHOD /path" key. Operation IDs with a
// "#variant" suffix distinguish contracts sharing one method and path.
func Route(op string) RouteSchema {
	for _, r := range Inventory().Routes {
		if r.Operation == op || r.Method+" "+r.Path == op {
			return r
		}
	}
	return RouteSchema{}
}

// ConnectionOptions returns the options contract of the email or sms strategy.
func ConnectionOptions(strategy string) Schema {
	for _, s := range Inventory().Connections {
		if s.Strategy == strategy {
			return s
		}
	}
	return Schema{}
}

func TemplateTypes() []TemplateType     { return Inventory().Templates }
func ProviderNames() []Provider         { return Inventory().Providers }
func Routing() []RoutingRule            { return Inventory().Routing }
func Screens() map[string][]string      { return Inventory().Screens }
func ProviderSchemas() []ProviderSchema { return Inventory().ProviderSchemas }

// ActionTrigger returns the frozen phone trigger contract.
func ActionTrigger(id string) Trigger {
	for _, t := range Inventory().Triggers {
		if t.ID == id {
			return t
		}
	}
	return Trigger{}
}

// MaskPhone applies the frozen masking rule: every character except the last
// Visible is replaced with Char; values no longer than Visible are fully masked.
func MaskPhone(e164 string) string {
	r := masking
	runes := []rune(e164)
	if len(runes) <= r.Visible {
		return strings.Repeat(r.Char, len(runes))
	}
	return strings.Repeat(r.Char, len(runes)-r.Visible) + string(runes[len(runes)-r.Visible:])
}
