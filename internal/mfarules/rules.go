// Package mfarules freezes the Plan 33 MFA wire contract. It contains no
// enrollment, challenge, delivery or token runtime; see D-0059 for local rulings.
package mfarules

import (
	_ "embed"
	"encoding/json"
)

const MethodIDPattern = `^[a-z-]+\|dev_[A-Za-z0-9]{20}$`
const EnrollmentIDPattern = `^dev_[A-Za-z0-9]{20}$`

type Factor struct{ Name, Status string }
type MethodType struct {
	Type      string
	Creatable bool
	Fields    []string
	Secret    []string
}

// RouteSchema uses a distinct name because Go shares a namespace between
// functions and types. Route retains the planned public lookup function.
type RouteSchema struct {
	Operation, Method, Path, Source string
	Scopes                          []string
	ScopeMode                       string `json:"scope_mode"`
	Parameters                      []map[string]any
	Body                            map[string]any
	Errors                          map[string]string
	Responses                       map[string]any
}
type Member struct {
	Name, Source         string
	Arguments            map[string]any
	Triggers             []string
	RequiresCustomizeMFA bool     `json:"requires_customize_mfa"`
	IncompatibleWith     []string `json:"incompatible_with"`
	AvailableFactors     []string `json:"available_factors"`
	UnavailableFactors   []string `json:"unavailable_factors"`
}
type LimitSchema struct {
	TOTPAlgorithm         string `json:"totp_algorithm"`
	TOTPDigits            int    `json:"totp_digits"`
	TOTPStepSeconds       int    `json:"totp_step_seconds"`
	TOTPWindow            int    `json:"totp_window"`
	RecoveryCodeLength    int    `json:"recovery_code_length"`
	RecoveryCodeAlphabet  string `json:"recovery_code_alphabet"`
	RecoveryCodesActive   int    `json:"recovery_codes_active"`
	MFATokenSeconds       int    `json:"mfa_token_seconds"`
	EmailCodeSeconds      int    `json:"email_code_seconds"`
	EmailCodeAttempts     int    `json:"email_code_attempts"`
	EmailCodeDigits       int    `json:"email_code_digits"`
	EnrollmentTicketDays  int    `json:"enrollment_ticket_days"`
	RememberBrowserDays   int    `json:"remember_browser_days"`
	DeviceWindowDays      int    `json:"device_window_days"`
	FailedAttempts        int    `json:"failed_attempts"`
	ThrottleWindowSeconds int    `json:"throttle_window_seconds"`
	EmailSends            int    `json:"email_sends"`
	EmailResendSeconds    int    `json:"email_resend_seconds"`
	IDRandomLength        int    `json:"id_random_length"`
	PerPageDefault        int    `json:"per_page_default"`
	PerPageMax            int    `json:"per_page_max"`
}
type Contract struct {
	Version           int
	ReviewedAt        string `json:"reviewed_at"`
	Decision          string
	Factors           []Factor
	MethodTypes       []MethodType `json:"method_types"`
	Routes            []RouteSchema
	Limits            LimitSchema
	Screens           map[string][]string
	ActionMembers     []Member            `json:"action_members"`
	DeployHandlers    map[string]string   `json:"deploy_handlers"`
	DeployLimitations map[string]string   `json:"deploy_limitations"`
	DeployRoutes      map[string][]string `json:"deploy_routes"`
	Gaps              []string
	Discovery         map[string]string
	SettingsSemantics string `json:"settings_semantics"`
	EmailEnrollment   string `json:"email_enrollment"`
	Events            map[string]any
}

//go:embed inventory.json
var inventoryJSON []byte

var Limits = Inventory().Limits

// Inventory returns a deep independent snapshot of the frozen contract.
func Inventory() Contract {
	var c Contract
	if err := json.Unmarshal(inventoryJSON, &c); err != nil {
		panic("mfarules: invalid inventory: " + err.Error())
	}
	return c
}
func Factors() []Factor { return Inventory().Factors }

// Route looks up an operation ID, or a METHOD /path key. Grant operation IDs
// distinguish the three MFA contracts sharing POST /oauth/token.
func Route(op string) RouteSchema {
	for _, r := range Inventory().Routes {
		if r.Operation == op || r.Method+" "+r.Path == op {
			return r
		}
	}
	return RouteSchema{}
}
func MethodTypes() []MethodType    { return Inventory().MethodTypes }
func Screens() map[string][]string { return Inventory().Screens }
func ActionMember(name string) Member {
	for _, m := range Inventory().ActionMembers {
		if m.Name == name {
			return m
		}
	}
	return Member{}
}
func DeployHandlers() map[string]string { return Inventory().DeployHandlers }
