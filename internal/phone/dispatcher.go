package phone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

// Route names the purpose of a send. ConnectionID is the sms connection's
// ID for passwordless (and optional context for other purposes).
type Route struct{ Purpose, ConnectionID string } // Purpose: mfa|passwordless|reset|verify

// ErrNoProvider reports that the routed provider does not work (D-0060
// LR3): nothing was sent. It is wrapped in a *SendError.
var ErrNoProvider = errors.New("phone: no working phone provider")

// Credential envelopes shared with the Management API writers.
const (
	ProviderCredentialsLabel = "phone-provider/v1"
	guardianProviderLabel    = "guardian-provider/v1"
	guardianPrefix           = "/guardian/factors/"
)

// ProviderCredentialsAAD binds a branding provider's sealed credentials.
func ProviderCredentialsAAD(tid, name string) []string { return []string{tid, name} }

// Dispatcher routes each phone message to its provider (phonerules.Routing)
// and renders its template. It is safe for concurrent use.
type Dispatcher struct {
	Store   store.Store
	Wrapper keys.Wrapper
	// Actions runs custom-phone-provider and send-phone-message; nil means
	// Action-backed providers never work.
	Actions ActionRunner
	// HTTP is the Twilio/SNS client; nil uses NewHTTPClient.
	HTTP *http.Client
	// GatewayHTTP is the sms_gateway client; nil uses NewGatewayClient.
	GatewayHTTP *http.Client
	Now         func() time.Time
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// FailureCode is the log type of a failed send: Guardian codes for MFA,
// "fn" for every other purpose (phonerules log_codes).
func FailureCode(purpose, method string) string {
	if purpose != "mfa" {
		return "fn"
	}
	if method == "voice" {
		return "gd_send_voice_failure"
	}
	return "gd_send_sms_failure"
}

// plan is a resolved route: the frozen rule and what it reads.
type plan struct {
	rule      phonerules.RoutingRule
	tenant    *store.Tenant
	provider  *store.PhoneProvider // branding provider, nil when none
	guardian  *store.GuardianSettings
	conn      *store.Connection
	sms       *connrules.SMSOptions
	gTwilio   map[string]string // Guardian Twilio public fields
	gSealed   []byte
	actionsOK bool // the rule's Action trigger has a bound Action
}

// lookupRule finds the routing rule. Guardian and connection providers
// apply only to mfa and passwordless respectively.
func lookupRule(purpose string, consolidated bool, guardian, connection string) (phonerules.RoutingRule, bool) {
	for _, r := range rules().routing {
		if r.Purpose == purpose && r.Consolidated == consolidated && r.GuardianProvider == guardian && r.ConnectionProvider == connection {
			return r, true
		}
	}
	return phonerules.RoutingRule{}, false
}

func (d *Dispatcher) resolve(ctx context.Context, tid string, r Route) (*plan, error) {
	t, err := d.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return nil, err
	}
	p := &plan{tenant: t}
	consolidated := tenantrules.PhoneSettingsOf(t).Consolidated
	if r.ConnectionID != "" {
		conn, err := d.Store.Connections().Get(ctx, tid, r.ConnectionID)
		if err != nil {
			return nil, err
		}
		p.conn = conn
	}
	guardian, connection := "", ""
	switch r.Purpose {
	case "mfa":
		g, err := d.Store.MFA().GetGuardian(ctx, tid)
		if err != nil && !errors.Is(err, store.ErrMFAUnavailable) {
			return nil, err
		}
		if g == nil {
			g = &store.GuardianSettings{}
		}
		p.guardian = g
		guardian = "auth0"
		var sel struct {
			Provider string `json:"provider"`
		}
		if raw := guardianStored(g, "selected-provider"); raw != nil && json.Unmarshal(raw, &sel) == nil && sel.Provider != "" {
			guardian = sel.Provider
		}
	case "passwordless":
		if p.conn == nil || p.conn.Strategy != connrules.StrategySMS {
			return nil, errors.New("phone: passwordless sends need an sms connection")
		}
		opts, err := connrules.PasswordlessOf(*p.conn, func(sealed []byte) (map[string]string, error) {
			return keys.OpenConnectionConfig(d.Wrapper, tid, p.conn.ID, sealed)
		})
		if err != nil {
			return nil, err
		}
		p.sms = opts.SMS
		connection = p.sms.Provider
		if connection == "" {
			connection = "twilio"
		}
	case "reset", "verify":
	default:
		return nil, fmt.Errorf("phone: unknown route purpose %q", r.Purpose)
	}
	rule, ok := lookupRule(r.Purpose, consolidated, guardian, connection)
	if !ok {
		return nil, fmt.Errorf("phone: no routing rule for %s", r.Purpose)
	}
	p.rule = rule
	switch rule.Sender {
	case "branding":
		list, err := d.Store.Phone().ListPhoneProviders(ctx, tid)
		if err != nil {
			return nil, err
		}
		if len(list) > 0 {
			p.provider = &list[0]
			if p.provider.Name == "custom" && !p.provider.Disabled {
				if p.actionsOK, err = d.bound(ctx, tid, TriggerCustomPhoneProvider); err != nil {
					return nil, err
				}
			}
		}
	case "guardian-twilio":
		p.gTwilio = map[string]string{}
		if raw := guardianStored(p.guardian, "providers/twilio"); raw != nil {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			for k, v := range m {
				if s, ok := v.(string); ok {
					p.gTwilio[k] = s
				}
			}
			p.gSealed = p.guardian.SealedSecrets[guardianKey(p.guardian, "providers/twilio")]
		}
	case "action:send-phone-message":
		if p.actionsOK, err = d.bound(ctx, tid, TriggerSendPhoneMessage); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (d *Dispatcher) bound(ctx context.Context, tid, trigger string) (bool, error) {
	if d.Actions == nil {
		return false, nil
	}
	return d.Actions.PhoneActionBound(ctx, tid, trigger)
}

// guardianKey prefers the phone factor's record and falls back to the
// legacy sms factor's (both are Plan 33 stored routes).
func guardianKey(g *store.GuardianSettings, suffix string) string {
	if g == nil {
		return ""
	}
	phoneKey := guardianPrefix + "phone/" + suffix
	if _, ok := g.Stored[phoneKey]; ok {
		return phoneKey
	}
	if _, ok := g.SealedSecrets[phoneKey]; ok {
		return phoneKey
	}
	return guardianPrefix + "sms/" + suffix
}

func guardianStored(g *store.GuardianSettings, suffix string) json.RawMessage {
	if g == nil {
		return nil
	}
	raw := g.Stored[guardianKey(g, suffix)]
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// working applies D-0060 LR3 to a resolved plan.
func (p *plan) working() bool {
	switch p.rule.Sender {
	case "branding":
		pr := p.provider
		if pr == nil || pr.Disabled {
			return false
		}
		if pr.Name == "custom" {
			return p.actionsOK
		}
		var cfg map[string]any
		if json.Unmarshal(pr.Configuration, &cfg) != nil {
			return false
		}
		for _, f := range rules().required[pr.Name] {
			if s, _ := cfg[f].(string); s == "" {
				return false
			}
		}
		return len(pr.SealedCredentials) > 0
	case "guardian-twilio":
		return p.gTwilio["sid"] != "" && (p.gTwilio["from"] != "" || p.gTwilio["messaging_service_sid"] != "") && len(p.gSealed) > 0
	case "action:send-phone-message":
		return p.actionsOK
	case "connection-twilio":
		return p.sms.TwilioSID != "" && p.sms.TwilioToken != ""
	case "connection-gateway":
		return p.sms.GatewayURL != ""
	}
	return false
}

// Working reports whether route r of tenant tid has a working provider:
// only then may a factor or SMS connection be offered.
func (d *Dispatcher) Working(ctx context.Context, tid string, r Route) (bool, error) {
	p, err := d.resolve(ctx, tid, r)
	if err != nil {
		return false, err
	}
	return p.working(), nil
}

// DeliveryMethods returns the delivery methods ("text", "voice") the
// working provider of route r can use, or nil when it does not work. A
// branding provider offers its configured delivery_methods limited to what
// its adapter supports (sns is text only); Guardian Twilio and the
// send-phone-message Action offer both.
func (d *Dispatcher) DeliveryMethods(ctx context.Context, tid string, r Route) ([]string, error) {
	p, err := d.resolve(ctx, tid, r)
	if err != nil || !p.working() {
		return nil, err
	}
	both := []string{"text", "voice"}
	if p.rule.Sender != "branding" {
		return both, nil
	}
	var cfg struct {
		Methods []string `json:"delivery_methods"`
	}
	_ = json.Unmarshal(p.provider.Configuration, &cfg)
	var supported []string
	for _, pr := range rules().providers {
		if pr.Name == p.provider.Name {
			supported = pr.DeliveryMethods
		}
	}
	var out []string
	for _, m := range both {
		if slices.Contains(cfg.Methods, m) && slices.Contains(supported, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// Send renders m's template for route r and delivers it. m needs To,
// DeliveryMethod, Type and Code; Body and From are set here. Failures are
// *SendError (ErrNoProvider, ErrTemplateDisabled and ErrActionUnbound
// wrapped) and never contain the code, number or credentials.
func (d *Dispatcher) Send(ctx context.Context, tid string, r Route, m Message) (Result, error) {
	p, err := d.resolve(ctx, tid, r)
	if err != nil {
		return Result{}, err
	}
	m.TenantID = tid
	if m.DeliveryMethod == "" {
		m.DeliveryMethod = "text"
	}
	if !p.working() {
		if p.rule.Sender == "connection-twilio" {
			// Auth0 fails the send when the connection's Twilio credentials
			// are missing.
			return Result{}, &SendError{Class: ClassProviderAuth, Err: errors.New("twilio_sid and twilio_token are required")}
		}
		return Result{}, &SendError{Class: ClassProviderAuth, Err: ErrNoProvider}
	}
	ri := renderInfo{tenant: p.tenant, code: m.Code, locale: m.Locale, request: RequestFrom(ctx), phone: m.To}
	if p.conn != nil {
		ri.connection = p.conn.Name
	}
	if m.UserID != "" {
		if u, err := d.Store.Users().Get(ctx, tid, m.UserID); err == nil {
			ri.user = u
		}
	}
	if m.ClientID != "" {
		if c, err := d.Store.Clients().Get(ctx, tid, m.ClientID); err == nil {
			ri.client = c
		}
	}
	typ := templateType(m.Type)
	text, voice, from, err := d.render(ctx, p, typ, m.DeliveryMethod, ri)
	if err != nil {
		return Result{}, &SendError{Class: ClassTransient, Err: err}
	}
	m.Body, m.From = text, from
	if m.DeliveryMethod == "voice" {
		m.Body = voice
	}
	switch p.rule.Sender {
	case "branding":
		pr := *p.provider
		if pr.Name == "custom" {
			return Result{}, d.Actions.RunPhoneAction(ctx, tid, ActionInput{Trigger: TriggerCustomPhoneProvider, Route: r, Message: m, MessageType: typ, AsText: text, AsVoice: voice, Request: ri.request})
		}
		s, err := SenderFor(pr, func(sealed []byte) ([]byte, error) {
			return keys.OpenBound(d.Wrapper, ProviderCredentialsLabel, ProviderCredentialsAAD(tid, pr.Name), sealed)
		}, d.HTTP)
		if err != nil {
			return Result{}, &SendError{Class: ClassProviderAuth, Err: err}
		}
		if pr.Name == "sns" && !alphanumericSenderID(m.From) {
			// SNS takes From as an alphanumeric sender ID; a phone number
			// would be rejected, so the provider's sender_id applies.
			m.From = ""
		}
		return s.Send(ctx, m)
	case "guardian-twilio":
		plain, err := keys.OpenBound(d.Wrapper, guardianProviderLabel, []string{tid, guardianKey(p.guardian, "providers/twilio")}, p.gSealed)
		var creds struct {
			AuthToken string `json:"auth_token"`
		}
		if err != nil || json.Unmarshal(plain, &creds) != nil || creds.AuthToken == "" {
			return Result{}, &SendError{Class: ClassProviderAuth, Err: errors.New("guardian Twilio credentials unavailable")}
		}
		m.From = ""
		return NewTwilio(TwilioConfig{SID: p.gTwilio["sid"], AuthToken: creds.AuthToken, DefaultFrom: p.gTwilio["from"], MessagingServiceSID: p.gTwilio["messaging_service_sid"]}, d.HTTP).Send(ctx, m)
	case "action:send-phone-message":
		return Result{}, d.Actions.RunPhoneAction(ctx, tid, ActionInput{Trigger: TriggerSendPhoneMessage, Route: r, Message: m, MessageType: typ, AsText: text, AsVoice: voice, Request: ri.request})
	case "connection-twilio":
		m.From = ""
		return NewTwilio(TwilioConfig{SID: p.sms.TwilioSID, AuthToken: p.sms.TwilioToken, DefaultFrom: p.sms.From, MessagingServiceSID: p.sms.MessagingServiceSID}, d.HTTP).Send(ctx, m)
	case "connection-gateway":
		cfg := GatewayConfig{URL: p.sms.GatewayURL, From: p.sms.From, ForwardReqInfo: p.sms.ForwardReqInfo}
		if a := p.sms.GatewayAuth; a != nil {
			cfg.Auth = &GatewayAuth{Audience: a.Audience, Subject: a.Subject, Secret: a.Secret, SecretBase64Encoded: a.SecretBase64Encoded}
		}
		return NewGateway(cfg, d.GatewayHTTP, d.now).Send(ctx, m)
	}
	return Result{}, &SendError{Class: ClassProviderAuth, Err: ErrNoProvider}
}

// render returns the text and voice bodies and the from value of the rule's
// template source. Only the selected method's body must render; the other
// is best effort (Actions receive both).
func (d *Dispatcher) render(ctx context.Context, p *plan, typ, method string, ri renderInfo) (text, voice, from string, err error) {
	source, _, _ := strings.Cut(p.rule.Template, ":")
	var srcText, srcVoice string
	var vars func(method string) map[string]any
	macros := false
	switch source {
	case "branding":
		c, err := brandingContent(ctx, d.Store, p.tenant.ID, typ)
		if err != nil {
			return "", "", "", err
		}
		srcText, srcVoice, from = c.Body.Text, c.Body.Voice, c.From
		vars = func(m string) map[string]any { return brandingVars(ri, m) }
	case "guardian":
		field := "verification_message"
		if typ == "otp_enroll" {
			field = "enrollment_message"
		}
		srcText = rules().guardianDefaults[field]
		var stored map[string]string
		if raw := guardianStored(p.guardian, "templates"); raw != nil && json.Unmarshal(raw, &stored) == nil && stored[field] != "" {
			srcText = stored[field]
		}
		srcVoice = srcText
		vars = func(m string) map[string]any { return guardianVars(ri, m) }
	case "connection":
		srcText = p.sms.Template
		srcVoice = srcText
		from = p.sms.From
		macros = p.sms.Syntax != "liquid"
		vars = func(string) map[string]any { return connectionVars(ri) }
	default:
		return "", "", "", errors.New("phone: unknown template source")
	}
	renderOne := func(src, m string) (string, error) {
		if macros {
			return renderMacros(src, vars(m))
		}
		return renderLiquid(ctx, src, vars(m))
	}
	text, terr := renderOne(srcText, "text")
	voice, verr := renderOne(srcVoice, "voice")
	if (method == "voice" && verr != nil) || (method != "voice" && terr != nil) {
		return "", "", "", errRender
	}
	return text, voice, from, nil
}

var senderIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,11}$`)

// alphanumericSenderID reports whether s is a valid SNS sender ID: 1–11
// letters and digits with at least one letter.
func alphanumericSenderID(s string) bool {
	return senderIDPattern.MatchString(s) && strings.ContainsAny(strings.ToLower(s), "abcdefghijklmnopqrstuvwxyz")
}
