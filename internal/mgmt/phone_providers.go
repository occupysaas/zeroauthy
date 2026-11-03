package mgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

var (
	errPhoneUnavailable      = &Error{Status: http.StatusNotImplemented, Code: "phone_unavailable", Message: "The storage plugin does not support phone messaging"}
	errPhoneProviderNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_phone_provider", Message: "Phone provider has not been configured"}
	errPhoneProviderConflict = &Error{Status: http.StatusConflict, Code: "conflict", Message: "A phone provider is already configured for this tenant"}
	errPhoneCustomConflict   = &Error{Status: http.StatusConflict, Code: "conflict", Message: "Custom phone provider conflict"}
	errPhoneCustomNoAction   = &Error{Status: http.StatusBadRequest, Code: "custom_email_provider_deployed_action_not_found", Message: "A deployed custom-phone-provider Action is required for the custom provider"}
	errPhoneThrottled        = &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Message: "Too many phone messages; retry later"}
)

// phoneContract caches the frozen phonerules data (Inventory re-parses its
// JSON on every call).
type phoneContract struct {
	providers map[string]phonerules.Provider
	schemas   map[string]phonerules.ProviderSchema
	templates map[string]phonerules.TemplateType
	order     []string // template types in contract order
}

var (
	phoneContractOnce sync.Once
	phoneContractData phoneContract
)

func phoneRules() *phoneContract {
	phoneContractOnce.Do(func() {
		c := phoneContract{providers: map[string]phonerules.Provider{}, schemas: map[string]phonerules.ProviderSchema{}, templates: map[string]phonerules.TemplateType{}}
		for _, p := range phonerules.ProviderNames() {
			c.providers[p.Name] = p
		}
		for _, s := range phonerules.ProviderSchemas() {
			c.schemas[s.Name] = s
		}
		for _, t := range phonerules.TemplateTypes() {
			c.templates[t.Type] = t
			c.order = append(c.order, t.Type)
		}
		phoneContractData = c
	})
	return &phoneContractData
}

// phoneFail maps store errors of the phone routes; old plugins answer 501.
func (h *Handlers) phoneFail(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, store.ErrPhoneUnavailable):
		Fail(w, errPhoneUnavailable)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errPhoneProviderConflict)
	default:
		h.failTx(w, r, what, err)
	}
}

func phoneWriteAllowed(h *Handlers, r *http.Request) error {
	t, err := h.Store.Tenants().Get(r.Context(), resolved(r).ID)
	if err != nil {
		return err
	}
	if t.Reserved {
		return errSystemTenant
	}
	return nil
}

func phoneProviderAAD(tid, name string) []string { return phone.ProviderCredentialsAAD(tid, name) }

const phoneProviderLabel = phone.ProviderCredentialsLabel

// phoneActions runs Action-backed phone providers: PhoneActions when set,
// otherwise the Actions engine.
func (h *Handlers) phoneActions() phone.ActionRunner {
	if h.PhoneActions != nil {
		return h.PhoneActions
	}
	if h.Actions != nil {
		return h.Actions
	}
	return nil
}

func (h *Handlers) sealPhoneCredentials(tid, name string, creds map[string]string) ([]byte, error) {
	plain, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}
	return keys.SealBound(h.Wrapper, phoneProviderLabel, phoneProviderAAD(tid, name), plain)
}

func (h *Handlers) openPhoneCredentials(p *store.PhoneProvider) ([]byte, error) {
	return keys.OpenBound(h.Wrapper, phoneProviderLabel, phoneProviderAAD(p.TenantID, p.Name), p.SealedCredentials)
}

func phoneProviderJSON(t *store.Tenant, p *store.PhoneProvider) map[string]any {
	cfg := map[string]any{}
	_ = json.Unmarshal(p.Configuration, &cfg)
	return map[string]any{"id": p.ID, "tenant": t.Name, "name": p.Name, "channel": "phone", "disabled": p.Disabled, "configuration": cfg, "created_at": p.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_at": p.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}

var (
	snsRegionRE   = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]$`)
	snsSenderIDRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,11}$`)
)

var phoneCredentialMax = map[string]int{"auth_token": 255, "access_key_id": 128, "secret_access_key": 255}

// validatePhoneConfiguration enforces the flattened PhoneProviderConfiguration
// per provider (phonerules provider_schemas) and returns the stored form.
func validatePhoneConfiguration(name string, raw json.RawMessage) (map[string]any, error) {
	rules := phoneRules()
	schema, ok := rules.schemas[name]
	if !ok {
		return nil, badBody("unknown phone provider")
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil || in == nil {
		return nil, badBody("configuration must be an object")
	}
	out := map[string]any{}
	for key, v := range in {
		if !slices.Contains(schema.Configuration, key) {
			return nil, badBody("configuration.%s is not valid for provider %s", key, name)
		}
		if key == "delivery_methods" {
			var methods []string
			if json.Unmarshal(v, &methods) != nil {
				return nil, badBody("configuration.delivery_methods must be an array of strings")
			}
			out[key] = methods
			continue
		}
		var s string
		if json.Unmarshal(v, &s) != nil || s == "" || len(s) > 255 {
			return nil, badBody("configuration.%s must be a non-empty string", key)
		}
		out[key] = s
	}
	for _, key := range schema.Required {
		if _, ok := out[key]; !ok {
			return nil, badBody("configuration.%s is required", key)
		}
	}
	methods, _ := out["delivery_methods"].([]string)
	allowed := rules.providers[name].DeliveryMethods
	if len(methods) == 0 || len(slices.Compact(slices.Sorted(slices.Values(methods)))) != len(methods) {
		return nil, badBody("configuration.delivery_methods needs one or more distinct methods")
	}
	for _, m := range methods {
		if !slices.Contains(allowed, m) {
			return nil, badBody("configuration.delivery_methods: %q is not supported by provider %s", m, name)
		}
	}
	switch name {
	case "twilio":
		_, from := out["default_from"]
		_, mssid := out["mssid"]
		if !from && !mssid {
			return nil, badBody("configuration needs default_from or mssid")
		}
		if slices.Contains(methods, "voice") && !from {
			return nil, badBody("configuration.default_from is required for voice")
		}
	case "sns":
		if !snsRegionRE.MatchString(out["region"].(string)) {
			return nil, badBody("configuration.region is not a valid AWS region")
		}
		if s, ok := out["sender_id"].(string); ok && !snsSenderIDRE.MatchString(s) {
			return nil, badBody("configuration.sender_id must be 1 to 11 letters, digits or hyphens")
		}
		if s, ok := out["sms_type"].(string); ok && s != "Transactional" && s != "Promotional" {
			return nil, badBody("configuration.sms_type must be Transactional or Promotional")
		}
	}
	return out, nil
}

// mergePhoneCredentials applies incoming credentials over current (same
// provider name only) and requires every credential field of the provider.
func (h *Handlers) mergePhoneCredentials(name string, current *store.PhoneProvider, incoming map[string]json.RawMessage, have bool) (map[string]string, bool, error) {
	schema := phoneRules().schemas[name]
	creds := map[string]string{}
	changed := have
	if current != nil && current.Name == name && len(current.SealedCredentials) > 0 {
		plain, err := h.openPhoneCredentials(current)
		if err != nil {
			return nil, false, errors.New("phone provider credentials unavailable")
		}
		if json.Unmarshal(plain, &creds) != nil {
			return nil, false, errors.New("phone provider credentials unavailable")
		}
	} else if len(schema.Credentials) > 0 {
		changed = true
	}
	for key, v := range incoming {
		if !slices.Contains(schema.Credentials, key) {
			return nil, false, badBody("credentials.%s is not valid for provider %s", key, name)
		}
		var s string
		if json.Unmarshal(v, &s) != nil || s == "" || len(s) > phoneCredentialMax[key] {
			return nil, false, badBody("credentials.%s must be a non-empty string of at most %d characters", key, phoneCredentialMax[key])
		}
		if isEmailCredentialPlaceholder(s) {
			// A deploy tool placeholder never replaces a configured secret.
			if _, ok := creds[key]; !ok {
				return nil, false, badBody("credentials.%s is a placeholder", key)
			}
			continue
		}
		creds[key] = s
	}
	for _, key := range schema.Credentials {
		if creds[key] == "" {
			return nil, false, badBody("credentials.%s is required", key)
		}
	}
	return creds, changed, nil
}

func (h *Handlers) customActionDeployed(ctx context.Context, tid string) (bool, error) {
	b, err := h.Store.Actions().Bindings(ctx, tid, "custom-phone-provider")
	if err != nil {
		return false, err
	}
	return len(b) > 0, nil
}

func decodePhoneProviderBody(r *http.Request, allowed ...string) (map[string]json.RawMessage, error) {
	raw, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	for k := range raw {
		if !slices.Contains(allowed, k) {
			return nil, badBody("unknown property %s", k)
		}
	}
	return raw, nil
}

func rawObject(raw map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool, error) {
	v, ok := raw[key]
	if !ok {
		return nil, false, nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(v, &m) != nil || m == nil {
		return nil, true, badBody("%s must be an object", key)
	}
	return m, true, nil
}

func rawName(raw map[string]json.RawMessage) (string, bool, error) {
	v, ok := raw["name"]
	if !ok {
		return "", false, nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", true, badBody("name must be a string")
	}
	if _, known := phoneRules().providers[s]; !known {
		return "", true, badBody("name must be one of twilio, custom, sns")
	}
	return s, true, nil
}

func rawDisabled(raw map[string]json.RawMessage) (bool, bool, error) {
	v, ok := raw["disabled"]
	if !ok {
		return false, false, nil
	}
	var b bool
	if json.Unmarshal(v, &b) != nil {
		return false, true, badBody("disabled must be a boolean")
	}
	return b, true, nil
}

func (h *Handlers) ListPhoneProviders(w http.ResponseWriter, r *http.Request, p mgmtapi.ListPhoneProvidersParams) {
	t := resolved(r)
	list, err := h.Store.Phone().ListPhoneProviders(r.Context(), t.ID)
	if err != nil {
		h.phoneFail(w, r, "list phone providers", err)
		return
	}
	out := []any{}
	for i := range list {
		if p.Disabled != nil && list[i].Disabled != *p.Disabled {
			continue
		}
		out = append(out, phoneProviderJSON(t, &list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (h *Handlers) GetPhoneProvider(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.Store.Phone().GetPhoneProvider(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneProviderNotFound)
		return
	}
	if err != nil {
		h.phoneFail(w, r, "get phone provider", err)
		return
	}
	writeJSON(w, http.StatusOK, phoneProviderJSON(resolved(r), p))
}

func (h *Handlers) CreatePhoneProvider(w http.ResponseWriter, r *http.Request) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "create phone provider", err)
		return
	}
	raw, err := decodePhoneProviderBody(r, "name", "disabled", "configuration", "credentials")
	if err != nil {
		Fail(w, err)
		return
	}
	name, ok, err := rawName(raw)
	if err != nil || !ok {
		if err == nil {
			err = badBody("name is required")
		}
		Fail(w, err)
		return
	}
	disabled, _, err := rawDisabled(raw)
	if err != nil {
		Fail(w, err)
		return
	}
	credsIn, hasCreds, err := rawObject(raw, "credentials")
	if err == nil && !hasCreds {
		err = badBody("credentials is required")
	}
	if err != nil {
		Fail(w, err)
		return
	}
	cfgRaw, hasCfg := raw["configuration"]
	if !hasCfg {
		Fail(w, badBody("configuration is required"))
		return
	}
	cfg, err := validatePhoneConfiguration(name, cfgRaw)
	if err != nil {
		Fail(w, err)
		return
	}
	creds, _, err := h.mergePhoneCredentials(name, nil, credsIn, true)
	if err != nil {
		h.phoneWriteError(w, r, "create phone provider", err)
		return
	}
	tid := resolved(r).ID
	if name == "custom" {
		if deployed, err := h.customActionDeployed(r.Context(), tid); err != nil {
			h.failTx(w, r, "check custom phone provider action", err)
			return
		} else if !deployed {
			Fail(w, errPhoneCustomNoAction)
			return
		}
	}
	sealed, err := h.sealPhoneCredentials(tid, name, creds)
	if err != nil {
		h.failTx(w, r, "seal phone provider credentials", err)
		return
	}
	cfgJSON, _ := json.Marshal(cfg)
	now := h.now()
	p := &store.PhoneProvider{TenantID: tid, ID: "pro_" + secrets.RandomString(22), Name: name, Disabled: disabled, Configuration: cfgJSON, SealedCredentials: sealed, CreatedAt: now, UpdatedAt: now}
	if err := h.Store.Phone().CreatePhoneProvider(r.Context(), p); err != nil {
		h.phoneFail(w, r, "create phone provider", err)
		return
	}
	logDetails(r, "create phone provider", "provider", name)
	writeJSON(w, http.StatusCreated, phoneProviderJSON(resolved(r), p))
}

// phoneWriteError keeps validation errors typed and everything else a 500.
func (h *Handlers) phoneWriteError(w http.ResponseWriter, r *http.Request, what string, err error) {
	var e *Error
	if errors.As(err, &e) {
		Fail(w, e)
		return
	}
	h.failTx(w, r, what, err)
}

func (h *Handlers) UpdatePhoneProvider(w http.ResponseWriter, r *http.Request, id string) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "update phone provider", err)
		return
	}
	raw, err := decodePhoneProviderBody(r, "name", "disabled", "configuration", "credentials")
	if err != nil {
		Fail(w, err)
		return
	}
	if len(raw) == 0 {
		Fail(w, badBody("at least one property is required"))
		return
	}
	tid := resolved(r).ID
	current, err := h.Store.Phone().GetPhoneProvider(r.Context(), tid, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneProviderNotFound)
		return
	}
	if err != nil {
		h.phoneFail(w, r, "get phone provider", err)
		return
	}
	next := *current
	name := current.Name
	if n, ok, err := rawName(raw); err != nil {
		Fail(w, err)
		return
	} else if ok {
		name = n
	}
	renamed := name != current.Name
	if d, ok, err := rawDisabled(raw); err != nil {
		Fail(w, err)
		return
	} else if ok {
		next.Disabled = d
	}
	// A configuration is replaced as a whole (Auth0's schema requires its
	// required fields on every write); renaming needs a full new one.
	if cfgRaw, ok := raw["configuration"]; ok {
		cfg, err := validatePhoneConfiguration(name, cfgRaw)
		if err != nil {
			Fail(w, err)
			return
		}
		next.Configuration, _ = json.Marshal(cfg)
	} else if renamed {
		Fail(w, badBody("configuration is required when the provider name changes"))
		return
	}
	credsIn, hasCreds, err := rawObject(raw, "credentials")
	if err != nil {
		Fail(w, err)
		return
	}
	if hasCreds || renamed {
		creds, _, err := h.mergePhoneCredentials(name, current, credsIn, hasCreds)
		if err != nil {
			h.phoneWriteError(w, r, "update phone provider", err)
			return
		}
		if next.SealedCredentials, err = h.sealPhoneCredentials(tid, name, creds); err != nil {
			h.failTx(w, r, "seal phone provider credentials", err)
			return
		}
	}
	if name == "custom" && (renamed || current.Name != "custom") {
		if deployed, err := h.customActionDeployed(r.Context(), tid); err != nil {
			h.failTx(w, r, "check custom phone provider action", err)
			return
		} else if !deployed {
			Fail(w, errPhoneCustomNoAction)
			return
		}
	}
	next.Name = name
	next.UpdatedAt = h.now()
	if err := h.Store.Phone().UpdatePhoneProvider(r.Context(), &next); errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneProviderNotFound)
		return
	} else if err != nil {
		h.phoneFail(w, r, "update phone provider", err)
		return
	}
	logDetails(r, "update phone provider", "provider", name)
	writeJSON(w, http.StatusOK, phoneProviderJSON(resolved(r), &next))
}

func (h *Handlers) DeletePhoneProvider(w http.ResponseWriter, r *http.Request, id string) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "delete phone provider", err)
		return
	}
	err := h.Store.Phone().DeletePhoneProvider(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneProviderNotFound)
		return
	}
	if err != nil {
		h.phoneFail(w, r, "delete phone provider", err)
		return
	}
	logDetails(r, "delete phone provider")
	w.WriteHeader(http.StatusNoContent)
}

// phoneTestRequest is the body of both try routes.
type phoneTestRequest struct {
	to, method string
}

func decodePhoneTest(r *http.Request, strict bool) (phoneTestRequest, error) {
	raw, err := decodeObject(r)
	if err != nil {
		return phoneTestRequest{}, err
	}
	var q phoneTestRequest
	for k, v := range raw {
		switch k {
		case "to":
			var s string
			if json.Unmarshal(v, &s) != nil || s == "" || len(s) > phonerules.Limits.PhoneNumberMax {
				return q, badBody("to must be an E.164 number")
			}
			q.to = s
		case "delivery_method":
			var s string
			if json.Unmarshal(v, &s) != nil || (s != "text" && s != "voice") {
				return q, badBody("delivery_method must be text or voice")
			}
			q.method = s
		default:
			if strict {
				return q, badBody("unknown property %s", k)
			}
		}
	}
	if q.to == "" {
		return q, badBody("to is required")
	}
	if q.method == "" {
		q.method = "text"
	}
	e164, err := phone.NormalizeE164(q.to, "")
	if err != nil || q.to[0] != '+' {
		return q, badBody("to must be an E.164 number")
	}
	q.to = e164
	return q, nil
}

func phoneSendKey(tid, kind, e164 string) store.ProtectionKey {
	sum := sha256.Sum256([]byte(e164))
	return store.ProtectionKey{TenantID: tid, Kind: kind, Identifier: "try:" + hex.EncodeToString(sum[:16])}
}

// reservePhoneSend takes the send budget (static limits, D-0060 P4/P14): 10
// messages per destination per hour and one new voice request per hour. Like
// the MFA email budget, a reserved send counts even when the transport fails.
func (h *Handlers) reservePhoneSend(r *http.Request, tid, method, e164 string) error {
	now := h.now()
	limits := []store.ProtectionLimit{{Key: phoneSendKey(tid, "phone-send", e164), Algorithm: "fixed-window", Capacity: phonerules.Limits.PhoneSendsPerUserPerHour, Window: time.Hour}}
	if method == "voice" {
		limits = append(limits, store.ProtectionLimit{Key: phoneSendKey(tid, "phone-voice", e164), Algorithm: "fixed-window", Capacity: phonerules.Limits.VoiceNewRequestsPerHour, Window: time.Hour})
	}
	a, err := h.Store.Protection().Reserve(r.Context(), limits, now)
	if err != nil {
		return err
	}
	if !a.Allowed {
		wait := int(a.RetryAt.Sub(now).Seconds()) + 1
		if wait < 1 {
			wait = 1
		}
		details := map[string]any{"delivery_method": method, "retry_after_seconds": wait}
		h.domainEvent(r, "limit_phone", nil, nil, details)
		return &phoneThrottle{wait: wait}
	}
	return h.Store.Protection().Complete(r.Context(), a.Receipt, "failure", now)
}

type phoneThrottle struct{ wait int }

func (e *phoneThrottle) Error() string { return "phone send budget exhausted" }

// sendPhoneTest runs a provider try. body is the rendered text; the number is
// never logged, only its masked form in the sender's own failure log.
func (h *Handlers) sendPhoneTest(w http.ResponseWriter, r *http.Request, p *store.PhoneProvider, q phoneTestRequest, msgType, from string, bodyFor func(method string) (string, error)) {
	t := resolved(r)
	var methods []string
	var cfg struct {
		Methods []string `json:"delivery_methods"`
	}
	if json.Unmarshal(p.Configuration, &cfg) == nil {
		methods = cfg.Methods
	}
	if !slices.Contains(methods, q.method) {
		Fail(w, badBody("delivery_method %q is not enabled for this provider", q.method))
		return
	}
	fresh, err := h.Store.Tenants().Get(r.Context(), t.ID)
	if err != nil {
		h.failTx(w, r, "get tenant", err)
		return
	}
	if !tenantrules.PhoneSettingsOf(fresh).CountryAllowed(phone.CountryCode(q.to)) {
		Fail(w, badBody("the destination country is not permitted by country_codes"))
		return
	}
	if p.Disabled {
		// A disabled provider does not work (D-0060 LR3).
		Fail(w, &Error{Status: http.StatusConflict, Code: "conflict", Message: "The phone provider is disabled"})
		return
	}
	var sender phone.Sender
	if p.Name == "custom" {
		// The custom provider runs the bound custom-phone-provider Action;
		// without one it does not work (D-0060 LR3).
		runner := h.phoneActions()
		if runner == nil {
			Fail(w, errPhoneCustomConflict)
			return
		}
		ok, err := runner.PhoneActionBound(r.Context(), t.ID, phone.TriggerCustomPhoneProvider)
		if err != nil {
			h.failTx(w, r, "read phone Action bindings", err)
			return
		}
		if !ok {
			Fail(w, errPhoneCustomConflict)
			return
		}
		sender = phone.NewActionSender(runner, phone.TriggerCustomPhoneProvider)
	} else {
		sender, err = phone.SenderFor(*p, func(sealed []byte) ([]byte, error) {
			return keys.OpenBound(h.Wrapper, phoneProviderLabel, phoneProviderAAD(p.TenantID, p.Name), sealed)
		}, h.PhoneHTTP)
		if err != nil {
			h.failTx(w, r, "build phone sender", err)
			return
		}
	}
	body, err := bodyFor(q.method)
	if err != nil {
		Fail(w, badBody("%s", err))
		return
	}
	if err := h.reservePhoneSend(r, t.ID, q.method, q.to); err != nil {
		var th *phoneThrottle
		if errors.As(err, &th) {
			w.Header().Set("Retry-After", strconv.Itoa(th.wait))
			Fail(w, errPhoneThrottled)
			return
		}
		h.failTx(w, r, "reserve phone send budget", err)
		return
	}
	_, err = sender.Send(r.Context(), phone.Message{TenantID: t.ID, To: q.to, DeliveryMethod: q.method, Type: msgType, Body: body, From: from})
	if err != nil {
		switch phone.ClassOf(err) {
		case phone.ClassInvalidNumber, phone.ClassUnsupportedDelivery:
			Fail(w, badBody("the provider rejected the destination or delivery method (%s)", phone.ClassOf(err)))
		case phone.ClassRateLimited:
			Fail(w, errPhoneThrottled)
		default:
			h.log().WarnContext(r.Context(), "phone try failed", "class", string(phone.ClassOf(err)), "provider", p.Name, "to", phone.Mask(q.to))
			Fail(w, &Error{Status: http.StatusBadGateway, Code: "phone_delivery_failed", Message: "The phone provider could not send the message"})
		}
		return
	}
	logDetails(r, "try phone message", "provider", p.Name, "delivery_method", q.method, "to", phone.Mask(q.to))
	writeJSON(w, http.StatusAccepted, map[string]any{"code": 202, "message": "Message sent"})
}

func (h *Handlers) TryPhoneProvider(w http.ResponseWriter, r *http.Request, id string) {
	q, err := decodePhoneTest(r, true)
	if err != nil {
		Fail(w, err)
		return
	}
	p, err := h.Store.Phone().GetPhoneProvider(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneProviderNotFound)
		return
	}
	if err != nil {
		h.phoneFail(w, r, "get phone provider", err)
		return
	}
	name := resolved(r).FriendlyName
	if name == "" {
		name = resolved(r).Name
	}
	h.sendPhoneTest(w, r, p, q, "otp_verify", "", func(string) (string, error) {
		return "This is a test message from " + name + ". No action is needed.", nil
	})
}
