package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/liquid"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type SeedPhoneProvider struct {
	Name          string         `yaml:"name"`
	Disabled      bool           `yaml:"disabled"`
	Configuration map[string]any `yaml:"configuration"`
	Credentials   map[string]any `yaml:"credentials"`
}
type SeedPhoneTemplate struct {
	Type     string         `yaml:"type"`
	Disabled bool           `yaml:"disabled"`
	Content  map[string]any `yaml:"content"`
}

func validatePhone(in *Tenant) error {
	if p := in.PhoneProvider; p != nil {
		if _, _, err := phoneProviderValues(p, false); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, t := range in.PhoneTemplates {
		if seen[t.Type] {
			return errors.New("duplicate phone template type")
		}
		seen[t.Type] = true
		if _, err := phoneTemplateContent(t); err != nil {
			return err
		}
	}
	for _, c := range in.Connections {
		if c.Strategy != "sms" {
			continue
		}
		if v, ok := c.Options["twilio_token"]; ok {
			if _, err := streamEnvValue(v, false, false); err != nil {
				return errors.New("passwordless credentials require whole environment references")
			}
		}
		if ga, ok := c.Options["gateway_authentication"].(map[string]any); ok {
			if v, ok := ga["secret"]; ok {
				if _, err := streamEnvValue(v, false, false); err != nil {
					return errors.New("passwordless credentials require whole environment references")
				}
			}
		}
	}
	for path, patch := range guardianPhonePatches(in.Guardian) {
		route := mfarules.Route("PUT " + path)
		if route.Path == "" {
			return errors.New("unknown Guardian phone provider")
		}
		public := cloneYAMLMap(patch)
		props, _ := route.Body["properties"].(map[string]any)
		for k, v := range public {
			schema, _ := props[k].(map[string]any)
			if schema["writeOnly"] == true {
				value, err := streamEnvValue(v, false, false)
				if err != nil {
					return errors.New("Guardian credentials require environment references")
				}
				public[k] = value
			}
		}
		if err := validatePhoneSchema(route.Body, public); err != nil {
			return fmt.Errorf("invalid Guardian phone configuration: %w", store.ErrInvalid)
		}
	}
	return nil
}

func validatePhoneSchema(body map[string]any, value any) error {
	raw, _ := json.Marshal(body)
	var s openapi3.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	// JSON-normalize YAML numbers and arrays before schema validation.
	raw, _ = json.Marshal(value)
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return s.VisitJSON(v, openapi3.VisitAsRequest())
}

func phoneProviderValues(p *SeedPhoneProvider, resolve bool) ([]byte, []byte, error) {
	var schema phonerules.ProviderSchema
	for _, s := range phonerules.ProviderSchemas() {
		if s.Name == p.Name {
			schema = s
		}
	}
	if schema.Name == "" {
		return nil, nil, errors.New("unknown phone provider")
	}
	for key, v := range p.Configuration {
		if !slices.Contains(schema.Configuration, key) {
			return nil, nil, errors.New("unknown phone provider configuration")
		}
		if key != "delivery_methods" {
			s, ok := v.(string)
			if !ok || s == "" || len(s) > 255 {
				return nil, nil, store.ErrInvalid
			}
		}
	}
	for _, key := range schema.Required {
		if _, ok := p.Configuration[key]; !ok {
			return nil, nil, errors.New("missing phone provider configuration")
		}
	}
	raw, _ := json.Marshal(p.Configuration["delivery_methods"])
	var methods []string
	if json.Unmarshal(raw, &methods) != nil || len(methods) == 0 {
		return nil, nil, store.ErrInvalid
	}
	seen := map[string]bool{}
	var allowed []string
	for _, v := range phonerules.ProviderNames() {
		if v.Name == p.Name {
			allowed = v.DeliveryMethods
		}
	}
	for _, m := range methods {
		if seen[m] || !slices.Contains(allowed, m) {
			return nil, nil, store.ErrInvalid
		}
		seen[m] = true
	}
	if p.Name == "twilio" {
		if p.Configuration["default_from"] == nil && p.Configuration["mssid"] == nil || seen["voice"] && p.Configuration["default_from"] == nil {
			return nil, nil, store.ErrInvalid
		}
	}
	if p.Name == "sns" {
		region, _ := p.Configuration["region"].(string)
		if !regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]$`).MatchString(region) {
			return nil, nil, store.ErrInvalid
		}
		if v, ok := p.Configuration["sender_id"]; ok && !regexp.MustCompile(`^[A-Za-z0-9-]{1,11}$`).MatchString(v.(string)) {
			return nil, nil, store.ErrInvalid
		}
		if v, ok := p.Configuration["sms_type"]; ok && v != "Transactional" && v != "Promotional" {
			return nil, nil, store.ErrInvalid
		}
	}
	creds := map[string]string{}
	for key, value := range p.Credentials {
		if !slices.Contains(schema.Credentials, key) {
			return nil, nil, errors.New("unknown phone provider credential")
		}
		v, err := streamEnvValue(value, resolve, false)
		if err != nil {
			return nil, nil, errors.New("phone provider credential reference missing or invalid")
		}
		limit := 255
		if key == "access_key_id" {
			limit = 128
		}
		if len(v) > limit {
			return nil, nil, store.ErrInvalid
		}
		creds[key] = v
	}
	for _, key := range schema.Credentials {
		if creds[key] == "" {
			return nil, nil, errors.New("missing phone provider credential reference")
		}
	}
	cfg, _ := json.Marshal(p.Configuration)
	private, _ := json.Marshal(creds)
	return cfg, private, nil
}

func phoneTemplateContent(t SeedPhoneTemplate) ([]byte, error) {
	var def *phonerules.Content
	for _, typ := range phonerules.TemplateTypes() {
		if typ.Type == t.Type {
			v := typ.Default
			def = &v
		}
	}
	if def == nil {
		return nil, errors.New("unknown phone template type")
	}
	if err := validatePhoneSchema(phonerules.Route("POST /api/v2/branding/phone/templates").Body, map[string]any{"type": t.Type, "disabled": t.Disabled, "content": t.Content}); err != nil {
		return nil, errors.New("invalid phone template")
	}
	raw, _ := json.Marshal(t.Content)
	if err := json.Unmarshal(raw, def); err != nil {
		return nil, err
	}
	if def.Syntax != "liquid" {
		return nil, errors.New("phone template syntax must be liquid")
	}
	for _, body := range []string{def.Body.Text, def.Body.Voice} {
		if err := liquid.Validate(context.Background(), body, liquid.Limits{MaxSourceBytes: phonerules.Limits.TemplateBodyMax, MaxOutputBytes: 64 << 10}); err != nil {
			return nil, errors.New("invalid phone template Liquid")
		}
	}
	return json.Marshal(def)
}

func guardianPhonePatches(g *Guardian) map[string]map[string]any {
	out := map[string]map[string]any{}
	if g == nil {
		return out
	}
	for path, v := range map[string]map[string]any{"/guardian/factors/phone/settings": g.PhoneSettings, "/guardian/factors/phone/selected-provider": g.PhoneSelectedProvider, "/guardian/factors/phone/message-types": g.PhoneMessageTypes, "/guardian/factors/phone/templates": g.PhoneTemplates} {
		if v != nil {
			out[path] = v
		}
	}
	for provider, v := range g.PhoneProviders {
		out["/guardian/factors/phone/providers/"+provider] = v
	}
	return out
}

// Phone provisioning shares the ordinary seed transaction. Create-only leaves
// existing resource identities and operator edits intact.
func applyPhone(ctx context.Context, st store.Store, tid string, in *Tenant, now time.Time, w keys.Wrapper) error {
	if in.PhoneProvider != nil && !(in.PhoneProvider.Name == "custom" && len(in.Actions) > 0) {
		rows, err := st.Phone().ListPhoneProviders(ctx, tid)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			p := in.PhoneProvider
			cfg, creds, err := phoneProviderValues(p, true)
			if err != nil {
				return err
			}
			if p.Name == "custom" {
				bindings, err := st.Actions().Bindings(ctx, tid, "custom-phone-provider")
				if err != nil {
					return err
				}
				if len(bindings) == 0 {
					return errors.New("custom phone provider requires a deployed bound Action")
				}
			}
			sealed, err := keys.SealBound(w, phone.ProviderCredentialsLabel, phone.ProviderCredentialsAAD(tid, p.Name), creds)
			if err != nil {
				return err
			}
			if err = st.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{TenantID: tid, ID: "pro_" + secrets.RandomString(22), Name: p.Name, Disabled: p.Disabled, Configuration: cfg, SealedCredentials: sealed, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
	}
	if len(in.PhoneTemplates) > 0 {
		rows, err := st.Phone().ListPhoneTemplates(ctx, tid)
		if err != nil {
			return err
		}
		for _, t := range in.PhoneTemplates {
			exists := false
			for _, row := range rows {
				if row.Type == t.Type {
					exists = true
				}
			}
			if exists {
				continue
			}
			raw, err := phoneTemplateContent(t)
			if err != nil {
				return err
			}
			if err = st.Phone().PutPhoneTemplate(ctx, &store.PhoneTemplate{TenantID: tid, ID: "tem_" + secrets.RandomString(22), Type: t.Type, Disabled: t.Disabled, Content: raw, Customizable: true, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
	}
	patches := guardianPhonePatches(in.Guardian)
	if len(patches) == 0 {
		return nil
	}
	g, err := st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		return err
	}
	before := map[string]json.RawMessage{}
	for k, v := range g.Stored {
		before[k] = v
	}
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	if g.SealedSecrets == nil {
		g.SealedSecrets = map[string][]byte{}
	}
	secretChanged := false
	for path, patch := range patches {
		public := map[string]any{}
		private := map[string]any{}
		if blob := g.SealedSecrets[path]; len(blob) > 0 {
			raw, err := keys.OpenBound(w, "guardian-provider/v1", []string{tid, path}, blob)
			if err != nil {
				return err
			}
			if json.Unmarshal(raw, &private) != nil {
				return store.ErrInvalid
			}
		}
		props, _ := mfarules.Route("PUT " + path).Body["properties"].(map[string]any)
		for k, v := range patch {
			schema, _ := props[k].(map[string]any)
			if schema["writeOnly"] == true {
				value, err := streamEnvValue(v, true, false)
				if err != nil {
					return errors.New("Guardian credential environment reference missing or invalid")
				}
				if private[k] != value {
					private[k] = value
					secretChanged = true
				}
			} else {
				public[k] = v
			}
		}
		g.Stored[path], _ = json.Marshal(public)
		if len(private) > 0 && secretChanged {
			raw, _ := json.Marshal(private)
			g.SealedSecrets[path], err = keys.SealBound(w, "guardian-provider/v1", []string{tid, path}, raw)
			if err != nil {
				return err
			}
		}
	}
	if reflect.DeepEqual(before, g.Stored) && !secretChanged {
		return nil
	}
	return st.MFA().PutGuardian(ctx, g, g.Version)
}
