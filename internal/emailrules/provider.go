package emailrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var ErrInvalidProvider = errors.New("invalid email provider")

var providerCredentials = map[string][]string{
	"smtp":     {"smtp_host", "smtp_port", "smtp_user", "smtp_pass"},
	"sendgrid": {"api_key"}, "mailgun": {"api_key", "domain", "region"},
	"mandrill": {"api_key"}, "sparkpost": {"api_key", "region"},
	"ses":      {"accessKeyId", "secretAccessKey", "region"},
	"azure_cs": {"connectionString"}, "ms365": {"tenantId", "clientId", "clientSecret"},
	"resend": {"api_key"}, "custom": {},
}

var providerRequired = map[string][]string{
	"smtp": {"smtp_host"}, "sendgrid": {"api_key"}, "mailgun": {"api_key", "domain"},
	"mandrill": {"api_key"}, "sparkpost": {"api_key"},
	"ses": {"accessKeyId", "secretAccessKey", "region"}, "azure_cs": {"connectionString"},
	"ms365": {"tenantId", "clientId", "clientSecret"}, "resend": {"api_key"},
}

// ValidateProvider checks the provider wire shape. A same-kind PATCH may omit
// credentials because the handler merges those with the encrypted snapshot.
func ValidateProvider(raw map[string]json.RawMessage, current *store.EmailProvider) error {
	if len(raw) == 0 {
		return ErrInvalidProvider
	}
	var name string
	if v, ok := raw["name"]; ok {
		if json.Unmarshal(v, &name) != nil {
			return ErrInvalidProvider
		}
	} else if current != nil {
		name = current.Name
	}
	if _, ok := providerCredentials[name]; !ok {
		return ErrInvalidProvider
	}
	if v, ok := raw["enabled"]; ok {
		var enabled bool
		if json.Unmarshal(v, &enabled) != nil {
			return ErrInvalidProvider
		}
	}
	from := ""
	if v, ok := raw["default_from_address"]; ok && string(v) != "null" {
		if json.Unmarshal(v, &from) != nil {
			return ErrInvalidProvider
		}
	} else if current != nil {
		from = current.DefaultFrom
	}
	if from != "" {
		a, e := mail.ParseAddress(from)
		if e != nil || a.Address != from || a.Name != "" {
			return ErrInvalidProvider
		}
	}
	for key := range raw {
		if key != "name" && key != "enabled" && key != "default_from_address" && key != "credentials" && key != "settings" {
			return ErrInvalidProvider
		}
	}
	creds := map[string]json.RawMessage{}
	if v, ok := raw["credentials"]; ok {
		if string(v) == "null" || json.Unmarshal(v, &creds) != nil {
			return ErrInvalidProvider
		}
	}
	allowed := map[string]bool{}
	for _, k := range providerCredentials[name] {
		allowed[k] = true
	}
	for key, value := range creds {
		if !allowed[key] {
			return ErrInvalidProvider
		}
		if string(bytes.TrimSpace(value)) == "null" && (name == "mailgun" || name == "sparkpost") && key == "region" {
			continue
		}
		var s string
		if key == "smtp_port" {
			var port int
			if json.Unmarshal(value, &port) != nil || port < 1 || port > 65535 {
				return ErrInvalidProvider
			}
			continue
		}
		if json.Unmarshal(value, &s) != nil || strings.TrimSpace(s) == "" || strings.Contains(s, "********") {
			return ErrInvalidProvider
		}
	}
	if len(creds) == 0 && (current == nil || current.Name != name) && name != "custom" {
		return ErrInvalidProvider
	}
	for _, key := range providerRequired[name] {
		if _, ok := creds[key]; !ok && (current == nil || current.Name != name) {
			return ErrInvalidProvider
		}
	}
	if name == "smtp" {
		_, user := creds["smtp_user"]
		_, pass := creds["smtp_pass"]
		if user != pass {
			return ErrInvalidProvider
		}
	}
	settings := map[string]json.RawMessage{}
	if v, ok := raw["settings"]; ok {
		if string(v) == "null" || json.Unmarshal(v, &settings) != nil {
			return ErrInvalidProvider
		}
	}
	allowedSettings := map[string]bool{}
	switch name {
	case "smtp":
		allowedSettings["headers"] = true
	case "ses":
		allowedSettings["configuration_set_name"] = true
	}
	for key, v := range settings {
		if !allowedSettings[key] {
			return ErrInvalidProvider
		}
		if key == "configuration_set_name" {
			var s string
			if json.Unmarshal(v, &s) != nil || len(s) > 255 {
				return ErrInvalidProvider
			}
		}
		if key == "headers" {
			var headers map[string]string
			if json.Unmarshal(v, &headers) != nil {
				return ErrInvalidProvider
			}
			for h, value := range headers {
				if h == "" || strings.ContainsAny(value, "\r\n") || len(value) > 998 {
					return ErrInvalidProvider
				}
				for _, r := range h {
					if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
						return ErrInvalidProvider
					}
				}
			}
		}
	}
	return nil
}

// ProjectProvider returns an allowlisted provider view and never includes the
// sealed credentials or whether any particular secret was configured.
func ProjectProvider(p *store.EmailProvider) map[string]any {
	out := map[string]any{"name": p.Name, "enabled": p.Enabled}
	if p.DefaultFrom != "" {
		out["default_from_address"] = p.DefaultFrom
	}
	settings := map[string]any{}
	for _, key := range []string{"region", "domain", "configuration_set_name", "headers"} {
		if v, ok := p.PublicConfig[key]; ok {
			settings[key] = v
		}
	}
	if len(settings) > 0 {
		out["settings"] = settings
	}
	return out
}
