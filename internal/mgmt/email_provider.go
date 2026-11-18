package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var errEmailProviderNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_email_provider", Message: "The email provider does not exist"}
var errEmailTemplateNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_email_template", Message: "The email template does not exist"}
var errEmailConflict = &Error{Status: http.StatusConflict, Code: "conflict", Message: "The email resource already exists or changed concurrently"}

func emailBody(r *http.Request) (map[string]json.RawMessage, error) { return decodeObject(r) }
func emailInvalid() *Error                                          { return badBody("invalid email provider or template configuration") }
func emailWriteAllowed(h *Handlers, r *http.Request) error {
	t, err := h.Store.Tenants().Get(r.Context(), resolved(r).ID)
	if err != nil {
		return err
	}
	if t.Reserved {
		return errSystemTenant
	}
	return nil
}

func (h *Handlers) GetEmailProvider(w http.ResponseWriter, r *http.Request) {
	fields, include, err := Fields(r)
	if err != nil {
		Fail(w, err)
		return
	}
	p, err := h.Store.EmailProviders().Get(r.Context(), resolved(r).ID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errEmailProviderNotFound)
		return
	}
	if err != nil {
		h.failTx(w, r, "get email provider", err)
		return
	}
	view := *p
	// Legacy region is exposed in both credentials and settings. Hydrate the
	// retained fields before applying the same projection to either row format.
	if len(fields) == 0 || slices.Contains(fields, "credentials") == include || slices.Contains(fields, "settings") == include {
		if err := emailrules.LegacyPublicConfig(h.Wrapper, resolved(r).ID, &view); err != nil {
			h.failTx(w, r, "get email provider", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, ProjectKeeping(emailrules.ProjectProvider(&view), fields, include, nil))
}

func (h *Handlers) CreateEmailProvider(w http.ResponseWriter, r *http.Request) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	raw, err := emailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if err = emailrules.ValidateProvider(raw, nil); err != nil {
		Fail(w, emailInvalid())
		return
	}
	tenantID := resolved(r).ID
	if _, err = h.Store.EmailProviders().Get(r.Context(), tenantID); err == nil {
		Fail(w, errEmailConflict)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		h.failTx(w, r, "get email provider", err)
		return
	}
	p, err := h.writeProvider(r, tenantID, nil, raw)
	if err != nil {
		h.emailWriteError(w, r, "create email provider", err)
		return
	}
	logDetails(r, "create email provider", "provider", p.Name)
	writeJSON(w, http.StatusCreated, emailrules.ProjectProvider(p))
}

func (h *Handlers) PatchEmailProvider(w http.ResponseWriter, r *http.Request) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	raw, err := emailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if len(raw) == 0 {
		Fail(w, emailInvalid())
		return
	}
	tenantID := resolved(r).ID
	for attempt := 0; attempt < 3; attempt++ {
		current, e := h.Store.EmailProviders().Get(r.Context(), tenantID)
		if errors.Is(e, store.ErrNotFound) {
			Fail(w, errEmailProviderNotFound)
			return
		}
		if e != nil {
			h.failTx(w, r, "get email provider", e)
			return
		}
		if emailrules.ValidateProvider(raw, current) != nil {
			Fail(w, emailInvalid())
			return
		}
		p, e := h.writeProvider(r, tenantID, current, raw)
		if errors.Is(e, store.ErrConflict) {
			continue
		}
		if e != nil {
			h.emailWriteError(w, r, "update email provider", e)
			return
		}
		logDetails(r, "update email provider", "provider", p.Name)
		writeJSON(w, http.StatusOK, emailrules.ProjectProvider(p))
		return
	}
	Fail(w, errEmailConflict)
}

func (h *Handlers) DeleteEmailProvider(w http.ResponseWriter, r *http.Request) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		p, err := h.Store.EmailProviders().Get(r.Context(), resolved(r).ID)
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			h.failTx(w, r, "get email provider", err)
			return
		}
		err = h.Store.EmailProviders().Delete(r.Context(), p.TenantID, p.Revision)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			h.emailWriteError(w, r, "delete email provider", err)
			return
		}
		logDetails(r, "delete email provider", "provider", p.Name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	Fail(w, errEmailConflict)
}

func (h *Handlers) writeProvider(r *http.Request, tenantID string, current *store.EmailProvider, raw map[string]json.RawMessage) (*store.EmailProvider, error) {
	name := stringField(raw, "name")
	if name == "" && current != nil {
		name = current.Name
	}
	enabled := boolField(raw, "enabled", current != nil && current.Enabled)
	from := stringField(raw, "default_from_address")
	if _, ok := raw["default_from_address"]; !ok && current != nil {
		from = current.DefaultFrom
	}
	creds := map[string]any{}
	if current != nil && current.Name == name {
		var err error
		creds, err = emailrules.OpenCredentials(h.Wrapper, tenantID, current)
		if err != nil {
			return nil, errors.New("email provider credentials unavailable")
		}
	}
	if v, ok := raw["credentials"]; ok {
		var incoming map[string]any
		if json.Unmarshal(v, &incoming) != nil {
			return nil, store.ErrInvalid
		}
		for k, val := range incoming {
			// auth0-deploy-cli emits ##NAME## placeholders for provider
			// credentials in public exports. They identify private values that
			// must be configured separately, so they must never replace a
			// destination's already configured credential.
			if placeholder, ok := val.(string); ok && isEmailCredentialPlaceholder(placeholder) {
				if _, configured := creds[k]; !configured {
					return nil, store.ErrInvalid
				}
				continue
			}
			if val == nil {
				delete(creds, k)
			} else {
				creds[k] = val
			}
		}
	}
	if name == "custom" {
		creds = map[string]any{}
	}
	settings := map[string]any{}
	if current != nil && current.Name == name {
		for k, v := range current.PublicConfig {
			settings[k] = v
		}
	}
	if v, ok := raw["settings"]; ok {
		var next map[string]any
		if json.Unmarshal(v, &next) != nil {
			return nil, store.ErrInvalid
		}
		for k, val := range next {
			if val == nil {
				delete(settings, k)
			} else {
				settings[k] = val
			}
		}
	}
	if val, ok := creds["domain"]; ok {
		settings["domain"] = val
	}

	if name != "custom" {
		if _, err := (&providers.Factory{}).New(r.Context(), tenantID, 1, providers.Config{Name: name, Credentials: creds, Settings: settings}); err != nil {
			return nil, store.ErrInvalid
		}
	}
	p := &store.EmailProvider{TenantID: tenantID, Name: name, Enabled: enabled, DefaultFrom: from, PublicConfig: settings}
	if err := emailrules.SealCredentials(h.Wrapper, p, creds); err != nil {
		return nil, err
	}
	expected := int64(0)
	if current != nil {
		expected = current.Revision
	}
	if err := h.Store.EmailProviders().Put(r.Context(), p, expected); err != nil {
		return nil, err
	}
	return h.Store.EmailProviders().Get(r.Context(), tenantID)
}

func isEmailCredentialPlaceholder(value string) bool {
	return strings.HasPrefix(value, "##") && strings.HasSuffix(value, "##") && len(value) > 4 && !strings.ContainsAny(value[2:len(value)-2], "#\r\n")
}

func (h *Handlers) emailWriteError(w http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, store.ErrInvalid) {
		Fail(w, emailInvalid())
		return
	}
	if errors.Is(err, store.ErrConflict) {
		Fail(w, errEmailConflict)
		return
	}
	h.failTx(w, r, what, err)
}
func stringField(raw map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(raw[key], &s)
	return s
}
func boolField(raw map[string]json.RawMessage, key string, def bool) bool {
	v, ok := raw[key]
	if !ok {
		return def
	}
	var b bool
	_ = json.Unmarshal(v, &b)
	return b
}
