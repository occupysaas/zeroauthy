package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
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
	p, err := h.Store.EmailProviders().Get(r.Context(), resolved(r).ID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errEmailProviderNotFound)
		return
	}
	if err != nil {
		h.failTx(w, r, "get email provider", err)
		return
	}
	writeJSON(w, http.StatusOK, emailrules.ProjectProvider(p))
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
	h.audit(r, "create email provider", "provider", p.Name)
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
		h.audit(r, "update email provider", "provider", p.Name)
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
		h.audit(r, "delete email provider", "provider", p.Name)
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
	if current != nil && current.Name == name && len(current.SealedCredentials) > 0 {
		plain, err := keys.OpenEmailProvider(h.Wrapper, tenantID, name, current.SealedCredentials)
		if err != nil {
			return nil, errors.New("email provider credentials unavailable")
		}
		if json.Unmarshal(plain, &creds) != nil {
			return nil, errors.New("email provider credentials unavailable")
		}
	}
	if v, ok := raw["credentials"]; ok {
		var incoming map[string]any
		if json.Unmarshal(v, &incoming) != nil {
			return nil, store.ErrInvalid
		}
		for k, val := range incoming {
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
	plain, err := json.Marshal(creds)
	if err != nil {
		return nil, err
	}
	sealed, err := keys.SealEmailProvider(h.Wrapper, tenantID, name, plain)
	if err != nil {
		return nil, errors.New("email provider encryption unavailable")
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
	if v, ok := raw["credentials"]; ok {
		var patch map[string]json.RawMessage
		if json.Unmarshal(v, &patch) == nil {
			if region, ok := patch["region"]; ok && string(region) == "null" {
				delete(settings, "region")
			}
		}
	}
	for _, key := range []string{"domain", "region"} {
		if val, ok := creds[key]; ok {
			settings[key] = val
		}
	}
	if name != "custom" {
		if _, err := (&providers.Factory{}).New(r.Context(), tenantID, 1, providers.Config{Name: name, Credentials: creds, Settings: settings}); err != nil {
			return nil, store.ErrInvalid
		}
	}
	p := &store.EmailProvider{TenantID: tenantID, Name: name, Enabled: enabled, DefaultFrom: from, PublicConfig: settings, SealedCredentials: sealed}
	expected := int64(0)
	if current != nil {
		expected = current.Revision
	}
	if err = h.Store.EmailProviders().Put(r.Context(), p, expected); err != nil {
		return nil, err
	}
	return h.Store.EmailProviders().Get(r.Context(), tenantID)
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
