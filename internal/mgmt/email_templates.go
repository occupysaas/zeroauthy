package mgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) CreateEmailTemplate(w http.ResponseWriter, r *http.Request) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	raw, err := emailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if emailrules.ValidateTemplate(raw, false) != nil {
		Fail(w, emailInvalid())
		return
	}
	name := stringField(raw, "template")
	tenantID := resolved(r).ID
	if _, err = h.Store.EmailTemplates().Get(r.Context(), tenantID, name); err == nil {
		Fail(w, errEmailConflict)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		h.failTx(w, r, "get email template", err)
		return
	}
	t := templateFromRaw(tenantID, name, raw)
	if err = h.Store.EmailTemplates().Put(r.Context(), t, 0); err != nil {
		h.emailWriteError(w, r, "create email template", err)
		return
	}
	h.audit(r, "create email template", "template", name)
	writeJSON(w, http.StatusOK, projectEmailTemplate(t))
}

func (h *Handlers) GetEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	t, err := h.Store.EmailTemplates().Get(r.Context(), resolved(r).ID, name)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errEmailTemplateNotFound)
		return
	}
	if err != nil {
		h.failTx(w, r, "get email template", err)
		return
	}
	writeJSON(w, http.StatusOK, projectEmailTemplate(t))
}

func (h *Handlers) PutEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	raw, err := emailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if bodyName := stringField(raw, "template"); bodyName != name {
		Fail(w, emailInvalid())
		return
	}
	if emailrules.ValidateTemplate(raw, false) != nil {
		Fail(w, emailInvalid())
		return
	}
	t := templateFromRaw(resolved(r).ID, name, raw)
	// A zero expected revision creates; a current revision replaces.
	current, e := h.Store.EmailTemplates().Get(r.Context(), resolved(r).ID, name)
	expected := int64(0)
	if e == nil {
		expected = current.Revision
	} else if !errors.Is(e, store.ErrNotFound) {
		h.failTx(w, r, "get email template", e)
		return
	}
	if err = h.Store.EmailTemplates().Put(r.Context(), t, expected); err != nil {
		h.emailWriteError(w, r, "put email template", err)
		return
	}
	h.audit(r, "put email template", "template", name)
	writeJSON(w, http.StatusOK, projectEmailTemplate(t))
}

func (h *Handlers) PatchEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	if err := emailWriteAllowed(h, r); err != nil {
		Fail(w, err)
		return
	}
	raw, err := emailBody(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if _, ok := raw["template"]; ok {
		Fail(w, emailInvalid())
		return
	}
	if emailrules.ValidateTemplate(raw, true) != nil {
		Fail(w, emailInvalid())
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, e := h.Store.EmailTemplates().Get(r.Context(), resolved(r).ID, name)
		if errors.Is(e, store.ErrNotFound) {
			Fail(w, errEmailTemplateNotFound)
			return
		}
		if e != nil {
			h.failTx(w, r, "get email template", e)
			return
		}
		fields := map[string]any{}
		for k, v := range current.Fields {
			fields[k] = v
		}
		for k, v := range raw {
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				switch k {
				case "from", "resultUrl", "urlLifetimeInSeconds", "includeEmailInRedirect":
					delete(fields, k)
				case "syntax":
					fields[k] = "liquid"
				default:
					Fail(w, emailInvalid())
					return
				}
				continue
			}
			var x any
			dec := json.NewDecoder(bytes.NewReader(v))
			dec.UseNumber()
			if dec.Decode(&x) != nil {
				Fail(w, emailInvalid())
				return
			}
			fields[k] = x
		}
		merged := rawFromFields(fields, name)
		if emailrules.ValidateTemplate(merged, false) != nil {
			Fail(w, emailInvalid())
			return
		}
		t := &store.EmailTemplate{TenantID: current.TenantID, Name: name, Fields: fields}
		e = h.Store.EmailTemplates().Put(r.Context(), t, current.Revision)
		if errors.Is(e, store.ErrConflict) {
			continue
		}
		if e != nil {
			h.emailWriteError(w, r, "patch email template", e)
			return
		}
		h.audit(r, "patch email template", "template", name)
		writeJSON(w, http.StatusOK, projectEmailTemplate(t))
		return
	}
	Fail(w, errEmailConflict)
}

func templateFromRaw(tenantID, name string, raw map[string]json.RawMessage) *store.EmailTemplate {
	fields := map[string]any{"template": name, "syntax": "liquid"}
	for k, v := range raw {
		if k == "template" {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			continue
		}
		var x any
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		_ = dec.Decode(&x)
		fields[k] = x
	}
	return &store.EmailTemplate{TenantID: tenantID, Name: name, Fields: fields}
}
func rawFromFields(fields map[string]any, name string) map[string]json.RawMessage {
	b, _ := json.Marshal(fields)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	raw["template"], _ = json.Marshal(name)
	return raw
}
func projectEmailTemplate(t *store.EmailTemplate) map[string]any {
	out := map[string]any{"template": t.Name}
	for k, v := range t.Fields {
		if k != "template" {
			out[k] = v
		}
	}
	return out
}
