package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/liquid"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	errPhoneTemplateNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_phone_template", Message: "Phone template does not exist"}
	errPhoneTemplateConflict = &Error{Status: http.StatusConflict, Code: "conflict", Message: "Phone template already configured for tenant"}
)

const defaultPhoneTemplatePrefix = "tem_default_"

// phoneTemplateContent is the full stored and returned content.
type phoneTemplateContent struct {
	Syntax string `json:"syntax"`
	From   string `json:"from"`
	Body   struct {
		Text  string `json:"text"`
		Voice string `json:"voice"`
	} `json:"body"`
}

func defaultPhoneContent(typ string) phoneTemplateContent {
	d := phoneRules().templates[typ].Default
	c := phoneTemplateContent{Syntax: d.Syntax, From: d.From}
	c.Body.Text, c.Body.Voice = d.Body.Text, d.Body.Voice
	return c
}

func phoneTemplateView(t *store.Tenant, id, typ string, disabled bool, c phoneTemplateContent) map[string]any {
	return map[string]any{"id": id, "channel": "phone", "customizable": true, "tenant": t.Name, "type": typ, "disabled": disabled,
		"content": map[string]any{"syntax": c.Syntax, "from": c.From, "body": map[string]any{"text": c.Body.Text, "voice": c.Body.Voice}}}
}

// storedPhoneContent reads a stored template over its type's defaults, so a
// row written by an older version still renders every field.
func storedPhoneContent(st *store.PhoneTemplate) phoneTemplateContent {
	c := defaultPhoneContent(st.Type)
	_ = json.Unmarshal(st.Content, &c)
	if c.Syntax == "" {
		c.Syntax = "liquid"
	}
	return c
}

func validatePhoneBodyText(ctx context.Context, which, s string) error {
	if s == "" || len(s) > phonerules.Limits.TemplateBodyMax {
		return badBody("content.body.%s must be 1 to %d characters", which, phonerules.Limits.TemplateBodyMax)
	}
	if err := liquid.Validate(ctx, s, liquid.Limits{MaxSourceBytes: phonerules.Limits.TemplateBodyMax, MaxOutputBytes: 64 << 10}); err != nil {
		return badBody("content.body.%s is not valid Liquid", which)
	}
	return nil
}

// applyPhoneContent merges a request content object into c. syntaxOK is true
// on create (the update schema has no syntax).
func applyPhoneContent(ctx context.Context, c *phoneTemplateContent, raw json.RawMessage, syntaxOK bool) error {
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil || len(in) == 0 {
		return badBody("content must be a non-empty object")
	}
	for k, v := range in {
		switch k {
		case "syntax":
			var s string
			if !syntaxOK || json.Unmarshal(v, &s) != nil || s != "liquid" {
				return badBody("content.syntax must be liquid")
			}
		case "from":
			var s string
			if json.Unmarshal(v, &s) != nil || s == "" || len(s) > 16 {
				return badBody("content.from must be 1 to 16 characters")
			}
			c.From = s
		case "body":
			var body map[string]json.RawMessage
			if json.Unmarshal(v, &body) != nil || len(body) == 0 {
				return badBody("content.body must be a non-empty object")
			}
			for bk, bv := range body {
				var s string
				if (bk != "text" && bk != "voice") || json.Unmarshal(bv, &s) != nil {
					return badBody("content.body.%s is not valid", bk)
				}
				if err := validatePhoneBodyText(ctx, bk, s); err != nil {
					return err
				}
				if bk == "text" {
					c.Body.Text = s
				} else {
					c.Body.Voice = s
				}
			}
		default:
			return badBody("unknown property content.%s", k)
		}
	}
	return nil
}

// loadPhoneTemplate resolves a stored template or the default of a type that
// is not configured yet (default is true then, and nothing is written).
func (h *Handlers) loadPhoneTemplate(r *http.Request, id string) (st *store.PhoneTemplate, defType string, err error) {
	tid := resolved(r).ID
	if typ, ok := strings.CutPrefix(id, defaultPhoneTemplatePrefix); ok {
		if _, known := phoneRules().templates[typ]; known {
			list, err := h.Store.Phone().ListPhoneTemplates(r.Context(), tid)
			if err != nil {
				return nil, "", err
			}
			for i := range list {
				if list[i].Type == typ { // configured since the id was handed out
					return &list[i], "", nil
				}
			}
			return nil, typ, nil
		}
	}
	st, err = h.Store.Phone().GetPhoneTemplate(r.Context(), tid, id)
	return st, "", err
}

func (h *Handlers) templateErr(w http.ResponseWriter, r *http.Request, what string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errPhoneTemplateNotFound)
		return
	}
	h.phoneFail(w, r, what, err)
}

func (h *Handlers) ListPhoneTemplates(w http.ResponseWriter, r *http.Request, p mgmtapi.ListPhoneTemplatesParams) {
	t := resolved(r)
	stored, err := h.Store.Phone().ListPhoneTemplates(r.Context(), t.ID)
	if err != nil {
		h.phoneFail(w, r, "list phone templates", err)
		return
	}
	byType := map[string]*store.PhoneTemplate{}
	for i := range stored {
		byType[stored[i].Type] = &stored[i]
	}
	out := []any{}
	for _, typ := range phoneRules().order {
		var view map[string]any
		if st := byType[typ]; st != nil {
			view = phoneTemplateView(t, st.ID, typ, st.Disabled, storedPhoneContent(st))
		} else {
			view = phoneTemplateView(t, defaultPhoneTemplatePrefix+typ, typ, false, defaultPhoneContent(typ))
		}
		if p.Disabled != nil && view["disabled"].(bool) != *p.Disabled {
			continue
		}
		out = append(out, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

func (h *Handlers) GetPhoneTemplate(w http.ResponseWriter, r *http.Request, id string) {
	st, def, err := h.loadPhoneTemplate(r, id)
	if err != nil {
		h.templateErr(w, r, "get phone template", err)
		return
	}
	t := resolved(r)
	if def != "" {
		writeJSON(w, http.StatusOK, phoneTemplateView(t, id, def, false, defaultPhoneContent(def)))
		return
	}
	writeJSON(w, http.StatusOK, phoneTemplateView(t, st.ID, st.Type, st.Disabled, storedPhoneContent(st)))
}

func (h *Handlers) CreatePhoneTemplate(w http.ResponseWriter, r *http.Request) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "create phone template", err)
		return
	}
	raw, err := decodePhoneProviderBody(r, "type", "disabled", "content")
	if err != nil {
		Fail(w, err)
		return
	}
	var typ string
	if json.Unmarshal(raw["type"], &typ) != nil {
		typ = ""
	}
	if _, ok := phoneRules().templates[typ]; !ok {
		Fail(w, badBody("type must be one of otp_verify, otp_enroll, change_password, blocked_account, password_breach"))
		return
	}
	disabled, _, err := rawDisabled(raw)
	if err != nil {
		Fail(w, err)
		return
	}
	c := defaultPhoneContent(typ)
	if v, ok := raw["content"]; ok {
		if err := applyPhoneContent(r.Context(), &c, v, true); err != nil {
			Fail(w, err)
			return
		}
	}
	content, _ := json.Marshal(c)
	now := h.now()
	tid := resolved(r).ID
	st := &store.PhoneTemplate{TenantID: tid, ID: "tem_" + secrets.RandomString(22), Type: typ, Disabled: disabled, Content: content, Customizable: true, CreatedAt: now, UpdatedAt: now}
	if err := h.Store.Phone().PutPhoneTemplate(r.Context(), st); err != nil {
		if errors.Is(err, store.ErrConflict) {
			Fail(w, errPhoneTemplateConflict)
			return
		}
		h.phoneFail(w, r, "create phone template", err)
		return
	}
	logDetails(r, "create phone template", "type", typ)
	writeJSON(w, http.StatusCreated, phoneTemplateView(resolved(r), st.ID, typ, disabled, c))
}

func (h *Handlers) UpdatePhoneTemplate(w http.ResponseWriter, r *http.Request, id string) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "update phone template", err)
		return
	}
	raw, err := decodePhoneProviderBody(r, "disabled", "content")
	if err != nil {
		Fail(w, err)
		return
	}
	st, def, err := h.loadPhoneTemplate(r, id)
	if err == nil && def != "" {
		err = store.ErrNotFound // a type must be created before it is changed
	}
	if err != nil {
		h.templateErr(w, r, "get phone template", err)
		return
	}
	c := storedPhoneContent(st)
	next := *st
	if v, ok := raw["content"]; ok {
		if err := applyPhoneContent(r.Context(), &c, v, false); err != nil {
			Fail(w, err)
			return
		}
	}
	if d, ok, err := rawDisabled(raw); err != nil {
		Fail(w, err)
		return
	} else if ok {
		next.Disabled = d
	}
	next.Content, _ = json.Marshal(c)
	next.UpdatedAt = h.now()
	if err := h.Store.Phone().PutPhoneTemplate(r.Context(), &next); err != nil {
		h.templateErr(w, r, "update phone template", err)
		return
	}
	logDetails(r, "update phone template", "type", next.Type)
	writeJSON(w, http.StatusOK, phoneTemplateView(resolved(r), next.ID, next.Type, next.Disabled, c))
}

func (h *Handlers) DeletePhoneTemplate(w http.ResponseWriter, r *http.Request, id string) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "delete phone template", err)
		return
	}
	st, def, err := h.loadPhoneTemplate(r, id)
	if err == nil && def != "" {
		err = store.ErrNotFound
	}
	if err != nil {
		h.templateErr(w, r, "get phone template", err)
		return
	}
	if err := h.Store.Phone().DeletePhoneTemplate(r.Context(), st.TenantID, st.ID); err != nil {
		h.templateErr(w, r, "delete phone template", err)
		return
	}
	logDetails(r, "delete phone template", "type", st.Type)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ResetPhoneTemplate(w http.ResponseWriter, r *http.Request, id string) {
	if err := phoneWriteAllowed(h, r); err != nil {
		h.failTx(w, r, "reset phone template", err)
		return
	}
	st, def, err := h.loadPhoneTemplate(r, id)
	if err != nil {
		h.templateErr(w, r, "get phone template", err)
		return
	}
	t := resolved(r)
	if def != "" {
		writeJSON(w, http.StatusOK, phoneTemplateView(t, id, def, false, defaultPhoneContent(def)))
		return
	}
	c := defaultPhoneContent(st.Type)
	next := *st
	next.Content, _ = json.Marshal(c)
	next.UpdatedAt = h.now()
	if err := h.Store.Phone().PutPhoneTemplate(r.Context(), &next); err != nil {
		h.templateErr(w, r, "reset phone template", err)
		return
	}
	logDetails(r, "reset phone template", "type", next.Type)
	writeJSON(w, http.StatusOK, phoneTemplateView(t, next.ID, next.Type, next.Disabled, c))
}

func (h *Handlers) TryPhoneTemplate(w http.ResponseWriter, r *http.Request, id string) {
	q, err := decodePhoneTest(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	st, def, err := h.loadPhoneTemplate(r, id)
	if err != nil {
		h.templateErr(w, r, "get phone template", err)
		return
	}
	typ, c := def, phoneTemplateContent{}
	if def != "" {
		c = defaultPhoneContent(def)
	} else {
		typ, c = st.Type, storedPhoneContent(st)
	}
	t := resolved(r)
	providers, err := h.Store.Phone().ListPhoneProviders(r.Context(), t.ID)
	if err != nil {
		h.phoneFail(w, r, "list phone providers", err)
		return
	}
	if len(providers) == 0 {
		Fail(w, errPhoneProviderNotFound)
		return
	}
	friendly := t.FriendlyName
	if friendly == "" {
		friendly = t.Name
	}
	vars := map[string]any{"code": "123456", "tenant": t.Name, "friendly_name": friendly, "support_email": t.SupportEmail, "support_url": t.SupportURL, "logo_url": t.Branding.LogoURL, "locale": "en",
		"user":   map[string]any{"name": "Test User", "nickname": "test", "phone_number": "", "phone_verified": true},
		"client": map[string]any{"name": "Test application"}}
	h.sendPhoneTest(w, r, &providers[0], q, typ, c.From, func(method string) (string, error) {
		src := c.Body.Text
		if method == "voice" {
			src = c.Body.Voice
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out, err := liquid.Render(ctx, src, vars, nil, liquid.Limits{MaxSourceBytes: phonerules.Limits.TemplateBodyMax, MaxOutputBytes: 64 << 10})
		if err != nil || strings.TrimSpace(out) == "" {
			return "", errors.New("the template could not be rendered")
		}
		return out, nil
	})
}
