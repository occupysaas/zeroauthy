package mgmt

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) hostedConfig(w http.ResponseWriter, r *http.Request) *store.HostedLoginConfig {
	c, err := (hostedlogin.Service{Store: h.Store}).Load(r.Context(), resolved(r).ID)
	if err != nil {
		h.failTx(w, r, "load hosted login configuration", err)
		return nil
	}
	return c
}

func hostedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
}

func (h *Handlers) mutateHosted(w http.ResponseWriter, r *http.Request, action string, change func(*store.HostedLoginConfig) (*store.HostedLoginConfig, error), response func(*store.HostedLoginConfig)) {
	if resolved(r).Reserved {
		Fail(w, badBody("the system tenant is read-only"))
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		current := h.hostedConfig(w, r)
		if current == nil {
			return
		}
		next, err := change(current)
		if errors.Is(err, store.ErrNotFound) {
			Fail(w, &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Resource not found"})
			return
		}
		if err != nil {
			Fail(w, badBody("%s", err))
			return
		}
		if err := hostedlogin.ValidatePresentation(next); err != nil {
			Fail(w, badBody("invalid branding or theme values"))
			return
		}
		err = h.Store.HostedLogins().Put(r.Context(), next, current.Revision)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			h.failTx(w, r, action, err)
			return
		}
		h.audit(r, action)
		response(next)
		return
	}
	Fail(w, &Error{Status: http.StatusConflict, Code: "conflict", Message: "Concurrent update; retry"})
}

func (h *Handlers) GetUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	if c.Template == nil {
		Fail(w, &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Template not found"})
		return
	}
	// body is the public GET contract (Deploy CLI reads it); template stays
	// for existing consumers. Both carry the same saved template.
	writeJSON(w, http.StatusOK, map[string]any{"body": *c.Template, "template": *c.Template})
}
func (h *Handlers) PutUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("template body too large"))
		return
	}
	var source string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		source = string(raw)
	} else {
		var v struct {
			Template *string `json:"template"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Template == nil {
			Fail(w, badBody("template must be a string"))
			return
		}
		source = *v.Template
	}
	if err := hostedlogin.ValidateSource(source, false); err != nil {
		Fail(w, badBody("invalid template"))
		return
	}
	h.mutateHosted(w, r, "put universal login template", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "template", []byte(source))
	}, func(*store.HostedLoginConfig) { w.WriteHeader(http.StatusOK) })
}
func (h *Handlers) DeleteUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	h.mutateHosted(w, r, "delete universal login template", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "template:delete", nil)
	}, func(*store.HostedLoginConfig) { w.WriteHeader(http.StatusNoContent) })
}

func (h *Handlers) CreateBrandingTheme(w http.ResponseWriter, r *http.Request) {
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("theme body too large"))
		return
	}
	h.mutateHosted(w, r, "create branding theme", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "theme:create", raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, themeResponse(c, c.DefaultThemeID)) })
}
func themeResponse(c *store.HostedLoginConfig, id string) map[string]any {
	out := store.CloneSettings(c.Themes[id])
	if out == nil {
		out = map[string]any{}
	}
	out["themeId"] = id
	return out
}
func (h *Handlers) GetDefaultBrandingTheme(w http.ResponseWriter, r *http.Request) {
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	h.writeTheme(w, c, c.DefaultThemeID)
}
func (h *Handlers) GetBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	if id == "default" {
		Fail(w, badBody("invalid theme id"))
		return
	}
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	h.writeTheme(w, c, id)
}
func (h *Handlers) writeTheme(w http.ResponseWriter, c *store.HostedLoginConfig, id string) {
	if _, ok := c.Themes[id]; !ok || id == "" {
		Fail(w, &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Theme not found"})
		return
	}
	writeJSON(w, http.StatusOK, themeResponse(c, id))
}
func (h *Handlers) UpdateBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	if id == "default" {
		Fail(w, badBody("invalid theme id"))
		return
	}
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("theme body too large"))
		return
	}
	h.mutateHosted(w, r, "update branding theme", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "theme:update:"+id, raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, themeResponse(c, id)) })
}
func (h *Handlers) DeleteBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	if id == "default" {
		Fail(w, badBody("invalid theme id"))
		return
	}
	h.mutateHosted(w, r, "delete branding theme", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "theme:delete:"+id, nil)
	}, func(*store.HostedLoginConfig) { w.WriteHeader(http.StatusNoContent) })
}

func (h *Handlers) GetPromptSettings(w http.ResponseWriter, r *http.Request) {
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	writeJSON(w, http.StatusOK, promptSettings(c))
}
func (h *Handlers) UpdatePromptSettings(w http.ResponseWriter, r *http.Request) {
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("prompt body too large"))
		return
	}
	h.mutateHosted(w, r, "update prompt settings", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "prompts", raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, promptSettings(c)) })
}
func promptSettings(c *store.HostedLoginConfig) map[string]any {
	p := map[string]any{"universal_login_experience": "new", "identifier_first": false, "webauthn_platform_first_factor": false}
	for k, v := range c.Prompts {
		p[k] = v
	}
	return p
}
func (h *Handlers) GetPromptCustomText(w http.ResponseWriter, r *http.Request, prompt, language string) {
	canonical, err := i18n.CanonicalLocale(language)
	if err != nil {
		Fail(w, badBody("invalid language"))
		return
	}
	language = canonical
	if !brandingrules.ValidTextPrompt(prompt) {
		Fail(w, badBody("unknown prompt"))
		return
	}
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	v := c.CustomText[prompt][language]
	if v == nil {
		for stored, screens := range c.CustomText[prompt] {
			canonical, err := i18n.CanonicalLocale(stored)
			if err == nil && canonical == language {
				v = screens
				break
			}
		}
	}
	if v == nil {
		v = map[string]map[string]string{}
	}
	writeJSON(w, http.StatusOK, v)
}
func (h *Handlers) PutPromptCustomText(w http.ResponseWriter, r *http.Request, prompt, language string) {
	canonical, localeErr := i18n.CanonicalLocale(language)
	if localeErr != nil {
		Fail(w, badBody("invalid language"))
		return
	}
	language = canonical
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("custom text body too large"))
		return
	}
	var screens map[string]map[string]string
	if json.Unmarshal(raw, &screens) != nil || screens == nil {
		Fail(w, badBody("custom text must be an object"))
		return
	}
	if err := i18n.ValidateCustomText(resolved(r).EnabledLocales, store.CustomText{prompt: {language: screens}}); err != nil {
		Fail(w, badBody("%s", err))
		return
	}
	h.mutateHosted(w, r, "put prompt custom text", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "text:"+prompt+":"+language, raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, c.CustomText[prompt][language]) })
}
func (h *Handlers) GetPromptPartials(w http.ResponseWriter, r *http.Request, prompt string) {
	if !brandingrules.ValidPrompt(prompt) {
		Fail(w, badBody("unknown prompt"))
		return
	}
	c := h.hostedConfig(w, r)
	if c == nil {
		return
	}
	v := c.Partials[prompt]
	if v == nil {
		v = map[string]map[string]string{}
	}
	writeJSON(w, http.StatusOK, v)
}
func (h *Handlers) PutPromptPartials(w http.ResponseWriter, r *http.Request, prompt string) {
	raw, err := hostedBody(w, r)
	if err != nil {
		Fail(w, badBody("partial body too large"))
		return
	}
	var screens map[string]map[string]string
	if json.Unmarshal(raw, &screens) != nil || screens == nil {
		Fail(w, badBody("partials must be an object"))
		return
	}
	if hostedlogin.ValidatePartials(screens) != nil {
		Fail(w, badBody("invalid partial"))
		return
	}
	h.mutateHosted(w, r, "put prompt partials", func(c *store.HostedLoginConfig) (*store.HostedLoginConfig, error) {
		return brandingrules.Merge(c, "partials:"+prompt, raw)
	}, func(c *store.HostedLoginConfig) { writeJSON(w, http.StatusOK, c.Partials[prompt]) })
}
