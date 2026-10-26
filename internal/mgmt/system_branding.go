package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

var activeBrandingPreviews atomic.Int32

// PreviewBranding reads configuration without invoking lazy migration or writing
// authentication state. Overrides are validated copies scoped to this render.
func (h *Handlers) PreviewBranding(w http.ResponseWriter, r *http.Request, name string) {
	t, c, ok := h.systemEmailTarget(w, r, name)
	if !ok {
		return
	}
	if !c.Has("read:branding") || !c.Has("read:prompts") {
		WriteError(w, http.StatusForbidden, "insufficient_scope", "Read branding and prompts scopes are required")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		Fail(w, badBody("the body is too large or unreadable"))
		return
	}
	var req struct {
		Screen    string                     `json:"screen"`
		Language  string                     `json:"language"`
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF || req.Screen == "" {
		Fail(w, badBody("invalid preview request"))
		return
	}
	config, err := h.Store.HostedLogins().Get(r.Context(), t.ID)
	if errors.Is(err, store.ErrNotFound) {
		config = brandingrules.FromLegacy(t)
	} else if err != nil {
		WriteError(w, 500, "internal_error", "Unable to load branding configuration")
		return
	}
	original := config
	config = config.Clone()
	for key := range req.Overrides {
		switch key {
		case "branding", "prompts", "template", "themes", "default_theme_id", "custom_text", "partials":
		default:
			Fail(w, badBody("invalid preview override"))
			return
		}
	}
	for _, key := range []string{"branding", "prompts", "template", "themes", "default_theme_id", "custom_text", "partials"} {
		value, present := req.Overrides[key]
		if !present {
			continue
		}
		switch key {
		case "branding", "prompts":
			config, err = brandingrules.Merge(config, key, value)
		case "template":
			var source string
			if string(value) == "null" {
				config.Template = nil
			} else if json.Unmarshal(value, &source) != nil {
				err = store.ErrInvalid
			} else {
				config.Template = &source
			}
		case "themes":
			var themes map[string]map[string]any
			err = json.Unmarshal(value, &themes)
			if err == nil {
				if config.Themes == nil {
					config.Themes = map[string]map[string]any{}
				}
				for id, theme := range themes {
					if _, exists := config.Themes[id]; exists {
						raw, _ := json.Marshal(theme)
						config, err = brandingrules.Merge(config, "theme:update:"+id, raw)
						if err != nil {
							break
						}
					} else {
						config.Themes[id] = theme
					}
				}
			}
		case "default_theme_id":
			err = json.Unmarshal(value, &config.DefaultThemeID)
		case "custom_text":
			var updates store.CustomText
			err = json.Unmarshal(value, &updates)
			if err == nil {
				if updates == nil {
					config.CustomText = nil
				} else {
					for prompt, languages := range updates {
						for language, screens := range languages {
							raw, _ := json.Marshal(screens)
							config, err = brandingrules.Merge(config, "text:"+prompt+":"+language, raw)
							if err != nil {
								break
							}
						}
						if err != nil {
							break
						}
					}
				}
			}
		case "partials":
			err = json.Unmarshal(value, &config.Partials)
		default:
			err = store.ErrInvalid
		}
		if err != nil {
			Fail(w, badBody("invalid preview override"))
			return
		}
	}
	if len(req.Overrides) > 0 {
		err = brandingrules.ValidateUpdate(original, config)
		if err == nil {
			err = hostedlogin.ValidatePresentation(config)
		}
		if err == nil && config.Template != nil {
			err = hostedlogin.ValidateSource(*config.Template, false)
		}
		if err != nil {
			Fail(w, badBody("invalid preview configuration"))
			return
		}
	}
	if activeBrandingPreviews.Add(1) > 8 {
		activeBrandingPreviews.Add(-1)
		WriteError(w, 429, "rate_limit_exceeded", "Preview capacity reached")
		return
	}
	defer activeBrandingPreviews.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
	defer cancel()
	result, err := ui.Preview(ctx, config, req.Screen, req.Language)
	if err != nil {
		Fail(w, badBody("preview could not be rendered"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, result)
}
