package brandingrules

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const maxAggregateBytes = 1 << 20

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
var errInvalid = errors.New("invalid hosted login configuration")

//go:embed inventory.json
var inventoryBytes []byte

var allowedThemeFields = func() map[string]bool {
	var inventory struct {
		ThemeFields []struct{ Name string } `json:"theme_fields"`
	}
	if err := json.Unmarshal(inventoryBytes, &inventory); err != nil {
		panic(err)
	}
	fields := make(map[string]bool, len(inventory.ThemeFields))
	for _, field := range inventory.ThemeFields {
		fields[field.Name] = true
	}
	return fields
}()

func ValidThemeField(group, field string) bool { return allowedThemeFields[group+"."+field] }

func FromLegacy(t *store.Tenant) *store.HostedLoginConfig {
	if t == nil {
		return nil
	}
	c := &store.HostedLoginConfig{TenantID: t.ID, CustomText: t.CustomText.Clone()}
	if t.Branding.LogoURL != "" {
		c.Branding = map[string]any{"logo_url": t.Branding.LogoURL}
	}
	if t.Branding.PrimaryColor != "" {
		if c.Branding == nil {
			c.Branding = map[string]any{}
		}
		c.Branding["colors"] = map[string]any{"primary": t.Branding.PrimaryColor}
	}
	return c
}

func Validate(c *store.HostedLoginConfig) error                   { return validate(c, nil) }
func ValidateUpdate(current, next *store.HostedLoginConfig) error { return validate(next, current) }
func validate(c, current *store.HostedLoginConfig) error {
	if c == nil || c.TenantID == "" {
		return fmt.Errorf("%w: tenant", errInvalid)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(b) > maxAggregateBytes {
		if current == nil {
			return fmt.Errorf("%w: aggregate over 1 MiB", errInvalid)
		}
		old, err := json.Marshal(current)
		if err != nil {
			return err
		}
		if len(b) >= len(old) {
			return fmt.Errorf("%w: oversized aggregate must shrink", errInvalid)
		}
	}
	if c.Template != nil {
		if !utf8.ValidString(*c.Template) || len(*c.Template) > 100<<10 {
			return fmt.Errorf("%w: template size", errInvalid)
		}
	}
	if len(c.Themes) > 20 {
		return fmt.Errorf("%w: too many themes", errInvalid)
	}
	if c.DefaultThemeID != "" {
		if _, ok := c.Themes[c.DefaultThemeID]; !ok {
			return fmt.Errorf("%w: default theme missing", errInvalid)
		}
	}
	if err := validateBranding(c.Branding); err != nil {
		return err
	}
	if err := validatePrompts(c.Prompts); err != nil {
		return err
	}
	for id, theme := range c.Themes {
		if len(id) != 32 {
			return fmt.Errorf("%w: theme id", errInvalid)
		}
		if err := validateTheme(theme); err != nil {
			return err
		}
	}
	for prompt, screens := range c.Partials {
		if !validPrompt(prompt) {
			return fmt.Errorf("%w: prompt", errInvalid)
		}
		for screen, slots := range screens {
			if screen == "" {
				return fmt.Errorf("%w: screen", errInvalid)
			}
			for slot, source := range slots {
				if !validSlot(slot) || !utf8.ValidString(source) || utf8.RuneCountInString(source) > 10000 || len(source) > 40<<10 {
					return fmt.Errorf("%w: partial", errInvalid)
				}
			}
		}
	}
	return nil
}
func validPrompt(p string) bool {
	switch p {
	case "login", "login-id", "login-password", "signup", "signup-id", "signup-password", "login-passwordless", "passkeys", "confirmation", "customized-consent":
		return true
	}
	return false
}
func ValidPrompt(p string) bool { return validPrompt(p) }
func ValidTextPrompt(p string) bool {
	if validPrompt(p) {
		return true
	}
	switch p {
	case "logout", "reset-password", "email-verification", "consent", "device-flow", "zeroauthy":
		return true
	}
	return false
}
func validSlot(s string) bool {
	switch s {
	case "form-content-start", "form-content-end", "form-footer-start", "form-footer-end", "secondary-actions-start", "secondary-actions-end":
		return true
	}
	return false
}
func validateBranding(b map[string]any) error {
	for k, v := range b {
		switch k {
		case "logo_url", "favicon_url":
			if v == nil {
				continue
			}
			s, ok := v.(string)
			if !ok || !validURL(s) {
				return fmt.Errorf("%w: %s", errInvalid, k)
			}
		case "colors":
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: colors", errInvalid)
			}
			for ck, cv := range m {
				if ck != "primary" && ck != "page_background" {
					return fmt.Errorf("%w: colors.%s", errInvalid, ck)
				}
				s, ok := cv.(string)
				if !ok || !hexColor.MatchString(s) {
					return fmt.Errorf("%w: color", errInvalid)
				}
			}
		case "font":
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: font", errInvalid)
			}
			for fk, fv := range m {
				if fk != "url" {
					return fmt.Errorf("%w: font.%s", errInvalid, fk)
				}
				if fv == nil {
					continue
				}
				s, ok := fv.(string)
				if !ok || !validURL(s) {
					return fmt.Errorf("%w: font url", errInvalid)
				}
			}
		default:
			return fmt.Errorf("%w: branding.%s", errInvalid, k)
		}
	}
	return nil
}
func validURL(s string) bool {
	if s == "" {
		return true
	}
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func validatePrompts(p map[string]any) error {
	for k, v := range p {
		switch k {
		case "identifier_first", "webauthn_platform_first_factor":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("%w: %s", errInvalid, k)
			}
		case "universal_login_experience":
			if v != "new" && v != "classic" {
				return fmt.Errorf("%w: experience", errInvalid)
			}
		default:
			return fmt.Errorf("%w: prompts.%s", errInvalid, k)
		}
	}
	return nil
}
func validateTheme(theme map[string]any) error {
	allowed := map[string]bool{"colors": true, "borders": true, "fonts": true, "page_background": true, "widget": true, "displayName": true, "identifiers": true}
	for k, v := range theme {
		if !allowed[k] {
			return fmt.Errorf("%w: theme.%s", errInvalid, k)
		}
		if k == "displayName" {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%w: displayName", errInvalid)
			}
			continue
		}
		if _, ok := v.(map[string]any); !ok {
			return fmt.Errorf("%w: theme.%s", errInvalid, k)
		}
		if k != "identifiers" {
			for field := range v.(map[string]any) {
				if !allowedThemeFields[k+"."+field] {
					return fmt.Errorf("%w: theme.%s.%s", errInvalid, k, field)
				}
			}
		}
	}
	return nil
}
func Merge(current *store.HostedLoginConfig, resource string, body []byte) (*store.HostedLoginConfig, error) {
	if current == nil {
		return nil, fmt.Errorf("%w: nil current", errInvalid)
	}
	next := current.Clone()
	switch {
	case resource == "branding":
		patch, err := decodeObject(body)
		if err != nil {
			return nil, err
		}
		if value, present := patch["colors"]; present && value == nil {
			return nil, fmt.Errorf("%w: colors cannot be null", errInvalid)
		}
		if colors, ok := patch["colors"].(map[string]any); ok {
			for key, value := range colors {
				if value == nil && (key == "primary" || key == "page_background") {
					return nil, fmt.Errorf("%w: required color cannot be null", errInvalid)
				}
			}
		}
		next.Branding = mergeMap(next.Branding, patch)
	case resource == "prompts":
		patch, err := decodeObject(body)
		if err != nil {
			return nil, err
		}
		next.Prompts = mergeMap(next.Prompts, patch)
	case resource == "template":
		if !utf8.Valid(body) {
			return nil, errInvalid
		}
		s := string(body)
		next.Template = &s
	case resource == "template:delete":
		next.Template = nil
	case resource == "theme:create":
		patch, err := decodeObject(body)
		if err != nil {
			return nil, err
		}
		var raw [16]byte
		if _, err = rand.Read(raw[:]); err != nil {
			return nil, err
		}
		id := hex.EncodeToString(raw[:])
		if next.Themes == nil {
			next.Themes = map[string]map[string]any{}
		}
		next.Themes[id] = patch
		next.DefaultThemeID = id
	case strings.HasPrefix(resource, "theme:delete:"):
		id := strings.TrimPrefix(resource, "theme:delete:")
		if _, ok := next.Themes[id]; !ok {
			return nil, store.ErrNotFound
		}
		delete(next.Themes, id)
		if next.DefaultThemeID == id {
			next.DefaultThemeID = ""
		}
	case strings.HasPrefix(resource, "theme:update:"):
		id := strings.TrimPrefix(resource, "theme:update:")
		if _, ok := next.Themes[id]; !ok {
			return nil, store.ErrNotFound
		}
		patch, err := decodeObject(body)
		if err != nil {
			return nil, err
		}
		next.Themes[id] = mergeMap(next.Themes[id], patch)
	case strings.HasPrefix(resource, "text:"):
		parts := strings.Split(strings.TrimPrefix(resource, "text:"), ":")
		if len(parts) != 2 || !ValidTextPrompt(parts[0]) || parts[1] == "" {
			return nil, errInvalid
		}
		var screens map[string]map[string]string
		if err := json.Unmarshal(body, &screens); err != nil || screens == nil {
			return nil, errInvalid
		}
		if next.CustomText == nil {
			next.CustomText = store.CustomText{}
		}
		if next.CustomText[parts[0]] == nil {
			next.CustomText[parts[0]] = map[string]map[string]map[string]string{}
		}
		next.CustomText[parts[0]][parts[1]] = screens
	case strings.HasPrefix(resource, "partials:"):
		prompt := strings.TrimPrefix(resource, "partials:")
		if !validPrompt(prompt) {
			return nil, errInvalid
		}
		var screens map[string]map[string]string
		if err := json.Unmarshal(body, &screens); err != nil || screens == nil {
			return nil, errInvalid
		}
		if next.Partials == nil {
			next.Partials = map[string]map[string]map[string]string{}
		}
		next.Partials[prompt] = screens
	default:
		return nil, fmt.Errorf("%w: unknown resource", errInvalid)
	}
	if err := ValidateUpdate(current, next); err != nil {
		return nil, err
	}
	return next, nil
}
func decodeObject(b []byte) (map[string]any, error) {
	if len(b) > 2<<20 {
		return nil, errInvalid
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errInvalid
	}
	return m, nil
}
func mergeMap(old, patch map[string]any) map[string]any {
	out := store.CloneSettings(old)
	if out == nil {
		out = map[string]any{}
	}
	for k, v := range patch {
		if v == nil {
			delete(out, k)
			continue
		}
		nested, ok := v.(map[string]any)
		if !ok {
			out[k] = v
			continue
		}
		base, _ := out[k].(map[string]any)
		out[k] = mergeMap(base, nested)
	}
	return out
}
