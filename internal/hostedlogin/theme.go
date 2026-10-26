package hostedlogin

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Theme contains only validated presentation values. CSS is assembled from
// fixed property names; tenant strings never become arbitrary declarations.
type Theme struct {
	LogoURL, FaviconURL, FontURL, BackgroundImageURL string
	PrimaryColor, BackgroundColor                    string
	Properties                                       map[string]string
}

func ValidatePresentation(c *store.HostedLoginConfig) error {
	if c == nil {
		return ErrTemplate
	}
	view := *c
	view.DefaultThemeID = ""
	if _, err := ResolveTheme(&view); err != nil {
		return err
	}
	for id := range c.Themes {
		view.DefaultThemeID = id
		if _, err := ResolveTheme(&view); err != nil {
			return err
		}
	}
	screens := map[string]map[string]string{}
	for prompt, parts := range c.Partials {
		for screen, slots := range parts {
			screens[prompt+"/"+screen] = slots
		}
	}
	return ValidatePartials(screens)
}

func (t Theme) CSS() string {
	keys := make([]string, 0, len(t.Properties))
	for k := range t.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(k)
		out.WriteByte(':')
		out.WriteString(t.Properties[k])
		out.WriteByte(';')
	}
	return out.String()
}

func ResolveTheme(c *store.HostedLoginConfig) (Theme, error) {
	t := Theme{Properties: map[string]string{}}
	if c == nil {
		return t, nil
	}
	if v, ok := c.Branding["logo_url"].(string); ok {
		t.LogoURL = v
	}
	if v, ok := c.Branding["favicon_url"].(string); ok {
		t.FaviconURL = v
	}
	if v, ok := c.Branding["font"].(map[string]any); ok {
		t.FontURL, _ = v["url"].(string)
	}
	if v, ok := c.Branding["colors"].(map[string]any); ok {
		t.PrimaryColor, _ = v["primary"].(string)
		t.BackgroundColor, _ = v["page_background"].(string)
	}
	if t.PrimaryColor != "" {
		if !hexColor.MatchString(t.PrimaryColor) {
			return Theme{}, ErrTemplate
		}
		t.Properties["--accent"] = t.PrimaryColor
	}
	if t.BackgroundColor != "" {
		if !hexColor.MatchString(t.BackgroundColor) {
			return Theme{}, ErrTemplate
		}
		t.Properties["--za-page-background-background-color"] = t.BackgroundColor
	}
	theme := c.Themes[c.DefaultThemeID]
	reference := 16.0
	if fonts, ok := theme["fonts"].(map[string]any); ok {
		if v, present := fonts["reference_text_size"]; present {
			n, ok := themeNumber(v, 12, 24)
			if !ok {
				return Theme{}, ErrTemplate
			}
			reference = n
		}
	}
	for group, raw := range theme {
		if group == "displayName" || group == "identifiers" {
			continue
		}
		fields, ok := raw.(map[string]any)
		if !ok {
			return Theme{}, ErrTemplate
		}
		for field, value := range fields {
			if !brandingrules.ValidThemeField(group, field) {
				return Theme{}, ErrTemplate
			}
			key := "--za-" + strings.ReplaceAll(group+"-"+field, "_", "-")
			switch group {
			case "colors":
				color, ok := value.(string)
				if !ok || !hexColor.MatchString(color) {
					return Theme{}, ErrTemplate
				}
				t.Properties[key] = color
				if field == "icons" {
					t.Properties["--za-error-icon"] = `"! "`
				}
			case "borders":
				switch field {
				case "buttons_style", "inputs_style":
					s, ok := themeEnum(value, "pill", "rounded", "sharp")
					if !ok {
						return Theme{}, ErrTemplate
					}
					radius := "8px"
					if s == "pill" {
						radius = "64px"
					}
					if s == "sharp" {
						radius = "0px"
					}
					t.Properties[key] = radius
				case "show_widget_shadow":
					b, ok := value.(bool)
					if !ok {
						return Theme{}, ErrTemplate
					}
					shadow := "none"
					if b {
						shadow = "0 6px 24px rgba(0,0,0,.08)"
					}
					t.Properties[key] = shadow
				default:
					n, ok := themeNumber(value, 0, 64)
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.Properties[key] = px(n)
				}
			case "fonts":
				switch field {
				case "font_url":
					s, ok := value.(string)
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.FontURL = s
				case "reference_text_size":
					t.Properties[key] = px(reference)
				case "links_style":
					s, ok := themeEnum(value, "normal", "underlined")
					if !ok {
						return Theme{}, ErrTemplate
					}
					decoration := "none"
					if s == "underlined" {
						decoration = "underline"
					}
					t.Properties[key] = decoration
				default:
					font, ok := value.(map[string]any)
					if !ok {
						return Theme{}, ErrTemplate
					}
					for k := range font {
						if k != "size" && k != "bold" {
							return Theme{}, ErrTemplate
						}
					}
					if v, present := font["size"]; present {
						n, ok := themeNumber(v, 50, 300)
						if !ok {
							return Theme{}, ErrTemplate
						}
						t.Properties[key+"-size"] = px(reference * n / 100)
					}
					if v, present := font["bold"]; present {
						b, ok := v.(bool)
						if !ok {
							return Theme{}, ErrTemplate
						}
						weight := "400"
						if b {
							weight = "700"
						}
						t.Properties[key+"-weight"] = weight
					}
				}
			case "page_background":
				switch field {
				case "background_color":
					s, ok := value.(string)
					if !ok || !hexColor.MatchString(s) {
						return Theme{}, ErrTemplate
					}
					t.BackgroundColor = s
					t.Properties[key] = s
				case "background_image_url":
					s, ok := value.(string)
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.BackgroundImageURL = s
				case "page_layout":
					s, ok := themeEnum(value, "left", "center", "right")
					if !ok {
						return Theme{}, ErrTemplate
					}
					position := map[string]string{"left": "start", "center": "center", "right": "end"}[s]
					t.Properties[key] = position
				default:
					return Theme{}, ErrTemplate
				}
			case "widget":
				switch field {
				case "logo_url":
					s, ok := value.(string)
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.LogoURL = s
				case "logo_height":
					n, ok := themeNumber(value, 0, 200)
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.Properties[key] = px(n)
				case "header_text_alignment":
					s, ok := themeEnum(value, "left", "center", "right")
					if !ok {
						return Theme{}, ErrTemplate
					}
					t.Properties[key] = s
				case "logo_position":
					s, ok := themeEnum(value, "left", "center", "right", "none")
					if !ok {
						return Theme{}, ErrTemplate
					}
					if s == "none" {
						t.Properties[key] = "none"
					} else {
						t.Properties[key] = "block"
						m := map[string]string{"left": "0 auto 0 0", "center": "0 auto", "right": "0 0 0 auto"}
						t.Properties["--za-widget-logo-margin"] = m[s]
					}
				case "social_buttons_layout":
					if _, ok := themeEnum(value, "top", "bottom"); !ok {
						return Theme{}, ErrTemplate
					}
				default:
					return Theme{}, ErrTemplate
				}
			default:
				return Theme{}, ErrTemplate
			}
		}
	}
	for _, asset := range []string{t.LogoURL, t.FaviconURL, t.FontURL, t.BackgroundImageURL} {
		if !safeAssetURL(asset) {
			return Theme{}, ErrTemplate
		}
	}
	if t.FontURL != "" {
		u, _ := url.Parse(t.FontURL)
		p := strings.ToLower(u.Path)
		if !strings.HasSuffix(p, ".woff") && !strings.HasSuffix(p, ".woff2") {
			return Theme{}, ErrTemplate
		}
	}
	return t, nil
}
func themeEnum(v any, allowed ...string) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	for _, a := range allowed {
		if s == a {
			return s, true
		}
	}
	return "", false
}
func themeNumber(v any, min, max float64) (float64, bool) {
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	default:
		return 0, false
	}
	return n, n >= min && n <= max
}
func px(n float64) string { return strconv.FormatFloat(n, 'f', -1, 64) + "px" }
func safeAssetURL(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(s, "\"'<>\\\n\r") {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
					return false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}
func AssetOrigin(s string) string {
	if !safeAssetURL(s) || s == "" {
		return ""
	}
	u, _ := url.Parse(s)
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}
