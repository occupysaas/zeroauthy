package hostedlogin

import (
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Context contains the public organization snapshot exposed to hosted templates.
type Context struct{ Organization *OrgView }

// OrgView contains presentation fields only, never organization policy or members.
type OrgView struct {
	ID, Name, DisplayName            string
	Metadata                         map[string]string
	LogoURL, Primary, PageBackground string
}

func NewContext(org *store.Organization) Context {
	if org == nil {
		return Context{}
	}
	v := &OrgView{ID: org.ID, Name: org.Name, DisplayName: org.DisplayName, Metadata: maps.Clone(org.Metadata)}
	if org.Branding != nil {
		if org.Branding.LogoURL != nil {
			v.LogoURL = *org.Branding.LogoURL
		}
		if org.Branding.Colors != nil {
			v.Primary, v.PageBackground = org.Branding.Colors.Primary, org.Branding.Colors.PageBackground
		}
	}
	return Context{Organization: v}
}

func (c Context) Variables() map[string]any {
	if c.Organization == nil {
		return map[string]any{}
	}
	o := c.Organization
	return map[string]any{"organization": map[string]any{"id": o.ID, "name": o.Name, "display_name": o.DisplayName, "metadata": maps.Clone(o.Metadata), "branding": map[string]any{"logo_url": o.LogoURL, "colors": map[string]any{"primary": o.Primary, "page_background": o.PageBackground}}}}
}

// ProjectContext exposes only stable presentation fields. It never projects
// arbitrary transaction, user or tenant maps into tenant-authored templates.
func ProjectContext(input map[string]any) map[string]any {
	out := map[string]any{}
	fields := map[string]map[string]bool{
		"application":   {"name": true, "logo_url": true},
		"tenant":        {"name": true, "friendly_name": true, "support_email": true, "support_url": true},
		"prompt":        {"name": true, "screen": true},
		"locale":        {"language": true},
		"branding":      {"logo_url": true, "primary_color": true},
		"user":          {"name": true},
		"organization":  {"id": true, "name": true, "display_name": true},
		"custom_domain": {"domain": true},
		"transaction":   {"screen": true},
	}
	for root, allowed := range fields {
		m, _ := input[root].(map[string]any)
		if m == nil {
			continue
		}
		v := map[string]any{}
		for key := range allowed {
			if s, ok := m[key].(string); ok {
				v[key] = s
			}
		}
		if root == "organization" {
			if md, ok := m["metadata"].(map[string]string); ok {
				public := map[string]any{}
				for k, value := range md {
					public[k] = value
				}
				v["metadata"] = public
			}
			if branding, ok := m["branding"].(map[string]any); ok {
				public := map[string]any{}
				if logo, ok := branding["logo_url"].(string); ok {
					public["logo_url"] = logo
				}
				if colors, ok := branding["colors"].(map[string]any); ok {
					safe := map[string]any{}
					for _, key := range []string{"primary", "page_background"} {
						if value, ok := colors[key].(string); ok {
							safe[key] = value
						}
					}
					public["colors"] = safe
				}
				v["branding"] = public
			}
		}
		if root == "custom_domain" {
			// Public metadata values only (strings), never other domain state.
			if md, ok := m["domain_metadata"].(map[string]string); ok {
				public := make(map[string]any, len(md))
				for k, value := range md {
					public[k] = value
				}
				v["domain_metadata"] = public
			}
		}
		if root == "prompt" {
			if screen, ok := m["screen"].(map[string]any); ok {
				public := map[string]any{}
				if name, ok := screen["name"].(string); ok {
					public["name"] = name
				}
				if texts, ok := screen["text"].(map[string]string); ok {
					text := map[string]any{}
					for k, value := range texts {
						text[k] = value
					}
					public["text"] = text
				}
				v["screen"] = public
			}
		}
		out[root] = v
	}
	return out
}
