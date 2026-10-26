package hostedlogin

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
		"organization":  {"name": true},
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
