package email

// BuildRenderContext returns only documented, presentation-safe context keys.
// Callers must resolve every input from the event's tenant, never from a
// recipient address or a background context.
// customDomain, when non-nil, is the link's public custom domain.
func BuildRenderContext(tenant, user, application, customDomain map[string]any, language, url string) (map[string]any, error) {
	ctx := map[string]any{"language": language, "url": url}
	if customDomain != nil {
		ctx["custom_domain"] = selectKeys(customDomain, "domain", "domain_metadata")
	}
	if tenant != nil {
		ctx["tenant"] = selectKeys(tenant, "name", "friendly_name", "support_email", "support_url")
		for _, key := range []string{"friendly_name", "support_email", "support_url"} {
			if v, ok := tenant[key]; ok {
				ctx[key] = v
			}
		}
	}
	if user != nil {
		ctx["user"] = selectKeys(user, "email", "email_verified", "picture", "nickname", "given_name", "family_name", "name", "user_metadata", "app_metadata")
	}
	if application != nil {
		ctx["application"] = selectKeys(application, "name", "clientID", "app_metadata")
	}
	projected, size, err := projectVariables(ctx, 0)
	if err != nil {
		return nil, err
	}
	if size > maxContextBytes {
		return nil, ErrRenderLimit
	}
	result, ok := projected.(map[string]any)
	if !ok {
		return nil, ErrRenderSyntax
	}
	return result, nil
}

func selectKeys(input map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		if value, ok := input[key]; ok {
			out[key] = value
		}
	}
	return out
}
