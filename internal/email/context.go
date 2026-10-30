package email

import "github.com/zeroauthy/zeroauthy/internal/store"

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

// OrganizationRenderContext exposes only validated presentation data. It is
// always selected by the ticket's tenant-scoped ID, never by metadata.
func OrganizationRenderContext(org *store.Organization) map[string]any {
	if org == nil {
		return nil
	}
	branding := map[string]any{}
	if org.Branding != nil {
		if org.Branding.LogoURL != nil {
			branding["logo_url"] = *org.Branding.LogoURL
		}
		if org.Branding.Colors != nil {
			branding["colors"] = map[string]any{"primary": org.Branding.Colors.Primary, "page_background": org.Branding.Colors.PageBackground}
		}
	}
	metadata := map[string]any{}
	for k, v := range org.Metadata {
		metadata[k] = v
	}
	return map[string]any{"id": org.ID, "name": org.Name, "display_name": org.DisplayName, "metadata": metadata, "branding": branding}
}
