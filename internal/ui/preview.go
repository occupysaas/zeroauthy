package ui

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	xhtml "golang.org/x/net/html"
)

type BrandingPreview struct {
	HTML     string   `json:"html"`
	Warnings []string `json:"warnings"`
}

// Preview uses only synthetic presentation values and has no storage or
// authentication dependency. The returned document is intended for srcdoc in
// an iframe whose sandbox grants no capabilities.
func Preview(ctx context.Context, config *store.HostedLoginConfig, screen, language string) (BrandingPreview, error) {
	if err := ctx.Err(); err != nil {
		return BrandingPreview{}, err
	}
	if language == "" {
		language = "en"
	}
	if i18n.ValidateLocales([]string{language}) != nil {
		return BrandingPreview{}, errors.New("invalid preview language")
	}
	name := screen
	if screen == "login-id" {
		name = "login_id"
	}
	if screen == "login-password" {
		name = "login_password"
	}
	data := map[string]any{
		"login":          LoginData{State: "preview-state", CSRF: "preview-csrf", Login: "alex@example.invalid"},
		"login_id":       LoginStageData{LoginData: LoginData{State: "preview-state", CSRF: "preview-csrf", Login: "alex@example.invalid"}, Revision: 1},
		"login_password": LoginStageData{LoginData: LoginData{State: "preview-state", CSRF: "preview-csrf", Login: "alex@example.invalid"}, Revision: 1},
		"signup":         SignupData{State: "preview-state", CSRF: "preview-csrf", Email: "alex@example.invalid"},
		"consent":        ConsentData{State: "preview-state", CSRF: "preview-csrf", APIName: "Example API", Scopes: []string{"read:example"}},
		"error":          errorData{Message: "Example error message"}, "logout_confirm": LogoutConfirmData{CSRF: "preview-csrf", Fields: url.Values{}}, "logged_out": nil,
		"reset_request": ResetRequestData{State: "preview-state", CSRF: "preview-csrf"}, "reset_email_sent": nil, "reset_password": ResetFormData{Ticket: "preview-ticket", CSRF: "preview-csrf"},
		"reset_success": nil, "reset_error": ResetErrorData{Title: "Example expired link", Description: "Request a new link to continue."},
		"email_verification": EmailVerificationData{Title: "Example verification", Description: "Your example email is verified.", Success: true},
		"device_code":        DeviceCodeData{State: "preview-state", CSRF: "preview-csrf", UserCode: "ABCD-EFGH"}, "device_confirm": DeviceConfirmData{State: "preview-state", CSRF: "preview-csrf", UserCode: "ABCD-EFGH", ClientName: "Example application"}, "device_result": true,
	}
	value, ok := data[name]
	if !ok {
		return BrandingPreview{}, errors.New("unsupported preview screen")
	}
	if config == nil {
		config = &store.HostedLoginConfig{TenantID: "preview"}
	}
	c := config.Clone()
	c.TenantID = "preview"
	warnings := []string{"External images and fonts are blocked in preview. Forms and links are disabled."}
	if c.Template != nil && hostedlogin.ValidateSource(*c.Template, false) != nil {
		c.Template = nil
		warnings = append(warnings, "The stored page template is invalid; the built-in page is shown.")
	}
	if _, err := hostedlogin.ResolveTheme(c); err != nil {
		warnings = append(warnings, "The stored theme is invalid; built-in styles are shown.")
	}
	tn := &store.Tenant{ID: "preview", Name: "Example tenant", FriendlyName: "Example tenant", EnabledLocales: []string{language}, CustomText: c.CustomText.Clone()}
	r, _ := http.NewRequestWithContext(hostedlogin.WithConfiguration(ctx, c), http.MethodGet, "https://example.invalid/preview", nil)
	view := RequestTenant(r, tn, i18n.New(tn, language).WithVar("clientName", "Example application"))
	if view.LogoURL != "" {
		view.LogoURL = "https://example.invalid/preview-logo"
	}
	view.FontURL, view.FaviconURL, view.BackgroundImageURL = "", "", ""
	view.warnings = &warnings
	prompt, promptScreen := promptForPage(name)
	if name == "login" || name == "login_id" || name == "login_password" || name == "signup" {
		partials, err := hostedlogin.RenderPartials(ctx, c.Partials[prompt][promptScreen], map[string]any{
			"tenant": map[string]any{"name": "Example tenant"}, "application": map[string]any{"name": "Example application"}, "locale": map[string]any{"language": language},
			"prompt": map[string]any{"name": prompt, "screen": map[string]any{"name": promptScreen, "text": view.L.ScreenText(prompt, promptScreen)}},
		}, nil, "")
		if err == nil {
			ApplyPartials(&view, partials)
		} else {
			warnings = append(warnings, "The stored partials could not be rendered.")
		}
	}
	response := &previewResponse{header: http.Header{}}
	render(response, http.StatusOK, name, view, value, "'none'")
	if err := ctx.Err(); err != nil {
		return BrandingPreview{}, err
	}
	if response.status != http.StatusOK {
		return BrandingPreview{}, errors.New("preview could not be rendered")
	}
	return BrandingPreview{HTML: restrictPreview(response.String()), Warnings: warnings}, nil
}

type previewResponse struct {
	bytes.Buffer
	header http.Header
	status int
}

func (w *previewResponse) Header() http.Header    { return w.header }
func (w *previewResponse) WriteHeader(status int) { w.status = status }

func restrictPreview(source string) string {
	nonce := newNonce()
	source = hostedlogin.NonceStyles(source, nonce)
	csp := "default-src 'none'; script-src 'none'; style-src 'nonce-" + nonce + "'; img-src 'none'; font-src 'none'; form-action 'none'; frame-src 'none'; base-uri 'none'"
	z := xhtml.NewTokenizer(strings.NewReader(source))
	var out strings.Builder
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			if z.Err() != io.EOF {
				return ""
			}
			break
		}
		raw := string(z.Raw())
		if tt != xhtml.StartTagToken && tt != xhtml.SelfClosingTagToken {
			out.WriteString(raw)
			continue
		}
		token := z.Token()
		if token.Data == "img" {
			out.WriteString(`<span role="img" aria-label="External image blocked">External image blocked</span>`)
			continue
		}
		attrs := token.Attr[:0]
		for _, a := range token.Attr {
			switch a.Key {
			case "href", "src", "srcset", "background", "action", "formaction":
				continue
			}
			attrs = append(attrs, a)
		}
		token.Attr = attrs
		out.WriteString(token.String())
		if token.Data == "head" {
			out.WriteString(`<meta http-equiv="Content-Security-Policy" content="` + html.EscapeString(csp) + `">`)
		}
	}
	return out.String()
}
