package email

import (
	"bytes"
	"embed"
	htmltemplate "html/template"
	texttemplate "text/template"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

//go:embed templates/*
var templateFS embed.FS

func tr(l *i18n.Localizer, key string, kv ...string) string { return l.T(key, kv...) }

var (
	resetText = texttemplate.Must(texttemplate.New("reset_password.txt").
			Funcs(texttemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/reset_password.txt"))
	resetHTML = htmltemplate.Must(htmltemplate.New("reset_password.html").
			Funcs(htmltemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/reset_password.html"))
)

// ResetPassword renders the password-reset email in l's language. The
// caller sets To.
func ResetPassword(l *i18n.Localizer, link string, organizations ...*store.Organization) Message {
	var org *store.Organization
	if len(organizations) > 0 {
		org = organizations[0]
	}
	logo, displayName, primary := "", "", "#3355cc"
	if org != nil {
		displayName = org.DisplayName
		if org.Branding != nil {
			if org.Branding.LogoURL != nil {
				logo = *org.Branding.LogoURL
			}
			if org.Branding.Colors != nil {
				primary = org.Branding.Colors.Primary
			}
		}
	}
	data := struct {
		L                          *i18n.Localizer
		Link                       string
		Logo, DisplayName, Primary string
	}{l, link, logo, displayName, primary}
	var txt, htm bytes.Buffer
	// The templates are embedded and the data is plain strings, so
	// execution cannot fail.
	if err := resetText.Execute(&txt, data); err != nil {
		panic(err)
	}
	if err := resetHTML.Execute(&htm, data); err != nil {
		panic(err)
	}
	organizationID := ""
	if org != nil {
		organizationID = org.ID
	}
	return Message{OrganizationID: organizationID, Type: "reset_email", Locale: l.Lang(), Subject: l.T(i18n.KeyEmailResetSubject), Text: txt.String(), HTML: htm.String()}
}
