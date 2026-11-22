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
	data := linkTemplateData(l, link, organizations)
	var txt, htm bytes.Buffer
	// The templates are embedded and the data is plain strings, so
	// execution cannot fail.
	if err := resetText.Execute(&txt, data); err != nil {
		panic(err)
	}
	if err := resetHTML.Execute(&htm, data); err != nil {
		panic(err)
	}
	return Message{OrganizationID: data.OrganizationID, Type: "reset_email", Locale: l.Lang(), Subject: l.T(i18n.KeyEmailResetSubject), Text: txt.String(), HTML: htm.String()}
}

type linkTemplateContext struct {
	L                          *i18n.Localizer
	Link, OrganizationID       string
	Logo, DisplayName, Primary string
}

func linkTemplateData(l *i18n.Localizer, link string, organizations []*store.Organization) linkTemplateContext {
	data := linkTemplateContext{L: l, Link: link, Primary: "#3355cc"}
	if len(organizations) == 0 || organizations[0] == nil {
		return data
	}
	org := organizations[0]
	data.OrganizationID, data.DisplayName = org.ID, org.DisplayName
	if org.Branding != nil {
		if org.Branding.LogoURL != nil {
			data.Logo = *org.Branding.LogoURL
		}
		if org.Branding.Colors != nil {
			data.Primary = org.Branding.Colors.Primary
		}
	}
	return data
}
