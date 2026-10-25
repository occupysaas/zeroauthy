package email

import (
	"bytes"
	htmltemplate "html/template"
	texttemplate "text/template"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
)

var (
	welcomeText = texttemplate.Must(texttemplate.New("welcome_email.txt").Funcs(texttemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/welcome_email.txt"))
	welcomeHTML = htmltemplate.Must(htmltemplate.New("welcome_email.html").Funcs(htmltemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/welcome_email.html"))
)

// WelcomeEmailMessage renders zeroauthy's original localized welcome copy.
// Welcome delivery remains opt-in through an enabled tenant template.
func WelcomeEmailMessage(l *i18n.Localizer) Message {
	data := struct{ L *i18n.Localizer }{l}
	var text, html bytes.Buffer
	if err := welcomeText.Execute(&text, data); err != nil {
		panic(err)
	}
	if err := welcomeHTML.Execute(&html, data); err != nil {
		panic(err)
	}
	return Message{Subject: l.T(i18n.KeyEmailWelcomeSubject), Text: text.String(), HTML: html.String()}
}
