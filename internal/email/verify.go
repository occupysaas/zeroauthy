package email

import (
	"bytes"
	"context"
	htmltemplate "html/template"
	texttemplate "text/template"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
)

var (
	verifyText = texttemplate.Must(texttemplate.New("verify_email.txt").
			Funcs(texttemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/verify_email.txt"))
	verifyHTML = htmltemplate.Must(htmltemplate.New("verify_email.html").
			Funcs(htmltemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/verify_email.html"))
)

// VerifyEmailMessage renders the email verification email in l's
// language. The caller sets To.
func VerifyEmailMessage(l *i18n.Localizer, link string) Message {
	data := struct {
		L    *i18n.Localizer
		Link string
	}{l, link}
	var txt, htm bytes.Buffer
	// The templates are embedded and the data is plain strings, so
	// execution cannot fail.
	if err := verifyText.Execute(&txt, data); err != nil {
		panic(err)
	}
	if err := verifyHTML.Execute(&htm, data); err != nil {
		panic(err)
	}
	return Message{Type: "verify_email", Locale: l.Lang(), Subject: l.T(i18n.KeyEmailVerifySubject), Text: txt.String(), HTML: htm.String()}
}

// VerifyEmail is one verification email: the recipient, the language and
// the email-verification ticket link.
type VerifyEmail struct {
	To   string
	L    *i18n.Localizer
	Link string
}

// Sender renders zeroauthy's emails and sends them through Mailer.
type Sender struct {
	Mailer Mailer
}

// SendVerifyEmail sends the email verification email.
func (s Sender) SendVerifyEmail(ctx context.Context, v VerifyEmail) error {
	m := VerifyEmailMessage(v.L, v.Link)
	m.To = v.To
	return s.Mailer.Send(ctx, m)
}
