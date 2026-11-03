package ui

import "net/http"

// PasswordlessData is a hosted passwordless screen (login-passwordless
// prompt): the identifier entry and the code entry.
type PasswordlessData struct {
	State, CSRF, Identifier, Error, RedirectURI string
	// Action is the code screen's path; Prefix its text key prefix
	// ("login-passwordless.<screen>.").
	Action, Prefix string
	Revision       int64
	// SMS selects the phone-number field and texts.
	SMS    bool
	Social []SocialButton
}

// RenderPasswordlessIdentifier asks for the email address or phone number a
// code is sent to.
func RenderPasswordlessIdentifier(w http.ResponseWriter, status int, t Tenant, d PasswordlessData) {
	render(w, status, "passwordless_identifier", t, d, formActionFor(d.RedirectURI))
}

// RenderPasswordlessCode asks for the code sent to d.Identifier.
func RenderPasswordlessCode(w http.ResponseWriter, status int, t Tenant, d PasswordlessData) {
	render(w, status, "passwordless_code", t, d, formActionFor(d.RedirectURI))
}

func init() {
	for _, page := range []string{"passwordless_identifier", "passwordless_code"} {
		pages[page] = parsePage("templates/layout.html", "templates/"+page+".html")
	}
}
