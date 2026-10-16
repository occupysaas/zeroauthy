// Package ui renders zeroauthy's hosted pages. Templates are embedded,
// original work, and every response carries a nonce-based CSP.
package ui

import (
	"bytes"
	"embed"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

//go:embed templates/*.html
var files embed.FS

var funcs = template.FuncMap{
	// t renders a catalog key: {{t .Tenant.L "login.login.title" "name" "value"}}.
	"t": func(l *i18n.Localizer, key string, kv ...string) string { return l.T(key, kv...) },
}

func parsePage(names ...string) *template.Template {
	return template.Must(template.New("").Funcs(funcs).ParseFS(files, names...))
}

var (
	pages = map[string]*template.Template{
		"login":            parsePage("templates/layout.html", "templates/login.html"),
		"signup":           parsePage("templates/layout.html", "templates/signup.html"),
		"consent":          parsePage("templates/layout.html", "templates/consent.html"),
		"error":            parsePage("templates/layout.html", "templates/error.html"),
		"logout_confirm":   parsePage("templates/layout.html", "templates/logout_confirm.html"),
		"logged_out":       parsePage("templates/layout.html", "templates/logged_out.html"),
		"reset_request":    parsePage("templates/layout.html", "templates/reset_request.html"),
		"reset_email_sent": parsePage("templates/layout.html", "templates/reset_email_sent.html"),
		"reset_password":   parsePage("templates/layout.html", "templates/reset_password.html"),
		"reset_success":    parsePage("templates/layout.html", "templates/reset_success.html"),
		"reset_error":      parsePage("templates/layout.html", "templates/reset_error.html"),
	}
	formPost   = parsePage("templates/form_post.html")
	webMessage = parsePage("templates/web_message.html")
)

// Tenant is the branding and language of a hosted page.
type Tenant struct {
	Name         string
	LogoURL      string
	PrimaryColor string
	L            *i18n.Localizer // nil renders English
	// HasClientName selects the login and signup subtitle that names the
	// application; without it the subtitle names only the tenant, so a
	// client ID is never shown to end users.
	HasClientName bool
}

// TenantView builds the page branding and language for a tenant.
func TenantView(t *store.Tenant, l *i18n.Localizer) Tenant {
	name := t.FriendlyName
	if name == "" {
		name = t.Name
	}
	return Tenant{Name: name, LogoURL: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor, L: l}
}

type LoginData struct {
	State, CSRF, Login string
	SignupURL          string // empty hides the signup link
	ForgotURL          string // empty hides the forgot-password link
	Error              string
	RedirectURI        string // the client's callback; its origin is allowed as form-action
}

type SignupData struct {
	State, CSRF, Email, Username string
	RequiresUsername             bool
	LoginURL                     string
	Error                        string
	RedirectURI                  string // the client's callback; its origin is allowed as form-action
}

type page struct {
	Tenant Tenant
	Nonce  string
	Data   any
}

func RenderLogin(w http.ResponseWriter, status int, t Tenant, d LoginData) {
	render(w, status, "login", t, d, formActionFor(d.RedirectURI))
}

func RenderSignup(w http.ResponseWriter, status int, t Tenant, d SignupData) {
	render(w, status, "signup", t, d, formActionFor(d.RedirectURI))
}

type errorData struct{ Message, Detail string }

func RenderError(w http.ResponseWriter, status int, t Tenant, message string) {
	RenderErrorDetail(w, status, t, message, "")
}

// RenderErrorDetail shows a localized message and an optional technical
// detail (OAuth error descriptions stay English).
func RenderErrorDetail(w http.ResponseWriter, status int, t Tenant, message, detail string) {
	render(w, status, "error", t, errorData{Message: message, Detail: detail}, "'self'")
}

// formActionFor returns the form-action source list for a page whose form
// submission ends in a redirect to redirectURI. Browsers apply form-action to
// the whole redirect chain, so the client's origin must be allowed or the
// final hop back to the application is blocked.
func formActionFor(redirectURI string) string {
	if o := origin(redirectURI); o != "'none'" {
		return "'self' " + o
	}
	if s := customScheme(redirectURI); s != "" {
		return "'self' " + s
	}
	return "'self'"
}

var (
	schemeSyntax = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
	// Schemes that execute or expose content and must never become a
	// form-action source.
	dangerousSchemes = []string{"javascript", "data", "vbscript", "file", "blob", "about", "filesystem"}
)

// customScheme returns the "<scheme>:" CSP source for a native-app
// redirect_uri (RFC 8252 private-use scheme), or "" for http(s), relative
// or malformed URIs.
func customScheme(redirectURI string) string {
	i := strings.IndexByte(redirectURI, ':')
	if i <= 0 {
		return ""
	}
	s := redirectURI[:i]
	if !schemeSyntax.MatchString(s) || s == "http" || s == "https" || slices.Contains(dangerousSchemes, s) {
		return ""
	}
	return s + ":"
}

func render(w http.ResponseWriter, status int, name string, t Tenant, data any, formAction string) {
	if t.L == nil {
		t.L = i18n.Default()
	}
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", formAction)
	write(w, status, pages[name], "layout", page{Tenant: t, Nonce: nonce, Data: data})
}

// RenderFormPost writes the OAuth 2.0 Form Post Response Mode page in the
// language of l (nil renders English).
func RenderFormPost(w http.ResponseWriter, l *i18n.Localizer, action string, params url.Values) {
	if l == nil {
		l = i18n.Default()
	}
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", origin(action))
	write(w, http.StatusOK, formPost, "form_post.html", map[string]any{"Action": action, "Params": params, "Nonce": nonce, "L": l})
}

// RenderWebMessage writes the Web Message Response Mode page, which posts
// the authorization response to targetOrigin from a popup or iframe.
func RenderWebMessage(w http.ResponseWriter, targetOrigin string, response map[string]string) {
	// The origin is used as a CSP source and as the postMessage target, so
	// only a strict scheme://host[:port] is accepted. Anything else (e.g. "*")
	// would leak the response or widen the CSP.
	if !validOrigin(targetOrigin) {
		slog.Error("refusing web_message: invalid target origin", "origin", targetOrigin)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := newNonce()
	setHeaders(w, nonce, targetOrigin, "'none'")
	write(w, http.StatusOK, webMessage, "web_message.html", map[string]any{"Origin": targetOrigin, "Response": response, "Nonce": nonce})
}

func newNonce() string { return secrets.RandomString(22) }

// setHeaders applies the shared security headers. frameAncestors is a CSP
// source ("'none'" or an origin); formAction likewise.
func setHeaders(w http.ResponseWriter, nonce, frameAncestors, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
		"img-src https:; form-action "+formAction+"; frame-ancestors "+frameAncestors+"; base-uri 'none'")
	if frameAncestors == "'none'" {
		h.Set("X-Frame-Options", "DENY")
	}
}

func write(w http.ResponseWriter, status int, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("render page", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// origin returns scheme://host[:port] of u, or "'none'" if u is not an
// absolute URL with a valid origin.
func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return "'none'"
	}
	o := p.Scheme + "://" + p.Host
	if !validOrigin(o) {
		return "'none'"
	}
	return o
}

var (
	dnsLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
	portNum  = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// validOrigin reports whether s is exactly http or https, followed by a DNS
// name, an IPv4 literal, or a bracketed IPv6 literal, with an optional port
// from 0 to 65535. Paths, queries, userinfo, wildcards and CSP delimiters are
// rejected.
func validOrigin(s string) bool {
	var rest string
	switch {
	case strings.HasPrefix(s, "https://"):
		rest = s[len("https://"):]
	case strings.HasPrefix(s, "http://"):
		rest = s[len("http://"):]
	default:
		return false
	}

	host, port := rest, ""
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return false
		}
		inner := rest[1:end]
		if ip := net.ParseIP(inner); ip == nil || !strings.Contains(inner, ":") {
			return false
		}
		host, port = rest[:end+1], rest[end+1:]
	} else if i := strings.IndexByte(rest, ':'); i >= 0 {
		host, port = rest[:i], rest[i:]
	}

	if port != "" {
		if !strings.HasPrefix(port, ":") || !portNum.MatchString(port[1:]) {
			return false
		}
		if n, err := strconv.Atoi(port[1:]); err != nil || n > 65535 {
			return false
		}
	}
	if strings.HasPrefix(host, "[") {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// RenderLoggedOut writes the page shown after a logout with nowhere to
// return to.
func RenderLoggedOut(w http.ResponseWriter, t Tenant) {
	render(w, http.StatusOK, "logged_out", t, nil, "'none'")
}

// LogoutConfirmData is the logout confirmation page.
type LogoutConfirmData struct {
	CSRF   string
	Fields url.Values // the logout request, posted again on confirmation
	// RedirectURI is where the browser goes after logout; its origin is
	// allowed as a form-action (D-0010).
	RedirectURI string
}

// RenderLogoutConfirm asks the user to confirm an RP-initiated logout.
func RenderLogoutConfirm(w http.ResponseWriter, t Tenant, d LogoutConfirmData) {
	render(w, http.StatusOK, "logout_confirm", t, d, formActionFor(d.RedirectURI))
}

// ResetRequestData is the forgot-password page (screen reset-password-request).
type ResetRequestData struct {
	State, CSRF, Email string
	LoginURL           string
	RedirectURI        string // the client's callback; its origin is allowed as form-action
	Error              string
}

// ResetFormData is the new-password form (screen reset-password).
type ResetFormData struct {
	Ticket, CSRF string
	Error        string
}

// ResetErrorData is a localized reset-password-error screen.
type ResetErrorData struct {
	Title, Description string
}

// RenderResetRequest asks for the email address to send a reset link to.
func RenderResetRequest(w http.ResponseWriter, status int, t Tenant, d ResetRequestData) {
	render(w, status, "reset_request", t, d, formActionFor(d.RedirectURI))
}

// RenderResetEmailSent tells the user to check their email. It never says
// whether the address belongs to an account.
func RenderResetEmailSent(w http.ResponseWriter, t Tenant) {
	render(w, http.StatusOK, "reset_email_sent", t, nil, "'none'")
}

// RenderResetForm asks for the new password. The form posts back to this
// origin, where the success page renders in place.
func RenderResetForm(w http.ResponseWriter, status int, t Tenant, d ResetFormData) {
	render(w, status, "reset_password", t, d, "'self'")
}

// RenderResetSuccess confirms the password change.
func RenderResetSuccess(w http.ResponseWriter, t Tenant) {
	render(w, http.StatusOK, "reset_success", t, nil, "'none'")
}

// RenderResetError explains why a reset link cannot be used.
func RenderResetError(w http.ResponseWriter, status int, t Tenant, d ResetErrorData) {
	render(w, status, "reset_error", t, d, "'none'")
}

// ConsentData is the consent or confirmation page of a transaction.
type ConsentData struct {
	State, CSRF    string
	Confirmation   bool
	ThirdParty     bool
	CallbackDomain string
	APIName        string
	Scopes         []string
	RedirectURI    string // its origin is allowed as form-action
}

// RenderConsent shows the consent or confirmation page of a transaction.
func RenderConsent(w http.ResponseWriter, status int, t Tenant, d ConsentData) {
	render(w, status, "consent", t, d, formActionFor(d.RedirectURI))
}
