// Package ui renders zeroauthy's hosted pages. Templates are embedded,
// original work, and every response carries a nonce-based CSP.
package ui

import (
	"bytes"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

//go:embed templates/*.html
var files embed.FS

var (
	pages = map[string]*template.Template{
		"login":  template.Must(template.ParseFS(files, "templates/layout.html", "templates/login.html")),
		"signup": template.Must(template.ParseFS(files, "templates/layout.html", "templates/signup.html")),
		"error":  template.Must(template.ParseFS(files, "templates/layout.html", "templates/error.html")),
	}
	formPost   = template.Must(template.ParseFS(files, "templates/form_post.html"))
	webMessage = template.Must(template.ParseFS(files, "templates/web_message.html"))
)

// Tenant is the branding shown on hosted pages.
type Tenant struct {
	Name         string
	LogoURL      string
	PrimaryColor string
}

// TenantView builds the page branding for a tenant.
func TenantView(t *store.Tenant) Tenant {
	name := t.FriendlyName
	if name == "" {
		name = t.Name
	}
	return Tenant{Name: name, LogoURL: t.Branding.LogoURL, PrimaryColor: t.Branding.PrimaryColor}
}

type LoginData struct {
	State, CSRF, Login string
	SignupURL          string // empty hides the signup link
	Error              string
}

type SignupData struct {
	State, CSRF, Email, Username string
	RequiresUsername             bool
	LoginURL                     string
	Error                        string
}

type page struct {
	Tenant Tenant
	Nonce  string
	Data   any
}

func RenderLogin(w http.ResponseWriter, status int, t Tenant, d LoginData) {
	render(w, status, "login", t, d)
}

func RenderSignup(w http.ResponseWriter, status int, t Tenant, d SignupData) {
	render(w, status, "signup", t, d)
}

func RenderError(w http.ResponseWriter, status int, t Tenant, message string) {
	render(w, status, "error", t, message)
}

func render(w http.ResponseWriter, status int, name string, t Tenant, data any) {
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", "'self'")
	write(w, status, pages[name], "layout", page{Tenant: t, Nonce: nonce, Data: data})
}

// RenderFormPost writes the OAuth 2.0 Form Post Response Mode page.
func RenderFormPost(w http.ResponseWriter, action string, params url.Values) {
	nonce := newNonce()
	setHeaders(w, nonce, "'none'", origin(action))
	write(w, http.StatusOK, formPost, "form_post.html", map[string]any{"Action": action, "Params": params, "Nonce": nonce})
}

// RenderWebMessage writes the Web Message Response Mode page, which posts
// the authorization response to targetOrigin from a popup or iframe.
func RenderWebMessage(w http.ResponseWriter, targetOrigin string, response map[string]string) {
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
// absolute URL.
func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return "'none'"
	}
	return p.Scheme + "://" + p.Host
}
