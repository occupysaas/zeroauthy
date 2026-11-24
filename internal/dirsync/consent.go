package dirsync

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Routes on tenant hosts. The Google OAuth client must list
// https://{host}/directory-provisioning/callback as a redirect URI
// (LR37c-15).
const (
	ConsentPath  = "/directory-provisioning/consent"
	CallbackPath = "/directory-provisioning/callback"
	cookieName   = "za_directory_consent"
	// TicketTTL bounds a consent link from the console; attemptTTL the
	// round trip through Google.
	TicketTTL  = 15 * time.Minute
	attemptTTL = 10 * time.Minute

	ticketLabel  = "directory-consent-ticket/v1"
	attemptLabel = "directory-consent-attempt/v1"
	grantLabel   = "directory-admin-grant/v1"
)

// SealGrant seals an administrator refresh token to its tenant and
// connection.
func SealGrant(w keys.Wrapper, tenantID, connectionID, refresh string) ([]byte, error) {
	if refresh == "" {
		return nil, errors.New("dirsync: empty grant")
	}
	return keys.SealBound(w, grantLabel, []string{tenantID, connectionID}, []byte(refresh))
}

// OpenGrant reverses SealGrant.
func OpenGrant(w keys.Wrapper, tenantID, connectionID string, sealed []byte) (string, error) {
	plain, err := keys.OpenBound(w, grantLabel, []string{tenantID, connectionID}, sealed)
	if err != nil || len(plain) == 0 {
		return "", errors.New("dirsync: administrator grant unreadable")
	}
	return string(plain), nil
}

type ticket struct {
	Connection string `json:"c"`
	Expires    int64  `json:"e"`
}

// NewTicket returns a consent link token for the connection, sealed to the
// tenant: only that tenant's hosts accept it, until TicketTTL passes.
func NewTicket(w keys.Wrapper, tenantID, connectionID string, now time.Time) (string, error) {
	plain, _ := json.Marshal(ticket{Connection: connectionID, Expires: now.Add(TicketTTL).Unix()})
	sealed, err := keys.SealBound(w, ticketLabel, []string{tenantID}, plain)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

type attempt struct {
	StateHash  string `json:"s"`
	Verifier   string `json:"v"`
	Nonce      string `json:"n"`
	Connection string `json:"c"`
	Host       string `json:"h"`
	Expires    int64  `json:"e"`
}

// Consent serves the administrator consent: ConsentPath redirects to Google
// with offline Directory API scopes, CallbackPath stores the sealed refresh
// token on the connection's directory provisioning and schedules a
// synchronization.
type Consent struct {
	Store     store.Store
	Wrapper   keys.Wrapper
	Providers *federation.Providers
	Now       func() time.Time
	Log       *slog.Logger
}

func (c *Consent) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Consent) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

var resultPage = template.Must(template.New("r").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Google Workspace directory access</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#111}</style></head>
<body><h1>{{.Title}}</h1><p>{{.Text}}</p></body></html>`))

func (c *Consent) page(w http.ResponseWriter, status int, title, text string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = resultPage.Execute(w, map[string]string{"Title": title, "Text": text})
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ServeHTTP dispatches the two routes (GET only).
func (c *Consent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res, ok := tenant.FromContext(r.Context())
	if !ok || res.Tenant == nil {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case ConsentPath:
		c.start(w, r, res)
	case CallbackPath:
		c.callback(w, r, res)
	default:
		http.NotFound(w, r)
	}
}

// target loads a google-apps connection that can consent: login credentials
// sealed and a directory provisioning configuration present.
func (c *Consent) target(r *http.Request, tid, connID string) (*store.Connection, federation.Config, error) {
	conn, err := c.Store.Connections().Get(r.Context(), tid, connID)
	if err != nil {
		return nil, federation.Config{}, err
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.GoogleApps == nil || len(conn.FederationSecretsSealed) == 0 {
		return nil, federation.Config{}, fmt.Errorf("dirsync: not a usable google-apps connection")
	}
	if _, err := c.Store.DirectorySync().GetProvisioning(r.Context(), tid, connID); err != nil {
		return nil, federation.Config{}, err
	}
	return conn, cfg, nil
}

func scopes(cfg federation.Config) []string {
	s := []string{rules.DirectoryUserScope}
	if cfg.GoogleApps.APIEnableGroups {
		s = append(s, rules.DirectoryGroupScope)
	}
	return s
}

func (c *Consent) start(w http.ResponseWriter, r *http.Request, res tenant.Resolved) {
	raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("ticket"))
	var t ticket
	if err == nil {
		var plain []byte
		if plain, err = keys.OpenBound(c.Wrapper, ticketLabel, []string{res.Tenant.ID}, raw); err == nil {
			err = json.Unmarshal(plain, &t)
		}
	}
	now := c.now()
	if err != nil || t.Connection == "" || now.Unix() > t.Expires {
		c.page(w, http.StatusBadRequest, "This link is not valid", "Start the authorization again from the zeroauthy console.")
		return
	}
	conn, cfg, err := c.target(r, res.Tenant.ID, t.Connection)
	if err != nil {
		c.page(w, http.StatusBadRequest, "Directory provisioning is not set up", "The connection needs Google Workspace credentials and a directory provisioning configuration.")
		return
	}
	endpoints, _, _ := c.Providers.Google()
	state, nonce, verifier := random(), random(), random()
	sum := sha256.Sum256([]byte(verifier))
	callback := "https://" + res.Host + CallbackPath
	u, err := c.Providers.For(cfg).AuthorizationURL(federation.StartInput{Config: cfg, Endpoints: endpoints, CallbackURL: callback,
		State: state, Nonce: nonce, CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), DirectoryConsent: scopes(cfg)})
	if err != nil {
		c.page(w, http.StatusInternalServerError, "Authorization could not start", "Try again later.")
		return
	}
	plain, _ := json.Marshal(attempt{StateHash: hash(state), Verifier: verifier, Nonce: nonce, Connection: conn.ID, Host: res.Host, Expires: now.Add(attemptTTL).Unix()})
	sealed, err := keys.SealBound(c.Wrapper, attemptLabel, []string{res.Tenant.ID}, plain)
	if err != nil {
		c.page(w, http.StatusInternalServerError, "Authorization could not start", "Try again later.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/directory-provisioning",
		MaxAge: int(attemptTTL / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (c *Consent) callback(w http.ResponseWriter, r *http.Request, res tenant.Resolved) {
	// The attempt cookie is single use whatever the outcome.
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/directory-provisioning", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	fail := func(status int, text string) { c.page(w, status, "Directory access was not granted", text) }
	var a attempt
	ck, err := r.Cookie(cookieName)
	if err == nil {
		var raw, plain []byte
		if raw, err = base64.RawURLEncoding.DecodeString(ck.Value); err == nil {
			if plain, err = keys.OpenBound(c.Wrapper, attemptLabel, []string{res.Tenant.ID}, raw); err == nil {
				err = json.Unmarshal(plain, &a)
			}
		}
	}
	q := r.URL.Query()
	now := c.now()
	if err != nil || a.Host != res.Host || now.Unix() > a.Expires || subtle.ConstantTimeCompare([]byte(hash(q.Get("state"))), []byte(a.StateHash)) != 1 {
		fail(http.StatusBadRequest, "The authorization expired or was started in another browser. Start it again from the console.")
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		fail(http.StatusBadRequest, "Google did not grant access. A Google Workspace administrator must approve the request.")
		return
	}
	ctx := r.Context()
	conn, cfg, err := c.target(r, res.Tenant.ID, a.Connection)
	if err != nil {
		fail(http.StatusBadRequest, "The connection's directory provisioning changed during the authorization.")
		return
	}
	creds, err := federation.OpenCredentials(c.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		fail(http.StatusInternalServerError, "The connection's credentials are unreadable.")
		return
	}
	endpoints, issuer, dirURL := c.Providers.Google()
	result, err := c.Providers.For(cfg).Exchange(ctx, federation.ExchangeInput{Config: cfg, Cache: federation.CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: conn.FederationRevision},
		Endpoints: endpoints, Issuer: issuer, CallbackURL: "https://" + res.Host + CallbackPath, Code: q.Get("code"), CodeVerifier: a.Verifier,
		Nonce: a.Nonce, ClientSecret: creds.ClientSecret, Now: now})
	if err != nil {
		c.log().WarnContext(ctx, "directory consent exchange failed", "tenant", conn.TenantID, "connection", conn.ID, "error", err)
		fail(http.StatusBadRequest, "The Google account could not be verified for this Workspace.")
		return
	}
	if result.Tokens.RefreshToken == "" {
		fail(http.StatusBadRequest, "Google returned no offline access. Remove the application's access in the Google account and try again.")
		return
	}
	// Only an administrator's token can read the directory: prove it before
	// replacing the stored grant.
	client := &Client{HTTP: c.Providers.HTTPClient(), TokenURL: endpoints.TokenURL, DirectoryURL: dirURL}
	if err := client.probe(ctx, result.Tokens.AccessToken, cfg.GoogleApps.Domain); err != nil {
		c.log().WarnContext(ctx, "directory consent probe failed", "tenant", conn.TenantID, "connection", conn.ID, "error", err)
		fail(http.StatusForbidden, "The account cannot read the Workspace directory. Sign in as a Google Workspace administrator.")
		return
	}
	sealed, err := SealGrant(c.Wrapper, conn.TenantID, conn.ID, result.Tokens.RefreshToken)
	if err != nil {
		fail(http.StatusInternalServerError, "The grant could not be stored.")
		return
	}
	err = c.Store.WithTx(ctx, func(tx store.Store) error {
		p, err := tx.DirectorySync().GetProvisioning(ctx, conn.TenantID, conn.ID)
		if err != nil {
			return err
		}
		p.AdminGrant, p.UpdatedAt = sealed, now
		schedule(p, now)
		return tx.DirectorySync().UpdateProvisioning(ctx, p)
	})
	if err != nil {
		fail(http.StatusInternalServerError, "The grant could not be stored.")
		return
	}
	c.log().InfoContext(ctx, "directory consent granted", "tenant", conn.TenantID, "connection", conn.ID)
	c.page(w, http.StatusOK, "Directory access granted", "zeroauthy can now read the Google Workspace directory. The first synchronization starts shortly; you can close this window.")
}

// probe lists one user of the domain.
func (c *Client) probe(ctx context.Context, token, domain string) error {
	q := map[string][]string{"domain": {domain}, "maxResults": {"1"}}
	req, err := c.get(ctx, token, "/users", q)
	if err != nil {
		return err
	}
	var page map[string]json.RawMessage
	_, err = c.do(req, &page)
	return err
}
