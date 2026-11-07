// Package server assembles zeroauthy's HTTP handler.
package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zeroauthy/zeroauthy/api"
	"github.com/zeroauthy/zeroauthy/console"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/login"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/oidc"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Deps struct {
	MFA *mfa.Service
	// Passkeys is shared by hosted and native ceremony consumers.
	Passkeys *passkey.Service
	// LogsConfig carries the secure stream defaults and deployment opt-ins.
	LogsConfig     logs.Config
	EventsConfig   events.Config
	EventDeliverer mgmt.EventDeliverer

	Recorder   logs.Recorder
	Protection *protection.Service

	Store        store.Store
	Keys         *keys.Manager
	Resolver     *tenant.Resolver
	Sessions     *session.Manager
	Log          *slog.Logger
	Mailer       email.Mailer
	EmailService *email.Service

	// JobNotify wakes the job workers after a job is stored; nil does
	// nothing.
	JobNotify func()

	// ExportKey signs the download links of user exports (derived from the
	// master key, mgmt.ExportLinkInfo); nil gives exports no links.
	ExportKey []byte

	// Wrapper opens sealed client secrets at the token endpoint. It must be
	// the master key wrapper the seed and the Management API seal with.
	Wrapper keys.Wrapper

	// Scripts runs custom database scripts; nil makes customized
	// connections fail.
	Scripts           *customdb.Client
	TrustProxyHeaders bool

	// Domains admits API custom domains and private origin aliases ahead of
	// tenant resolution and constrains legacy forwarded-header trust; nil
	// serves no custom domains.
	Domains *customdomain.Service

	// BaseDomain is server.base_domain, and SystemHost the system tenant's
	// canonical host (tenant.SystemHost). They name the tenants'
	// Management API identifiers, the operator-token issuer and the only
	// origin CORS allows on /api/v2 and /api/system.
	BaseDomain          string
	SystemHost          string
	RestrictSharedRPIDs bool

	// Console is the built admin console; nil means the embedded one.
	Console fs.FS

	// Device code entry limits; see login.Handlers. The IP and tenant
	// throttles may be nil (off).
	DeviceTxnThrottle    *identity.Throttle
	DeviceIPThrottle     *identity.Throttle
	DeviceTenantThrottle *identity.Throttle

	// Federation runs social and OIDC login (Plan 24); nil offers none.
	Federation *federation.FlowService

	// Actions runs post-login and credentials-exchange flows (Plan 27);
	// nil runs none. Its effects are sealed with Wrapper.
	Actions *actions.Engine

	// Phone routes SMS and voice messages to the tenant's providers and
	// phone Actions (Plan 34); passwordless, MFA and phone reset send
	// through it. nil sends none.
	Phone *phone.Dispatcher

	// RateLimit limits every tenant Authentication API route per tenant,
	// client IP and endpoint group; nil limits nothing.
	RateLimit *ratelimit.Middleware

	// LegacySecretSlots caps concurrent legacy client secret checks in
	// this process; nil gets the default cap.
	LegacySecretSlots *ratelimit.Semaphore

	// Auth0RefreshErrorStatus opts into Auth0's 403 for unusable refresh
	// tokens (compatibility.auth0_refresh_error_status).
	Auth0RefreshErrorStatus bool
}

// authGroup is the rate-limit group of a tenant Authentication API path.
func authGroup(path string) ratelimit.Group {
	switch {
	case path == "/oauth/token":
		return ratelimit.GroupToken
	case path == "/authorize" || strings.HasPrefix(path, "/authorize/"):
		return ratelimit.GroupAuthorize
	case path == "/userinfo":
		return ratelimit.GroupUserinfo
	case strings.HasPrefix(path, "/.well-known/"):
		return ratelimit.GroupDiscovery
	}
	return ratelimit.GroupOther
}

// authAPI adapts the handler groups to the generated ServerInterface.
// The var _ assertion fails to compile when api/authentication.yaml gains
// an operation that has no forwarding method here.
type authAPI struct {
	oidc   *oidc.Handlers
	oauth  *oauth.Handlers
	authz  *authz.Handlers
	dbconn *dbconn.Handlers

	passwordless *passwordless.Handlers
}

func (a authAPI) Discovery(w http.ResponseWriter, r *http.Request)   { a.oidc.Discovery(w, r) }
func (a authAPI) Jwks(w http.ResponseWriter, r *http.Request)        { a.oidc.Jwks(w, r) }
func (a authAPI) OauthToken(w http.ResponseWriter, r *http.Request)  { a.oauth.OauthToken(w, r) }
func (a authAPI) OauthRevoke(w http.ResponseWriter, r *http.Request) { a.oauth.OauthRevoke(w, r) }
func (a authAPI) OauthPar(w http.ResponseWriter, r *http.Request)    { a.oauth.OauthPar(w, r) }
func (a authAPI) OauthDeviceCode(w http.ResponseWriter, r *http.Request) {
	a.oauth.OauthDeviceCode(w, r)
}
func (a authAPI) Userinfo(w http.ResponseWriter, r *http.Request)     { a.oidc.Userinfo(w, r) }
func (a authAPI) UserinfoPost(w http.ResponseWriter, r *http.Request) { a.oidc.Userinfo(w, r) }

func (a authAPI) DbconnectionsSignup(w http.ResponseWriter, r *http.Request) { a.dbconn.Signup(w, r) }
func (a authAPI) DbconnectionsChangePassword(w http.ResponseWriter, r *http.Request) {
	a.dbconn.ChangePassword(w, r)
}

func (a authAPI) Authorize(w http.ResponseWriter, r *http.Request, _ authapi.AuthorizeParams) {
	a.authz.Authorize(w, r)
}

func (a authAPI) AuthorizePost(w http.ResponseWriter, r *http.Request) { a.authz.Authorize(w, r) }

func (a authAPI) Logout(w http.ResponseWriter, r *http.Request, _ authapi.LogoutParams) {
	a.oidc.Logout(w, r)
}

func (a authAPI) OidcLogout(w http.ResponseWriter, r *http.Request, _ authapi.OidcLogoutParams) {
	a.oidc.OidcLogout(w, r)
}
func (a authAPI) OidcLogoutPost(w http.ResponseWriter, r *http.Request) { a.oidc.OidcLogout(w, r) }

var _ authapi.ServerInterface = authAPI{}

func New(d Deps) http.Handler {
	if d.Recorder == nil {
		d.Recorder = logs.Nop
	}
	if d.EmailService == nil {
		renderer, _ := email.NewRenderer()
		d.EmailService = &email.Service{Recorder: d.Recorder, Store: d.Store, Wrapper: d.Wrapper, Renderer: renderer, Providers: &providers.Factory{}, Fallback: d.Mailer, DefaultFrom: "zeroauthy@localhost"}
	}
	if d.EmailService.Recorder == nil {
		d.EmailService.Recorder = d.Recorder
	}
	if d.Actions != nil {
		d.Actions.InvitationEmail = d.EmailService
	}
	if d.LegacySecretSlots == nil {
		d.LegacySecretSlots = ratelimit.NewSecretVerifications(0)
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID, requestLog(d.Log), recoverer(d.Log))

	// Operational endpoints answer on any host.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := d.Store.Ping(ctx); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.AuthenticationYAML)
	})
	r.Get("/docs", serveDocs)

	az := &authz.Handlers{Passkeys: d.Passkeys, MFA: d.MFA, Store: d.Store, Sessions: d.Sessions, Log: d.Log,
		Actions: d.Actions, Wrapper: d.Wrapper, TrustProxyHeaders: d.TrustProxyHeaders}
	db := &identity.Database{Store: d.Store, Scripts: d.Scripts, Log: d.Log}
	// One mailer sends every verification email: after a signup (API and
	// hosted page) and for the Management API's verify_email.
	verification := &login.VerificationMailer{Recorder: d.Recorder, Store: d.Store, Mailer: d.Mailer, Email: d.EmailService, BaseDomain: d.BaseDomain, Log: d.Log}
	// All password flows use the store-backed policy service. Reset send
	// budgets also remain shared across independently constructed servers.
	sharedProtection := d.Protection
	if sharedProtection == nil {
		sharedProtection = &protection.Service{Store: d.Store, Log: d.Log}
	}
	sharedProtection.Recorder = d.Recorder
	if sharedProtection.Notifier == nil && d.EmailService != nil {
		sharedProtection.Notifier = d.EmailService
	}
	dbconnHandlers := &dbconn.Handlers{
		Recorder: d.Recorder,
		Store:    d.Store, Database: db, Actions: d.Actions,
		Protection: sharedProtection, TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log,
		Mailer:       d.Mailer,
		Email:        d.EmailService,
		Verification: verification,
	}
	lg := &login.Handlers{
		MFA:      d.MFA,
		Recorder: d.Recorder,
		Store:    d.Store, Sessions: d.Sessions, Authz: az,
		Database:          db,
		Passkeys:          d.Passkeys,
		Actions:           d.Actions,
		Resets:            dbconnHandlers,
		Federation:        d.Federation,
		Verification:      verification,
		Protection:        sharedProtection,
		DeviceTxnThrottle: d.DeviceTxnThrottle, DeviceIPThrottle: d.DeviceIPThrottle, DeviceTenantThrottle: d.DeviceTenantThrottle,
		TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log,
	}
	az.ResetContinue = lg.ResetContinue
	pwl := &passwordless.Service{Store: d.Store, Wrapper: d.Wrapper, Email: d.EmailService, Protection: sharedProtection,
		Actions: d.Actions, Database: db, Recorder: d.Recorder, Log: d.Log}
	if d.Phone != nil {
		pwl.SMS = d.Phone
	}
	lg.Passwordless = pwl

	// Authentication API: every route is tenant-scoped.
	r.Group(func(tr chi.Router) {
		// The limiter runs right after tenant resolution, ahead of any
		// other store work (CORS origin lookups included).
		limit := d.RateLimit.Handler(func(r *http.Request) (string, string, ratelimit.Group, bool) {
			res, ok := tenant.FromContext(r.Context())
			if !ok {
				return "", "", "", false
			}
			return res.Tenant.ID, httpx.ClientIP(r, d.TrustProxyHeaders), authGroup(r.URL.Path), true
		})
		tr.Use(d.Resolver.Middleware, limit, cors(d.Store), hostedPresentation(d.Store), func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), d.Recorder)))
			})
		})
		authapi.HandlerWithOptions(authAPI{
			oidc: &oidc.Handlers{Keys: d.Keys, Store: d.Store, Sessions: d.Sessions, Log: d.Log},
			oauth: &oauth.Handlers{
				MFA:      d.MFA,
				Recorder: d.Recorder,
				Store:    d.Store, Log: d.Log, Minter: &oauth.Minter{Keys: d.Keys}, Wrapper: d.Wrapper,
				LegacySecretSlots:       d.LegacySecretSlots,
				Auth0RefreshErrorStatus: d.Auth0RefreshErrorStatus,
				BaseDomain:              d.BaseDomain,
				Database:                db,
				Protection:              sharedProtection,
				TrustProxyHeaders:       d.TrustProxyHeaders,
				Actions:                 d.Actions,
				Passwordless:            pwl,
			},
			authz:        az,
			dbconn:       dbconnHandlers,
			passwordless: &passwordless.Handlers{Service: pwl, Authz: az, Sessions: d.Sessions, TrustProxyHeaders: d.TrustProxyHeaders, Log: d.Log},
		}, authapi.ChiServerOptions{
			BaseRouter: tr,
			ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
			},
		})
		preflight := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		tr.Options("/oauth/token", preflight)
		tr.Options("/oauth/revoke", preflight)
		tr.Options("/oauth/device/code", preflight)
		tr.Options("/userinfo", preflight)
		tr.Options("/dbconnections/signup", preflight)
		tr.Options("/dbconnections/change_password", preflight)
		tr.Options("/passwordless/start", preflight)
		tr.Get("/continue", az.Continue)
		tr.Post("/continue", az.Continue)
		for _, path := range []string{"/u/mfa-detect-browser-capabilities", "/u/mfa-webauthn-platform-enrollment", "/u/mfa-webauthn-platform-challenge", "/u/mfa-webauthn-roaming-enrollment", "/u/mfa-webauthn-roaming-challenge", "/u/mfa-webauthn-change-key-nickname", "/u/mfa-webauthn-enrollment-success", "/u/mfa-phone-enrollment", "/u/mfa-sms-challenge", "/u/mfa-voice-challenge", "/u/mfa", "/u/mfa-otp-enrollment", "/u/mfa-otp-challenge", "/u/mfa-email-challenge", "/u/mfa-recovery-code-enrollment", "/u/mfa-recovery-code-challenge"} {
			tr.Get(path, lg.MFAPage)
			tr.Post(path, lg.MFASubmit)
		}
		tr.Get("/u/mfa-enroll-ticket", lg.MFATicket)
		tr.Get("/u/login", lg.LoginPage)
		tr.Post("/u/login", lg.LoginSubmit)
		for _, path := range []string{"/u/login-passwordless-email-code", "/u/login-passwordless-sms-otp"} {
			tr.Get(path, lg.PasswordlessCodePage)
			tr.Post(path, lg.PasswordlessCodeSubmit)
		}
		tr.Get("/u/login/password", lg.LoginPasswordGet)
		tr.Post("/u/login/password", lg.LoginPasswordPost)
		tr.Post("/u/login/identifier", lg.LoginIdentifierResetPost)
		tr.Post("/u/login/passkey", lg.LoginPasskeyPost)
		tr.Get("/u/passkey-enrollment", lg.PasskeyEnrollmentPage)
		tr.Post("/u/passkey-enrollment", lg.PasskeyEnrollmentPost)
		tr.Get("/u/passkey-enrollment-local", lg.PasskeyEnrollmentPage)
		tr.Post("/u/passkey-enrollment-local", lg.PasskeyEnrollmentPost)
		tr.Post("/u/login/social", lg.SocialStart)
		tr.Get("/login/callback", lg.SocialCallback)
		tr.Get("/u/consent", lg.ConsentPage)
		tr.Post("/u/consent", lg.ConsentSubmit)
		tr.Get("/u/signup", lg.SignupPage)
		tr.Post("/u/signup", lg.SignupSubmit)
		tr.Get("/u/signup/identifier", lg.SignupPage)
		tr.Post("/u/signup/identifier", lg.SignupIdentifierPost)
		tr.Get("/u/signup/passkey", lg.SignupPage)
		tr.Post("/u/signup/passkey", lg.SignupPasskeyPost)
		tr.Get("/u/signup/password", lg.SignupPage)
		tr.Post("/u/signup/password", lg.SignupSubmit)
		tr.Get("/u/reset-password/request", lg.ResetRequestPage)
		tr.Post("/u/reset-password/request", lg.ResetRequestSubmit)
		tr.Get("/u/reset-password", lg.ResetPasswordPage)
		tr.Post("/u/reset-password", lg.ResetPasswordSubmit)
		// Management API ticket links (U6).
		tr.Get("/u/reset-verify", lg.ResetVerify)
		tr.Get("/u/email-verification", lg.EmailVerificationPage)
		// Device flow pages, at the paths observed on Auth0.
		tr.Get("/activate", lg.Activate)
		tr.Post("/activate", lg.ActivateSubmit)
		tr.Get("/device/confirmation", lg.DeviceConfirmPage)
		tr.Post("/device/confirmation", lg.DeviceConfirmSubmit)
		tr.Get("/device/success", lg.DeviceSuccess)
		tr.Get("/device/denied", lg.DeviceDenied)
	})

	// The Management API, on every host of every tenant, and the system
	// API, on the system tenant only, share one router built from
	// api/management.yaml. Its middlewares run for every request, preflights
	// and unknown paths included; CORS runs before authentication so that
	// preflights need no token.
	auth := mgmt.Auth(mgmt.Config{Store: d.Store, Keys: d.Keys, BaseDomain: d.BaseDomain, SystemHost: d.SystemHost, Log: d.Log})
	systemOrigin := ""
	if d.SystemHost != "" {
		systemOrigin = "https://" + tenant.NormalizeHost(d.SystemHost)
	}
	mr := chi.NewRouter()
	mh := &mgmt.Handlers{
		LogsConfig:     d.LogsConfig,
		EventsConfig:   d.EventsConfig,
		EventDeliverer: d.EventDeliverer,
		Actions:        d.Actions,
		Recorder:       d.Recorder,
		Store:          d.Store, Wrapper: d.Wrapper, BaseDomain: d.BaseDomain, SystemHost: d.SystemHost, Log: d.Log,
		Scripts: d.Scripts, Keys: d.Keys, Verification: verification, Notify: d.JobNotify, EmailService: d.EmailService,
		TrustProxyHeaders:      d.TrustProxyHeaders,
		BreachCheckerAvailable: sharedProtection.BreachChecker != nil,
		Protection:             sharedProtection,
		Domains:                d.Domains,
		RestrictSharedRPIDs:    d.RestrictSharedRPIDs,
	}
	mr.Use(d.Resolver.Middleware, systemOnly, mgmtCORS(systemOrigin), auth, mh.LogMiddleware, operatorOnly)
	for _, method := range []string{"GET", "PUT"} {
		mr.MethodFunc(method, "/api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings", func(w http.ResponseWriter, r *http.Request) { mh.RoamingUVSettings(w, r, chi.URLParam(r, "tenant")) })
	}
	mr.Get("/api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites", func(w http.ResponseWriter, r *http.Request) {
		mh.PasskeyPrerequisites(w, r, chi.URLParam(r, "tenant"), chi.URLParam(r, "id"))
	})
	if len(d.ExportKey) > 0 {
		mh.Export = &mgmt.ExportLink{Key: d.ExportKey}
	}
	mgmtapi.HandlerWithOptions(mgmtAPI{h: mh}, mgmtapi.ChiServerOptions{
		BaseRouter: mr,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.URL.Path == "/api/v2/events" || r.URL.Path == "/api/v2/event-streams" || strings.HasPrefix(r.URL.Path, "/api/v2/event-streams/") {
				mgmt.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid event stream query")
				return
			}
			mgmt.WriteError(w, http.StatusBadRequest, "invalid_query_string", "Query validation error: "+err.Error())
		},
	})
	// Checkpoint mode ignores typed page/projection/query parameters. Bind the
	// raw query here so generated page binding cannot reject ignored values.
	mr.Get("/api/v2/logs", func(w http.ResponseWriter, r *http.Request) {
		scopedAll(w, r, mh.ListLogs, "read:logs")
	})
	mr.NotFound(mgmtNotFound)
	mr.MethodNotAllowed(mgmtNotFound)
	// mr routes on the full path, independently of r.
	own := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mr.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, nil)))
	})
	r.Handle("/api/v2/*", own)
	r.Handle("/api/system/*", own)
	r.Handle("/api/console/*", own)

	// Export downloads (D-0044): a signed link, no token, on any tenant host.
	r.Group(func(er chi.Router) {
		er.Use(d.Resolver.Middleware)
		er.Get("/export/{job}/{file}", mh.DownloadExport)
	})

	// The console, on the system host only.
	files := d.Console
	if files == nil {
		files = console.Files()
	}
	r.Group(func(ar chi.Router) {
		ar.Use(d.Resolver.Middleware)
		a := admin{files: files, store: d.Store, baseDomain: d.BaseDomain}
		ar.Method(http.MethodGet, "/admin", a)
		ar.Method(http.MethodGet, "/admin/*", a)
		ar.Method(http.MethodHead, "/admin/*", a)
	})
	if d.Domains != nil {
		// Admission precedes everything, logging included, so proxy keys and
		// spoofed forwarding headers never reach a handler or a log line.
		// Operational endpoints answer on any host and never consult the
		// registry, so liveness survives a store outage.
		admitted := d.Domains.Middleware(r)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/healthz" || req.URL.Path == "/readyz" {
				r.ServeHTTP(w, req)
				return
			}
			admitted.ServeHTTP(w, req)
		})
	}
	return r
}

func mgmtNotFound(w http.ResponseWriter, _ *http.Request) {
	mgmt.WriteError(w, http.StatusNotFound, "", "Not Found")
}

func isSystemAPI(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/system/") }

// systemOnly answers 404 to the system API on every tenant but the system
// tenant.
func systemOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSystemAPI(r) && !strings.HasPrefix(r.URL.Path, "/api/console/") {
			next.ServeHTTP(w, r)
			return
		}
		if res, ok := tenant.FromContext(r.Context()); !ok || !res.Tenant.Reserved || res.Tenant.Name != tenant.SystemName {
			mgmtNotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// operatorOnly refuses every caller but an operator on the system API.
func operatorOnly(next http.Handler) http.Handler {
	operators := mgmt.RequireOperator(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSystemAPI(r) || strings.HasPrefix(r.URL.Path, "/api/console/") {
			operators.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
