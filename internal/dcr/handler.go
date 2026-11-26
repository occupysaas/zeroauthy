package dcr

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

const (
	// maxBody bounds a registration body.
	maxBody = 64 << 10
	// ClientIDPrefix starts every dynamically registered client ID.
	ClientIDPrefix = "tpc_"
	clientIDLength = 22
	secretLength   = 64
	// rateLimitKeys bounds the tenants the limiter tracks.
	rateLimitKeys = 10000
)

// Rate is Auth0's documented /oidc/register limit: 5 requests per second
// per tenant. Counters live in this process only, as for the general
// limiter.
var Rate = ratelimit.Rate{PerSecond: 5, Burst: 5}

// Handler serves POST /oidc/register.
type Handler struct {
	Store store.Store
	// Wrapper seals the client secret (D-0038).
	Wrapper keys.Wrapper
	Log     *slog.Logger
	Now     func() time.Time
	limiter *ratelimit.Limiter
}

// NewHandler returns a registration handler with its per-tenant limiter.
func NewHandler(st store.Store, w keys.Wrapper, log *slog.Logger) *Handler {
	h := &Handler{Store: st, Wrapper: w, Log: log}
	h.limiter = ratelimit.NewLimiter(Rate, rateLimitKeys).WithClock(h.now)
	return h
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// NewClientID returns a third-party client ID: tpc_ and 22 letters and
// digits.
func NewClientID() string { return ClientIDPrefix + secrets.RandomString(clientIDLength) }

// Response is the RFC 7591 §3.2.1 answer with Auth0's documented members.
type Response struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientSecretExpiresAt   int      `json:"client_secret_expires_at"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok || !tenantrules.DynamicClientRegistration(res.Tenant) {
		// R41-2: off answers as an unknown route.
		httpx.WriteError(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	if d := h.limiter.Allow(res.Tenant.ID); !d.Allowed {
		ratelimit.WriteTooManyRequests(w, d.RetryAfter)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, metadataError("the body must be a JSON object of at most %d bytes", maxBody))
		return
	}
	req, perr := Parse(body)
	if perr != nil {
		writeError(w, perr)
		return
	}
	c, secret, perr := h.newClient(res.Tenant, req)
	if perr != nil {
		writeError(w, perr)
		return
	}
	if err := h.Store.Clients().Create(r.Context(), c); err != nil {
		if errors.Is(err, store.ErrCIMDUnavailable) {
			httpx.WriteError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "The storage backend cannot hold dynamically registered clients")
			return
		}
		h.log().Error("dynamic client registration failed", "tenant", res.Tenant.ID, "error", err)
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "The application could not be registered")
		return
	}
	// LR41b-9: a server log line; Auth0 documents no tenant log event.
	h.log().Info("dynamic client registered", "tenant", res.Tenant.ID, "client_id", c.ClientID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httpx.WriteJSON(w, http.StatusCreated, Response{
		ClientID: c.ClientID, ClientSecret: secret, ClientName: c.Name, RedirectURIs: c.Callbacks,
		GrantTypes: c.GrantTypes, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: req.AuthMethod,
	})
}

// newClient is the third-party client req registers (D-0025, LR41b-8) and
// its secret, which is returned once and stored sealed.
func (h *Handler) newClient(tn *store.Tenant, req Request) (*store.Client, string, *Error) {
	appType := string(store.AppTypeRegularWeb)
	if req.AuthMethod == store.AuthMethodNone {
		appType = string(store.AppTypeSPA) // R41-5
	}
	firstParty := false
	spec := clientrules.Spec{
		Name: req.Name, AppType: appType, TokenEndpointAuthMethod: req.AuthMethod,
		GrantTypes: req.GrantTypes, Callbacks: req.RedirectURIs, AllowedOrigins: CallbackOrigins(req.RedirectURIs),
		IsFirstParty: &firstParty, ThirdPartySecurityMode: tenantrules.DynamicClientRegistrationMode(tn),
	}
	if errs := clientrules.Normalize(&spec, tn.PushedAuthorizationRequestsSupported); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return nil, "", metadataError("%s", strings.Join(msgs, "; "))
	}
	now := h.now()
	c := &store.Client{TenantID: tn.ID, ClientID: NewClientID(), CreatedAt: now, Origin: store.OriginAPI}
	clientrules.Apply(c, &spec)
	c.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataDCR, CreatedBy: store.ExternalCreatedByClient}
	if req.AuthMethod == store.AuthMethodNone {
		return c, "", nil
	}
	secret := secrets.RandomString(secretLength)
	sealed, err := keys.SealClientSecret(h.Wrapper, c.TenantID, c.ClientID, secret)
	if err != nil {
		h.log().Error("sealing a registered client secret failed", "tenant", tn.ID, "error", err)
		return nil, "", &Error{Code: "server_error", Description: "The application could not be registered"}
	}
	c.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: now}}
	return c, secret, nil
}

func writeError(w http.ResponseWriter, e *Error) {
	status := http.StatusBadRequest
	if e.Code == "server_error" {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, status, e)
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
