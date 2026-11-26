package oauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/ciba"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// CIBA limits (Auth0): requests per tenant and per user, and pending
// requests per tenant. Counters live in this process.
const (
	cibaTenantPerMinute = 500
	cibaUserPerMinute   = 5
	cibaMaxPending      = 5000
	cibaLimitKeys       = 100000
	cibaMailTimeout     = 30 * time.Second
)

// ApprovalMailer sends CIBA approval emails (email.Service).
type ApprovalMailer interface {
	SendAsyncApproval(ctx context.Context, m email.AsyncApprovalEmail) error
}

// CIBAService holds /bc-authorize's limits and mailer (Plan 41c).
type CIBAService struct {
	Mail   ApprovalMailer
	tenant *ratelimit.Limiter
	user   *ratelimit.Limiter
	// sent is closed-over by tests to wait for asynchronous mail.
	sent func()
}

// NewCIBAService returns a service delivering through mail; now is the
// limiters' clock (nil is time.Now).
func NewCIBAService(mail ApprovalMailer, now func() time.Time) *CIBAService {
	if now == nil {
		now = time.Now
	}
	return &CIBAService{Mail: mail,
		tenant: ratelimit.NewLimiter(ratelimit.Rate{PerSecond: cibaTenantPerMinute / 60.0, Burst: cibaTenantPerMinute}, cibaLimitKeys).WithClock(now),
		user:   ratelimit.NewLimiter(ratelimit.Rate{PerSecond: cibaUserPerMinute / 60.0, Burst: cibaUserPerMinute}, cibaLimitKeys).WithClock(now),
	}
}

type bcAuthorizeResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BcAuthorize is POST /bc-authorize (OpenID CIBA, poll mode; D-0100).
func (h *Handlers) BcAuthorize(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	out, c, oerr := h.bcAuthorize(w, r, res)
	if oerr != nil {
		h.event(requestEventContext(r), res, c, "ciba_start_failed", nil, "")
		writeError(w, oerr)
		return
	}
	h.event(requestEventContext(r), res, c, "ciba_start_succeeded", nil, "")
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handlers) bcAuthorize(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*bcAuthorizeResponse, *store.Client, *Error) {
	if h.CIBA == nil {
		return nil, nil, serverError()
	}
	ctx := r.Context()
	t := res.Tenant
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		return nil, nil, oerr
	}
	ctx = logscrub.WithCredentials(ctx, form.Get("request"))
	c, oerr := h.authenticateClient(ctx, r, form, t.ID)
	if oerr != nil {
		return nil, nil, oerr
	}
	if !slices.Contains(c.GrantTypes, clientrules.GrantCIBA) || !c.IsFirstParty || c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, c, unauthorizedClient("the client is not allowed to use the CIBA grant")
	}
	if !slices.Contains(c.AsyncApprovalNotificationChannels, clientrules.ChannelEmail) {
		return nil, c, invalidRequest("the client has no available notification channel: guardian-push is not available") // LR41c-2
	}
	if raw := form.Get("request"); raw != "" {
		inner, err := authz.VerifySignedRequestObject(ctx, h.Store, t, res.Issuer(), h.now(), c, raw)
		if err != nil {
			h.log().InfoContext(ctx, "backchannel request object refused", "tenant", t.ID, "client_id", c.ClientID, "reason", err.Error())
			return nil, c, &Error{Status: http.StatusBadRequest, Code: "invalid_request_object", Description: "the request object is invalid"}
		}
		// Parameters inside the object take precedence.
		for k, v := range inner {
			form[k] = v
		}
		form.Del("request")
	}
	req, cerr := ciba.Parse(form, res.Issuer())
	if cerr != nil {
		return nil, c, &Error{Status: http.StatusBadRequest, Code: cerr.Code, Description: cerr.Description}
	}
	if req.Audience == "" {
		req.Audience = t.DefaultAudience
	}
	if req.Audience != "" {
		if id, ok := tenant.APIIdentifier(res, req.Audience); ok {
			req.Audience = id
		}
		if _, err := h.Store.ResourceServers().GetByIdentifier(ctx, t.ID, req.Audience); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, c, invalidRequest("unknown audience")
			}
			return nil, c, serverError()
		}
	}
	if !h.CIBA.tenant.Allow(t.ID).Allowed || !h.CIBA.user.Allow(t.ID+"\x00"+req.UserID).Allowed {
		return nil, c, tooManyRequests()
	}
	repo, err := store.CIBA(ctx, h.Store)
	if err != nil {
		h.log().ErrorContext(ctx, "CIBA store unavailable", "tenant", t.ID, "err", err)
		return nil, c, serverError()
	}
	now := h.now()
	if n, err := repo.CountPendingCIBARequests(ctx, t.ID, now); err != nil {
		return nil, c, serverError()
	} else if n >= cibaMaxPending {
		return nil, c, tooManyRequests()
	}
	// LR41c-7: an unknown user, or one without a verified email, gets the
	// same answer; the request is recorded without a user and never sent.
	userID := ""
	u, err := h.Store.Users().Get(ctx, t.ID, req.UserID)
	switch {
	case err == nil && u.Email != "" && u.EmailVerified && !u.Blocked:
		userID = u.UserID
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return nil, c, serverError()
	}
	id, ticket := secrets.RandomString(43), secrets.RandomString(43)
	ctx = logscrub.WithCredentials(ctx, id, ticket)
	rec := &store.CIBARequest{Origin: res.Origin(), TenantID: t.ID, IDHash: secrets.HashToken(id), TicketHash: secrets.HashToken(ticket),
		ClientID: c.ClientID, UserID: userID, Scopes: req.Scopes, Audience: req.Audience, BindingMessage: req.BindingMessage,
		Status: store.CIBAPending, Interval: ciba.Interval, ExpiresAt: now.Add(req.Lifetime()), CreatedAt: now}
	if err := repo.CreateCIBARequest(ctx, rec); err != nil {
		h.log().ErrorContext(ctx, "store CIBA request", "tenant", t.ID, "client_id", c.ClientID, "err", err)
		return nil, c, serverError()
	}
	if userID != "" {
		// Delivered off the request path, so a deliverable user takes no
		// longer to answer than an unknown one (Review Focus 1).
		h.sendApproval(context.WithoutCancel(ctx), res, c, u, rec, ticket, r.Header.Get("Accept-Language"))
	}
	return &bcAuthorizeResponse{AuthReqID: id, ExpiresIn: req.Expiry, Interval: ciba.Interval}, c, nil
}

func (h *Handlers) sendApproval(ctx context.Context, res tenant.Resolved, c *store.Client, u *store.User, rec *store.CIBARequest, ticket, language string) {
	svc, log := h.CIBA, h.log()
	link := res.Origin() + "/bc-verify?consent=" + ticket
	go func() {
		ctx, cancel := context.WithTimeout(ctx, cibaMailTimeout)
		defer cancel()
		if svc.sent != nil {
			defer svc.sent()
		}
		if svc.Mail == nil {
			log.WarnContext(ctx, "CIBA approval email not sent: no mailer", "tenant", res.Tenant.ID, "client_id", c.ClientID)
			return
		}
		lang := ""
		if len(language) >= 2 {
			lang = language[:2]
		}
		if err := svc.Mail.SendAsyncApproval(ctx, email.AsyncApprovalEmail{TenantID: res.Tenant.ID, ClientID: c.ClientID, Language: lang,
			User: u, URL: link, BindingMessage: rec.BindingMessage}); err != nil {
			log.LogAttrs(ctx, slog.LevelWarn, "CIBA approval email failed", slog.String("tenant", res.Tenant.ID), slog.String("client_id", c.ClientID), slog.String("err", err.Error()))
		}
	}()
}
