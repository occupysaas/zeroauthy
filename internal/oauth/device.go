package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/devicecode"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const (
	GrantDeviceCode    = "urn:ietf:params:oauth:grant-type:device_code"
	DeviceCodeLifetime = 900 * time.Second
	DeviceInterval     = 5

	// deviceCreateAttempts bounds retries when a generated code collides.
	deviceCreateAttempts = 3
)

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// OauthDeviceCode implements POST /oauth/device/code (RFC 8628 §3.1).
func (h *Handlers) OauthDeviceCode(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	out, oerr := h.deviceCode(w, r, res)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handlers) deviceCode(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*deviceCodeResponse, *Error) {
	ctx := r.Context()
	t := res.Tenant
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		if oerr.Description == `parameter "client_id" is repeated` {
			return nil, unauthorizedClient("client_id must not be repeated") // D3
		}
		return nil, oerr
	}
	// Auth0 answers every client problem here with unauthorized_client (D3).
	// Device clients are public, so any credential is a mismatch.
	if _, _, hasBasic := r.BasicAuth(); hasBasic || r.Header.Get("Authorization") != "" || form.Get("client_secret") != "" {
		return nil, unauthorizedClient("device clients do not authenticate")
	}
	clientID := form.Get("client_id")
	c, err := h.Store.Clients().Get(ctx, t.ID, clientID)
	if clientID == "" || errors.Is(err, store.ErrNotFound) {
		return nil, unauthorizedClient("unknown client")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client", "tenant", t.ID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	if c.TokenEndpointAuthMethod != store.AuthMethodNone || !slices.Contains(c.GrantTypes, GrantDeviceCode) {
		return nil, unauthorizedClient("the client is not allowed to use the device authorization flow")
	}

	aud := form.Get("audience")
	if aud == "" {
		aud = t.DefaultAudience
	}
	var rs *store.ResourceServer
	if aud != "" {
		rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, t.ID, aud)
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalidRequest("unknown audience") // D3
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load resource server", "tenant", t.ID, "audience", aud, "err", err)
			return nil, serverError()
		}
	}
	scopes := strings.Fields(form.Get("scope"))
	if _, oerr := h.decide(ctx, t.ID, access.Device, c, rs, scopes); oerr != nil {
		return nil, oerr
	}

	charset, mask := devicecode.Settings(t)
	now := h.now().UTC()
	for range deviceCreateAttempts {
		deviceCode := secrets.RandomString(24)
		userCode := devicecode.Generate(charset, mask)
		err = h.Store.DeviceCodes().Create(ctx, &store.DeviceCode{
			TenantID: t.ID, DeviceCodeHash: secrets.HashToken(deviceCode),
			UserCodeHash: secrets.HashToken(devicecode.Normalize(userCode)),
			ClientID:     c.ClientID, Scopes: scopes, Audience: aud, Status: store.DeviceCodePending,
			ExpiresAt: now.Add(DeviceCodeLifetime), CreatedAt: now,
		})
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			break
		}
		uri := strings.TrimSuffix(res.Issuer(), "/") + "/activate"
		return &deviceCodeResponse{
			DeviceCode: deviceCode, UserCode: userCode, VerificationURI: uri,
			VerificationURIComplete: uri + "?user_code=" + url.QueryEscape(userCode),
			ExpiresIn:               int(DeviceCodeLifetime.Seconds()), Interval: DeviceInterval,
		}, nil
	}
	h.log().ErrorContext(ctx, "store device code", "tenant", t.ID, "client_id", c.ClientID, "err", err)
	return nil, serverError()
}
