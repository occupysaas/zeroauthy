package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

type revocationSubject struct{ Format, Issuer, Subject, Email string }

func revocationObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, store.ErrInvalid
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, store.ErrInvalid
		}
		key, ok := tok.(string)
		if !ok {
			return nil, store.ErrInvalid
		}
		if _, seen := out[key]; seen {
			return nil, store.ErrInvalid
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, store.ErrInvalid
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, store.ErrInvalid
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, store.ErrInvalid
	}
	return out, nil
}
func readRevocationSubject(w http.ResponseWriter, r *http.Request) (revocationSubject, error) {
	var out revocationSubject
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return out, store.ErrInvalid
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil || !utf8.Valid(raw) {
		return out, store.ErrInvalid
	}
	object, err := revocationObject(raw)
	if err != nil || len(object) != 1 {
		return out, store.ErrInvalid
	}
	sub, err := revocationObject(object["sub_id"])
	if err != nil {
		return out, store.ErrInvalid
	}
	for name, value := range sub {
		var text string
		if json.Unmarshal(value, &text) != nil || text == "" || len(text) > 2048 {
			return out, store.ErrInvalid
		}
		switch name {
		case "format":
			out.Format = text
		case "iss":
			out.Issuer = text
		case "sub":
			out.Subject = text
		case "email":
			out.Email = text
		default:
			return out, store.ErrInvalid
		}
	}
	switch out.Format {
	case "iss_sub":
		if len(sub) != 3 || out.Issuer == "" || out.Subject == "" {
			return out, store.ErrInvalid
		}
	case "email":
		if len(sub) != 2 || out.Email == "" || len(out.Email) > 320 || !strings.Contains(out.Email, "@") {
			return out, store.ErrInvalid
		}
	default:
		return out, store.ErrInvalid
	}
	return out, nil
}

func (h *Handlers) GlobalTokenRevocation(w http.ResponseWriter, r *http.Request, name string) {
	noStore(w)
	registerOAuthAuthorization(r)
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conn, err := h.Store.Connections().GetByName(ctx, res.Tenant.ID, name)
	if errors.Is(err, store.ErrNotFound) || err == nil && conn.Strategy != federation.StrategyOIDC && conn.Strategy != federation.StrategyOkta {
		httpx.WriteError(w, 404, "not_found", "connection not found")
		return
	}
	if err != nil {
		writeError(w, serverError())
		return
	}
	subject, err := readRevocationSubject(w, r)
	if err != nil {
		httpx.WriteError(w, 400, "invalid_request", "malformed revocation request")
		return
	}
	record := func(success bool) {
		kind := "universal_logout_failed"
		if success {
			kind = "universal_logout_succeeded"
		}
		logs.RecordEvent(ctx, h.Recorder, logs.Event{TenantID: res.Tenant.ID, Type: kind, Date: h.now().UTC(), ConnectionID: conn.ID})
	}
	refuse := func() {
		record(false)
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.WriteError(w, 401, "invalid_token", "invalid revocation authentication")
	}
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) != 1 || len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") || len(auth[1]) > 16*1024 || h.Federation == nil || h.Federation.Providers == nil {
		refuse()
		return
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(conn))
	if err != nil {
		refuse()
		return
	}
	verified, err := h.Federation.Providers.VerifyGlobalRevocation(ctx, federation.CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: conn.FederationRevision}, cfg, auth[1], strings.TrimSuffix(res.Issuer(), "/")+"/oauth/global-token-revocation/connection/"+url.PathEscape(conn.Name), h.now().UTC())
	if err != nil {
		refuse()
		return
	}
	if h.Logout == nil {
		record(false)
		writeError(w, serverError())
		return
	}
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		// Get takes the shared policy boundary in transactional SQL/plugin stores.
		live, err := tx.Connections().Get(ctx, res.Tenant.ID, conn.ID)
		if err != nil {
			return err
		}
		if live.FederationRevision != conn.FederationRevision || live.Name != conn.Name || live.Strategy != conn.Strategy {
			return federation.ErrGlobalRevocationToken
		}
		repo, ok := tx.(store.GlobalRevocationStore)
		if !ok {
			return store.ErrOIDCLogoutUnavailable
		}
		if !verified.ExpiresAt.After(h.now().UTC()) {
			return federation.ErrGlobalRevocationToken
		}
		if err := repo.UseGlobalRevocationJTI(ctx, res.Tenant.ID, conn.ID, verified.JTI, verified.ExpiresAt, h.now().UTC()); err != nil {
			return err
		}
		var user *store.User
		switch subject.Format {
		case "iss_sub":
			if subject.Issuer != cfg.Issuer {
				return nil
			}
			user, err = tx.Users().FindByIdentity(ctx, res.Tenant.ID, conn.ID, subject.Subject)
		case "email":
			user, err = repo.FindByFederatedEmail(ctx, res.Tenant.ID, conn.ID, subject.Email)
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Users().BumpVersion(ctx, res.Tenant.ID, user.UserID); err != nil {
			return err
		}
		if _, err := tx.RefreshTokens().RevokeByUser(ctx, res.Tenant.ID, user.UserID, h.now().UTC()); err != nil {
			return err
		}
		return h.Logout.WithStore(tx).EndUserSessions(ctx, res.Tenant.ID, user.UserID, logout.IDPLogout)
	})
	if errors.Is(err, store.ErrConflict) || errors.Is(err, federation.ErrGlobalRevocationToken) {
		refuse()
		return
	}
	if err != nil {
		record(false)
		writeError(w, serverError())
		return
	}
	record(true)
	w.WriteHeader(http.StatusNoContent)
}
