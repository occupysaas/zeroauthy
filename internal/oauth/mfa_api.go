package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (h *Handlers) isMFAAudience(ctx context.Context, tid, aud string) bool {
	return mfa.APIAudience(ctx, h.Store, tid, aud)
}
func mfaResourceServer(tid, aud string) *store.ResourceServer { return mfa.APIResourceServer(tid, aud) }
func (h *Handlers) mfaRoute(w http.ResponseWriter, r *http.Request) (tenant.Resolved, bool) {
	noStore(w)
	if h.MFA == nil {
		writeError(w, mfaUnavailableError())
		return tenant.Resolved{}, false
	}
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return res, false
	}
	if _, err := h.Store.MFA().GetGuardian(r.Context(), res.Tenant.ID); err != nil {
		writeError(w, mfaError(err))
		return res, false
	}
	registerOAuthAuthorization(r)
	*r = *r.WithContext(logs.WithEvent(logs.WithRecorder(r.Context(), h.Recorder), logs.FromRequest(r)))
	return res, true
}

type mfaCaller struct {
	uid     string
	token   *store.MFAToken
	request *mfaRequest
}

func (h *Handlers) mfaBearer(r *http.Request, res tenant.Resolved, scope string) (mfaCaller, *Error) {
	scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	raw = strings.TrimSpace(raw)
	bad := &Error{Status: 401, Code: "invalid_token", Description: "Invalid bearer token"}
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return mfaCaller{}, bad
	}
	logs.AddCredentials(r.Context(), raw)
	*r = *r.WithContext(logscrub.WithCredentials(r.Context(), raw))
	ctx := r.Context()
	// An opaque MFA token has read/enroll authority only. It never authorizes
	// deletion, nor does it become a normal user access token.
	_, err := h.Store.MFA().PeekMFAToken(ctx, res.Tenant.ID, secrets.HashToken(raw), h.now())
	if err == nil {
		t, p, e := h.pendingMFAToken(ctx, res, raw, "")
		if e != nil {
			return mfaCaller{}, bad
		}
		if scope == "remove:authenticators" {
			return mfaCaller{}, &Error{Status: 403, Code: "insufficient_scope", Description: "An MFA API access token is required"}
		}
		return mfaCaller{uid: t.UserID, token: t, request: p}, nil
	}
	if errors.Is(err, store.ErrMFAUnavailable) {
		return mfaCaller{}, mfaUnavailableError()
	}
	if h.Minter == nil || h.Minter.Keys == nil {
		return mfaCaller{}, bad
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(parsed.Headers) != 1 {
		return mfaCaller{}, bad
	}
	tokenType, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if tokenType != "JWT" && tokenType != "at+jwt" {
		return mfaCaller{}, bad
	}
	var std jwt.Claims
	var extra struct {
		Scope    string `json:"scope"`
		AZP      string `json:"azp"`
		Grant    string `json:"gty"`
		ClientID string `json:"client_id"`
	}
	if h.Minter.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra) != nil || std.Expiry == nil || std.Subject == "" || (extra.AZP == "" && extra.ClientID == "") || extra.Grant == "client-credentials" || strings.HasSuffix(std.Subject, "@clients") || std.ValidateWithLeeway(jwt.Expected{Issuer: res.Issuer(), Time: h.now()}, 0) != nil {
		return mfaCaller{}, bad
	}
	if tokenType == "at+jwt" && (extra.ClientID == "" || std.IssuedAt == nil || std.ID == "") {
		return mfaCaller{}, bad
	}
	audience := false
	for _, a := range std.Audience {
		audience = audience || h.isMFAAudience(ctx, res.Tenant.ID, a)
	}
	if !audience {
		return mfaCaller{}, bad
	}
	if _, e := h.activeUser(ctx, res.Tenant.ID, std.Subject); e != nil {
		return mfaCaller{}, bad
	}
	if !slices.Contains(strings.Fields(extra.Scope), scope) {
		return mfaCaller{}, &Error{Status: 403, Code: "insufficient_scope", Description: "Insufficient scope"}
	}
	return mfaCaller{uid: std.Subject}, nil
}
func decodeMFAJSON(w http.ResponseWriter, r *http.Request, out any) *Error {
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return invalidRequest("Content-Type must be application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTokenRequestBytes))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return invalidRequest("malformed JSON body")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return invalidRequest("malformed JSON body")
		}
		name, ok := key.(string)
		if !ok {
			return invalidRequest("malformed JSON body")
		}
		if _, exists := fields[name]; exists {
			return repeatedParam(name)
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return invalidRequest("malformed JSON body")
		}
		fields[name] = v
		if logscrub.SensitiveKey(name) {
			var s string
			if json.Unmarshal(v, &s) == nil {
				*r = *r.WithContext(logscrub.WithCredentials(r.Context(), s))
			}
		}
	}
	if _, err = dec.Token(); err != nil {
		return invalidRequest("malformed JSON body")
	}
	if _, err = dec.Token(); err != io.EOF {
		return invalidRequest("unexpected data after JSON body")
	}
	b, _ := json.Marshal(fields)
	if json.Unmarshal(b, out) != nil {
		return invalidRequest("invalid MFA parameters")
	}
	return nil
}
func (h *Handlers) MFAAssociate(w http.ResponseWriter, r *http.Request) {
	res, ok := h.mfaRoute(w, r)
	if !ok {
		return
	}
	caller, e := h.mfaBearer(r, res, "enroll")
	if e != nil {
		writeError(w, e)
		return
	}
	var in authapi.MFAAssociateRequest
	if e = decodeMFAJSON(w, r, &in); e != nil {
		writeError(w, e)
		return
	}
	if len(in.AuthenticatorTypes) != 1 {
		writeError(w, invalidRequest("one authenticator type is required"))
		return
	}
	factor := string(in.AuthenticatorTypes[0])
	switch factor {
	case "otp":
		if in.OobChannels != nil {
			writeError(w, invalidRequest("oob_channels requires oob"))
			return
		}
	case "oob":
		if in.OobChannels == nil || len(*in.OobChannels) != 1 {
			writeError(w, invalidRequest("one oob channel is required"))
			return
		}
		if (*in.OobChannels)[0] != "email" {
			writeError(w, invalidRequest("Unsupported challenge type"))
			return
		}
		factor = "email"
		u, x := h.activeUser(r.Context(), res.Tenant.ID, caller.uid)
		if x != nil {
			writeError(w, x)
			return
		}
		if in.Email == nil || !u.EmailVerified || *in.Email != u.Email {
			writeError(w, invalidRequest("email must match the user's verified email"))
			return
		}
	default:
		writeError(w, invalidRequest("unsupported authenticator type"))
		return
	}
	if caller.request != nil && !caller.request.Requirement.Enroll {
		writeError(w, accessDenied("an enrolled authenticator must satisfy this challenge"))
		return
	}
	if caller.request != nil && !slices.Contains(caller.request.Requirement.Factors, factor) {
		writeError(w, accessDenied("authenticator type is not permitted"))
		return
	}
	svc := h.MFA
	actionEnroll := caller.request != nil && caller.request.Effects != nil && caller.request.Effects.MFA != nil && caller.request.Effects.MFA.Mode == "enroll"
	if actionEnroll {
		svc = svc.WithNewFactorEnrollment()
	}
	// §7 displays the first recovery code at OTP association, before the OTP
	// is confirmed. It is persisted only by the confirmation (see
	// Service.WithPendingRecovery), so an abandoned association leaves none.
	recovery := ""
	if factor == "otp" {
		list, err := h.Store.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, caller.uid)
		if err != nil {
			writeError(w, mfaError(err))
			return
		}
		// Show it only to the first association: not when a recovery method
		// exists, nor while another recent association already displayed one
		// (whichever confirms first persists its code; a later confirmation
		// without a displayed code receives a fresh one in the grant).
		outstanding := func(a store.Authenticator) bool {
			return a.Type == "recovery-code" || a.Type == "totp" && !a.Confirmed && a.CodeHash != "" && h.now().Before(a.CreatedAt.Add(mfaTokenLifetime))
		}
		if !slices.ContainsFunc(list, outstanding) {
			recovery = mfa.NewRecoveryCode()
			logs.AddCredentials(r.Context(), recovery)
			svc = svc.WithPendingRecovery(secrets.HashToken(recovery))
		}
	}
	enrollment, err := svc.BeginEnroll(r.Context(), res.Tenant.ID, caller.uid, factor, "")
	if err != nil {
		if actionEnroll && errors.Is(err, mfa.ErrNoFactor) {
			writeError(w, accessDenied("authenticator type is already enrolled"))
		} else {
			writeError(w, mfaError(err))
		}
		return
	}
	body := map[string]any{}
	if factor == "otp" {
		body["authenticator_type"] = "otp"
		body["secret"] = enrollment.Secret
		body["barcode_uri"] = enrollment.URI
		if recovery != "" {
			body["recovery_codes"] = []string{recovery}
		}
	} else {
		body["authenticator_type"] = "oob"
		body["oob_channel"] = "email"
		body["binding_method"] = "prompt"
		body["oob_code"] = enrollment.ChallengeID
	}
	httpx.WriteJSON(w, 200, body)
}
func (h *Handlers) MFAChallenge(w http.ResponseWriter, r *http.Request) {
	res, ok := h.mfaRoute(w, r)
	if !ok {
		return
	}
	form, e := parseTokenRequest(w, r)
	if e != nil {
		writeError(w, e)
		return
	}
	c, e := h.authenticateClient(r.Context(), r, form, res.Tenant.ID)
	if e != nil {
		writeError(w, e)
		return
	}
	t, p, e := h.pendingMFAToken(r.Context(), res, form.Get("mfa_token"), c.ClientID)
	if e != nil {
		writeError(w, e)
		return
	}
	typ := form.Get("challenge_type")
	if typ != "otp" && typ != "oob" && typ != "otp oob" {
		writeError(w, invalidRequest("unsupported challenge_type"))
		return
	}
	list, err := h.Store.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, t.UserID)
	if err != nil {
		writeError(w, mfaError(err))
		return
	}
	var chosen *store.Authenticator
	for _, a := range list {
		if a.Confirmed == p.Requirement.Enroll {
			continue
		}
		factor := a.Type
		if factor == "totp" {
			factor = "otp"
		}
		if !slices.Contains(p.Requirement.Factors, factor) || (factor != "otp" && factor != "email") {
			continue
		}
		if typ == "otp" && factor != "otp" || typ == "oob" && factor != "email" {
			continue
		}
		if id := form.Get("authenticator_id"); id != "" && id != a.ID {
			continue
		}
		v := a
		chosen = &v
		break
	}
	if chosen == nil {
		writeError(w, invalidRequest("invalid authenticator_id or challenge_type"))
		return
	}
	ch, err := h.MFA.BeginChallenge(r.Context(), res.Tenant.ID, t.UserID, chosen.ID, "")
	if err != nil {
		writeError(w, mfaError(err))
		return
	}
	out := map[string]any{"challenge_type": "otp"}
	if chosen.Type == "email" {
		out["challenge_type"] = "oob"
		out["oob_code"] = ch.ID
		out["binding_method"] = "prompt"
	}
	httpx.WriteJSON(w, 200, out)
}
func (h *Handlers) MFAListAuthenticators(w http.ResponseWriter, r *http.Request) {
	res, ok := h.mfaRoute(w, r)
	if !ok {
		return
	}
	caller, e := h.mfaBearer(r, res, "read:authenticators")
	if e != nil {
		writeError(w, e)
		return
	}
	list, err := h.Store.MFA().ListAuthenticators(r.Context(), res.Tenant.ID, caller.uid)
	if err != nil {
		writeError(w, mfaError(err))
		return
	}
	out := []authapi.MFAAuthenticator{}
	for _, a := range list {
		typ := a.Type
		switch typ {
		case "totp":
			typ = "otp"
		case "email":
			typ = "oob"
		case "recovery-code":
		default:
			continue
		}
		v := authapi.MFAAuthenticator{Id: a.ID, Active: a.Confirmed, AuthenticatorType: authapi.MFAAuthenticatorAuthenticatorType(typ)}
		if a.Name != "" {
			v.Name = &a.Name
		}
		if a.Type == "email" {
			channel := "email"
			v.OobChannel = &channel
		}
		out = append(out, v)
	}
	httpx.WriteJSON(w, 200, out)
}
func (h *Handlers) MFADeleteAuthenticator(w http.ResponseWriter, r *http.Request, id string) {
	res, ok := h.mfaRoute(w, r)
	if !ok {
		return
	}
	caller, e := h.mfaBearer(r, res, "remove:authenticators")
	if e != nil {
		writeError(w, e)
		return
	}
	if err := h.MFA.Unenroll(r.Context(), res.Tenant.ID, caller.uid, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, &Error{Status: 404, Code: "not_found", Description: "Authenticator not found"})
		} else {
			writeError(w, mfaError(err))
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
