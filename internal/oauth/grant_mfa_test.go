package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const otpGrant = "http://auth0.com/oauth/grant-type/mfa-otp"
const oobGrant = "http://auth0.com/oauth/grant-type/mfa-oob"
const recoveryGrant = "http://auth0.com/oauth/grant-type/mfa-recovery-code"

type mfaMail struct{ code string }

func (m *mfaMail) Send(_ context.Context, e email.Event) error {
	m.code, _ = e.Variables["code"].(string)
	return nil
}
func mfaFixture(t *testing.T) (*fixture, *mfaMail) {
	t.Helper()
	f := newFixture(t)
	tid := f.tenantID(t, "acme")
	ctx := context.Background()
	g, e := f.st.MFA().GetGuardian(ctx, tid)
	if e != nil {
		t.Fatal(e)
	}
	g.Factors = map[string]bool{"otp": true, "email": true, "recovery-code": true}
	g.Policies = []string{"all-applications"}
	if e = f.st.MFA().PutGuardian(ctx, g, g.Version); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"ropg", "other-ropg"} {
		c, e := f.st.Clients().Get(ctx, tid, id)
		if e != nil {
			t.Fatal(e)
		}
		c.GrantTypes = append(c.GrantTypes, otpGrant, oobGrant, recoveryGrant)
		if e = f.st.Clients().Update(ctx, c); e != nil {
			t.Fatal(e)
		}
	}
	mail := &mfaMail{}
	f.h.MFA = mfa.NewService(f.st, f.wrapper, mail, nil, f.h.Log, func() time.Time { return f.h.now() })
	return f, mail
}
func (f *fixture) mfaRequired(t *testing.T) string {
	t.Helper()
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid read:things offline_access")})
	if w.Code != 403 || b["error"] != "mfa_required" || b["error_description"] != "Multifactor authentication required" || len(b) != 3 {
		t.Fatalf("MFA required: %d %v", w.Code, b)
	}
	tok, _ := b["mfa_token"].(string)
	if len(tok) < 32 {
		t.Fatalf("token=%q", tok)
	}
	return tok
}
func (f *fixture) mfaAPI(t *testing.T, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "https://acme.example.test"+path, strings.NewReader(body))
	r.Host = "acme.example.test"
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case path == "/mfa/associate":
			f.h.MFAAssociate(w, r)
		case path == "/mfa/challenge":
			f.h.MFAChallenge(w, r)
		case method == "GET":
			f.h.MFAListAuthenticators(w, r)
		default:
			f.h.MFADeleteAuthenticator(w, r, strings.TrimPrefix(path, "/mfa/authenticators/"))
		}
	})
	tenant.NewResolver(f.st.Tenants(), "", false).Middleware(handler).ServeHTTP(w, r)
	var b map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return w, b
}
func (f *fixture) associateOTP(t *testing.T, tok string) (string, string) {
	t.Helper()
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["otp"]}`)
	if w.Code != 200 {
		t.Fatalf("associate=%d %v", w.Code, b)
	}
	codes, _ := b["recovery_codes"].([]any)
	if len(codes) != 1 || len(codes[0].(string)) != 24 {
		t.Fatalf("initial recovery codes=%v", b)
	}
	secret, _ := b["secret"].(string)
	if secret == "" || !strings.HasPrefix(b["barcode_uri"].(string), "otpauth://totp/") {
		t.Fatalf("enrollment=%v", b)
	}
	return secret, codes[0].(string)
}
func otpAt(secret string, now time.Time) string {
	k, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, k)
	h.Write(b[:])
	sum := h.Sum(nil)
	i := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[i:i+4])&0x7fffffff)%1000000)
}
func mfaForm(grant, tok, key, value string) url.Values {
	return url.Values{"grant_type": {grant}, "client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "mfa_token": {tok}, key: {value}}
}
func (f *fixture) proveOTP(t *testing.T, tok, secret string) map[string]any {
	t.Helper()
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now()))})
	if w.Code != 200 {
		t.Fatalf("OTP grant=%d %v", w.Code, b)
	}
	return b
}
func TestPasswordGrantMFARequired(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	stored, e := f.st.MFA().PeekMFAToken(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(tok), fixedNow())
	if e != nil || stored.ClientID != "ropg" || stored.UserID != f.aliceID(t) || !stored.ExpiresAt.Equal(fixedNow().Add(10*time.Minute)) {
		t.Fatalf("stored=%+v %v", stored, e)
	}
}
func TestAssociateOTPThenOTPGrant(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	s, _ := f.associateOTP(t, tok)
	b := f.proveOTP(t, tok, s)
	if b["refresh_token"] == nil {
		t.Fatal(b)
	}
	id, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), b["id_token"].(string))
	amr, _ := id["amr"].([]any)
	if len(amr) != 1 || amr[0] != "mfa" {
		t.Fatalf("amr=%v", id)
	}
}
func TestAssociateEmailOOBAndGrant(t *testing.T) {
	f, mail := mfaFixture(t)
	tok := f.mfaRequired(t)
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["email"],"email":"foreign@acme.test"}`)
	if w.Code == 200 {
		t.Fatal("foreign email accepted")
	}
	w, b = f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["email"],"email":"alice@acme.test"}`)
	if w.Code != 200 || b["binding_method"] != "prompt" || len(mail.code) != 6 {
		t.Fatalf("email associate=%d %v code length %d", w.Code, b, len(mail.code))
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", mail.code)
	w, b = f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	if w.Code != 200 {
		t.Fatalf("OOB=%d %v", w.Code, b)
	}
}
func TestRecoveryCodeGrantReturnsNewCode(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	s, code := f.associateOTP(t, tok)
	f.proveOTP(t, tok, s)
	tok = f.mfaRequired(t)
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: mfaForm(recoveryGrant, tok, "recovery_code", code)})
	next, _ := b["recovery_code"].(string)
	if w.Code != 200 || len(next) != 24 || next == code {
		t.Fatalf("recovery=%d %v", w.Code, b)
	}
}
func TestMFATokenReuse(t *testing.T) {
	for _, kind := range []string{"reuse", "other client", "expired", "bound request"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := mfaFixture(t)
			tok := f.mfaRequired(t)
			s, _ := f.associateOTP(t, tok)
			form := mfaForm(otpGrant, tok, "otp", otpAt(s, f.h.now()))
			switch kind {
			case "reuse":
				f.proveOTP(t, tok, s)
			case "other client":
				form.Set("client_id", "other-ropg")
				form.Set("client_secret", "other-secret")
			case "expired":
				f.h.Now = func() time.Time { return fixedNow().Add(10*time.Minute + time.Second) }
			case "bound request":
				form.Set("scope", "write:things")
				form.Set("audience", "https://billing.acme.test")
			}
			w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
			if kind == "bound request" {
				if w.Code != 200 || b["scope"] != "openid read:things offline_access" {
					t.Fatalf("bound=%d %v", w.Code, b)
				}
				claims, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), b["access_token"].(string))
				if !strings.Contains(fmt.Sprint(claims["aud"]), "https://api.acme.test") {
					t.Fatal(claims)
				}
			} else if w.Code != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("%s=%d %v", kind, w.Code, b)
			}
		})
	}
}
func TestMFAGrantNotInClientGrantTypes(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	c, _ := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "ropg")
	c.GrantTypes = []string{"password"}
	if e := f.st.Clients().Update(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: mfaForm(otpGrant, tok, "otp", "123456")})
	if w.Code != 403 || b["error"] != "unauthorized_client" {
		t.Fatalf("grant=%d %v", w.Code, b)
	}
}
func TestAssociateSMSUnsupported(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	for _, channel := range []string{"sms", "voice", "auth0"} {
		w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["`+channel+`"]}`)
		if w.Code != 400 || b["error"] != "invalid_request" {
			t.Fatalf("channel=%s %d %v", channel, w.Code, b)
		}
	}
}
func TestMFAAuthenticatorsWithMFATokenAndAPIToken(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	s, _ := f.associateOTP(t, tok)
	w, _ := f.mfaAPI(t, "GET", "/mfa/authenticators", tok, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	list, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	id := ""
	for _, a := range list {
		if a.Type == "totp" {
			id = a.ID
		}
	}
	w, b := f.mfaAPI(t, "DELETE", "/mfa/authenticators/"+id, tok, "")
	if w.Code != 403 {
		t.Fatalf("token deletion=%d %v", w.Code, b)
	}
	f.proveOTP(t, tok, s)
	raw, e := f.h.Minter.AccessToken(context.Background(), AccessTokenParams{TenantID: f.tenantID(t, "acme"), Issuer: "https://acme.example.test/", Subject: f.aliceID(t), Audience: []string{"https://acme.example.test/mfa/"}, ClientID: "ropg", Scopes: []string{"read:authenticators", "remove:authenticators"}})
	if e != nil {
		t.Fatal(e)
	}
	w, _ = f.mfaAPI(t, "GET", "/mfa/authenticators", raw, "")
	if w.Code != 200 {
		t.Fatalf("API list=%d %s", w.Code, w.Body.String())
	}
	w, b = f.mfaAPI(t, "DELETE", "/mfa/authenticators/"+id, raw, "")
	if w.Code != 204 {
		t.Fatalf("API delete=%d %v", w.Code, b)
	}
}
func TestMFAAudienceClientCredentialsDenied(t *testing.T) {
	f, _ := mfaFixture(t)
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://acme.example.test/mfa/")})
	if w.Code != 403 || b["error"] != "access_denied" {
		t.Fatalf("M2M=%d %v", w.Code, b)
	}
}
func TestRefreshNeverMFA(t *testing.T) {
	f, _ := mfaFixture(t)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"openid"}, acmeAPI)
	w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw)})
	if w.Code != 200 {
		t.Fatalf("refresh=%d %v", w.Code, b)
	}
}
func TestMFAGrantFailureLogCodes(t *testing.T) {
	for grant, code := range map[string]string{otpGrant: "feotpft", oobGrant: "feoobft", recoveryGrant: "fercft"} {
		t.Run(code, func(t *testing.T) {
			f, _ := mfaFixture(t)
			tok := f.mfaRequired(t)
			f.associateOTP(t, tok)
			rec := &eventRecorder{}
			f.h.Recorder = rec
			f.call(t, false, tokenCall{host: "acme.example.test", form: mfaForm(grant, tok, "otp", "000000")})
			for _, e := range rec.events {
				if e.Type == code {
					return
				}
			}
			t.Fatalf("missing %s: %v", code, rec.events)
		})
	}
}
func TestMFAGrantThrottle(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	s, _ := f.associateOTP(t, tok)
	wrong := "000000"
	for i := 0; ; i++ {
		wrong = fmt.Sprintf("%06d", i)
		if _, valid := mfa.VerifyTOTP(s, wrong, f.h.now()); !valid {
			break
		}
	}
	list, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	id := ""
	for _, a := range list {
		if a.Type == "totp" {
			id = a.ID
		}
	}
	ch, err := f.h.MFA.BeginChallenge(context.Background(), f.tenantID(t, "acme"), f.aliceID(t), id, "")
	if err != nil {
		t.Fatal(err)
	}
	// Hosted/service proof failures and token grants share the durable counter.
	for i := 0; i < 5; i++ {
		_, err = f.h.MFA.ConfirmEnroll(context.Background(), f.tenantID(t, "acme"), f.aliceID(t), &mfa.Enrollment{AuthenticatorID: id, ChallengeID: ch.ID}, mfa.Proof{Code: wrong})
		if !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	for i := 5; i < 11; i++ {
		w, b := f.call(t, false, tokenCall{host: "acme.example.test", form: mfaForm(otpGrant, tok, "otp", wrong)})
		want := "invalid_grant"
		if i == 10 {
			want = "too_many_attempts"
		}
		if b["error"] != want {
			t.Fatalf("attempt %d=%d %v", i, w.Code, b)
		}
	}
}

func TestMFAAudienceUserGrants(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		f := newFixture(t)
		w, b := f.call(t, true, tokenCall{host: acmeHost, form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://acme.example.test/mfa/", "scope", "enroll read:authenticators remove:authenticators unknown")})
		if w.Code != 200 || b["scope"] != "enroll read:authenticators remove:authenticators" {
			t.Fatalf("password audience=%d %v", w.Code, b)
		}
		if _, err := f.st.ResourceServers().GetByIdentifier(context.Background(), f.tenantID(t, "acme"), "https://acme.example.test/mfa/"); err == nil {
			t.Fatal("built-in audience persisted")
		}
	})
	t.Run("authorization code", func(t *testing.T) {
		f := newActionsFixture(t)
		q := url.Values{"client_id": {"code-spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid enroll read:authenticators"}, "audience": {"https://acme.example.test/mfa/"}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"}}
		r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
		r.AddCookie(f.sessionCookie(t))
		w := httptest.NewRecorder()
		tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.az.Authorize)).ServeHTTP(w, r)
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("code") == "" {
			t.Fatalf("authorize=%d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
		}
		w, b := f.call(t, true, tokenCall{host: acmeHost, form: codeForm(loc.Query().Get("code"), "code-spa", "https://app.acme.test/cb", pkceVerifier)})
		if w.Code != 200 || b["scope"] != "openid enroll read:authenticators" {
			t.Fatalf("code audience=%d %v", w.Code, b)
		}
	})
	t.Run("device authorization", func(t *testing.T) {
		f := newFixture(t)
		w, b := f.deviceCode(t, acmeHost, formType, "client_id=dev&audience=https%3A%2F%2Facme.example.test%2Fmfa%2F&scope=enroll")
		if w.Code != 200 {
			t.Fatalf("device audience=%d %v", w.Code, b)
		}
	})
}

func TestMFAConcurrentTokenConsumption(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	secret, recovery := f.associateOTP(t, tok)
	f.proveOTP(t, tok, secret)
	f.h.Now = func() time.Time { return fixedNow().Add(30 * time.Second) }
	tok = f.mfaRequired(t)
	forms := []url.Values{mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now())), mfaForm(recoveryGrant, tok, "recovery_code", recovery)}
	results := make(chan int, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, form := range forms {
		wg.Add(1)
		go func(form url.Values) {
			defer wg.Done()
			<-start
			w, _ := f.call(t, false, tokenCall{host: acmeHost, form: form})
			results <- w.Code
		}(form)
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 200 {
			success++
		} else if status != 400 {
			t.Fatalf("concurrent status=%d", status)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent successes=%d", success)
	}
	tokens, err := f.st.RefreshTokens().ListByUser(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	if err != nil || len(tokens) != 2 {
		t.Fatalf("refresh writes=%d %v", len(tokens), err)
	}
}

type failMFACommitStore struct{ store.Store }

func (s failMFACommitStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(failMFACommitStore{tx}) })
}
func (s failMFACommitStore) MFA() store.MFA { return failMFACommitRepo{s.Store.MFA()} }

type failMFACommitRepo struct{ store.MFA }

func (s failMFACommitRepo) ConsumeMFAToken(ctx context.Context, tid, hash, client string, now time.Time) (*store.MFAToken, error) {
	t, err := s.MFA.ConsumeMFAToken(ctx, tid, hash, client, now)
	if err != nil {
		return t, err
	}
	return nil, errors.New("injected commit failure")
}
func TestMFAProofTransactionRollback(t *testing.T) {
	f, mail := mfaFixture(t)
	tok := f.mfaRequired(t)
	secret, _ := f.associateOTP(t, tok)
	failed := failMFACommitStore{f.st}
	f.h.Store = failed
	f.h.MFA = mfa.NewService(failed, f.wrapper, mail, nil, f.h.Log, f.h.Now)
	w, b := f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now()))})
	if w.Code != 500 {
		t.Fatalf("injected failure=%d %v", w.Code, b)
	}
	list, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	for _, a := range list {
		if a.Type == "totp" && (a.Confirmed || a.LastStep != -1) {
			t.Fatalf("proof escaped rollback: %+v", a)
		}
	}
	tokens, _ := f.st.RefreshTokens().ListByUser(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	if len(tokens) != 0 {
		t.Fatalf("refresh escaped rollback=%d", len(tokens))
	}
	f.h.Store = f.st
	f.h.MFA = mfa.NewService(f.st, f.wrapper, mail, nil, f.h.Log, f.h.Now)
	f.proveOTP(t, tok, secret)
}
func TestMFAChallengeValidation(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	f.associateOTP(t, tok)
	list, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	id := ""
	for _, a := range list {
		if a.Type == "totp" {
			id = a.ID
		}
	}
	for _, tc := range []struct {
		name, typ, id, client, secret string
		status                        int
	}{{"OTP", "otp", id, "ropg", "ropg-secret", 200}, {"combined", "otp oob", id, "ropg", "ropg-secret", 200}, {"mismatched type", "oob", id, "ropg", "ropg-secret", 400}, {"unknown type", "sms", id, "ropg", "ropg-secret", 400}, {"foreign id", "otp", "totp|dev_missing", "ropg", "ropg-secret", 400}, {"other client", "otp", id, "other-ropg", "other-secret", 400}, {"bad credentials", "otp", id, "ropg", "bad", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"mfa_token": tok, "client_id": tc.client, "client_secret": tc.secret, "challenge_type": tc.typ, "authenticator_id": tc.id})
			w, b := f.mfaAPI(t, "POST", "/mfa/challenge", "", string(body))
			if w.Code != tc.status {
				t.Fatalf("challenge=%d %v", w.Code, b)
			}
		})
	}
}
func TestMFAAPITokenPermissions(t *testing.T) {
	f, _ := mfaFixture(t)
	for _, tc := range []struct {
		name, scope, aud, subject, gty string
		status                         int
	}{{"read only", "read:authenticators", "https://acme.example.test/mfa/", "", "", 200}, {"missing scope", "enroll", "https://acme.example.test/mfa/", "", "", 403}, {"wrong audience", "read:authenticators", acmeAPI, "", "", 401}, {"machine subject", "read:authenticators", "https://acme.example.test/mfa/", "m2m@clients", "client-credentials", 401}, {"unknown user", "read:authenticators", "https://acme.example.test/mfa/", "auth0|missing", "", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			sub := tc.subject
			if sub == "" {
				sub = f.aliceID(t)
			}
			raw, err := f.h.Minter.AccessToken(context.Background(), AccessTokenParams{TenantID: f.tenantID(t, "acme"), Issuer: "https://acme.example.test/", Subject: sub, Audience: []string{tc.aud}, ClientID: "ropg", GrantType: tc.gty, Scopes: strings.Fields(tc.scope)})
			if err != nil {
				t.Fatal(err)
			}
			w, _ := f.mfaAPI(t, "GET", "/mfa/authenticators", raw, "")
			if w.Code != tc.status {
				t.Fatalf("permission=%d %s", w.Code, w.Body.String())
			}
			if tc.name == "read only" {
				w, _ = f.mfaAPI(t, "POST", "/mfa/associate", raw, `{"authenticator_types":["otp"]}`)
				if w.Code != 403 {
					t.Fatalf("read token enroll=%d", w.Code)
				}
				w, _ = f.mfaAPI(t, "DELETE", "/mfa/authenticators/missing", raw, "")
				if w.Code != 403 {
					t.Fatalf("read token delete=%d", w.Code)
				}
			}
		})
	}
}
func TestMFAEmailFirstRecoveryDisplay(t *testing.T) {
	f, mail := mfaFixture(t)
	tok := f.mfaRequired(t)
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["email"],"email":"alice@acme.test"}`)
	if w.Code != 200 {
		t.Fatal(b)
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", mail.code)
	w, b = f.call(t, true, tokenCall{host: acmeHost, form: form})
	code, _ := b["recovery_code"].(string)
	if w.Code != 200 || len(code) != 24 {
		t.Fatalf("email first recovery display=%d %v", w.Code, b)
	}
	tok = f.mfaRequired(t)
	w, b = f.call(t, true, tokenCall{host: acmeHost, form: mfaForm(recoveryGrant, tok, "recovery_code", code)})
	if w.Code != 200 || b["recovery_code"] == code {
		t.Fatalf("usable email recovery=%d %v", w.Code, b)
	}
	f.h.Now = func() time.Time { return fixedNow().Add(30 * time.Second) }
	tok = f.mfaRequired(t)
	methods, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tenantID(t, "acme"), f.aliceID(t))
	id := ""
	for _, method := range methods {
		if method.Type == "email" {
			id = method.ID
		}
	}
	body, _ := json.Marshal(map[string]string{"client_id": "ropg", "client_secret": "ropg-secret", "mfa_token": tok, "challenge_type": "oob", "authenticator_id": id})
	w, b = f.mfaAPI(t, "POST", "/mfa/challenge", "", string(body))
	if w.Code != 200 {
		t.Fatalf("subsequent email challenge=%d %v", w.Code, b)
	}
	form = mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", mail.code)
	w, b = f.call(t, true, tokenCall{host: acmeHost, form: form})
	if w.Code != 200 || b["recovery_code"] != nil {
		t.Fatalf("recovery redisplay=%d %v", w.Code, b)
	}
}

func TestMFAAPIBearerTokenType(t *testing.T) {
	for _, tc := range []struct {
		name, typ, dialect string
		status             int
	}{{"RFC access token", "at+jwt", "rfc9068_profile", 200}, {"unrelated JWT type", "unrelated+jwt", "", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := mfaFixture(t)
			tid := f.tenantID(t, "acme")
			raw, err := f.h.Minter.AccessToken(context.Background(), AccessTokenParams{TenantID: tid, Issuer: "https://acme.example.test/", Subject: f.aliceID(t), Audience: []string{"https://acme.example.test/mfa/"}, ClientID: "ropg", TokenDialect: tc.dialect, Scopes: []string{"read:authenticators"}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.typ != "at+jwt" {
				claims, _ := verifyToken(t, f.keys, tid, raw)
				private, x := rsa.GenerateKey(rand.Reader, 2048)
				if x != nil {
					t.Fatal(x)
				}
				pub := jose.JSONWebKey{Key: &private.PublicKey, KeyID: "fixture-other-type", Algorithm: "RS256", Use: "sig"}
				public, x := pub.MarshalJSON()
				if x != nil {
					t.Fatal(x)
				}
				if x = f.st.SigningKeys().Create(context.Background(), &store.SigningKey{TenantID: tid, KID: pub.KeyID, Status: store.KeyCurrent, Alg: "RS256", PublicJWK: public, CreatedAt: fixedNow()}); x != nil {
					t.Fatal(x)
				}
				f.h.Minter.Keys = keys.NewManager(f.st.SigningKeys(), f.wrapper)
				signer, x := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithType(jose.ContentType(tc.typ)).WithHeader("kid", pub.KeyID))
				if x != nil {
					t.Fatal(x)
				}
				raw, err = jwt.Signed(signer).Claims(claims).Serialize()
				if err != nil {
					t.Fatal(err)
				}
			}
			w, _ := f.mfaAPI(t, "GET", "/mfa/authenticators", raw, "")
			if w.Code != tc.status {
				t.Fatalf("token type=%d %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestMFAAPIBearerNoSecretLogs(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	recorder := logs.NewRecorder(f.st, logs.Config{Now: fixedNow}, f.h.Log)
	f.h.Recorder = recorder
	r := httptest.NewRequest("POST", "https://acme.example.test/mfa/associate", strings.NewReader(`{"authenticator_types":["otp"]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	r = r.WithContext(logs.WithEvent(r.Context(), logs.Event{UserAgent: tok}))
	w := httptest.NewRecorder()
	tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.MFAAssociate)).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("associate=%d %s", w.Code, w.Body.String())
	}
	if err := recorder.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.st.Logs().SearchLogs(context.Background(), f.tenantID(t, "acme"), nil, store.LogPage{PerPage: 100})
	if err != nil || len(rows) == 0 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	seen := false
	for _, row := range rows {
		if strings.Contains(string(row.Body), tok) {
			t.Fatal("incoming bearer MFA token leaked into recorder")
		}
		var doc map[string]any
		_ = json.Unmarshal(row.Body, &doc)
		if doc["user_agent"] == logscrub.Marker {
			seen = true
		}
	}
	if !seen {
		t.Fatal("masked request attribution missing")
	}
}
func TestMFASealedActionEffects(t *testing.T) {
	f, _ := mfaFixture(t)
	env := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = env.Engine
	tid := f.tenantID(t, "acme")
	env.PostLogin(t, tid, "mfa-sealed-claims", `exports.onExecutePostLogin=async(event,api)=>{api.accessToken.setCustomClaim('https://example.test/private','sensitive-action-material');api.idToken.setCustomClaim('https://example.test/id','carried');api.accessToken.addScope('write:things');};`)
	tok := f.mfaRequired(t)
	saved, err := f.st.MFA().PeekMFAToken(context.Background(), tid, secrets.HashToken(tok), f.h.now())
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{tok, "sensitive-action-material", "alice password 1", "https://example.test/private"} {
		if strings.Contains(string(saved.Request), plain) {
			t.Fatalf("plaintext continuation material stored: %q", plain)
		}
	}
	// A continuation must neither rerun Actions nor use a replacement binding.
	env.PostLogin(t, tid, "mfa-sealed-replacement", `exports.onExecutePostLogin=async()=>{throw Error('must not rerun');};`)
	secret, _ := f.associateOTP(t, tok)
	b := f.proveOTP(t, tok, secret)
	claims, _ := verifyToken(t, f.keys, tid, b["access_token"].(string))
	if claims["https://example.test/private"] != "sensitive-action-material" || !strings.Contains(b["scope"].(string), "write:things") {
		t.Fatalf("effects lost=%v", claims)
	}
	id, _ := verifyToken(t, f.keys, tid, b["id_token"].(string))
	if id["https://example.test/id"] != "carried" {
		t.Fatal(id)
	}
	raw := b["refresh_token"].(string)
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), tid, secrets.HashToken(raw))
	if err != nil || strings.Contains(strings.Join(rt.Scopes, " "), "write:things") {
		t.Fatalf("refresh ceiling=%+v %v", rt, err)
	}
}

func TestMFAAudienceHostBoundaries(t *testing.T) {
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	for _, name := range []string{"pending", "verified"} {
		d := &store.CustomDomain{TenantID: tid, ID: name, Domain: name + ".example.test", Generation: 1}
		if err := f.st.CustomDomains().Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		if err := f.st.CustomDomains().PutHost(ctx, &store.HostBinding{TenantID: tid, Host: d.Domain, DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: name == "verified"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		aud string
		ok  bool
	}{{"https://acme.example.test/mfa/", true}, {"https://verified.example.test/mfa/", true}, {"https://pending.example.test/mfa/", false}, {"https://globex.example.test/mfa/", false}, {"http://acme.example.test/mfa/", false}, {"https://acme.example.test/mfa/?x=1", false}, {"https://acme.example.test/mfa/#fragment", false}, {"https://user@acme.example.test/mfa/", false}, {"https://acme.example.test/%6dfa/", false}} {
		if got := f.h.isMFAAudience(ctx, tid, tc.aud); got != tc.ok {
			t.Fatalf("audience %s=%v", tc.aud, got)
		}
	}
}
func TestPasswordRealmMFARequired(t *testing.T) {
	f, _ := mfaFixture(t)
	form := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "realm", "Username-Password-Authentication", "scope", "openid")
	form.Set("grant_type", GrantPasswordRealm)
	w, b := f.call(t, true, tokenCall{host: acmeHost, form: form})
	if w.Code != 403 || b["error"] != "mfa_required" || len(b) != 3 {
		t.Fatalf("realm MFA=%d %v", w.Code, b)
	}
	secret, _ := f.associateOTP(t, b["mfa_token"].(string))
	f.proveOTP(t, b["mfa_token"].(string), secret)
}
func TestMFARequiredFailClosed(t *testing.T) {
	f, _ := mfaFixture(t)
	tid := f.tenantID(t, "acme")
	g, _ := f.st.MFA().GetGuardian(context.Background(), tid)
	g.Factors = map[string]bool{}
	if err := f.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
		t.Fatal(err)
	}
	w, b := f.call(t, true, tokenCall{host: acmeHost, form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1")})
	if w.Code != 403 || b["error"] != "access_denied" || b["access_token"] != nil {
		t.Fatalf("required impossible=%d %v", w.Code, b)
	}
}

func TestMFAPrimaryPasswordCannotReplaceSecondFactor(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	secret, _ := f.associateOTP(t, tok)
	f.proveOTP(t, tok, secret)
	tok = f.mfaRequired(t)
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["otp"]}`)
	if w.Code != 403 || b["error"] != "access_denied" {
		t.Fatalf("challenge-only token enrolled new OTP: %d %v", w.Code, b)
	}
	// Even a pending method created by a separately authorized enrollment must
	// not satisfy the original challenge with an attacker-controlled new secret.
	pending, err := f.h.MFA.BeginEnroll(context.Background(), f.tenantID(t, "acme"), f.aliceID(t), "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	w, b = f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(otpGrant, tok, "otp", otpAt(pending.Secret, f.h.now()))})
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("pending method bypassed existing factor: %d %v", w.Code, b)
	}
	if _, err = f.st.MFA().PeekMFAToken(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(tok), f.h.now()); err != nil {
		t.Fatal("failed bypass consumed token", err)
	}
}

func TestMFAForcedEnrollmentRejectsExistingMethod(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	old, _ := f.associateOTP(t, tok)
	f.proveOTP(t, tok, old)
	f.h.Now = func() time.Time { return fixedNow().Add(30 * time.Second) }
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	tn, _ := f.st.Tenants().Get(ctx, tid)
	tn.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	c, _ := f.st.Clients().Get(ctx, tid, "ropg")
	u, _ := f.st.Users().Get(ctx, tid, f.aliceID(t))
	conn, _ := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	required := f.h.passwordMFA(ctx, tenant.Resolved{Tenant: tn, Host: acmeHost}, c, u, conn, acmeAPI, []string{"openid"}, []string{"openid"}, &actions.Effects{MFA: &actions.MFAEffects{Mode: "enroll", Factors: [][]string{{"otp"}}}}, f.h.now())
	if required == nil || required.MFAToken == "" {
		t.Fatalf("forced enrollment=%v", required)
	}
	tok = required.MFAToken
	w, b := f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(otpGrant, tok, "otp", otpAt(old, f.h.now()))})
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("existing method bypassed enrollment=%d %v", w.Code, b)
	}
	w, b = f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["otp"]}`)
	if w.Code != 200 || b["recovery_codes"] != nil {
		t.Fatalf("second enrollment recovery redisplay=%d %v", w.Code, b)
	}
	f.proveOTP(t, tok, b["secret"].(string))
}

func TestMFAGrantHonorsCurrentClientGrant(t *testing.T) {
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	form := pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://granted.test", "scope", "openid a")
	w, b := f.call(t, true, tokenCall{host: acmeHost, form: form})
	if w.Code != 403 || b["error"] != "mfa_required" {
		t.Fatalf("required=%d %v", w.Code, b)
	}
	tok := b["mfa_token"].(string)
	secret, _ := f.associateOTP(t, tok)
	grant, err := f.st.ClientGrants().Find(ctx, tid, "ropg", "https://granted.test", store.SubjectTypeUser)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.st.ClientGrants().Delete(ctx, tid, grant.ID); err != nil {
		t.Fatal(err)
	}
	w, b = f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(otpGrant, tok, "otp", otpAt(secret, f.h.now()))})
	if w.Code == 200 || b["access_token"] != nil {
		t.Fatalf("revoked grant bypassed=%d %v", w.Code, b)
	}
	if err = f.st.ClientGrants().Create(ctx, grant); err != nil {
		t.Fatal(err)
	}
	f.proveOTP(t, tok, secret)
}

func TestMFAEnrollmentTokenCannotBypassLaterEnrollment(t *testing.T) {
	f, _ := mfaFixture(t)
	first := f.mfaRequired(t)
	second := f.mfaRequired(t)
	secret, _ := f.associateOTP(t, first)
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", second, `{"authenticator_types":["otp"]}`)
	if w.Code != 200 || b["recovery_codes"] != nil {
		t.Fatalf("second initial association=%d %v", w.Code, b)
	}
	secondSecret := b["secret"].(string)
	f.proveOTP(t, first, secret)
	w, b = f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(otpGrant, second, "otp", otpAt(secondSecret, f.h.now()))})
	if w.Code != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("stale enrollment authority bypassed existing factor: %d %v", w.Code, b)
	}
}

type unavailableMFAStore struct{ store.Store }

func (s unavailableMFAStore) MFA() store.MFA { return store.UnimplementedMFA{} }
func TestMFAUnavailableActionSkip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	tn, _ := f.st.Tenants().Get(ctx, tid)
	c, _ := f.st.Clients().Get(ctx, tid, "ropg")
	u, _ := f.st.Users().Get(ctx, tid, f.aliceID(t))
	conn, _ := f.st.Connections().GetByName(ctx, tid, "Username-Password-Authentication")
	f.h.Store = unavailableMFAStore{f.st}
	res := tenant.Resolved{Tenant: tn, Host: acmeHost}
	if e := f.h.passwordMFA(ctx, res, c, u, conn, acmeAPI, nil, nil, &actions.Effects{MFA: &actions.MFAEffects{Provider: "none"}}, f.h.now()); e != nil {
		t.Fatalf("explicit skip with unavailable MFA=%v", e)
	}
	if e := f.h.passwordMFA(ctx, res, c, u, conn, acmeAPI, nil, nil, &actions.Effects{MFA: &actions.MFAEffects{Provider: "any"}}, f.h.now()); e == nil || e.Status != 501 {
		t.Fatalf("required unavailable MFA=%v", e)
	}
}
