package oauth

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// issueCode stores a code for alice as /authorize would, and returns it.
func (f *fixture) issueCode(t *testing.T, clientID, redirectURI, audience string, scopes []string, challenge string) string {
	t.Helper()
	ctx := context.Background()
	tenantID := f.tenantID(t, "acme")
	u, err := f.st.Users().FindByLogin(ctx, tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	code := secrets.RandomString(43)
	ac := &store.AuthCode{
		TenantID: tenantID, CodeHash: secrets.HashToken(code), ClientID: clientID, RedirectURI: redirectURI,
		UserID: u.UserID, SessionID: "sid-1", Scopes: scopes, Audience: audience, Nonce: "n-1",
		AuthTime: fixedNow().Add(-time.Minute), ExpiresAt: fixedNow().Add(time.Minute), CreatedAt: fixedNow(),
	}
	if challenge != "" {
		ac.CodeChallenge, ac.CodeChallengeMethod = challenge, "S256"
	}
	if err := f.st.AuthCodes().Create(ctx, ac); err != nil {
		t.Fatal(err)
	}
	return code
}

func codeForm(code, clientID, redirectURI, verifier string) url.Values {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		v.Set("code_verifier", verifier)
	}
	return v
}

func TestAuthorizationCodeSPA(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "profile", "email", "read:things", "undefined:scope", "offline_access"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["scope"] != "openid profile email read:things" || body["token_type"] != "Bearer" || body["expires_in"] != float64(3600) {
		t.Fatalf("body = %v", body)
	}
	tenantID := f.tenantID(t, "acme")
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	aud, _ := at["aud"].([]any)
	if len(aud) != 2 || aud[0] != "https://api.acme.test" || aud[1] != "https://acme.example.test/userinfo" ||
		!strings.HasPrefix(at["sub"].(string), "auth0|") || at["azp"] != "code-spa" || at["gty"] != nil {
		t.Fatalf("access token claims = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	if idt["aud"] != "code-spa" || idt["nonce"] != "n-1" || idt["sid"] != "sid-1" || idt["email"] != "alice@acme.test" ||
		idt["name"] != "Alice" || idt["at_hash"] == nil || idt["exp"].(float64)-idt["iat"].(float64) != 600 || idt["sub"] != at["sub"] {
		t.Fatalf("id token claims = %v", idt)
	}
}

func TestAuthorizationCodeWithoutAudience(t *testing.T) {
	f := newFixture(t)
	// The fixture tenant has default_audience set; codes carry the audience
	// chosen at /authorize, so an empty audience here means "none".
	code := f.issueCode(t, "code-web", "https://web.acme.test/cb", "", []string{"openid", "read:things"}, "")
	form := codeForm(code, "code-web", "https://web.acme.test/cb", "")
	form.Set("client_secret", "code-web-secret")
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 || body["scope"] != "openid" || body["expires_in"] != float64(86400) {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://acme.example.test/userinfo" {
		t.Fatalf("aud = %v", at["aud"])
	}
}

func TestAuthorizationCodeNoOpenID(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "code-spa", "https://app.acme.test/cb", "https://api.acme.test", []string{"read:things"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 || body["id_token"] != nil {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	at, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
	if at["aud"] != "https://api.acme.test" {
		t.Fatalf("aud = %v (no openid scope: API audience only)", at["aud"])
	}
}

// Review focus 2.
func TestAuthorizationCodeMisuse(t *testing.T) {
	f := newFixture(t)
	spa := func() string {
		return f.issueCode(t, "code-spa", "https://app.acme.test/cb", "", []string{"openid"}, pkceChallenge)
	}

	t.Run("replay", func(t *testing.T) {
		code := spa()
		form := codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)
		if rec, _ := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 200 {
			t.Fatalf("first use = %d", rec.Code)
		}
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("replay = %d %v", rec.Code, body)
		}
	})

	cases := map[string]func() tokenCall{
		"unknown code": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm("nope", "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
		"other client": func() tokenCall {
			form := codeForm(spa(), "code-web", "https://app.acme.test/cb", pkceVerifier)
			form.Set("client_secret", "code-web-secret")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"other redirect_uri": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/other", pkceVerifier)}
		},
		"missing redirect_uri": func() tokenCall {
			form := codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)
			form.Del("redirect_uri")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"missing verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", "")}
		},
		"wrong verifier": func() tokenCall {
			return tokenCall{host: "acme.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", strings.Repeat("a", 43))}
		},
		"verifier without challenge": func() tokenCall {
			code := f.issueCode(t, "code-web", "https://web.acme.test/cb", "", []string{"openid"}, "")
			form := codeForm(code, "code-web", "https://web.acme.test/cb", pkceVerifier)
			form.Set("client_secret", "code-web-secret")
			return tokenCall{host: "acme.example.test", form: form}
		},
		"other tenant": func() tokenCall {
			return tokenCall{host: "globex.example.test", form: codeForm(spa(), "code-spa", "https://app.acme.test/cb", pkceVerifier)}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := f.call(t, true, mk())
			if rec.Code == 200 || body["access_token"] != nil {
				t.Fatalf("tokens issued: %d %v", rec.Code, body)
			}
			want := "invalid_grant"
			if name == "other tenant" {
				if body["error"] != "invalid_client" && body["error"] != want {
					t.Fatalf("error = %v", body["error"])
				}
				return
			}
			if body["error"] != want {
				t.Fatalf("error = %v, want %s", body["error"], want)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		code := spa()
		f.h.Now = func() time.Time { return fixedNow().Add(2 * time.Minute) }
		defer func() { f.h.Now = fixedNow }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("expired = %d %v", rec.Code, body)
		}
	})

	t.Run("blocked user", func(t *testing.T) {
		code := spa()
		ctx := context.Background()
		u, err := f.st.Users().FindByLogin(ctx, f.tenantID(t, "acme"), "Username-Password-Authentication", "alice@acme.test")
		if err != nil {
			t.Fatal(err)
		}
		u.Blocked = true
		_ = f.st.Users().Update(ctx, u)
		defer func() { u.Blocked = false; _ = f.st.Users().Update(ctx, u) }()
		if rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "code-spa", "https://app.acme.test/cb", pkceVerifier)}); rec.Code != 400 || body["error"] != "invalid_grant" {
			t.Fatalf("blocked = %d %v", rec.Code, body)
		}
	})
}

func TestCodeIssuesRefreshToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "offline_access", "read:things"}, pkceChallenge)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)})
	if rec.Code != 200 {
		t.Fatalf("status %d: %v", rec.Code, body)
	}
	if body["scope"] != "openid offline_access read:things" {
		t.Errorf("scope = %v", body["scope"])
	}
	raw, _ := body["refresh_token"].(string)
	if len(raw) != 48 {
		t.Fatalf("refresh_token = %q", raw)
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(ctx, f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if rt.ClientID != "rt-spa" || rt.FamilyID != familyForCode(secrets.HashToken(code)) || !rt.Rotating ||
		rt.SessionID != "sid-1" || rt.Audience != "https://api.acme.test" ||
		!rt.AuthTime.Equal(fixedNow().Add(-time.Minute)) ||
		!rt.ExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenLifetime)) ||
		!rt.IdleExpiresAt.Equal(fixedNow().Add(DefaultRefreshTokenIdleLifetime)) ||
		!slices.Equal(rt.Scopes, []string{"openid", "offline_access", "read:things"}) {
		t.Fatalf("stored refresh token = %+v", rt)
	}
}

func TestRefreshTokenOnlyWhenAllowed(t *testing.T) {
	cases := []struct {
		name, client, redirect, audience string
		scopes                           []string
		want                             bool
	}{
		{"client without refresh_token grant", "code-spa", "https://app.acme.test/cb", "https://api.acme.test", []string{"openid", "offline_access"}, false},
		{"API without offline access", "rt-spa", "https://rt.acme.test/cb", "https://billing.acme.test", []string{"openid", "offline_access"}, false},
		{"offline_access not requested", "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test", []string{"openid"}, false},
		{"no API", "rt-spa", "https://rt.acme.test/cb", "", []string{"openid", "offline_access"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			code := f.issueCode(t, tc.client, tc.redirect, tc.audience, tc.scopes, pkceChallenge)
			rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: codeForm(code, tc.client, tc.redirect, pkceVerifier)})
			if rec.Code != 200 {
				t.Fatalf("status %d: %v", rec.Code, body)
			}
			_, got := body["refresh_token"]
			offline := slices.Contains(strings.Fields(body["scope"].(string)), "offline_access")
			if got != tc.want || offline != tc.want {
				t.Fatalf("refresh_token present = %v, offline_access in scope = %v; want %v (%v)", got, offline, tc.want, body)
			}
		})
	}
}

func TestCodeReplayRevokesRefreshTokens(t *testing.T) {
	f := newFixture(t)
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "offline_access"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 200 {
		t.Fatalf("first exchange: %d %v", rec.Code, body)
	}
	raw := body["refresh_token"].(string)
	rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", rec.Code, body)
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(raw))
	if err != nil || rt.RevokedAt == nil {
		t.Fatalf("refresh token after code replay = %+v, %v; want revoked", rt, err)
	}
}

// raceStore blocks the first Users().Get until release is closed, and
// records the refresh tokens created through it.
type raceStore struct {
	store.Store
	entered, release chan struct{}
	once             sync.Once
	mu               sync.Mutex
	createdHashes    []string
}

func (s *raceStore) Users() store.Users { return raceUsers{s.Store.Users(), s} }

func (s *raceStore) RefreshTokens() store.RefreshTokens {
	return raceRefreshTokens{s.Store.RefreshTokens(), s}
}

type raceUsers struct {
	store.Users
	s *raceStore
}

func (u raceUsers) Get(ctx context.Context, tenantID, userID string) (*store.User, error) {
	first := false
	u.s.once.Do(func() { first = true })
	if first {
		close(u.s.entered)
		<-u.s.release
	}
	return u.Users.Get(ctx, tenantID, userID)
}

type raceRefreshTokens struct {
	store.RefreshTokens
	s *raceStore
}

func (r raceRefreshTokens) Create(ctx context.Context, t *store.RefreshToken) error {
	err := r.RefreshTokens.Create(ctx, t)
	if err == nil {
		r.s.mu.Lock()
		r.s.createdHashes = append(r.s.createdHashes, t.TokenHash)
		r.s.mu.Unlock()
	}
	return err
}

// A replay that lands after the first exchange consumed the code but
// before it stored its refresh token must still leave no live token.
func TestCodeReplayDuringFirstExchange(t *testing.T) {
	f := newFixture(t)
	rs := &raceStore{Store: f.st, entered: make(chan struct{}), release: make(chan struct{})}
	f.h.Store = rs
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", "https://api.acme.test",
		[]string{"openid", "offline_access"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)

	type result struct {
		status int
		body   map[string]any
	}
	done := make(chan result, 1)
	go func() {
		rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
		done <- result{rec.Code, body}
	}()
	<-rs.entered // the first exchange has consumed the code and is loading the user

	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
	if rec.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", rec.Code, body)
	}
	close(rs.release)
	first := <-done
	if first.status != 400 || first.body["error"] != "invalid_grant" || first.body["refresh_token"] != nil || first.body["access_token"] != nil {
		t.Fatalf("first exchange after replay: %d %v; want 400 invalid_grant without tokens", first.status, first.body)
	}

	rs.mu.Lock()
	hashes := slices.Clone(rs.createdHashes)
	rs.mu.Unlock()
	if len(hashes) != 1 {
		t.Fatalf("refresh tokens created = %d; want 1", len(hashes))
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(context.Background(), f.tenantID(t, "acme"), hashes[0])
	if err != nil || rt.RevokedAt == nil || rt.FamilyID != familyForCode(secrets.HashToken(code)) {
		t.Fatalf("refresh token of the replayed code = %+v, %v; want revoked", rt, err)
	}
}
