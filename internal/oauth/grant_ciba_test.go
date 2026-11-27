package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pollFixture struct {
	*cibaFixture
	clock time.Time
	mu    sync.Mutex
}

func newPollFixture(t *testing.T) *pollFixture {
	f := &pollFixture{cibaFixture: newCIBAFixture(t), clock: fixedNow()}
	now := func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock }
	f.h.Now = now
	f.h.Minter.Now = now
	return f
}

func (f *pollFixture) advance(d time.Duration) { f.mu.Lock(); f.clock = f.clock.Add(d); f.mu.Unlock() }

// request stores a pending request for alice by ciba-app and returns its
// auth_req_id.
func (f *pollFixture) request(t *testing.T, scopes ...string) string {
	t.Helper()
	id := secrets.RandomString(43)
	if len(scopes) == 0 {
		scopes = []string{"openid", "email"}
	}
	if err := f.st.(store.CIBAStore).CreateCIBARequest(context.Background(), &store.CIBARequest{Origin: "https://acme.example.test", TenantID: f.tid,
		IDHash: secrets.HashToken(id), TicketHash: secrets.HashToken("t" + id), ClientID: "ciba-app", UserID: f.alice.UserID, Scopes: scopes,
		BindingMessage: "X", Status: store.CIBAPending, Interval: 5, ExpiresAt: f.clock.Add(10 * time.Minute), CreatedAt: f.clock}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *pollFixture) decide(t *testing.T, id string, status store.CIBAStatus, scopes ...string) {
	t.Helper()
	if _, err := f.st.(store.CIBAStore).DecideCIBARequest(context.Background(), f.tid, secrets.HashToken(id),
		store.CIBADecision{Status: status, GrantedScopes: scopes, AuthTime: f.clock.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func (f *pollFixture) poll(t *testing.T, clientID, secret, id string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {cibaGrant}, "client_id": {clientID}, "client_secret": {secret}, "auth_req_id": {id}}
	r := httptest.NewRequest(http.MethodPost, "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.server(t, true).ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestCIBAPollStates(t *testing.T) {
	f := newPollFixture(t)
	id := f.request(t)
	rec, out := f.poll(t, "ciba-app", "ciba-secret", id)
	if rec.Code != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", rec.Code, out)
	}
	f.advance(2 * time.Second)
	rec, out = f.poll(t, "ciba-app", "ciba-secret", id)
	if rec.Code != 400 || out["error"] != "slow_down" || out["interval"] != float64(10) {
		t.Fatalf("slow_down: %d %v", rec.Code, out)
	}
	f.advance(11 * time.Second)
	if _, out := f.poll(t, "ciba-app", "ciba-secret", id); out["error"] != "authorization_pending" {
		t.Fatalf("after waiting: %v", out)
	}
	// Denied, and expired, are access_denied (Auth0).
	f.decide(t, id, store.CIBADenied)
	f.advance(11 * time.Second)
	if _, out := f.poll(t, "ciba-app", "ciba-secret", id); out["error"] != "access_denied" {
		t.Fatalf("denied: %v", out)
	}
	expired := f.request(t)
	f.advance(11 * time.Minute)
	if _, out := f.poll(t, "ciba-app", "ciba-secret", expired); out["error"] != "access_denied" {
		t.Fatalf("expired: %v", out)
	}
	if _, out := f.poll(t, "ciba-app", "ciba-secret", "unknown"); out["error"] != "invalid_grant" {
		t.Fatalf("unknown: %v", out)
	}
}

func TestCIBATokens(t *testing.T) {
	f := newPollFixture(t)
	c, _ := f.st.Clients().Get(context.Background(), f.tid, "ciba-app")
	c.GrantTypes = append(c.GrantTypes, "refresh_token")
	_ = f.st.Clients().Update(context.Background(), c)
	id := f.request(t, "openid", "email", "offline_access")
	f.decide(t, id, store.CIBAApproved, "openid", "email", "offline_access")
	rec, out := f.poll(t, "ciba-app", "ciba-secret", id)
	if rec.Code != 200 || out["access_token"] == nil || out["id_token"] == nil || out["refresh_token"] == nil {
		t.Fatalf("tokens: %d %v", rec.Code, out)
	}
	tok, err := jwt.ParseSigned(out["id_token"].(string), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	_ = tok.UnsafeClaimsWithoutVerification(&claims)
	if claims["sub"] != f.alice.UserID || claims["aud"] != "ciba-app" || claims["auth_time"] == nil {
		t.Fatalf("ID token claims %v", claims)
	}
	// Redeemed: the next poll is invalid_grant.
	f.advance(10 * time.Second)
	if _, out := f.poll(t, "ciba-app", "ciba-secret", id); out["error"] != "invalid_grant" {
		t.Fatalf("second redemption: %v", out)
	}
	_ = keys.SealClientSecret
}

// Review Focus 3: concurrent polls after approval redeem once.
func TestCIBARedeemOnce(t *testing.T) {
	f := newPollFixture(t)
	id := f.request(t)
	f.decide(t, id, store.CIBAApproved, "openid")
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[string]int{}
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, out := f.poll(t, "ciba-app", "ciba-secret", id)
			key := "200"
			if rec.Code != 200 {
				key, _ = out["error"].(string)
			}
			mu.Lock()
			codes[key]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes["200"] != 1 || codes["200"]+codes["invalid_grant"] != 6 {
		t.Fatalf("outcomes %v", codes)
	}
}

// Review Focus 4: another client polling the request learns nothing and
// changes nothing.
func TestCIBAOtherClient(t *testing.T) {
	f := newPollFixture(t)
	sealed, _ := keys.SealClientSecret(f.wrapper, f.tid, "ciba-other", "other-secret")
	if err := f.st.Clients().Create(context.Background(), &store.Client{TenantID: f.tid, ClientID: "ciba-other", Name: "Other", AppType: store.AppTypeRegularWeb, IsFirstParty: true,
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, Secrets: []store.ClientSecret{{Sealed: sealed, CreatedAt: fixedNow()}},
		GrantTypes: []string{cibaGrant}, AsyncApprovalNotificationChannels: []string{"email"}, CreatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
	id := f.request(t)
	f.decide(t, id, store.CIBAApproved, "openid")
	before, _ := f.st.(store.CIBAStore).GetCIBARequest(context.Background(), f.tid, secrets.HashToken(id))
	if rec, out := f.poll(t, "ciba-other", "other-secret", id); rec.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("other client: %d %v", rec.Code, out)
	}
	after, _ := f.st.(store.CIBAStore).GetCIBARequest(context.Background(), f.tid, secrets.HashToken(id))
	if after.Status != before.Status || after.LastPolledAt != nil || after.Interval != before.Interval {
		t.Fatalf("state changed: %+v -> %+v", before, after)
	}
	if rec, _ := f.poll(t, "ciba-app", "ciba-secret", id); rec.Code != 200 {
		t.Fatalf("owner after the intruder: %d", rec.Code)
	}
}

// A request started on another host is refused before the poll, so an
// approval is not consumed there.
func TestCIBAOtherOrigin(t *testing.T) {
	f := newPollFixture(t)
	repo := f.st.(store.CIBAStore)
	other := secrets.RandomString(43)
	if err := repo.CreateCIBARequest(context.Background(), &store.CIBARequest{Origin: "https://other.example.test", TenantID: f.tid, IDHash: secrets.HashToken(other), TicketHash: "tother",
		ClientID: "ciba-app", UserID: f.alice.UserID, Scopes: []string{"openid"}, Status: store.CIBAPending, Interval: 5, ExpiresAt: f.clock.Add(time.Hour), CreatedAt: f.clock}); err != nil {
		t.Fatal(err)
	}
	f.decide(t, other, store.CIBAApproved, "openid")
	if rec, out := f.poll(t, "ciba-app", "ciba-secret", other); rec.Code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("other origin: %d %v", rec.Code, out)
	}
	if got, _ := repo.GetCIBARequest(context.Background(), f.tid, secrets.HashToken(other)); got.Status != store.CIBAApproved {
		t.Fatalf("approval consumed on the wrong host: %s", got.Status)
	}
}
