package federation

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestTwitterOAuth2 checks X's OAuth 2.0 specifics: S256 PKCE and
// client_secret_basic at the token endpoint, no email.
func TestTwitterOAuth2(t *testing.T) {
	c := tier1Cases[indexOfCase("twitter")]
	f := c.fixture(t)
	ps := f.providers()
	cfg := socConfig(t, "twitter", `,"offline_access":true`)
	if strings.Join(cfg.Scopes, " ") != "tweet.read users.read offline.access" || cfg.OAuth1 != nil {
		t.Fatalf("scopes %v oauth1 %v", cfg.Scopes, cfg.OAuth1)
	}
	e, _ := ps.SocialEndpoints(cfg, "")
	if e.PKCEMethod != "S256" || e.TokenAuthMethod != authBasic {
		t.Fatalf("endpoints %+v", e)
	}
	res, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
	if err != nil || res.Profile.Email != nil || res.Profile.Nickname == nil || *res.Profile.Nickname != "XDevelopers" {
		t.Fatalf("profile %+v %v", res.Profile, err)
	}
	if form := f.forms["/twitter/2/oauth2/token"]; form.Get("code_verifier") != "verifier-1" || form.Has("client_secret") {
		t.Fatalf("token form %v", form)
	}
}

const twitterCredentials = `{"id":783214,"id_str":"783214","name":"Twitter","screen_name":"Twitter","email":"tw@example.com","profile_image_url_https":"https://pbs.twimg.example/p.png"}`

// TestTwitterOAuth1 runs protocol oauth1 end to end: request token, the
// verifier exchange and a signed GET of verify_credentials with
// include_email. The email is never verified (SP-7).
func TestTwitterOAuth1(t *testing.T) {
	f := newO1FixtureAt(t, "twitter", "throwaway-client", socTestSecret)
	f.accessTokenResponse = "oauth_token=" + o1AccessToken + "&oauth_token_secret=" + o1AccessSecret + "&user_id=783214&screen_name=Twitter"
	var verifyQuery url.Values
	f.on("/twitter/1.1/account/verify_credentials.json", func(w http.ResponseWriter, r *http.Request) {
		p := f.verify(r, o1AccessSecret)
		if p["oauth_token"] != o1AccessToken {
			f.sigFails++
		}
		verifyQuery = r.URL.Query()
		jsonHandler(200, twitterCredentials)(w, r)
	})
	e := newSocFlowEnv(t, f.socFixture, "twitter", map[string]any{"protocol": "oauth1"})
	begun, err := e.begin(t, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(begun.URL)
	if u.Path != "/twitter/oauth/authenticate" || u.Query().Get("oauth_token") != o1RequestToken {
		t.Fatalf("authorize redirect %s", begun.URL)
	}
	p, err := ParseCallback("oauth_token=" + o1RequestToken + "&oauth_verifier=" + o1Verifier)
	if err != nil {
		t.Fatal(err)
	}
	done, err := e.svc.Complete(e.ctx, CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Params: p, CookieValue: begun.CookieValue})
	if err != nil {
		t.Fatal(err)
	}
	if f.sigFails != 0 || verifyQuery.Get("include_email") != "true" || verifyQuery.Get("skip_status") != "true" {
		t.Fatalf("signature failures %d, query %v", f.sigFails, verifyQuery)
	}
	if done.UserID != "twitter|783214" {
		t.Fatalf("user %s", done.UserID)
	}
	usr, _ := e.st.Users().Get(e.ctx, "ten", done.UserID)
	if usr.Email != "tw@example.com" || usr.EmailVerified || usr.Nickname != "Twitter" {
		t.Fatalf("user %+v", usr)
	}
}

func TestEveryInventoryStrategyHasDescriptor(t *testing.T) {
	want := []string{"bitbucket", "box", "dropbox", "facebook", "line", "linkedin", "amazon", "paypal", "paypal-sandbox",
		"salesforce", "salesforce-community", "salesforce-sandbox", "shopify", "twitter", "yahoo"}
	for _, s := range want {
		if !providers.Is(s) {
			t.Errorf("%s has no descriptor", s)
		}
	}
	if len(providers.Strategies()) != len(want) {
		t.Errorf("descriptors %v", providers.Strategies())
	}
}
