package federation

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// wpVariant is the WordPress descriptor with edits, run against the
// fixture under /wordpress.
func wpVariant(t *testing.T, edit func(d *providers.Descriptor)) (*socFixture, socialProvider, Config, Endpoints) {
	t.Helper()
	d, _ := providers.Get("wordpress")
	edit(d)
	f := newSocFixture(t)
	ps := f.providers()
	cfg := socConfig(t, "wordpress", "")
	e, err := ps.socialEndpoints(d, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	return f, socialProvider{ps: ps, d: d}, cfg, e
}

func (p socialProvider) exchangeTest(t *testing.T, cfg Config, e Endpoints) (ProviderResult, error) {
	t.Helper()
	return p.Exchange(context.Background(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
}

const wpProfile = `{"ID":42,"username":"wp","display_name":"W P","email":"wp@example.com","email_verified":true}`

func TestTokenRequestShape(t *testing.T) {
	f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) {
		d.TokenMethod, d.TokenAuth, d.TokenResponsePath, d.TokenAccept, d.TokenTypeOptional = "GET", providers.AuthQuery, "response", "application/json", true
	})
	f.on("/wordpress/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			jsonHandler(400, `{}`)(w, r)
			return
		}
		jsonHandler(200, `{"meta":{"code":200},"response":{"access_token":"`+socTestToken+`"}}`)(w, r)
	})
	f.on("/wordpress/rest/v1.1/me", jsonHandler(200, wpProfile))
	res, err := p.exchangeTest(t, cfg, e)
	if err != nil || res.Profile.Subject != "42" || res.Tokens.AccessToken != socTestToken {
		t.Fatalf("result %+v %v", res, err)
	}
	q, _ := url.ParseQuery(f.queries["/wordpress/oauth2/token"])
	if q.Get("client_id") != "throwaway-client" || q.Get("client_secret") != socTestSecret || q.Get("code") != "code-1" || q.Get("grant_type") != "authorization_code" || q.Get("redirect_uri") == "" {
		t.Fatalf("token query %v", q)
	}
}

func TestRedirectParamAndFixedParams(t *testing.T) {
	f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) {
		d.RedirectParam = "redirect_url"
		d.AuthorizeParams = map[string]string{"type": "web_server"}
		d.TokenParams = map[string]string{"type": "web_server"}
		d.ProfileParams = map[string]string{"v": "5.199"}
	})
	raw, err := p.AuthorizationURL(StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback", State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	q := mustQuery(t, raw)
	if q.Get("redirect_url") != "https://login.example/login/callback" || q.Has("redirect_uri") || q.Get("type") != "web_server" {
		t.Fatalf("authorize %s", raw)
	}
	f.on("/wordpress/oauth2/token", jsonHandler(200, tokenOK))
	f.on("/wordpress/rest/v1.1/me", jsonHandler(200, wpProfile))
	if _, err := p.exchangeTest(t, cfg, e); err != nil {
		t.Fatal(err)
	}
	form := f.forms["/wordpress/oauth2/token"]
	if form.Get("redirect_url") == "" || form.Has("redirect_uri") || form.Get("type") != "web_server" {
		t.Fatalf("token form %v", form)
	}
	if pq, _ := url.ParseQuery(f.queries["/wordpress/rest/v1.1/me"]); pq.Get("v") != "5.199" {
		t.Fatalf("profile query %v", pq)
	}
}

func TestProfileAuthModes(t *testing.T) {
	for mode, check := range map[string]func(h http.Header, q url.Values) bool{
		"query:access_token": func(h http.Header, q url.Values) bool {
			return q.Get("access_token") == socTestToken && h.Get("Authorization") == ""
		},
		"scheme:OAuth": func(h http.Header, q url.Values) bool {
			return h.Get("Authorization") == "OAuth "+socTestToken && !q.Has("access_token")
		},
	} {
		t.Run(mode, func(t *testing.T) {
			f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) { d.ProfileAuth = mode; d.ProfileAccept = "application/vnd.example+json" })
			f.on("/wordpress/oauth2/token", jsonHandler(200, tokenOK))
			f.on("/wordpress/rest/v1.1/me", jsonHandler(200, wpProfile))
			if _, err := p.exchangeTest(t, cfg, e); err != nil {
				t.Fatal(err)
			}
			q, _ := url.ParseQuery(f.queries["/wordpress/rest/v1.1/me"])
			h := f.headers["/wordpress/rest/v1.1/me"]
			if !check(h, q) || h.Get("Accept") != "application/vnd.example+json" {
				t.Fatalf("headers %v query %v", h, q)
			}
		})
	}
}

func TestTokenValues(t *testing.T) {
	f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) {
		d.ProfileURL = "https://public-api.wordpress.com/2/users/show.json?uid={token.uid}"
		d.Profile.UserID, d.Profile.Email = "token:uid", "token:email"
		d.EmailVerified = providers.EmailRule{Rule: providers.EmailNever}
	})
	e.UserInfoURL = p.ps.socialURL("wordpress", p.d.ProfileURL)
	f.on("/wordpress/oauth2/token", jsonHandler(200, `{"access_token":"`+socTestToken+`","token_type":"bearer","uid":5678901234,"email":"vk@example.com"}`))
	f.on("/wordpress/2/users/show.json", jsonHandler(200, `{"display_name":"From Profile"}`))
	res, err := p.exchangeTest(t, cfg, e)
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile.Subject != "5678901234" || res.Profile.Email == nil || *res.Profile.Email != "vk@example.com" || *res.Profile.EmailVerified || *res.Profile.Name != "From Profile" {
		t.Fatalf("profile %+v", res.Profile)
	}
	if q, _ := url.ParseQuery(f.queries["/wordpress/2/users/show.json"]); q.Get("uid") != "5678901234" {
		t.Fatalf("profile query %v", q)
	}
}

// TestTokenValueSubstitution (Review Focus 1): a token-response value that
// is not a bounded plain token is refused before any profile call.
func TestTokenValueSubstitution(t *testing.T) {
	for name, uid := range map[string]string{"dot dot": `"../x"`, "at": `"a@b"`, "slash": `"a/b"`, "too long": `"` + strings.Repeat("a", 129) + `"`, "missing": ``, "object": `{"a":1}`, "fraction": `1.5`} {
		t.Run(name, func(t *testing.T) {
			f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) {
				d.ProfileURL = "https://public-api.wordpress.com/2/users/show.json?uid={token.uid}"
			})
			e.UserInfoURL = p.ps.socialURL("wordpress", p.d.ProfileURL)
			body := `{"access_token":"` + socTestToken + `","token_type":"bearer"`
			if uid != "" {
				body += `,"uid":` + uid
			}
			f.on("/wordpress/oauth2/token", jsonHandler(200, body+"}"))
			f.on("/wordpress/2/users/show.json", jsonHandler(200, wpProfile))
			if _, err := p.exchangeTest(t, cfg, e); err == nil {
				t.Fatal("accepted")
			}
			if f.calls["/wordpress/2/users/show.json"] != 0 {
				t.Fatal("profile called with a refused value")
			}
		})
	}
}

// TestQueryTokenNotInErrors (Review Focus 2): a provider that takes the
// access token in the query never surfaces it in an error.
func TestQueryTokenNotInErrors(t *testing.T) {
	for name, h := range map[string]func(http.ResponseWriter, *http.Request){
		"401":     jsonHandler(401, `{}`),
		"500":     jsonHandler(500, `{}`),
		"garbage": jsonHandler(200, `not json`),
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, p, cfg, e := wpVariant(t, func(d *providers.Descriptor) { d.ProfileAuth = "query:access_token" })
			f.on("/wordpress/oauth2/token", jsonHandler(200, tokenOK))
			f.on("/wordpress/rest/v1.1/me", h)
			_, err := p.exchangeTest(t, cfg, e)
			if err == nil {
				t.Fatal("accepted")
			}
			socNoSecrets(t, err, "access_token=", f.srv.URL)
		})
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
