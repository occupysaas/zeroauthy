package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// tier1Case is one descriptor provider run against the fixture: the options,
// the fixture paths and bodies, and the expected scope and profile.
type tier1Case struct {
	strategy, options string
	tokenPath         string
	tokenBody         string
	profilePath       string
	profileBody       string
	extra             map[string]string // more fixture paths → bodies
	scope             string            // the authorize URL scope
	subject           string
	email             string
	verified          bool
	name              string
	hint              string
}

const tokenOK = `{"access_token":"` + socTestToken + `","token_type":"bearer","expires_in":3600}`

var tier1Cases = []tier1Case{
	{strategy: "facebook", options: `,"email":true,"user_birthday":true`, tokenPath: "/facebook/v24.0/oauth/access_token", tokenBody: tokenOK,
		profilePath: "/facebook/v24.0/me", profileBody: `{"id":"10150000000000001","name":"Fay Book","first_name":"Fay","last_name":"Book","email":"fay@example.com","picture":{"data":{"url":"https://graph.example/pic.jpg"}}}`,
		scope: "public_profile,email,user_birthday", subject: "10150000000000001", email: "fay@example.com", verified: true, name: "Fay Book"},
	{strategy: "linkedin", options: `,"email":true`, tokenPath: "/linkedin/oauth/v2/accessToken", tokenBody: tokenOK,
		profilePath: "/linkedin/v2/userinfo", profileBody: `{"sub":"782bbtaQ","name":"Lin Kedin","given_name":"Lin","family_name":"Kedin","email":"lin@example.com","email_verified":true,"picture":"https://media.example/p.jpg"}`,
		scope: "openid profile email", subject: "782bbtaQ", email: "lin@example.com", verified: true, name: "Lin Kedin"},
	{strategy: "paypal", options: `,"email":true`, tokenPath: "/paypal/v1/oauth2/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"Bearer","expires_in":28800}`,
		profilePath: "/paypal/v1/identity/oauth2/userinfo", profileBody: `{"user_id":"https://www.paypal.com/webapps/auth/identity/user/THROWAWAY","name":"Pay Pal","given_name":"Pay","family_name":"Pal","emails":[{"value":"old@example.com","primary":false,"confirmed":true},{"value":"pay@example.com","primary":true,"confirmed":false}]}`,
		scope: "openid email", subject: "https://www.paypal.com/webapps/auth/identity/user/THROWAWAY", email: "pay@example.com", verified: false, name: "Pay Pal"},
	{strategy: "paypal-sandbox", options: `,"profile":true`, tokenPath: "/paypal-sandbox/v1/oauth2/token", tokenBody: tokenOK,
		profilePath: "/paypal-sandbox/v1/identity/oauth2/userinfo", profileBody: `{"user_id":"https://www.sandbox.paypal.com/webapps/auth/identity/user/SANDBOX","name":"Sand Box","emails":[{"value":"sb@example.com","primary":true,"confirmed":true}]}`,
		scope: "openid profile", subject: "https://www.sandbox.paypal.com/webapps/auth/identity/user/SANDBOX", email: "sb@example.com", verified: true, name: "Sand Box"},
	{strategy: "salesforce", tokenPath: "/salesforce/services/oauth2/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"Bearer","id":"{base}/salesforce/id/00Dxx0000001gPL/005xx000001X8Uz","instance_url":"https://example.my.salesforce.com"}`,
		profilePath: "/salesforce/id/00Dxx0000001gPL/005xx000001X8Uz", profileBody: `{"user_id":"005xx000001X8Uz","organization_id":"00Dxx0000001gPL","display_name":"Sales Force","first_name":"Sales","last_name":"Force","email":"sf@example.com","email_verified":true}`,
		scope: "id profile", subject: "005xx000001X8Uz", email: "sf@example.com", verified: true, name: "Sales Force"},
	{strategy: "salesforce-sandbox", options: `,"profile":false`, tokenPath: "/salesforce-sandbox/services/oauth2/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"Bearer","id":"{base}/salesforce-sandbox/id/00D/005SB"}`,
		profilePath: "/salesforce-sandbox/id/00D/005SB", profileBody: `{"user_id":"005SB","display_name":"Sand Force","email":"sfsb@example.com","email_verified":false}`,
		scope: "id", subject: "005SB", email: "sfsb@example.com", verified: false, name: "Sand Force"},
	{strategy: "salesforce-community", options: `,"community_base_url":"https://community.example.com"`, tokenPath: "/salesforce-community/services/oauth2/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"Bearer","id":"{base}/salesforce-community/id/00D/005C"}`,
		profilePath: "/salesforce-community/id/00D/005C", profileBody: `{"user_id":"005C","display_name":"Com Munity","email":"c@example.com","email_verified":true}`,
		scope: "id profile", subject: "005C", email: "c@example.com", verified: true, name: "Com Munity"},
	{strategy: "yahoo", tokenPath: "/yahoo/oauth2/get_token", tokenBody: tokenOK,
		profilePath: "/yahoo/openid/v1/userinfo", profileBody: `{"sub":"YAHOO123","name":"Ya Hoo","given_name":"Ya","family_name":"Hoo","email":"y@example.com","email_verified":true,"picture":"https://s.yimg.example/p.png"}`,
		scope: "openid profile email", subject: "YAHOO123", email: "y@example.com", verified: true, name: "Ya Hoo"},
	{strategy: "line", options: `,"email":true`, tokenPath: "/line/oauth2/v2.1/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"Bearer","expires_in":2592000,"id_token":"throwaway.id.token"}`,
		profilePath: "/line/v2/profile", profileBody: `{"userId":"U4af4980629","displayName":"Li Ne","pictureUrl":"https://profile.line-scdn.example/p"}`,
		extra: map[string]string{"/line/oauth2/v2.1/verify": `{"iss":"https://access.line.me","sub":"U4af4980629","aud":"throwaway-client","exp":1893456000,"email":"line@example.com"}`},
		scope: "openid profile email", subject: "U4af4980629", email: "line@example.com", verified: false, name: "Li Ne"},
	{strategy: "dropbox", tokenPath: "/dropbox/oauth2/token", tokenBody: tokenOK,
		profilePath: "/dropbox/2/users/get_current_account", profileBody: `{"account_id":"dbid:AAH4f99T0taONIb","name":{"display_name":"Drop Box","given_name":"Drop","surname":"Box"},"email":"d@example.com","email_verified":true}`,
		scope: "account_info.read", subject: "dbid:AAH4f99T0taONIb", email: "d@example.com", verified: true, name: "Drop Box"},
	{strategy: "box", tokenPath: "/box/oauth2/token", tokenBody: tokenOK,
		profilePath: "/box/2.0/users/me", profileBody: `{"type":"user","id":"11446498","name":"Bo X","login":"box@example.com","avatar_url":"https://app.box.example/a"}`,
		scope: "", subject: "11446498", email: "box@example.com", verified: false, name: "Bo X"},
	{strategy: "bitbucket", tokenPath: "/bitbucket/site/oauth2/access_token", tokenBody: tokenOK,
		profilePath: "/bitbucket/2.0/user", profileBody: `{"uuid":"{c788b2da-b7a2-404c-9e26-d3f077557007}","account_id":"557058:x","display_name":"Bit Bucket","nickname":"bitb"}`,
		extra: map[string]string{"/bitbucket/2.0/user/emails": `{"values":[{"email":"other@example.com","is_primary":false,"is_confirmed":true},{"email":"bb@example.com","is_primary":true,"is_confirmed":true}]}`},
		scope: "account email", subject: "{c788b2da-b7a2-404c-9e26-d3f077557007}", email: "bb@example.com", verified: true, name: "Bit Bucket"},
	{strategy: "twitter", tokenPath: "/twitter/2/oauth2/token", tokenBody: `{"access_token":"` + socTestToken + `","token_type":"bearer","expires_in":7200,"scope":"tweet.read users.read"}`,
		profilePath: "/twitter/2/users/me", profileBody: `{"data":{"id":"2244994945","name":"X Dev","username":"XDevelopers","profile_image_url":"https://pbs.twimg.example/p.jpg"}}`,
		scope: "tweet.read users.read", subject: "2244994945", name: "X Dev"},
	{strategy: "shopify", hint: "my-shop", tokenPath: "/shopify/admin/oauth/access_token", tokenBody: `{"access_token":"` + socTestToken + `","scope":"read_products"}`,
		profilePath: "/shopify/admin/api/2025-10/shop.json", profileBody: `{"shop":{"id":548380009,"name":"My Shop","email":"owner@example.com","myshopify_domain":"my-shop.myshopify.com"}}`,
		scope: "", subject: "548380009", email: "owner@example.com", verified: false, name: "My Shop"},
}

func (c tier1Case) fixture(t *testing.T) *socFixture {
	f := newSocFixture(t)
	f.on(c.tokenPath, jsonHandler(200, strings.ReplaceAll(c.tokenBody, "{base}", f.srv.URL)))
	f.on(c.profilePath, jsonHandler(200, c.profileBody))
	for p, b := range c.extra {
		f.on(p, jsonHandler(200, b))
	}
	return f
}

func TestTier1Providers(t *testing.T) {
	for _, c := range tier1Cases {
		t.Run(c.strategy, func(t *testing.T) {
			f := c.fixture(t)
			ps := f.providers()
			cfg := socConfig(t, c.strategy, c.options)
			e, err := ps.SocialEndpoints(cfg, c.hint)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback", State: "s", CodeChallenge: "c"})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(raw)
			if got := u.Query().Get("scope"); got != c.scope {
				t.Fatalf("scope %q, want %q", got, c.scope)
			}
			res, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
			if err != nil {
				t.Fatal(err)
			}
			p := res.Profile
			if p.Subject != c.subject || (c.name != "" && (p.Name == nil || *p.Name != c.name)) {
				t.Fatalf("profile %+v", p)
			}
			if c.email == "" {
				if p.Email != nil || p.EmailVerified != nil {
					t.Fatalf("unexpected email %+v", p)
				}
				return
			}
			if p.Email == nil || *p.Email != c.email || p.EmailVerified == nil || *p.EmailVerified != c.verified {
				t.Fatalf("email %v verified %v", p.Email, p.EmailVerified)
			}
		})
	}
}

// TestDescriptorEmailRules (Review Focus 1): email_verified follows the
// descriptor rule and never defaults to true. For every descriptor whose rule
// is a field, a profile with the field false or missing is unverified; only
// the rule "always" verifies without a field.
func TestDescriptorEmailRules(t *testing.T) {
	for _, d := range providers.All() {
		if d.Profile.Email == "" {
			continue
		}
		t.Run(d.Strategy, func(t *testing.T) {
			doc := map[string]any{}
			setPath(doc, d.Profile.UserID, "subject-1")
			setPath(doc, d.Profile.Email, "person@example.com")
			p, err := mapSocialProfile(d, doc, doc)
			if err != nil {
				t.Fatal(err)
			}
			if p.Email == nil || p.EmailVerified == nil {
				t.Fatalf("email not mapped: %+v", p)
			}
			if *p.EmailVerified != (d.EmailVerified.Rule == providers.EmailAlways) {
				t.Fatalf("rule %s without a verification field gave verified=%v", d.EmailVerified.Rule, *p.EmailVerified)
			}
			if d.EmailVerified.Rule == providers.EmailField {
				setPath(doc, d.EmailVerified.Path, false)
				if p, _ := mapSocialProfile(d, doc, doc); *p.EmailVerified {
					t.Fatal("field false gave verified")
				}
				setPath(doc, d.EmailVerified.Path, "yes")
				if p, _ := mapSocialProfile(d, doc, doc); *p.EmailVerified {
					t.Fatal("non-boolean field gave verified")
				}
				setPath(doc, d.EmailVerified.Path, true)
				if p, _ := mapSocialProfile(d, doc, doc); !*p.EmailVerified {
					t.Fatal("field true gave unverified")
				}
			}
		})
	}
}

// setPath writes v at a Lookup path, creating objects and a one-element
// selected array for [?field] segments.
func setPath(doc map[string]any, path string, v any) {
	segs := splitPath(path)
	cur := doc
	for i, seg := range segs {
		name, filter := seg[0], seg[1]
		last := i == len(segs)-1
		if filter != "" {
			list, _ := cur[name].([]any)
			if len(list) == 0 {
				list = []any{map[string]any{filter: true}}
				cur[name] = list
			}
			cur = list[0].(map[string]any)
			continue
		}
		if last {
			cur[name] = v
			return
		}
		next, ok := cur[name].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[name] = next
		}
		cur = next
	}
}

func splitPath(path string) [][2]string {
	var out [][2]string
	for _, seg := range splitDots(path) {
		if i := indexOf(seg, "[?"); i >= 0 {
			out = append(out, [2]string{seg[:i], seg[i+2 : len(seg)-1]})
		} else {
			out = append(out, [2]string{seg, ""})
		}
	}
	return out
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestFacebookAppSecretProof(t *testing.T) {
	c := tier1Cases[0]
	f := c.fixture(t)
	ps := f.providers()
	cfg := socConfig(t, "facebook", "")
	e, _ := ps.SocialEndpoints(cfg, "")
	if _, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime}); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(f.queries["/facebook/v24.0/me"])
	mac := hmac.New(sha256.New, []byte(socTestSecret))
	mac.Write([]byte(socTestToken))
	if q.Get("appsecret_proof") != hex.EncodeToString(mac.Sum(nil)) || q.Get("fields") != "id,name,first_name,last_name,email,picture" {
		t.Fatalf("graph query %v", q)
	}
}

func TestLinkedInRetiredVersionsRefused(t *testing.T) {
	ps := NewProviders(NetworkPolicy{}, nil)
	for _, v := range []string{"1", "2"} {
		cfg := socConfig(t, "linkedin", `,"strategy_version":`+v)
		if _, err := ps.SocialEndpoints(cfg, ""); !errors.Is(err, ErrConnectionUnusable) {
			t.Fatalf("strategy_version %s: %v", v, err)
		}
	}
	if _, err := ps.SocialEndpoints(socConfig(t, "linkedin", `,"strategy_version":3`), ""); err != nil {
		t.Fatal(err)
	}
}

// TestSalesforceIdentityURL: the profile is read from the token response's
// identity URL only when it is https on the token endpoint's host
// (LR39b-7); anything else is refused before any profile call.
func TestSalesforceIdentityURL(t *testing.T) {
	for name, id := range map[string]string{
		"other host": `"https://evil.example/id/00D/005"`,
		"http":       `"{http}/salesforce/id/00D/005"`,
		"missing":    ``,
		"not string": `42`,
		"userinfo":   `"https://user@{host}/salesforce/id/00D/005"`,
		"relative":   `"/salesforce/id/00D/005"`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newSocFixture(t)
			host := strings.TrimPrefix(f.srv.URL, "https://")
			id = strings.NewReplacer("{http}", "http://"+host, "{host}", host).Replace(id)
			body := `{"access_token":"` + socTestToken + `","token_type":"Bearer"`
			if id != "" {
				body += `,"id":` + id
			}
			f.on("/salesforce/services/oauth2/token", jsonHandler(200, body+"}"))
			f.on("/salesforce/id/00D/005", jsonHandler(200, `{"user_id":"005"}`))
			ps := f.providers()
			cfg := socConfig(t, "salesforce", "")
			e, _ := ps.SocialEndpoints(cfg, "")
			_, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
			if !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("err %v", err)
			}
			if f.calls["/salesforce/id/00D/005"] != 0 {
				t.Fatal("profile fetched from a refused identity URL")
			}
			socNoSecrets(t, err)
		})
	}
}

func TestSalesforceCommunityEndpoints(t *testing.T) {
	ps := NewProviders(NetworkPolicy{}, nil)
	e, err := ps.SocialEndpoints(socConfig(t, "salesforce-community", `,"community_base_url":"https://community.example.com/partners"`), "")
	if err != nil {
		t.Fatal(err)
	}
	if e.AuthorizationURL != "https://community.example.com/partners/services/oauth2/authorize" || e.TokenURL != "https://community.example.com/partners/services/oauth2/token" {
		t.Fatalf("endpoints %+v", e)
	}
}

func TestLineEmailClaims(t *testing.T) {
	c := tier1Cases[indexOfCase("line")]
	for name, verify := range map[string]string{
		"wrong audience": `{"iss":"https://access.line.me","sub":"U4af4980629","aud":"someone-else","email":"line@example.com"}`,
		"wrong issuer":   `{"iss":"https://evil.example","sub":"U4af4980629","aud":"throwaway-client","email":"line@example.com"}`,
		"wrong subject":  `{"iss":"https://access.line.me","sub":"Uother","aud":"throwaway-client","email":"line@example.com"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c.extra = map[string]string{"/line/oauth2/v2.1/verify": verify}
			f := c.fixture(t)
			ps := f.providers()
			cfg := socConfig(t, "line", c.options)
			e, _ := ps.SocialEndpoints(cfg, "")
			_, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
			if !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("err %v", err)
			}
		})
	}
	// With email off no verify call is made and no email is set.
	c.extra = nil
	f := c.fixture(t)
	ps := f.providers()
	cfg := socConfig(t, "line", "")
	e, _ := ps.SocialEndpoints(cfg, "")
	res, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime})
	if err != nil || res.Profile.Email != nil || f.calls["/line/oauth2/v2.1/verify"] != 0 {
		t.Fatalf("email off: %+v %v", res.Profile, err)
	}
	if form := f.forms["/line/oauth2/v2.1/token"]; form.Get("code_verifier") != "verifier-1" {
		t.Fatalf("line token form %v", form)
	}
}

func indexOfCase(strategy string) int {
	for i, c := range tier1Cases {
		if c.strategy == strategy {
			return i
		}
	}
	panic(strategy)
}

// TestShopifyShop (LR39b-8, SP-9): the shop comes only from login_hint and
// must be a myshopify.com shop name; its endpoints are built from it.
func TestShopifyShop(t *testing.T) {
	ps := NewProviders(NetworkPolicy{}, nil)
	cfg := socConfig(t, "shopify", "")
	for hint, want := range map[string]string{"my-shop": "my-shop.myshopify.com", "My-Shop.myshopify.com": "my-shop.myshopify.com", "shop1": "shop1.myshopify.com"} {
		e, err := ps.SocialEndpoints(cfg, hint)
		if err != nil {
			t.Fatalf("%s: %v", hint, err)
		}
		if e.AuthorizationURL != "https://"+want+"/admin/oauth/authorize" || e.TokenURL != "https://"+want+"/admin/oauth/access_token" ||
			e.UserInfoURL != "https://"+want+"/admin/api/2025-10/shop.json" {
			t.Fatalf("%s: %+v", hint, e)
		}
	}
	for _, hint := range []string{"", "-shop", "shop.example.com", "evil.com/x.myshopify.com", "a.b.myshopify.com", "shop@evil", "sh op", strings.Repeat("a", 61), "127.0.0.1", "shop.myshopify.com.evil.com"} {
		if _, err := ps.SocialEndpoints(cfg, hint); !errors.Is(err, ErrConnectionUnusable) {
			t.Fatalf("hint %q: %v", hint, err)
		}
	}
	// The access token travels in X-Shopify-Access-Token, not Authorization.
	c := tier1Cases[indexOfCase("shopify")]
	f := c.fixture(t)
	fps := f.providers()
	e, _ := fps.SocialEndpoints(cfg, "my-shop")
	if _, err := fps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", ClientSecret: socTestSecret, Now: fixedTime}); err != nil {
		t.Fatal(err)
	}
	h := f.headers["/shopify/admin/api/2025-10/shop.json"]
	if h.Get("X-Shopify-Access-Token") != socTestToken || h.Get("Authorization") != "" {
		t.Fatalf("shopify profile headers %v", h)
	}
}

func TestDropboxProfileIsPOST(t *testing.T) {
	c := tier1Cases[indexOfCase("dropbox")]
	f := newSocFixture(t)
	f.on(c.tokenPath, jsonHandler(200, c.tokenBody))
	f.on(c.profilePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonHandler(405, `{}`)(w, r)
			return
		}
		jsonHandler(200, c.profileBody)(w, r)
	})
	ps := f.providers()
	cfg := socConfig(t, "dropbox", "")
	e, _ := ps.SocialEndpoints(cfg, "")
	if _, err := ps.For(cfg).Exchange(t.Context(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "v", ClientSecret: socTestSecret, Now: fixedTime}); err != nil {
		t.Fatal(err)
	}
}
