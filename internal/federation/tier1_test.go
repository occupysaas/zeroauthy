package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
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
}

func (c tier1Case) fixture(t *testing.T) *socFixture {
	f := newSocFixture(t)
	f.on(c.tokenPath, jsonHandler(200, c.tokenBody))
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
