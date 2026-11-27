package federation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/oauth1sig"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const (
	o1ConsumerSecret = "throwaway-consumer-secret"
	o1RequestToken   = "throwaway-request-token"
	o1RequestSecret  = "throwaway-request-token-secret"
	o1AccessToken    = "throwaway-access-token"
	o1AccessSecret   = "throwaway-access-token-secret"
	o1Verifier       = "throwaway-verifier"
)

func TestParseCallbackOAuth1(t *testing.T) {
	p, err := ParseCallback("oauth_token=rt&oauth_verifier=v")
	if err != nil || !p.OAuth1 || p.State != "rt" || p.Code != "v" || p.Error != "" {
		t.Fatalf("callback %+v %v", p, err)
	}
	p, err = ParseCallback("denied=rt")
	if err != nil || !p.OAuth1 || p.State != "rt" || p.Error != "access_denied" {
		t.Fatalf("denied %+v %v", p, err)
	}
	for _, q := range []string{"oauth_token=rt", "oauth_verifier=v", "state=s&oauth_token=rt&oauth_verifier=v", "oauth_token=rt&oauth_verifier=v&code=c", "oauth_token=a&oauth_token=b&oauth_verifier=v"} {
		if _, err := ParseCallback(q); !errors.Is(err, ErrCallbackRejected) {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if p, err := ParseCallback("state=s&code=c"); err != nil || p.OAuth1 {
		t.Fatalf("oauth2 callback %+v %v", p, err)
	}
}

// o1Fixture serves the OAuth 1.0a endpoints of a generic oauth1 connection
// under <srv>/oauth1 and checks every signature with the consumer secret.
type o1Fixture struct {
	*socFixture
	t        *testing.T
	sigFails int
}

func newO1Fixture(t *testing.T) *o1Fixture {
	f := &o1Fixture{socFixture: newSocFixture(t), t: t}
	f.on("/oauth1/oauth/request_token", func(w http.ResponseWriter, r *http.Request) {
		p := f.verify(r, "")
		if p["oauth_callback"] != "https://login.example/login/callback" || p["oauth_token"] != "" {
			f.sigFails++
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("oauth_token=" + o1RequestToken + "&oauth_token_secret=" + o1RequestSecret + "&oauth_callback_confirmed=true"))
	})
	f.on("/oauth1/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		p := f.verify(r, o1RequestSecret)
		if p["oauth_token"] != o1RequestToken || p["oauth_verifier"] != o1Verifier {
			f.sigFails++
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte("oauth_token=" + o1AccessToken + "&oauth_token_secret=" + o1AccessSecret + "&user_id=42&screen_name=someone"))
	})
	return f
}

// verify checks the request's OAuth signature and returns its parameters.
func (f *o1Fixture) verify(r *http.Request, tokenSecret string) map[string]string {
	h := r.Header.Get("Authorization")
	p := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(h, "OAuth "), ", ") {
		k, v, _ := strings.Cut(part, "=")
		v, _ = url.QueryUnescape(strings.Trim(v, `"`))
		p[k] = v
	}
	sig := p["oauth_signature"]
	delete(p, "oauth_signature")
	creds := oauth1sig.Credentials{ConsumerKey: p["oauth_consumer_key"], ConsumerSecret: o1ConsumerSecret, TokenSecret: tokenSecret}
	_ = r.ParseForm()
	want, _ := oauth1sig.Sign(creds, r.Method, "https://"+r.Host+r.URL.RequestURI(), r.PostForm, p)
	if sig == "" || sig != want || p["oauth_consumer_key"] != "consumer-key" {
		f.sigFails++
	}
	return p
}

type o1FlowEnv struct {
	*socFlowEnv
	exec *fakeExecutor
}

func newO1FlowEnv(t *testing.T, f *o1Fixture) *o1FlowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	_ = st.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten"})
	_ = st.Clients().Create(ctx, &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true, GrantTypes: []string{"authorization_code"}})
	spec := connrules.Spec{Name: "o1", Strategy: StrategyOAuth1, EnabledClients: []string{"client"}, Options: connrules.Options{Extra: map[string]any{
		"client_id": "consumer-key", "requestTokenURL": "https://provider.example/oauth/request_token",
		"accessTokenURL": "https://provider.example/oauth/access_token", "userAuthorizationURL": "https://provider.example/oauth/authorize?force_login=true",
		"scripts": map[string]any{"fetchUserProfile": "function fetchUserProfile(t, s, c, cb) {}"}}}}
	c := &store.Connection{TenantID: "ten", ID: "con_o1", FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed, _ = SealCredentials(w, "ten", c.ID, Credentials{ClientSecret: o1ConsumerSecret})
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	ex := &fakeExecutor{out: `{"user_id":"42","name":"Some One","nickname":"someone"}`}
	svc := &FlowService{Service: Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, Store: st, Providers: f.providers().WithScripts(ex)}
	return &o1FlowEnv{socFlowEnv: &socFlowEnv{ctx: ctx, st: st, svc: svc, conn: c}, exec: ex}
}

func (e *o1FlowEnv) callback(t *testing.T, begun *Begun, query string) (*Completion, error) {
	t.Helper()
	p, err := ParseCallback(query)
	if err != nil {
		return nil, err
	}
	return e.svc.Complete(e.ctx, CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Params: p, CookieValue: begun.CookieValue})
}

func TestOAuth1Flow(t *testing.T) {
	f := newO1Fixture(t)
	e := newO1FlowEnv(t, f)
	begun, err := e.begin(t, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(begun.URL)
	if u.Path != "/oauth1/oauth/authorize" || u.Query().Get("oauth_token") != o1RequestToken || u.Query().Get("force_login") != "true" {
		t.Fatalf("authorize redirect %s", begun.URL)
	}
	// The request-token secret is sealed: no stored attempt byte carries it.
	attempts, _ := e.st.Federation().GetAttempt(e.ctx, "ten", StateHash(o1RequestToken))
	if attempts == nil || bytes.Contains(attempts.SealedProof, []byte(o1RequestSecret)) || strings.Contains(fmt.Sprintf("%+v", attempts), o1RequestSecret) {
		t.Fatalf("attempt %+v", attempts)
	}
	done, err := e.callback(t, begun, "oauth_token="+o1RequestToken+"&oauth_verifier="+o1Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if f.sigFails != 0 {
		t.Fatalf("%d signature failures", f.sigFails)
	}
	if done.UserID != "oauth1|o1|42" {
		t.Fatalf("user %s", done.UserID)
	}
	r := e.exec.last
	if r.AccessToken != o1AccessToken || r.TokenSecret != o1AccessSecret || r.OAuth1 == nil || r.OAuth1.ConsumerSecret != o1ConsumerSecret ||
		r.OAuth1.Token != o1AccessToken || r.OAuth1.TokenSecret != o1AccessSecret || r.Context["screen_name"] != "someone" || r.Context["user_id"] != "42" {
		t.Fatalf("script request %+v", r)
	}
	for _, k := range []string{"oauth_token", "oauth_token_secret"} {
		if _, ok := r.Context[k]; ok {
			t.Fatalf("context carries %s", k)
		}
	}
	sealed, err := e.st.Federation().GetTokens(e.ctx, store.FederatedIdentityKey{TenantID: "ten", ConnectionID: "con_o1", Subject: "42"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := OpenTokens(e.svc.Wrapper, store.FederatedIdentityKey{TenantID: "ten", ConnectionID: "con_o1", Subject: "42"}, sealed)
	if err != nil || tok.AccessToken != o1AccessToken || tok.TokenSecret != o1AccessSecret {
		t.Fatalf("stored tokens %+v %v", tok, err)
	}
}

func TestOAuth1CallbackChecks(t *testing.T) {
	for name, query := range map[string]func(string) string{
		"verifier wrong":   func(rt string) string { return "oauth_token=" + rt + "&oauth_verifier=wrong" },
		"token mismatch":   func(string) string { return "oauth_token=other-token&oauth_verifier=" + o1Verifier },
		"denied":           func(rt string) string { return "denied=" + rt },
		"oauth2 callback":  func(rt string) string { return "state=" + rt + "&code=x" },
		"verifier missing": func(rt string) string { return "oauth_token=" + rt },
	} {
		t.Run(name, func(t *testing.T) {
			f := newO1Fixture(t)
			e := newO1FlowEnv(t, f)
			begun, err := e.begin(t, "")
			if err != nil {
				t.Fatal(err)
			}
			done, err := e.callback(t, begun, query(o1RequestToken))
			if err == nil {
				t.Fatalf("login succeeded: %+v", done)
			}
			for _, s := range []string{o1RequestSecret, o1ConsumerSecret, o1AccessSecret} {
				if strings.Contains(err.Error(), s) {
					t.Fatalf("error leaks %s", s)
				}
			}
		})
	}
}

func TestOAuth1RequestTokenRefused(t *testing.T) {
	for name, body := range map[string]string{
		"not confirmed": "oauth_token=" + o1RequestToken + "&oauth_token_secret=" + o1RequestSecret,
		"no secret":     "oauth_token=" + o1RequestToken + "&oauth_callback_confirmed=true",
		"no token":      "oauth_token_secret=" + o1RequestSecret + "&oauth_callback_confirmed=true",
	} {
		t.Run(name, func(t *testing.T) {
			f := newO1Fixture(t)
			f.on("/oauth1/oauth/request_token", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
			e := newO1FlowEnv(t, f)
			if _, err := e.begin(t, ""); !errors.Is(err, ErrProviderResponse) || strings.Contains(err.Error(), o1RequestSecret) {
				t.Fatalf("begin: %v", err)
			}
		})
	}
	f := newO1Fixture(t)
	e := newO1FlowEnv(t, f)
	e.svc.Store = predecessorStore{e.st}
	if _, err := e.begin(t, ""); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("begin on a store without social.v1: %v", err)
	}
}
