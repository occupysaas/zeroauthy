package federation

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// evernoteFixture serves Evernote's single /oauth endpoint (request and
// access token) under <srv>/<strategy>, with Evernote's empty secrets.
func evernoteFixture(t *testing.T, strategy string) *o1Fixture {
	f := &o1Fixture{socFixture: newSocFixture(t), t: t, consumer: "throwaway-client", secret: socTestSecret}
	f.on("/"+strategy+"/oauth", func(w http.ResponseWriter, r *http.Request) {
		p := f.verify(r, "")
		if p["oauth_verifier"] == "" {
			if p["oauth_callback"] != "https://login.example/login/callback" {
				f.sigFails++
			}
			_, _ = w.Write([]byte("oauth_token=" + o1RequestToken + "&oauth_token_secret=&oauth_callback_confirmed=true"))
			return
		}
		if p["oauth_token"] != o1RequestToken || p["oauth_verifier"] != o1Verifier {
			f.sigFails++
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte("oauth_token=S%3Ds1%3AU%3D7b%3AE%3Dthrowaway&oauth_token_secret=&edam_shard=s1&edam_userId=123&edam_expires=1893456000000&edam_noteStoreUrl=https%3A%2F%2Fwww.evernote.com%2Fshard%2Fs1%2Fnotestore"))
	})
	return f
}

func TestEvernoteFlow(t *testing.T) {
	for _, strategy := range []string{"evernote", "evernote-sandbox"} {
		t.Run(strategy, func(t *testing.T) {
			f := evernoteFixture(t, strategy)
			e := newSocFlowEnv(t, f.socFixture, strategy, nil)
			begun, err := e.begin(t, "")
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(begun.URL)
			if u.Path != "/"+strategy+"/OAuth.action" || u.Query().Get("oauth_token") != o1RequestToken {
				t.Fatalf("authorize %s", begun.URL)
			}
			p, _ := ParseCallback("oauth_token=" + o1RequestToken + "&oauth_verifier=" + o1Verifier)
			done, err := e.svc.Complete(e.ctx, CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Params: p, CookieValue: begun.CookieValue})
			if err != nil {
				t.Fatal(err)
			}
			if f.sigFails != 0 || done.UserID != strategy+"|123" {
				t.Fatalf("user %s, %d signature failures", done.UserID, f.sigFails)
			}
			usr, _ := e.st.Users().Get(e.ctx, "ten", done.UserID)
			if usr.Email != "" {
				t.Fatalf("email %q", usr.Email)
			}
		})
	}
}

// TestEvernoteEmptySecret (Review Focus 5): an empty token secret is
// accepted only by descriptors that declare it; generic oauth1 and Twitter
// still refuse it.
func TestEvernoteEmptySecret(t *testing.T) {
	f := newO1Fixture(t)
	f.on("/oauth1/oauth/request_token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("oauth_token=" + o1RequestToken + "&oauth_token_secret=&oauth_callback_confirmed=true"))
	})
	e := newO1FlowEnv(t, f)
	if _, err := e.begin(t, ""); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("generic oauth1 with an empty request secret: %v", err)
	}
	tw := newO1FixtureAt(t, "twitter", "throwaway-client", socTestSecret)
	tw.on("/twitter/oauth/request_token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("oauth_token=" + o1RequestToken + "&oauth_token_secret=&oauth_callback_confirmed=true"))
	})
	te := newSocFlowEnv(t, tw.socFixture, "twitter", map[string]any{"protocol": "oauth1"})
	if _, err := te.begin(t, ""); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("twitter oauth1 with an empty request secret: %v", err)
	}
}
