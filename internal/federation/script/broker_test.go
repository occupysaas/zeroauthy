package script

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// loopbackClient reaches local fixtures; production brokers get the
// federation transport client.
func loopbackClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func tlsClient(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }
	return c
}

// refusingTransport stands in for the federation network policy.
type refusingTransport struct{ hits atomic.Int32 }

func (rt *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	return nil, errors.New("federation: outbound request refused by network policy")
}

func TestScriptBroker(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	r := newTestRunner(t, tlsClient(api))

	t.Run("four call limit", func(t *testing.T) {
		hits.Store(0)
		m, err := run(t, r, `function fetchUserProfile(a, c, cb) {
			let n = 0, failed = 0;
			const next = () => request.get({url: '`+api.URL+`/x'}, (e) => { if (e) failed++; else n++; if (n + failed < 5) next(); else cb(null, {user_id: n + '/' + failed}); });
			next();
		}`)
		if err != nil || m["user_id"] != "4/1" || hits.Load() != 4 {
			t.Fatalf("%v %v hits=%d", m, err, hits.Load())
		}
	})
	t.Run("redirect refused", func(t *testing.T) {
		m, err := run(t, r, `function fetchUserProfile(a, c, cb) {
			request.get({url: '`+api.URL+`/redirect'}, (e, resp) => cb(null, {user_id: e ? 'refused' : String(resp.statusCode)}));
		}`)
		if err != nil || m["user_id"] != "refused" {
			t.Fatalf("%v %v", m, err)
		}
	})
	t.Run("policy refusal surfaces as a request error", func(t *testing.T) {
		rt := &refusingTransport{}
		pr := newTestRunner(t, &http.Client{Transport: rt})
		m, err := run(t, pr, `function fetchUserProfile(a, c, cb) {
			request.get({url: 'https://internal.example/meta'}, (e) => cb(null, {user_id: e ? 'refused' : 'reached'}));
		}`)
		if err != nil || m["user_id"] != "refused" || rt.hits.Load() != 1 {
			t.Fatalf("%v %v", m, err)
		}
	})
	t.Run("literal https targets only", func(t *testing.T) {
		b := NewBroker(tlsClient(api))
		for _, u := range []string{"ftp://x.example/a", "https://user:pw@x.example/a", "https://x.example/a#f", "/relative", "javascript:alert(1)"} {
			if _, err := b.get(context.Background(), &execution{}, GetOptions{URL: u}); !errors.Is(err, ErrBroker) {
				t.Errorf("%s: %v", u, err)
			}
		}
		if _, err := b.get(context.Background(), &execution{}, GetOptions{URL: api.URL, Headers: map[string]string{"Bad\nHeader": "x"}}); !errors.Is(err, ErrBroker) {
			t.Errorf("header injection: %v", err)
		}
	})
	t.Run("logs discarded", func(t *testing.T) {
		raw, err := r.Execute(context.Background(), Request{TenantID: "t", Source: `function fetchUserProfile(a, c, cb) {
			console.log('token', a); console.error(a); cb(null, {user_id: 'x'});
		}`, AccessToken: "upstream-access-token"})
		if err != nil || strings.Contains(string(raw), "upstream-access-token") {
			t.Fatalf("%s %v", raw, err)
		}
	})
}
