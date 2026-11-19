package provider

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEnterpriseFrontChannelFixture(t *testing.T) {
	p, e := New("https://idp.e2e.test")
	if e != nil {
		t.Fatal(e)
	}
	if e := p.RegisterEnterprise(EnterpriseRegistration{ClientID: "front"}); e != nil {
		t.Fatal(e)
	}
	q := url.Values{"client_id": {"front"}, "redirect_uri": {"https://sdk.e2e.test/login/callback"}, "response_type": {"id_token"}, "response_mode": {"form_post"}, "state": {"state"}, "nonce": {"nonce"}, "scope": {"openid"}}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "https://idp.e2e.test/enterprise/authorize?"+q.Encode(), nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	q.Set("subject", "front-user")
	q.Set("decision", "allow")
	r := httptest.NewRequest("POST", "https://idp.e2e.test/enterprise/authorize", strings.NewReader(q.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="id_token"`) || strings.Contains(w.Body.String(), `name="code"`) || !strings.Contains(w.Body.String(), `name="state" value="state"`) || strings.Contains(w.Body.String(), `value="[`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
