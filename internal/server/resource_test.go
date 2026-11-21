package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRepeatedResourceThroughGeneratedRouter(t *testing.T) {
	e := newFlowEnv(t)
	client := e.client(t)
	tn, err := e.st.Tenants().GetByName(t.Context(), "flow")
	if err != nil {
		t.Fatal(err)
	}
	tn.SettingsExtra = map[string]any{"resource_parameter_profile": "compatibility"}
	if err := e.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(authorizeURL(e.base))
	q := target.Query()
	q["resource"] = []string{"https://api.flow.test", "https://api.flow.test"}
	for _, method := range []string{"GET", "POST"} {
		var req *http.Request
		if method == "GET" {
			target.RawQuery = q.Encode()
			req, _ = http.NewRequest(method, target.String(), nil)
		} else {
			req, _ = http.NewRequest(method, e.base+"/authorize", strings.NewReader(q.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, _ := mustDo(t, client, req)
		location, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || location.Query().Get("error") != "invalid_target" {
			t.Fatalf("%s repeated resources: status=%d location=%s", method, resp.StatusCode, location)
		}
	}
}
