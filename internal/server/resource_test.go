package server

import (
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestRPLogoutEnqueuesBackchannel(t *testing.T) {
	var service *logout.Service
	e := newFlowEnvSeed(t, flowSeed, func(d *Deps) {
		service = &logout.Service{Store: d.Store, Keys: d.Keys, Wrapper: d.Wrapper}
		d.Logout = service
	})
	client := e.client(t)
	tn, err := e.st.Tenants().GetByName(t.Context(), "flow")
	if err != nil {
		t.Fatal(err)
	}
	rp, err := e.st.Clients().Get(t.Context(), tn.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	rp.OIDCLogout = &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}}
	if err := e.st.Clients().Update(t.Context(), rp); err != nil {
		t.Fatal(err)
	}
	e.codeFlow(t, client)
	resp, _ := fetch(t, client, e.base+"/v2/logout?client_id=spa")
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		t.Fatalf("logout status=%d", resp.StatusCode)
	}
	jobs, err := e.st.Actions().ClaimJobs(t.Context(), time.Now().UTC(), time.Minute, 10)
	if err != nil || len(jobs) != 1 || jobs[0].Trigger != logout.JobKind {
		t.Fatalf("logout notifications=%d err=%v", len(jobs), err)
	}
}
