package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func (f *fixture) deviceCode(t *testing.T, host, contentType, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	h := contract.WrapResponses(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthDeviceCode)))
	req := httptest.NewRequest("POST", "https://"+host+"/oauth/device/code", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

const acmeHost = "acme.example.test"

func TestDeviceCodeIssues(t *testing.T) {
	f := newFixture(t)
	rec, body := f.deviceCode(t, acmeHost, formType, url.Values{
		"client_id": {"dev"}, "scope": {"openid offline_access"}, "audience": {"https://api.acme.test"}}.Encode())
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d headers %v body %v", rec.Code, rec.Header(), body)
	}
	dc, _ := body["device_code"].(string)
	uc, _ := body["user_code"].(string)
	if len(dc) != 24 || !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(uc) {
		t.Fatalf("codes %q %q", dc, uc)
	}
	uri := "https://acme.example.test/activate"
	if body["verification_uri"] != uri || body["verification_uri_complete"] != uri+"?user_code="+url.QueryEscape(uc) ||
		body["expires_in"] != float64(900) || body["interval"] != float64(5) {
		t.Fatalf("body %v", body)
	}
	d, err := f.st.DeviceCodes().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(dc))
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != store.DeviceCodePending || !reflect.DeepEqual(d.Scopes, []string{"openid", "offline_access"}) ||
		d.Audience != "https://api.acme.test" || d.ClientID != "dev" || d.UserCodeHash == uc || d.DeviceCodeHash == dc ||
		!d.ExpiresAt.Equal(fixedNow().Add(DeviceCodeLifetime)) || !d.CreatedAt.Equal(fixedNow()) {
		t.Fatalf("stored %+v", d)
	}
}

func TestDeviceCodeEmptyAudienceIsAbsent(t *testing.T) {
	f := newFixture(t)
	rec, body := f.deviceCode(t, acmeHost, formType, "client_id=dev&audience=&scope=")
	if rec.Code != 200 {
		t.Fatalf("status %d body %v", rec.Code, body)
	}
	d, err := f.st.DeviceCodes().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(body["device_code"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Audience != "https://api.acme.test" || len(d.Scopes) != 0 {
		t.Fatalf("stored %+v", d)
	}
}

func TestDeviceCodeErrors(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, body string
		status     int
		code       string
	}{
		{"unknown client", "client_id=nope", 403, "unauthorized_client"},
		{"no client", "scope=openid", 403, "unauthorized_client"},
		{"no device grant", "client_id=web&client_secret=web-secret", 403, "unauthorized_client"},
		{"secret sent", "client_id=dev&client_secret=x", 403, "unauthorized_client"},
		{"unknown audience", "client_id=dev&audience=https://nope.test", 400, "invalid_request"},
		{"deny_all", "client_id=dev&audience=https://locked.test", 400, "invalid_request"},
		{"repeated client_id", "client_id=dev&client_id=dev", 403, "unauthorized_client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := f.deviceCode(t, acmeHost, formType, tc.body)
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Fatalf("status %d body %v", rec.Code, body)
			}
		})
	}
}

// Seed validation rejects such clients; the endpoint checks again.
func TestDeviceCodeRequiresFirstPartyNative(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*store.Client)
	}{
		{"spa", func(c *store.Client) { c.AppType = store.AppTypeSPA }},
		{"third party", func(c *store.Client) { c.IsFirstParty = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			c, err := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "dev")
			if err != nil {
				t.Fatal(err)
			}
			tc.change(c)
			if err := f.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			rec, body := f.deviceCode(t, acmeHost, formType, "client_id=dev")
			if rec.Code != 403 || body["error"] != "unauthorized_client" {
				t.Fatalf("status %d body %v", rec.Code, body)
			}
		})
	}
}

func TestDeviceCodeJSONBody(t *testing.T) {
	f := newFixture(t)
	rec, body := f.deviceCode(t, acmeHost, "application/json", `{"client_id":"dev","scope":"openid"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d body %v", rec.Code, body)
	}
}

func TestDeviceCodeNoScope(t *testing.T) {
	f := newFixture(t)
	if rec, body := f.deviceCode(t, acmeHost, formType, "client_id=dev"); rec.Code != 200 {
		t.Fatalf("status %d body %v", rec.Code, body)
	}
}

type conflictDeviceCodes struct {
	store.DeviceCodes
	fail  int
	calls int
}

func (c *conflictDeviceCodes) Create(ctx context.Context, d *store.DeviceCode) error {
	c.calls++
	if c.calls <= c.fail {
		return store.ErrConflict
	}
	return c.DeviceCodes.Create(ctx, d)
}

type conflictStore struct {
	store.Store
	dc *conflictDeviceCodes
}

func (s conflictStore) DeviceCodes() store.DeviceCodes { return s.dc }

func TestDeviceCodeUserCodeCollisionRetries(t *testing.T) {
	for _, tc := range []struct {
		fail, status, calls int
	}{{1, 200, 2}, {2, 200, 3}, {3, 500, 3}} {
		f := newFixture(t)
		dc := &conflictDeviceCodes{DeviceCodes: f.st.DeviceCodes(), fail: tc.fail}
		f.h.Store = conflictStore{Store: f.st, dc: dc}
		rec, body := f.deviceCode(t, acmeHost, formType, "client_id=dev")
		if rec.Code != tc.status || dc.calls != tc.calls {
			t.Fatalf("fail=%d: status %d calls %d body %v", tc.fail, rec.Code, dc.calls, body)
		}
		if tc.status == 500 && body["error"] != "server_error" {
			t.Fatalf("body %v", body)
		}
	}
}

func TestDeviceCodeDigitsTenant(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tn, err := f.st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	tn.DeviceFlowCharset, tn.DeviceFlowMask = "digits", "***-***-***"
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	rec, body := f.deviceCode(t, acmeHost, formType, "client_id=dev")
	if rec.Code != 200 || !regexp.MustCompile(`^\d{3}-\d{3}-\d{3}$`).MatchString(body["user_code"].(string)) {
		t.Fatalf("status %d body %v", rec.Code, body)
	}
}

func TestDeviceCodeTenantMaskSafety(t *testing.T) {
	for _, mask := range []string{"", "literal", "*", "!!!!-!!!!"} {
		t.Run(mask, func(t *testing.T) {
			f := newFixture(t)
			tn, err := f.st.Tenants().GetByName(context.Background(), "acme")
			if err != nil {
				t.Fatal(err)
			}
			tn.DeviceFlowMask = mask
			tn.SettingsPresence = map[string]bool{"device_flow.mask": true}
			if err = f.st.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
			rec, out := f.deviceCode(t, acmeHost, "application/x-www-form-urlencoded", "client_id=dev&scope=openid")
			if mask == "" {
				if rec.Code != 200 {
					t.Fatalf("empty fallback: %d %s", rec.Code, rec.Body)
				}
			} else if rec.Code != 400 || out["error"] != "invalid_request" || out["device_code"] != nil {
				t.Fatalf("unsafe mask issued: %d %s", rec.Code, rec.Body)
			}
		})
	}
}
