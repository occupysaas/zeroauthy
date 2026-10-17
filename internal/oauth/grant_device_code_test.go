package oauth

import (
	"context"
	"net/url"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// newDeviceCode creates a device code for client in the store and returns
// its device_code value and hash. At is the fixture clock.
func (f *fixture) newDeviceCode(t *testing.T, clientID string, status store.DeviceCodeStatus, userID string, granted []string) (string, string) {
	t.Helper()
	raw := secrets.RandomString(24)
	hash := secrets.HashToken(raw)
	d := &store.DeviceCode{
		TenantID: f.tenantID(t, "acme"), DeviceCodeHash: hash, UserCodeHash: "uc-" + hash, ClientID: clientID,
		Scopes: []string{"openid", "offline_access"}, Audience: acmeAPI, Status: store.DeviceCodePending,
		ExpiresAt: fixedNow().Add(DeviceCodeLifetime), CreatedAt: fixedNow(),
	}
	if err := f.st.DeviceCodes().Create(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if status != store.DeviceCodePending {
		if _, err := f.st.DeviceCodes().Decide(context.Background(), d.TenantID, hash, store.DeviceDecision{Status: status, UserID: userID, GrantedScopes: granted}); err != nil {
			t.Fatal(err)
		}
	}
	return raw, hash
}

func (f *fixture) aliceID(t *testing.T) string {
	t.Helper()
	u, err := f.st.Users().FindByLogin(context.Background(), f.tenantID(t, "acme"), "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	return u.UserID
}

func deviceForm(clientID, code string) url.Values {
	return url.Values{"grant_type": {GrantDeviceCode}, "client_id": {clientID}, "device_code": {code}}
}

// pollAt polls with the handlers' clock set to at.
func (f *fixture) pollAt(t *testing.T, at time.Time, form url.Values) (int, map[string]any) {
	t.Helper()
	f.h.Now = func() time.Time { return at }
	f.h.Minter.Now = f.h.Now
	rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form})
	return rec.Code, body
}

func wantErr(t *testing.T, code int, body map[string]any, status int, errCode string) {
	t.Helper()
	if code != status || body["error"] != errCode {
		t.Fatalf("got %d %v, want %d %s", code, body, status, errCode)
	}
}

func TestDeviceGrantPending(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodePending, "", nil)
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "authorization_pending")
}

func TestDeviceGrantSlowDown(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodePending, "", nil)
	f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	code, body := f.pollAt(t, fixedNow().Add(300*time.Millisecond), deviceForm("dev", raw))
	wantErr(t, code, body, 429, "slow_down")
	if _, ok := body["interval"]; ok {
		t.Fatalf("body %v", body)
	}
	code, body = f.pollAt(t, fixedNow().Add(time.Second), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "authorization_pending")
}

func TestDeviceGrantDenied(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeDenied, f.aliceID(t), nil)
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "access_denied")
	code, body = f.pollAt(t, fixedNow().Add(2*time.Second), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "invalid_grant")
}

func TestDeviceGrantExpired(t *testing.T) {
	f := newFixture(t)
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodePending, "", nil)
	at := fixedNow().Add(DeviceCodeLifetime)
	code, body := f.pollAt(t, at, deviceForm("dev", raw))
	wantErr(t, code, body, 403, "expired_token")
	code, body = f.pollAt(t, at.Add(2*time.Second), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "invalid_grant")
}

func TestDeviceGrantUnknown(t *testing.T) {
	f := newFixture(t)
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", "nope"))
	wantErr(t, code, body, 403, "invalid_grant")
}

func TestDeviceGrantMissingDeviceCode(t *testing.T) {
	f := newFixture(t)
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", ""))
	wantErr(t, code, body, 400, "invalid_request")
}

func TestDeviceGrantOtherClient(t *testing.T) {
	f := newFixture(t)
	tenantID := f.tenantID(t, "acme")
	c, err := f.st.Clients().Get(context.Background(), tenantID, "dev")
	if err != nil {
		t.Fatal(err)
	}
	c.ClientID = "dev2"
	if err := f.st.Clients().Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	raw, hash := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid"})
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev2", raw))
	wantErr(t, code, body, 403, "invalid_grant")
	d, err := f.st.DeviceCodes().Get(context.Background(), tenantID, hash)
	if err != nil || d.Status != store.DeviceCodeApproved {
		t.Fatalf("code %+v err %v", d, err)
	}
}

func (f *fixture) approvedDevice(t *testing.T) (map[string]any, string) {
	t.Helper()
	raw, hash := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid", "offline_access"})
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	if code != 200 {
		t.Fatalf("status %d %v", code, body)
	}
	return body, hash
}

func TestDeviceGrantIssues(t *testing.T) {
	f := newFixture(t)
	tenantID := f.tenantID(t, "acme")
	raw, hash := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid", "offline_access"})
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	if code != 200 {
		t.Fatalf("status %d %v", code, body)
	}
	at, _ := verifyToken(t, f.keys, tenantID, body["access_token"].(string))
	aud, _ := at["aud"].([]any)
	if len(aud) != 2 || aud[0] != acmeAPI || aud[1] != "https://acme.example.test/userinfo" || at["gty"] != nil || at["azp"] != "dev" {
		t.Fatalf("access token %v", at)
	}
	idt, _ := verifyToken(t, f.keys, tenantID, body["id_token"].(string))
	var keys []string
	for k := range idt {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !slices.Equal(keys, []string{"aud", "exp", "iat", "iss", "sub"}) {
		t.Fatalf("id token claims %v", idt)
	}
	rt := f.storedRT(t, body["refresh_token"].(string))
	if rt.FamilyID != familyForDevice(hash) || rt.SessionID != "" || !rt.AuthTime.IsZero() {
		t.Fatalf("refresh token %+v", rt)
	}
	code, body = f.pollAt(t, fixedNow().Add(2*time.Second), deviceForm("dev", raw))
	wantErr(t, code, body, 403, "invalid_grant")
}

func TestDeviceGrantRefreshRotates(t *testing.T) {
	f := newFixture(t)
	body, _ := f.approvedDevice(t)
	first := body["refresh_token"].(string)
	code, next := f.refresh(t, refreshForm("dev", first))
	if code != 200 || next["refresh_token"] == nil || next["refresh_token"] == first {
		t.Fatalf("status %d %v", code, next)
	}
}

func TestRefreshOfDeviceTokenHasNoSid(t *testing.T) {
	f := newFixture(t)
	body, _ := f.approvedDevice(t)
	code, next := f.refresh(t, refreshForm("dev", body["refresh_token"].(string)))
	if code != 200 {
		t.Fatalf("status %d %v", code, next)
	}
	idt, _ := verifyToken(t, f.keys, f.tenantID(t, "acme"), next["id_token"].(string))
	if idt["sid"] != nil || idt["auth_time"] != nil {
		t.Fatalf("id token %v", idt)
	}
}

func TestDeviceGrantBlockedUser(t *testing.T) {
	f := newFixture(t)
	tenantID := f.tenantID(t, "acme")
	carol, err := f.st.Users().FindByLogin(context.Background(), tenantID, "Username-Password-Authentication", "carol@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, carol.UserID, []string{"openid"})
	code, body := f.pollAt(t, fixedNow(), deviceForm("dev", raw))
	if code == 200 || body["error"] == nil {
		t.Fatalf("got %d %v", code, body)
	}
}
