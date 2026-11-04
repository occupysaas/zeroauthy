package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A Basic-authenticated client remains known when later PAR validation fails.
func TestPARBasicFailureEventAttribution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	client, err := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "par-basic")
	if err != nil {
		t.Fatal(err)
	}
	client.Name = "Basic PAR app"
	if err := f.st.Clients().Update(ctx, client); err != nil {
		t.Fatal(err)
	}
	capture := &eventRecorder{}
	f.h.Recorder = capture
	form := parForm("redirect_uri", "https://wrong.test/cb")
	form.Del("client_id")
	form.Del("client_secret")
	response, body := f.par(t, acmeHost, formType, form.Encode(), "par-basic", "par-basic-secret")
	if response.Code != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("response=%d %v", response.Code, body)
	}
	if len(capture.events) != 1 {
		t.Fatalf("events=%+v", capture.events)
	}
	got := capture.events[0]
	if got.Type != "fpar" || got.TenantID != client.TenantID || got.ClientID != "par-basic" || got.ClientName != "Basic PAR app" || got.Hostname != acmeHost || got.IP == "" || got.UserID != "" || got.ConnectionID != "" {
		t.Fatalf("event=%+v", got)
	}
}

// Token-owned IDs must be captured before reuse/expiry checks without loading a user.
func TestRefreshFailureEventAttribution(t *testing.T) {
	for _, reason := range []string{"reuse", "expiry", "revoked", "audience", "scope", "other client", "other origin"} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			client, err := f.st.Clients().Get(ctx, tid, "rt-spa")
			if err != nil {
				t.Fatal(err)
			}
			client.Name = "Refresh app"
			if err := f.st.Clients().Update(ctx, client); err != nil {
				t.Fatal(err)
			}
			now := fixedNow()
			raw := "known-refresh-token"
			rt := &store.RefreshToken{TenantID: tid, ID: "rt_known", TokenHash: secrets.HashToken(raw), FamilyID: "rtf_known", ClientID: "rt-spa", UserID: "auth0|unloaded", OrganizationID: "org_known", OrganizationConnectionID: "con_known", Audience: acmeAPI, Scopes: []string{"openid", "offline_access", "read:things"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			form := refreshForm("rt-spa", raw)
			wantError, wantStatus := "invalid_grant", http.StatusBadRequest
			switch reason {
			case "reuse":
				rt.Rotating = true
				rt.RotatedAt = &now
			case "expiry":
				rt.ExpiresAt = now
			case "revoked":
				rt.RevokedAt = &now
			case "audience":
				form.Set("audience", "https://other.test")
				wantError, wantStatus = "invalid_request", http.StatusBadRequest
			case "scope":
				form.Set("scope", "write:things")
				wantError, wantStatus = "invalid_scope", http.StatusBadRequest
			case "other client":
				rt.ClientID = "other-client"
			case "other origin":
				rt.Origin = "https://foreign.test"
			}
			if err := f.st.RefreshTokens().Create(ctx, rt); err != nil {
				t.Fatal(err)
			}
			capture := &eventRecorder{}
			f.h.Recorder = capture
			status, body := f.refresh(t, form)
			if status != wantStatus || body["error"] != wantError {
				t.Fatalf("response=%d %v", status, body)
			}
			wantCount := 1
			if reason == "reuse" {
				wantCount = 2
			}
			if len(capture.events) != wantCount {
				t.Fatalf("events=%+v", capture.events)
			}
			for i, got := range capture.events {
				code := "fertft"
				if reason == "reuse" && i == 0 {
					code = "ferrt"
				}
				userID, orgID, connID := "auth0|unloaded", "org_known", "con_known"
				if reason == "other client" || reason == "other origin" {
					userID, orgID, connID = "", "", ""
				}
				if got.Type != code || got.TenantID != tid || got.ClientID != "rt-spa" || got.ClientName != "Refresh app" || got.UserID != userID || got.OrganizationID != orgID || got.ConnectionID != connID || got.UserName != "" || got.Connection != "" || got.Strategy != "" || got.StrategyType != "" {
					t.Fatalf("event=%+v", got)
				}
			}
		})
	}
}
