package server

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestManagementMFARoutesScopedAndMounted(t *testing.T) {
	scopes := []string{}
	for _, route := range mfarules.Inventory().Routes {
		if strings.HasPrefix(route.Path, "/guardian") || strings.HasPrefix(route.Path, "/users") {
			for _, scope := range route.Scopes {
				if !slices.Contains(scopes, scope) {
					scopes = append(scopes, scope)
				}
			}
		}
	}
	raw, _ := json.Marshal(scopes)
	seed := strings.Replace(usersSeed, `scopes: ["read:users",`, "scopes: ["+string(raw[1:len(raw)-1])+`, "read:users",`, 1)
	h, st := newMgmtEnvOn(t, memory.New(), seed, nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "users", "users-s3cret")
	restricted := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "usersro", "usersro-s3cret")
	for _, route := range mfarules.Inventory().Routes {
		if !strings.HasPrefix(route.Path, "/guardian") && !strings.HasPrefix(route.Path, "/users") {
			continue
		}
		t.Run(route.Operation, func(t *testing.T) {
			path := strings.ReplaceAll(route.Path, "{id}", "auth0|missing")
			path = strings.ReplaceAll(path, "{name}", "otp")
			path = strings.ReplaceAll(path, "{provider}", "google-authenticator")
			path = strings.ReplaceAll(path, "{authentication_method_id}", "email|dev_12345678901234567890")
			req := httptest.NewRequest(route.Method, "https://acme.example.test/api/v2"+path, bytes.NewBufferString(`{}`))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == 401 || rec.Code == 403 || rec.Code == 501 || rec.Code >= 500 {
				t.Fatalf("route missing/unscoped: %d %s", rec.Code, rec.Body)
			}
			if !slices.Contains(route.Scopes, "read:users") && !slices.Contains(route.Scopes, "update:users") {
				denied := httptest.NewRequest(route.Method, "https://acme.example.test/api/v2"+path, bytes.NewBufferString(`{}`))
				denied.Header.Set("Authorization", "Bearer "+restricted)
				deniedRec := httptest.NewRecorder()
				h.ServeHTTP(deniedRec, denied)
				if deniedRec.Code != 403 {
					t.Fatalf("missing exact scope: %d %s", deniedRec.Code, deniedRec.Body)
				}
			}
			req = httptest.NewRequest(route.Method, "https://acme.example.test/api/v2"+path, bytes.NewBufferString(`{}`))
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Fatalf("route without bearer: %d", rec.Code)
			}
		})
	}
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := st.ClientGrants().Find(context.Background(), tn.ID, "users", acmeMgmtAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	grant.Scopes = []string{}
	if err = st.ClientGrants().Update(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://acme.example.test/api/v2/guardian/factors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("stale grant kept MFA scope: %d %s", rec.Code, rec.Body)
	}

}
