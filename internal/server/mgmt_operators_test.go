package server

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestOperatorTenantRoutes(t *testing.T) {
	h, st := newMgmtEnv(t)
	admin, _ := operatorToken(t, st, "admin@example.test")
	scoped, id := operatorToken(t, st, "scoped@example.test")
	origin := "https://" + mgmtSystemHost
	patch := origin + "/api/system/operators/" + url.PathEscape(id)
	rec, _ := sendRaw(h, "PATCH", patch, admin, map[string]any{"tenants": []string{"acme"}})
	if rec.Code != 200 {
		t.Fatalf("PATCH = %d %s", rec.Code, rec.Body)
	}
	rec, out := sendRaw(h, "GET", origin+"/api/console/tenants", scoped, nil)
	list, _ := out.([]any)
	if rec.Code != 200 || len(list) != 1 || list[0].(map[string]any)["name"] != "acme" {
		t.Fatalf("discovery = %d %s", rec.Code, rec.Body)
	}
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/system/tenants", nil}, {"GET", "/api/system/operators", nil},
		{"POST", "/api/system/operators", map[string]any{"email": "forbidden@example.test"}},
		{"PATCH", "/api/system/operators/" + url.PathEscape(id), map[string]any{"tenants": []string{"*"}}},
		{"DELETE", "/api/system/operators/" + url.PathEscape(id), nil},
	} {
		rec, _ := sendRaw(h, call.method, origin+call.path, scoped, call.body)
		if rec.Code != 403 {
			t.Errorf("tenant-only %s %s = %d %s", call.method, call.path, rec.Code, rec.Body)
		}
	}
	rec, _ = sendRaw(h, "GET", "https://acme.example.test/api/console/tenants", scoped, nil)
	if rec.Code != 404 {
		t.Errorf("tenant host = %d", rec.Code)
	}
	rec, _ = sendRaw(h, "POST", origin+"/api/console/tenants", scoped, nil)
	if rec.Code != 403 {
		t.Errorf("POST discovery = %d", rec.Code)
	}
	rec, _ = sendRaw(h, "GET", origin+"/api/console/tenants", "", nil)
	if rec.Code != 401 {
		t.Errorf("anonymous discovery = %d", rec.Code)
	}
	m2m := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	rec, _ = sendRaw(h, "GET", origin+"/api/console/tenants", m2m, nil)
	if rec.Code != 401 {
		t.Errorf("M2M discovery = %d", rec.Code)
	}
	rec, _ = sendRaw(h, "PATCH", patch, admin, map[string]any{"tenants": []string{}})
	if rec.Code != 200 {
		t.Fatalf("shrink = %d %s", rec.Code, rec.Body)
	}
	rec, out = sendRaw(h, "GET", origin+"/api/console/tenants", scoped, nil)
	list, _ = out.([]any)
	if rec.Code != 200 || len(list) != 0 {
		t.Errorf("shrunk discovery = %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendRaw(h, "GET", "https://acme.example.test/api/v2/clients", scoped, nil)
	if rec.Code != 403 {
		t.Errorf("old token tenant request = %d", rec.Code)
	}
}

func TestSystemTenantUsersKeepLastSystemOperator(t *testing.T) {
	h, st := newMgmtEnv(t)
	admin, adminID := operatorToken(t, st, "admin@example.test")
	_, scopedID := operatorToken(t, st, "scoped@example.test")
	sys, _ := st.Tenants().GetByName(context.Background(), tenant.SystemName)
	if err := st.Operators().Upsert(context.Background(), &store.Operator{TenantID: sys.ID, UserID: scopedID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	users := "https://" + mgmtSystemHost + "/api/v2/users/"
	for _, method := range []string{"DELETE", "PATCH"} {
		rec, out := sendRaw(h, method, users+url.PathEscape(adminID), admin, map[string]any{"blocked": true})
		if rec.Code != 409 || errCode(out) != "last_operator" {
			t.Errorf("%s last system admin = %d %s", method, rec.Code, rec.Body)
		}
	}
	// Linking away the sole system-capable operator must be refused too.
	rec, out := sendRaw(h, "POST", users+url.PathEscape(scopedID)+"/identities", admin, map[string]any{"provider": "auth0", "user_id": adminID[len("auth0|"):]})
	if rec.Code != 409 || errCode(out) != "last_operator" {
		t.Errorf("link last system admin = %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendRaw(h, "DELETE", users+url.PathEscape(scopedID), admin, nil)
	if rec.Code != 204 {
		t.Errorf("delete tenant-only operator = %d %s", rec.Code, rec.Body)
	}
}

func TestOperatorTenantsBlockedAlternative(t *testing.T) {
	for _, operation := range []string{"shrink", "delete operator", "delete user", "block user"} {
		t.Run(operation, func(t *testing.T) {
			h, st := newMgmtEnv(t)
			raw, id := operatorToken(t, st, "admin@example.test")
			_, blockedID := operatorToken(t, st, "blocked@example.test")
			sys, _ := st.Tenants().GetByName(context.Background(), tenant.SystemName) // An orphaned operator row cannot keep system administration available.
			if err := st.Operators().Upsert(context.Background(), &store.Operator{TenantID: sys.ID, UserID: "auth0|missing", Tenants: []string{"*"}}); err != nil {
				t.Fatal(err)
			}

			u, err := st.Users().Get(context.Background(), sys.ID, blockedID)
			if err != nil {
				t.Fatal(err)
			}
			u.Blocked = true
			if err := st.Users().Update(context.Background(), u); err != nil {
				t.Fatal(err)
			}
			method, path, body := "PATCH", "/api/system/operators/"+url.PathEscape(id), any(map[string]any{"tenants": []string{"acme"}})
			switch operation {
			case "delete operator":
				method = "DELETE"
			case "delete user":
				method = "DELETE"
				path = "/api/v2/users/" + url.PathEscape(id)
			case "block user":
				path = "/api/v2/users/" + url.PathEscape(id)
				body = map[string]any{"blocked": true}
			}
			rec, out := sendRaw(h, method, "https://"+mgmtSystemHost+path, raw, body)
			if rec.Code != 409 || errCode(out) != "last_operator" {
				t.Fatalf("%s with blocked alternative = %d %s", operation, rec.Code, rec.Body)
			}
		})
	}
}

// All paths which can remove a usable system administrator share the tenant
// lock, including user deletion, blocking and linking as a secondary identity.
func TestOperatorTenantsConcurrentMutations(t *testing.T) {
	backends := []string{"memory", "sqlite"}
	if os.Getenv("ZA_TEST_POSTGRES_DSN") != "" {
		backends = append(backends, "postgres")
	}
	for _, backend := range backends {
		for _, other := range []string{"shrink", "delete operator", "delete user", "block user", "link user"} {
			t.Run(backend+"/"+other, func(t *testing.T) {
				var st store.Store
				switch backend {
				case "memory":
					st = memory.New()
					t.Cleanup(func() { _ = st.Close() })
				case "sqlite":
					st = openSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "operators.db"))
				case "postgres":
					st = openSQL(t, freshPostgres(t, os.Getenv("ZA_TEST_POSTGRES_DSN")))
				}
				h, _ := newMgmtEnvOn(t, st, mgmtSeed, nil)
				first, firstID := operatorToken(t, st, "first@example.test")
				second, secondID := operatorToken(t, st, "second@example.test")
				origin := "https://" + mgmtSystemHost
				method, path, body := "PATCH", "/api/system/operators/"+url.PathEscape(secondID), any(map[string]any{"tenants": []string{"acme"}})
				switch other {
				case "delete operator":
					method = "DELETE"
				case "delete user":
					method = "DELETE"
					path = "/api/v2/users/" + url.PathEscape(secondID)
				case "block user":
					path = "/api/v2/users/" + url.PathEscape(secondID)
					body = map[string]any{"blocked": true}
				case "link user":
					sys, _ := st.Tenants().GetByName(context.Background(), tenant.SystemName)
					primary := &store.User{TenantID: sys.ID, UserID: "auth0|primary", Email: "primary@example.test", Identities: []store.Identity{{Connection: system.OperatorsConnection, Provider: "auth0", UserID: "primary"}}}
					if err := st.Users().Create(context.Background(), primary); err != nil {
						t.Fatal(err)
					}
					method = "POST"
					path = "/api/v2/users/auth0%7Cprimary/identities"
					body = map[string]any{"provider": "auth0", "user_id": strings.TrimPrefix(secondID, "auth0|")}
				}
				start := make(chan struct{})
				codes := make(chan int, 2)
				go func() {
					<-start
					rec, _ := sendRaw(h, "PATCH", origin+"/api/system/operators/"+url.PathEscape(firstID), first, map[string]any{"tenants": []string{"acme"}})
					codes <- rec.Code
				}()
				go func() { <-start; rec, _ := sendRaw(h, method, origin+path, second, body); codes <- rec.Code }()
				close(start)
				results := []int{<-codes, <-codes}
				sort.Ints(results)
				if (results[0] < 200 || results[0] >= 300) || results[1] != 409 {
					t.Fatalf("concurrent changes = %v; want success and 409", results)
				}
				sys, _ := st.Tenants().GetByName(context.Background(), tenant.SystemName)
				ops, err := st.Operators().List(context.Background(), sys.ID)
				if err != nil {
					t.Fatal(err)
				}
				usable := 0
				for _, op := range ops {
					if !slices.Contains(op.Tenants, "*") && !slices.Contains(op.Tenants, "system") {
						continue
					}
					user, err := st.Users().Get(context.Background(), sys.ID, op.UserID)
					if err == nil && !user.Blocked {
						usable++
					}
				}
				if usable != 1 {
					t.Fatalf("usable system administrators = %d", usable)
				}
			})
		}
	}
}
