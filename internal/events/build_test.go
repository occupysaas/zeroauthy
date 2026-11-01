package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var testTenant = &store.Tenant{ID: "my-tenant", CanonicalHost: "canonical.example.test"}
var testTime = time.Date(2026, 11, 1, 12, 34, 56, 123456789, time.FixedZone("offset", 3600))

func testUser() *store.User {
	return &store.User{TenantID: "my-tenant", UserID: "auth0|example", Email: "example@example.test", CreatedAt: testTime, UpdatedAt: testTime, Identities: []store.Identity{{Provider: "auth0", Connection: "database", UserID: "example"}}}
}
func built(t *testing.T, typ string, obj, prev any, ctx context.Context) map[string]any {
	t.Helper()
	e, err := Build(ctx, testTenant, typ, obj, prev, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err = eventrules.ValidateEvent(e.Body); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(e.Body, &m); err != nil {
		t.Fatal(err)
	}
	if e.ID != m["id"] || e.TenantID != testTenant.ID || e.Type != typ || !e.Time.Equal(testTime) {
		t.Fatal("event model mismatch")
	}
	return m
}
func data(m map[string]any) map[string]any { return m["data"].(map[string]any) }
func TestBuildUserCreatedMatchesCatalog(t *testing.T) {
	m := built(t, "user.created", testUser(), nil, context.Background())
	if m["source"] != "urn:auth0:canonical.example.test" || m["a0tenant"] != "my-tenant" || m["time"] != "2026-11-01T11:34:56.123Z" {
		t.Fatal(m)
	}
	if _, ok := data(m)["previous_object"]; ok {
		t.Fatal("unexpected previous")
	}
}
func TestBuildUserExcludesSecrets(t *testing.T) {
	u := testUser()
	u.AppMetadata = map[string]any{"password": "customer-data"}
	u.Identities[0].PasswordHash = "password-hash-secret"
	u.Identities[0].ImportedHash = "imported-hash-secret"
	u.Identities[0].ProfileData = map[string]any{"email": "linked@example.test", "access_token": "access-secret", "refresh_token": "refresh-secret", "password": "profile-secret", "nested": map[string]any{"token": "nested-secret"}}
	m := built(t, "user.updated", u, u, context.Background())
	b, _ := json.Marshal(m)
	for _, secret := range []string{"password-hash-secret", "imported-hash-secret", "access-secret", "refresh-secret", "profile-secret", "nested-secret"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	if !strings.Contains(string(b), "customer-data") {
		t.Fatal("lost customer metadata")
	}
}
func TestBuildUpdatedHasPrevious(t *testing.T) {
	u := testUser()
	p := testUser()
	p.Email = "old@example.test"
	m := built(t, "user.updated", u, p, context.Background())
	if data(m)["previous_object"].(map[string]any)["email"] != p.Email {
		t.Fatal(m)
	}
}
func TestBuildDeletedHasDeletedAt(t *testing.T) {
	m := built(t, "user.deleted", testUser(), nil, context.Background())
	if data(m)["object"].(map[string]any)["deleted_at"] != "2026-11-01T11:34:56.123Z" {
		t.Fatal(m)
	}
}
func TestBuildOrgMemberRoleShape(t *testing.T) {
	obj := map[string]any{"organization": map[string]any{"id": "org_1234567890abcdef", "secret": "hidden"}, "user": map[string]any{"user_id": "auth0|example", "email": "hidden"}, "role": map[string]any{"id": "rol_1234567890abcdef", "name": "reader", "secret": "hidden"}}
	m := built(t, "organization.member.role.assigned", obj, nil, context.Background())
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "hidden") {
		t.Fatal(m)
	}
}
func TestBuildConnectionOnlyCatalogStrategies(t *testing.T) {
	for _, s := range []string{"oidc", "auth0", "google-oauth2"} {
		c := &store.Connection{ID: "con_1234567890abcdef", Name: "enterprise", Strategy: s}
		_, err := Build(context.Background(), testTenant, "connection.created", c, nil, testTime)
		if s == "oidc" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrNotEmitted) {
			t.Fatalf("%s: %v", s, err)
		}
	}
}
func TestBuildContextFromRequest(t *testing.T) {
	r := httptest.NewRequest("PATCH", "https://custom.example.test/api/v2/users/id", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	c := FromRequest(r)
	c.ClientID = "client"
	c.ClientName = "name"
	m := built(t, "user.created", testUser(), nil, WithContext(r.Context(), c))
	cx := data(m)["context"].(map[string]any)
	req := cx["request"].(map[string]any)
	if req["ip"] != "192.0.2.1" || req["hostname"] != "custom.example.test" || req["method"] != "PATCH" || req["user_agent"] != "test-agent" || len(req["geo"].(map[string]any)) != 0 {
		t.Fatal(cx)
	}
	if cx["tenant"].(map[string]any)["id"] != "my-tenant" {
		t.Fatal(cx)
	}
}
func TestIDFormats(t *testing.T) {
	seen := map[string]bool{}
	for range 10000 {
		for _, id := range []string{NewEventID(), NewStreamID()} {
			if !regexp.MustCompile(`^(evt|est)_[A-Za-z0-9]{22}$`).MatchString(id) || seen[id] {
				t.Fatal(id)
			}
			seen[id] = true
		}
	}
}
func TestStamp(t *testing.T) {
	m := built(t, "user.created", testUser(), nil, context.Background())
	body, _ := json.Marshal(m)
	out := Stamp(body, "est_1234567890123456789012", true)
	var v map[string]any
	json.Unmarshal(out, &v)
	if v["a0stream"] != "est_1234567890123456789012" || v["a0purpose"] != "test" {
		t.Fatal(v)
	}
	if strings.Contains(string(body), "a0stream") {
		t.Fatal("mutated original")
	}
	if err := eventrules.ValidateEvent(out); err != nil {
		t.Fatal(err)
	}
}

func TestBuildOrganizationSharedView(t *testing.T) {
	obj := &store.Organization{ID: "org_1234567890abcdef", Name: "example", DisplayName: "Example", Metadata: map[string]string{"password": "customer-data"}}
	m := built(t, "organization.created", obj, nil, context.Background())
	if data(m)["object"].(map[string]any)["display_name"] != "Example" {
		t.Fatal(m)
	}
}
func TestBuildCatalogExamples(t *testing.T) {
	for _, rule := range eventrules.Types() {
		if !rule.Emitted {
			continue
		}
		t.Run(rule.Name, func(t *testing.T) {
			var example map[string]any
			json.Unmarshal(eventrules.Example(rule.Name), &example)
			obj := data(example)["object"]
			var prev any
			if strings.HasSuffix(rule.Name, ".updated") {
				prev = obj
			}
			built(t, rule.Name, obj, prev, context.Background())
		})
	}
}
func TestBuildRejectsInvalidInputs(t *testing.T) {
	for _, typ := range []string{"unknown", "group.created"} {
		if _, err := Build(context.Background(), testTenant, typ, testUser(), nil, testTime); !errors.Is(err, ErrNotEmitted) {
			t.Fatal(err)
		}
	}
	for _, obj := range []any{nil, (*store.User)(nil), "scalar", []string{"array"}} {
		if _, err := Build(context.Background(), testTenant, "user.created", obj, nil, testTime); err == nil {
			t.Fatal("accepted invalid object")
		}
	}
}
func TestBuildResolvedCustomDomain(t *testing.T) {
	r := httptest.NewRequest("POST", "https://custom.example.test/path", nil)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: testTenant, Host: "custom.example.test"}))
	c := FromRequest(r)
	if c.CustomDomain != "custom.example.test" {
		t.Fatal(c)
	}
	m := built(t, "user.created", testUser(), nil, WithContext(r.Context(), c))
	if m["source"] != "urn:auth0:canonical.example.test" {
		t.Fatal(m)
	}
}
func TestStampNormalAndInvalid(t *testing.T) {
	in := []byte(`{"id":"event","a0purpose":"test"}`)
	out := Stamp(in, "stream", false)
	if bytes.Contains(out, []byte("a0purpose")) {
		t.Fatal(string(out))
	}
	bad := []byte("invalid")
	if !bytes.Equal(Stamp(bad, "stream", true), bad) {
		t.Fatal("changed invalid JSON")
	}
}

func TestBuildUpdatedRequiresPrevious(t *testing.T) {
	for _, rule := range eventrules.Types() {
		if !rule.Emitted || !strings.HasSuffix(rule.Name, ".updated") {
			continue
		}
		t.Run(rule.Name, func(t *testing.T) {
			var example map[string]any
			if err := json.Unmarshal(eventrules.Example(rule.Name), &example); err != nil {
				t.Fatal(err)
			}
			for name, previous := range map[string]any{"absent": nil, "typed-nil-user": (*store.User)(nil), "typed-nil-map": map[string]any(nil), "empty": map[string]any{}, "no-catalog-fields": map[string]any{"unknown": "ignored"}} {
				t.Run(name, func(t *testing.T) {
					event, err := Build(context.Background(), testTenant, rule.Name, data(example)["object"], previous, testTime)
					if err == nil {
						t.Fatal("accepted update without a meaningful prior object")
					}
					if len(event.Body) != 0 || event.ID != "" {
						t.Fatal("returned an event on error")
					}
				})
			}
		})
	}
}
