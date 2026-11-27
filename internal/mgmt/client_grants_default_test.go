package mgmt_test

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Default grants for third-party applications (Plan 41b, LR41b-4).
func TestDefaultClientGrant(t *testing.T) {
	e := newCGEnv(t)
	out := e.mustCreate(t, map[string]any{"default_for": "third_party_clients", "audience": ordersAPI, "subject_type": "user", "scope": []string{"read:orders"}})
	if out["default_for"] != "third_party_clients" || out["subject_type"] != "user" {
		t.Fatalf("view %v", out)
	}
	if _, has := out["client_id"]; has {
		t.Fatalf("default grant reports a client_id: %v", out)
	}
	id := out["id"].(string)
	g, err := e.st.ClientGrants().Find(context.Background(), e.tn.ID, "", ordersAPI, store.SubjectTypeUser)
	if err != nil || g.ID != id || g.DefaultFor != store.GrantDefaultForThirdParty {
		t.Fatalf("stored %+v %v", g, err)
	}

	// One default per API and subject type.
	rec, _ := e.create(t, map[string]any{"default_for": "third_party_clients", "audience": ordersAPI, "subject_type": "user", "scope": []string{}})
	if rec.Code != 409 {
		t.Fatalf("duplicate default: %d %s", rec.Code, rec.Body)
	}
	for name, body := range map[string]map[string]any{
		"both":          {"default_for": "third_party_clients", "client_id": e.client, "audience": ordersAPI, "scope": []string{}},
		"neither":       {"audience": ordersAPI, "scope": []string{}},
		"other group":   {"default_for": "first_party_clients", "audience": ordersAPI, "scope": []string{}},
		"organizations": {"default_for": "third_party_clients", "audience": ordersAPI, "organization_usage": "allow", "scope": []string{}},
		"management":    {"default_for": "third_party_clients", "audience": "https://login.acme.test/api/v2/", "scope": []string{}},
	} {
		if rec, _ := e.create(t, body); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}

	// Listing by default_for; updating keeps it a default grant.
	e.grant(t, "read:orders")
	rec, list := e.list(t, "?default_for=third_party_clients")
	if items, _ := list.([]any); rec.Code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != id {
		t.Fatalf("filtered list %d %v", rec.Code, list)
	}
	if rec, _ := e.list(t, "?default_for=everyone"); rec.Code != 400 {
		t.Fatalf("bad filter: %d", rec.Code)
	}
	if rec, out := e.patch(t, id, map[string]any{"scope": []string{"read:orders", "write:orders"}}); rec.Code != 200 || out["default_for"] != "third_party_clients" {
		t.Fatalf("patch %d %v", rec.Code, out)
	}
	if rec, _ := e.patch(t, id, map[string]any{"default_for": nil}); rec.Code != 400 {
		t.Fatalf("default_for is not updatable: %d", rec.Code)
	}
	if rec := e.del(t, id); rec.Code != 204 {
		t.Fatalf("delete %d", rec.Code)
	}
}
