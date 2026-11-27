package mgmt_test

import (
	"testing"
)

// The CIBA grant and its channels through the Management API (Plan 41c).
func TestClientCIBAGrant(t *testing.T) {
	e := newClientsEnv(t)
	const ciba = "urn:openid:params:grant-type:ciba"
	out := e.mustCreate(t, map[string]any{"name": "Agent backend", "app_type": "regular_web", "grant_types": []string{"authorization_code", ciba}, "async_approval_notification_channels": []string{"email"}})
	if gt := strs(out["grant_types"]); len(gt) != 2 || gt[1] != ciba || strs(out["async_approval_notification_channels"])[0] != "email" {
		t.Fatalf("created %v", out)
	}
	id := out["client_id"].(string)
	for name, body := range map[string]map[string]any{
		"no channels": {"name": "x", "app_type": "regular_web", "grant_types": []string{ciba}},
		"push only":   {"name": "x", "app_type": "regular_web", "grant_types": []string{ciba}, "async_approval_notification_channels": []string{"guardian-push"}},
		"public":      {"name": "x", "app_type": "spa", "grant_types": []string{ciba}, "async_approval_notification_channels": []string{"email"}},
		"bad channel": {"name": "x", "app_type": "regular_web", "async_approval_notification_channels": []string{"fax"}},
		"empty":       {"name": "x", "app_type": "regular_web", "async_approval_notification_channels": []string{}},
	} {
		if rec, _ := e.create(t, m2mCaller(allClientScopes...), body); rec.Code != 400 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// Removing email while the grant is on is refused; null clears with the grant removed.
	if rec, _ := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"async_approval_notification_channels": []string{"guardian-push"}}); rec.Code != 400 {
		t.Fatalf("push-only patch: %d", rec.Code)
	}
	rec, patched := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"grant_types": []string{"authorization_code"}, "async_approval_notification_channels": nil})
	if rec.Code != 200 {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	if _, has := patched["async_approval_notification_channels"]; has {
		t.Fatalf("cleared channels reported: %v", patched)
	}
}
