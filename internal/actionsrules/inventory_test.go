package actionsrules

import (
	"strings"
	"testing"
)

func TestActionsInventory(t *testing.T) {
	inv := Inventory()
	want := map[string]int{
		"GET /api/v2/actions/actions":                                   200,
		"POST /api/v2/actions/actions":                                  201,
		"GET /api/v2/actions/actions/{id}":                              200,
		"PATCH /api/v2/actions/actions/{id}":                            200,
		"DELETE /api/v2/actions/actions/{id}":                           204,
		"POST /api/v2/actions/actions/{id}/deploy":                      202,
		"GET /api/v2/actions/actions/{id}/versions":                     200,
		"GET /api/v2/actions/actions/{id}/versions/{versionId}":         200,
		"POST /api/v2/actions/actions/{id}/versions/{versionId}/deploy": 202,
		"POST /api/v2/actions/actions/{id}/test":                        200,
		"GET /api/v2/actions/triggers":                                  200,
		"GET /api/v2/actions/triggers/{triggerId}/bindings":             200,
		"PATCH /api/v2/actions/triggers/{triggerId}/bindings":           200,
		"GET /api/v2/actions/executions/{id}":                           200,
	}
	if len(inv.Operations) != 14 {
		t.Fatalf("operations=%d, want 14", len(inv.Operations))
	}
	for _, op := range inv.Operations {
		key := op.Method + " " + op.Path
		status, ok := want[key]
		if !ok {
			t.Fatalf("unexpected or duplicate operation %s", key)
		}
		delete(want, key)
		if op.SuccessStatus != status {
			t.Errorf("%s status=%d want %d", key, op.SuccessStatus, status)
		}
		if len(op.RequiredScopes) != 1 || !strings.HasSuffix(op.RequiredScopes[0], ":actions") {
			t.Errorf("%s scopes=%v", key, op.RequiredScopes)
		}
		if op.SourceURL == "" || op.ResponseShape == "" || len(op.ErrorStatuses) == 0 {
			t.Errorf("%s incomplete contract", key)
		}
		switch op.Evidence {
		case "documented", "observed", "local":
		default:
			t.Errorf("%s evidence=%q", key, op.Evidence)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing operations %v", want)
	}

	if len(inv.Triggers) != 2 {
		t.Fatalf("triggers=%d", len(inv.Triggers))
	}
	members := map[string][]string{
		"post-login": {
			"access.deny", "accessToken.setCustomClaim", "accessToken.addScope", "accessToken.removeScope",
			"idToken.setCustomClaim", "transaction.setMetadata", "transaction.addTargetScope",
			"transaction.removeTargetScope", "transaction.setTargetScopes", "transaction.clearTargetScopes",
			"user.setAppMetadata", "user.setUserMetadata", "roles.getUserEffectiveRoles",
			"roles.getUserEffectiveRolesByIds", "roles.getUserEffectiveRolesByNames",
			"groups.getUserGroups", "groups.hasGroupMembership", "redirect.sendUserTo",
			"redirect.encodeToken", "redirect.validateToken", "redirect.canRedirect",
			"cache.get", "cache.set", "cache.delete", "validation.error", "rules.wasExecuted",
			"session.revoke", "session.setExpiresAt", "session.setIdleExpiresAt", "session.setCookieMode",
			"session.setMetadata", "session.deleteMetadata", "session.evictMetadata",
			"refreshToken.revoke", "refreshToken.setExpiresAt", "refreshToken.setIdleExpiresAt",
			"refreshToken.setMetadata", "refreshToken.deleteMetadata", "refreshToken.evictMetadata",
			"authentication.challengeWith", "authentication.challengeWithAny", "authentication.enrollWith",
			"authentication.enrollWithAny", "authentication.recordMethod", "authentication.setPrimaryUser",
			"multifactor.enable", "prompt.render", "samlResponse.setAttribute",
		},
		"credentials-exchange": {
			"access.deny", "accessToken.setCustomClaim", "transaction.addTargetScope",
			"transaction.removeTargetScope", "transaction.setTargetScopes", "transaction.clearTargetScopes",
			"cache.get", "cache.set", "cache.delete",
		},
	}
	for _, tr := range inv.Triggers {
		need, ok := members[tr.ID]
		if !ok {
			t.Fatalf("unexpected trigger %q", tr.ID)
		}
		if len(tr.Event) == 0 {
			t.Errorf("%s has no event fields", tr.ID)
		}
		got := map[string]string{}
		for _, m := range tr.API {
			got[m.Name] = m.Support
			switch m.Support {
			case "supported", "empty", "unsupported":
			default:
				t.Errorf("%s.%s support=%q", tr.ID, m.Name, m.Support)
			}
		}
		for _, name := range need {
			if got[name] == "" {
				t.Errorf("%s: api.%s not classified", tr.ID, name)
			}
		}
	}

	for _, name := range []string{
		"code_bytes", "name_min", "name_max", "secrets_max", "secret_name_max", "secret_value_max",
		"dependencies_max", "bindings_per_trigger_max", "flow_budget_seconds", "artifact_bytes_max",
		"cache_entries_max", "cache_key_bytes_max", "cache_value_bytes_max", "cache_total_bytes_max",
		"cache_default_ttl_seconds", "cache_max_ttl_seconds", "continue_state_seconds",
		"redirects_per_login_max", "execution_retention_days", "custom_claims_bytes_max",
		"transaction_metadata_key_max", "transaction_metadata_value_bytes_max", "transaction_metadata_total_bytes_max",
	} {
		if inv.Limits[name] <= 0 {
			t.Errorf("limit %s missing", name)
		}
		src := inv.LimitSources[name]
		if !strings.HasPrefix(src, "https://") && src != "D-0053" {
			t.Errorf("limit %s has no source or decision: %q", name, src)
		}
	}
}
