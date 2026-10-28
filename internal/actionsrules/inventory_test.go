package actionsrules

import (
	"strings"
	"testing"
)

func TestActionsInventory(t *testing.T) {
	inv := Inventory()
	want := map[string]int{
		"GET /api/v2/actions/modules":                                   200,
		"POST /api/v2/actions/modules":                                  201,
		"GET /api/v2/actions/modules/{id}":                              200,
		"PATCH /api/v2/actions/modules/{id}":                            200,
		"DELETE /api/v2/actions/modules/{id}":                           204,
		"GET /api/v2/actions/modules/{id}/actions":                      200,
		"POST /api/v2/actions/modules/{id}/rollback":                    200,
		"GET /api/v2/actions/modules/{id}/versions":                     200,
		"POST /api/v2/actions/modules/{id}/versions":                    200,
		"GET /api/v2/actions/modules/{id}/versions/{versionId}":         200,
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
	wantScope := map[string]string{
		"GET /api/v2/actions/modules":                                   "read:actions",
		"POST /api/v2/actions/modules":                                  "create:actions",
		"GET /api/v2/actions/modules/{id}":                              "read:actions",
		"PATCH /api/v2/actions/modules/{id}":                            "update:actions",
		"DELETE /api/v2/actions/modules/{id}":                           "delete:actions",
		"GET /api/v2/actions/modules/{id}/actions":                      "read:actions",
		"POST /api/v2/actions/modules/{id}/rollback":                    "update:actions",
		"GET /api/v2/actions/modules/{id}/versions":                     "read:actions",
		"POST /api/v2/actions/modules/{id}/versions":                    "update:actions",
		"GET /api/v2/actions/modules/{id}/versions/{versionId}":         "read:actions",
		"GET /api/v2/actions/actions":                                   "read:actions",
		"POST /api/v2/actions/actions":                                  "create:actions",
		"GET /api/v2/actions/actions/{id}":                              "read:actions",
		"PATCH /api/v2/actions/actions/{id}":                            "update:actions",
		"DELETE /api/v2/actions/actions/{id}":                           "delete:actions",
		"POST /api/v2/actions/actions/{id}/deploy":                      "create:actions",
		"GET /api/v2/actions/actions/{id}/versions":                     "read:actions",
		"GET /api/v2/actions/actions/{id}/versions/{versionId}":         "read:actions",
		"POST /api/v2/actions/actions/{id}/versions/{versionId}/deploy": "create:actions",
		"POST /api/v2/actions/actions/{id}/test":                        "create:actions",
		"GET /api/v2/actions/triggers":                                  "read:actions",
		"GET /api/v2/actions/triggers/{triggerId}/bindings":             "read:actions",
		"PATCH /api/v2/actions/triggers/{triggerId}/bindings":           "update:actions",
		"GET /api/v2/actions/executions/{id}":                           "read:actions",
	}
	if len(inv.Operations) != 24 {
		t.Fatalf("operations=%d, want 24", len(inv.Operations))
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
		if len(op.RequiredScopes) != 1 || op.RequiredScopes[0] != wantScope[key] {
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

	if len(inv.Triggers) != 7 {
		t.Fatalf("triggers=%d", len(inv.Triggers))
	}
	members := map[string][]string{
		"pre-user-registration":         {"access.deny", "user.setAppMetadata", "user.setUserMetadata", "cache.get", "cache.set", "cache.delete", "validation.error"},
		"post-user-registration":        {"cache.get", "cache.set", "cache.delete"},
		"post-change-password":          {"cache.get", "cache.set", "cache.delete"},
		"password-reset-post-challenge": {"access.deny", "authentication.challengeWith", "authentication.challengeWithAny", "redirect.sendUserTo", "redirect.encodeToken", "redirect.validateToken", "redirect.canRedirect", "cache.get", "cache.set", "cache.delete", "prompt.render", "transaction.setResultUrl"},
		"custom-email-provider":         {"cache.get", "cache.set", "cache.delete", "notification.retry", "notification.drop"},
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
	handlers := map[string]struct {
		execute, resume string
		blocking        bool
	}{
		"post-login":                    {"onExecutePostLogin", "onContinuePostLogin", true},
		"credentials-exchange":          {"onExecuteCredentialsExchange", "", true},
		"pre-user-registration":         {"onExecutePreUserRegistration", "", true},
		"post-user-registration":        {"onExecutePostUserRegistration", "", false},
		"post-change-password":          {"onExecutePostChangePassword", "", false},
		"password-reset-post-challenge": {"onExecutePostChallenge", "onContinuePostChallenge", true},
		"custom-email-provider":         {"onExecuteCustomEmailProvider", "", false},
	}
	events := map[string][]string{
		"pre-user-registration":         {"user", "connection", "client", "request", "request.body", "tenant", "transaction", "secrets", "custom_domain.domain"},
		"post-user-registration":        {"user", "user.user_id", "user.created_at", "connection", "request", "tenant", "transaction", "secrets"},
		"post-change-password":          {"user", "user.last_password_reset", "connection", "request", "tenant", "secrets"},
		"password-reset-post-challenge": {"user", "connection", "client", "request", "tenant", "transaction", "secrets"},
		"custom-email-provider":         {"notification.from", "notification.to", "notification.subject", "notification.html", "notification.text", "notification.locale", "notification.message_type", "user", "client", "tenant", "request", "connection", "secrets"},
	}
	for _, tr := range inv.Triggers {
		need, ok := members[tr.ID]
		if !ok {
			t.Fatalf("unexpected trigger %q", tr.ID)
		}
		delete(members, tr.ID)
		switch tr.ID {
		case "pre-user-registration", "post-user-registration", "post-change-password":
			if tr.Version != "v2" {
				t.Errorf("%s version=%q want observed current v2", tr.ID, tr.Version)
			}
		}
		h := handlers[tr.ID]
		if tr.Handler != h.execute || tr.ContinueHandler != h.resume || tr.Blocking != h.blocking {
			t.Errorf("%s handlers/blocking=(%q,%q,%v), want (%q,%q,%v)", tr.ID, tr.Handler, tr.ContinueHandler, tr.Blocking, h.execute, h.resume, h.blocking)
		}
		if tr.SourceURL == "" {
			t.Errorf("%s missing source", tr.ID)
		}
		fields := map[string]bool{}
		for _, field := range tr.Event {
			fields[field] = true
		}
		for _, field := range events[tr.ID] {
			if !fields[field] {
				t.Errorf("%s missing event.%s", tr.ID, field)
			}
		}
		if len(tr.Event) == 0 {
			t.Errorf("%s has no event fields", tr.ID)
		}
		got := map[string]string{}
		for _, m := range tr.API {
			if _, duplicate := got[m.Name]; duplicate {
				t.Errorf("%s duplicate api.%s", tr.ID, m.Name)
			}
			if m.Evidence != "documented" && m.Evidence != "observed" && m.Evidence != "local" {
				t.Errorf("%s.%s missing provenance", tr.ID, m.Name)
			}
			got[m.Name] = m.Support
			switch m.Support {
			case "supported", "empty", "unsupported":
			default:
				t.Errorf("%s.%s support=%q", tr.ID, m.Name, m.Support)
			}
		}
		if len(got) != len(need) {
			t.Errorf("%s classified %d api members, want %d", tr.ID, len(got), len(need))
		}
		for _, name := range need {
			if got[name] == "" {
				t.Errorf("%s: api.%s not classified", tr.ID, name)
			}
			if w := wantSupport(tr.ID, name); got[name] != w {
				t.Errorf("%s: api.%s=%q want %q", tr.ID, name, got[name], w)
			}
		}
	}

	if len(members) != 0 {
		t.Errorf("missing triggers %v", members)
	}
	deferred := map[string]string{
		"send-phone-message": "34", "custom-phone-provider": "34", "custom-token-exchange": "35", "event-stream": "32",
		"password-hash-migration": "deferred", "login-post-identifier": "deferred", "signup-post-identifier": "deferred", "post-credential-validation": "deferred",
	}
	for _, tr := range inv.DeferredTriggers {
		plan, ok := deferred[tr.ID]
		if !ok || tr.Plan != plan {
			t.Errorf("unexpected deferred trigger %+v", tr)
		}
		delete(deferred, tr.ID)
		if _, supported := handlers[tr.ID]; supported {
			t.Errorf("%s both supported and deferred", tr.ID)
		}
	}
	if len(deferred) != 0 {
		t.Errorf("missing deferred triggers %v", deferred)
	}
	for name, want := range map[string]int{
		"module_code_chars": 65536, "module_name_chars": 255, "module_versions": 100, "modules_per_tenant": 100,
		"modules_per_action": 10, "job_lease_seconds": 60, "job_pending_per_tenant": 10000, "email_retries": 5, "notification_reason_chars": 1024,
	} {
		if inv.Limits[name] != want {
			t.Errorf("limit %s=%d want %d", name, inv.Limits[name], want)
		}
	}
	for name := range inv.Limits {
		if _, ok := inv.LimitSources[name]; !ok {
			t.Errorf("limit %s missing source", name)
		}
	}
	for _, name := range []string{
		"code_bytes", "name_min", "name_max", "secrets_max", "secret_name_max", "secret_value_max",
		"dependencies_max", "bindings_per_trigger_max", "custom_email_provider_bindings_max", "flow_budget_seconds", "artifact_bytes_max",
		"cache_entries_max", "cache_key_bytes_max", "cache_value_bytes_max", "cache_total_bytes_max",
		"cache_default_ttl_seconds", "cache_max_ttl_seconds", "continue_state_seconds",
		"redirects_per_login_max", "execution_retention_days", "custom_claims_bytes_max",
		"transaction_metadata_key_max", "transaction_metadata_value_bytes_max", "transaction_metadata_total_bytes_max",
		"console_log_chars_per_action", "module_code_chars", "module_name_chars", "module_versions", "modules_per_tenant", "modules_per_action", "job_lease_seconds", "job_pending_per_tenant", "email_retries", "notification_reason_chars",
	} {
		if inv.Limits[name] <= 0 {
			t.Errorf("limit %s missing", name)
		}
		src := inv.LimitSources[name]
		if !strings.HasPrefix(src, "https://") && src != "D-0053" && src != "D-0054" {
			t.Errorf("limit %s has no source or decision: %q", name, src)
		}
	}
}

func wantSupport(trigger, name string) string {
	switch name {
	case "groups.getUserGroups", "groups.hasGroupMembership", "rules.wasExecuted":
		return "empty"
	}
	for _, ns := range []string{"session.", "refreshToken.", "authentication.", "multifactor.", "prompt.", "samlResponse."} {
		if strings.HasPrefix(name, ns) {
			return "unsupported"
		}
	}
	return "supported"
}
