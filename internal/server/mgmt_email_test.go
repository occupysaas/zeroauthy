package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestManagementEmailProviderAndTemplateAPIs(t *testing.T) {
	seedText := strings.Replace(mgmtSeed, `"delete:connections"]`, `"delete:connections", "read:email_provider", "create:email_provider", "update:email_provider", "delete:email_provider", "read:email_templates", "create:email_templates", "update:email_templates"]`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	c := newMgmtContract(t)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	base := "https://acme.example.test/api/v2/emails/provider"
	if status, _ := c.do(h, "GET", base, reader, nil); status != http.StatusForbidden {
		t.Fatalf("missing provider scope: %d", status)
	}
	if status, _ := c.do(h, "GET", base, admin, nil); status != http.StatusNotFound {
		t.Fatalf("missing provider: %d", status)
	}
	if status, _ := c.do(h, "GET", "https://"+mgmtSystemHost+"/api/v2/emails/provider", admin, nil); status != http.StatusUnauthorized {
		t.Fatalf("foreign issuer/tenant token: %d", status)
	}
	op, _ := operatorToken(t, st, "operator@example.test")
	if status, _ := c.do(h, "POST", "https://"+mgmtSystemHost+"/api/v2/emails/provider", op, map[string]any{"name": "custom", "enabled": false}); status != http.StatusForbidden {
		t.Fatalf("reserved tenant write: %d", status)
	}
	secret := "SENTINEL_MANAGEMENT_EMAIL_SECRET"
	provider := map[string]any{"name": "sendgrid", "enabled": true, "default_from_address": "mail@example.test", "credentials": map[string]any{"api_key": secret}}
	if status, body := c.do(h, "POST", base, admin, provider); status != http.StatusCreated || strings.Contains(string(body), secret) {
		t.Fatalf("create provider leaked or failed: %d %s", status, body)
	}
	if status, _ := c.do(h, "POST", base, admin, provider); status != http.StatusConflict {
		t.Fatalf("duplicate provider: %d", status)
	}
	if status, body := c.do(h, "GET", base, admin, nil); status != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("get provider leaked or failed: %d %s", status, body)
	}
	if status, body := c.do(h, "PATCH", base, admin, map[string]any{"enabled": false}); status != http.StatusOK || strings.Contains(string(body), secret) {
		t.Fatalf("patch provider leaked or failed: %d %s", status, body)
	}
	if status, body := c.do(h, "PATCH", base, admin, map[string]any{"credentials": map[string]any{"api_key": "##SENDGRID_API_KEY##"}}); status != http.StatusOK || strings.Contains(string(body), "##SENDGRID_API_KEY##") {
		t.Fatalf("deploy credential placeholder patch: %d %s", status, body)
	}
	if status, body := c.do(h, "PATCH", base, admin, map[string]any{"credentials": map[string]any{"api_key": ""}}); status != http.StatusBadRequest || strings.Contains(string(body), secret) {
		t.Fatalf("blank credential patch: %d %s", status, body)
	}
	if status, _ := c.do(h, "DELETE", base, admin, nil); status != http.StatusNoContent {
		t.Fatalf("delete provider: %d", status)
	}
	if status, _ := c.do(h, "GET", base, admin, nil); status != http.StatusNotFound {
		t.Fatalf("deleted provider: %d", status)
	}
	if status, _ := c.do(h, "POST", base, admin, map[string]any{"name": "custom", "enabled": true}); status != http.StatusBadRequest {
		t.Fatalf("enabled custom provider: %d", status)
	}
	if status, _ := c.do(h, "POST", base, admin, map[string]any{"name": "custom", "enabled": false}); status != http.StatusCreated {
		t.Fatalf("disabled custom provider: %d", status)
	}
	if status, _ := c.do(h, "DELETE", base, admin, nil); status != http.StatusNoContent {
		t.Fatalf("delete custom provider: %d", status)
	}
	if status, _ := c.do(h, "POST", base, admin, map[string]any{"name": "sendgrid", "enabled": true, "credentials": map[string]any{"api_key": "##SENDGRID_API_KEY##"}}); status != http.StatusBadRequest {
		t.Fatalf("placeholder cannot configure a new provider: %d", status)
	}

	templates := "https://acme.example.test/api/v2/email-templates"
	body := map[string]any{"template": "verify_email", "body": "<p>Hello {{ user.email | escape }}</p>", "subject": "Verify", "enabled": true}
	if status, raw := c.do(h, "POST", templates, admin, body); status != http.StatusOK {
		t.Fatalf("create template: %d %s", status, raw)
	}
	if status, _ := c.do(h, "POST", templates, admin, body); status != http.StatusConflict {
		t.Fatalf("duplicate template: %d", status)
	}
	item := templates + "/verify_email"
	if status, raw := c.do(h, "GET", item, admin, nil); status != http.StatusOK {
		t.Fatalf("get template: %d %s", status, raw)
	}
	if status, raw := c.do(h, "PATCH", item, admin, map[string]any{"template": "verify_email", "subject": "SDK update"}); status != http.StatusOK {
		t.Fatalf("SDK patch with matching template identity: %d %s", status, raw)
	}
	if status, _ := c.do(h, "PATCH", item, admin, map[string]any{"template": "reset_email"}); status != http.StatusBadRequest {
		t.Fatalf("mismatched template identity: %d", status)
	}
	if status, raw := c.do(h, "PATCH", item, admin, map[string]any{"enabled": false, "from": nil}); status != http.StatusOK {
		t.Fatalf("patch template: %d %s", status, raw)
	}
	replacement := map[string]any{"template": "verify_email", "body": "Updated", "subject": "New", "enabled": true}
	if status, raw := c.do(h, "PUT", item, admin, replacement); status != http.StatusOK {
		t.Fatalf("put template: %d %s", status, raw)
	}
	if status, _ := c.do(h, "PATCH", templates+"/reset_email", admin, map[string]any{"enabled": false}); status != http.StatusNotFound {
		t.Fatalf("patch absent template: %d", status)
	}
	if status, _ := c.do(h, "POST", templates, admin, map[string]any{"template": "verify_email", "body": "{% include 'evil' %}", "subject": "x", "enabled": true}); status != http.StatusBadRequest {
		t.Fatalf("invalid Liquid: %d", status)
	}
	var projected map[string]any
	_, raw := c.do(h, "GET", item, admin, nil)
	_ = json.Unmarshal(raw, &projected)
	if projected["enabled"] != true || projected["body"] != "Updated" {
		t.Fatalf("replacement semantics: %v", projected)
	}
}
