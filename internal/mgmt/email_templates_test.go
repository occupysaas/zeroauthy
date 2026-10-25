package mgmt_test

import (
	"net/http"
	"testing"
)

func TestInvalidEmailTemplateDoesNotSave(t *testing.T) {
	e := newClientsEnv(t)
	rec, _ := e.call(t, e.tn, m2mCaller("create:email_templates"), "POST", "/api/v2/email-templates", map[string]any{"template": "verify_email", "body": "{% include 'x' %}", "subject": "x", "enabled": true}, e.h.CreateEmailTemplate)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid template accepted: %d %s", rec.Code, rec.Body)
	}
	if _, err := e.st.EmailTemplates().Get(t.Context(), e.tn.ID, "verify_email"); err == nil {
		t.Fatal("invalid template persisted")
	}
}
