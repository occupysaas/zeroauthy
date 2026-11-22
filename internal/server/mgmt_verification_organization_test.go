package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/login"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestVerificationOrganizationID(t *testing.T) {
	t.Run("default email", func(t *testing.T) {
		testVerificationOrganizationID(t, memory.New(), false)
	})
	t.Run("stored template and SQLite tickets", func(t *testing.T) {
		testVerificationOrganizationID(t, openSQL(t, "sqlite://"+filepath.Join(t.TempDir(), "z.db")), true)
	})
}

func testVerificationOrganizationID(t *testing.T, st store.Store, storedTemplate bool) {
	t.Helper()
	ctx := t.Context()
	mail := &countingMailer{}
	renderer, err := email.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	svc := &email.Service{Store: st, Fallback: mail, Renderer: renderer}
	a := newUsersAPIOn(t, st, func(d *Deps) {
		d.Mailer = mail
		d.EmailService = svc
	})
	const connection = "Username-Password-Authentication"
	tenantID := a.tenantID()
	orgLogo := "https://assets.example.test/verification-org.png"
	org := &store.Organization{TenantID: tenantID, ID: "org_0000000000000045", Name: "verify-org", DisplayName: "Verification Team",
		Branding: &store.OrgBranding{LogoURL: &orgLogo, Colors: &store.OrgColors{Primary: "#226688", PageBackground: "#eeeeee"}}}
	connID := connectionID(t, a, connection)
	if err := st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: tenantID, OrganizationID: org.ID, ConnectionID: connID, ShowAsButton: true}}); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if storedTemplate {
		tmpl := &store.EmailTemplate{TenantID: tenantID, Name: "verify_email", Fields: map[string]any{
			"enabled": true, "subject": "Verify {{ organization.id }}",
			"body": `<p>{{ organization.display_name }}</p><img src="{{ organization.branding.logo_url }}"><a href="{{ url }}">{{ url }}</a>`,
		}}
		if err := st.EmailTemplates().Put(ctx, tmpl, 0); err != nil {
			t.Fatal(err)
		}
	}

	for _, endpoint := range []struct {
		name string
		url  string
	}{
		{"job", jobsBase + "/verification-email"},
		{"ticket", "https://acme.example.test/api/v2/tickets/email-verification"},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			rec, user := a.do("POST", usersBase, map[string]any{
				"connection": connection, "email": endpoint.name + "@example.test", "password": "first horse 1", "verify_email": false,
			})
			if rec.Code != http.StatusCreated {
				t.Fatalf("create user = %d %s", rec.Code, rec.Body)
			}
			userID := user["user_id"].(string)
			body := map[string]any{"user_id": userID, "organization_id": org.ID}
			rec, _ = a.do("POST", endpoint.url, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("non-member = %d %s, want 400", rec.Code, rec.Body)
			}
			if err := st.Organizations().AddMembers(ctx, tenantID, org.ID, []string{userID}); err != nil {
				t.Fatal(err)
			}
			rec, out := a.do("POST", endpoint.url, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("member = %d %s, want 201", rec.Code, rec.Body)
			}

			var link string
			if endpoint.name == "job" {
				job, err := st.Jobs().Get(ctx, tenantID, out["id"].(string))
				if err != nil {
					t.Fatal(err)
				}
				processor := jobs.VerifyEmail{Sender: &login.VerificationMailer{Store: st, Email: svc}}
				status, details, err := processor.Run(ctx, st, job, nil)
				if status != store.JobCompleted || err != nil || mail.count() != 1 {
					t.Fatalf("job = %s %q %v, sent %d messages", status, details, err, mail.count())
				}
				msg := mail.sent[0]
				if msg.OrganizationID != org.ID || !strings.Contains(msg.Text, org.DisplayName) || !strings.Contains(msg.HTML, orgLogo) {
					t.Fatalf("missing organization in delivery %+v", msg)
				}
				if storedTemplate && msg.Subject != "Verify "+org.ID {
					t.Fatalf("subject = %q", msg.Subject)
				}
				if !storedTemplate && !strings.Contains(msg.HTML, "background:#226688") {
					t.Fatal("missing organization button color")
				}
				for _, field := range strings.Fields(msg.Text) {
					if strings.HasPrefix(field, "https://acme.example.test/u/email-verification?ticket=") {
						link = field
						break
					}
				}
				if link == "" {
					t.Fatal("verification email has no link")
				}
			} else {
				link = out["ticket"].(string)
			}

			page := httptest.NewRecorder()
			a.h.ServeHTTP(page, httptest.NewRequest("GET", strings.TrimSuffix(link, "#"), nil))
			if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), orgLogo) {
				t.Fatalf("verification page lacks organization branding: %d %s", page.Code, page.Body)
			}
			_, verified := a.do("GET", usersBase+"/"+userID, nil)
			if verified["email_verified"] != true {
				t.Fatalf("user not verified: %v", verified)
			}
		})
	}
}
