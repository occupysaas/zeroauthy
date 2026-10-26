package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const domainTemplate = `<html><head>{% auth0:head %}</head><body><p id="cd">[{{ custom_domain.domain }}|{{ custom_domain.domain_metadata.brand }}|{{ custom_domain.origin_host }}]</p>{% auth0:widget %}</body></html>`

// Hosted templates see the public custom domain and its metadata only, from
// the admitted request; canonical requests see none; preview is synthetic.
func TestPublicCustomDomainContext(t *testing.T) {
	source := domainTemplate
	c := &store.HostedLoginConfig{TenantID: "t1", Template: &source}
	tn := &store.Tenant{ID: "t1", Name: "acme", EnabledLocales: []string{"en"}}
	page := func(ctx context.Context) string {
		r := httptest.NewRequest(http.MethodGet, "https://id.acme.test/u/login", nil).WithContext(hostedlogin.WithConfiguration(ctx, c))
		view := RequestTenant(r, tn, i18n.New(tn, "en"))
		rec := httptest.NewRecorder()
		RenderLogin(rec, http.StatusOK, view, LoginData{})
		return rec.Body.String()
	}
	pd := &customdomain.PublicDomain{Domain: "id.acme.test", Metadata: map[string]string{"brand": "<b>Acme</b>"}}
	got := page(customdomain.WithPublicDomain(context.Background(), pd))
	if !strings.Contains(got, `[id.acme.test|&lt;b&gt;Acme&lt;/b&gt;|]`) {
		t.Fatalf("custom domain page: %s", excerpt(got))
	}
	if got := page(context.Background()); !strings.Contains(got, `[||]`) {
		t.Fatalf("canonical page: %s", excerpt(got))
	}
	preview, err := Preview(context.Background(), c, "login", "en")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.HTML, "[login.example.com|example|]") {
		t.Fatalf("preview: %s", excerpt(preview.HTML))
	}
}

func excerpt(s string) string {
	if i := strings.Index(s, `<p id="cd">`); i >= 0 {
		return s[i:min(len(s), i+120)]
	}
	return s[:min(len(s), 300)]
}
