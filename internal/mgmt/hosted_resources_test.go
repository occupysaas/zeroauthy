package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"sync"
	"testing"
)

type noHostedRepository struct{ store.Store }

func (noHostedRepository) HostedLogins() store.HostedLogins { return store.UnimplementedHostedLogins{} }

func TestThemeManagementContract(t *testing.T) {
	e := newClientsEnv(t)
	created, body := e.call(t, e.tn, m2mCaller("create:branding"), "POST", "/api/v2/branding/themes", map[string]any{"colors": map[string]any{}}, e.h.CreateBrandingTheme)
	if created.Code != http.StatusOK {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	id, _ := body.(map[string]any)["themeId"].(string)
	if id == "" {
		t.Fatal("missing theme id")
	}
	got, _ := e.call(t, e.tn, m2mCaller("read:branding"), "GET", "/api/v2/branding/themes/default", nil, e.h.GetDefaultBrandingTheme)
	if got.Code != http.StatusOK {
		t.Fatalf("default %d %s", got.Code, got.Body.String())
	}
	update, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PATCH", "/api/v2/branding/themes/"+id, map[string]any{"displayName": "Acme"}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateBrandingTheme(w, r, id) })
	if update.Code != http.StatusOK {
		t.Fatalf("update %d %s", update.Code, update.Body.String())
	}
	del, _ := e.call(t, e.tn, m2mCaller("delete:branding"), "DELETE", "/api/v2/branding/themes/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteBrandingTheme(w, r, id) })
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", del.Code, del.Body.String())
	}
	missing, _ := e.call(t, e.tn, m2mCaller("read:branding"), "GET", "/api/v2/branding/themes/default", nil, e.h.GetDefaultBrandingTheme)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing default %d", missing.Code)
	}
}

func TestPromptManagementContract(t *testing.T) {
	e := newClientsEnv(t)
	unknown, _ := e.call(t, e.tn, m2mCaller("read:prompts"), "GET", "/api/v2/prompts/unknown/partials", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetPromptPartials(w, r, "unknown") })
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown prompt=%d", unknown.Code)
	}
	set, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PATCH", "/api/v2/prompts", map[string]any{"identifier_first": true}, e.h.UpdatePromptSettings)
	if set.Code != http.StatusOK {
		t.Fatalf("settings %d %s", set.Code, set.Body.String())
	}
	text, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PUT", "/api/v2/prompts/login/custom-text/en", map[string]any{"login": map[string]any{"title": "Welcome"}}, func(w http.ResponseWriter, r *http.Request) { e.h.PutPromptCustomText(w, r, "login", "en") })
	if text.Code != http.StatusOK {
		t.Fatalf("text %d %s", text.Code, text.Body.String())
	}
	badText, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PUT", "/api/v2/prompts/login/custom-text/invalid", map[string]any{"login": map[string]any{"title": "Welcome"}}, func(w http.ResponseWriter, r *http.Request) { e.h.PutPromptCustomText(w, r, "login", "invalid") })
	if badText.Code != http.StatusBadRequest {
		t.Fatalf("disabled language accepted: %d", badText.Code)
	}
	part, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PUT", "/api/v2/prompts/login/partials", map[string]any{"login": map[string]any{"form-content-start": "<p>Hello</p>"}}, func(w http.ResponseWriter, r *http.Request) { e.h.PutPromptPartials(w, r, "login") })
	if part.Code != http.StatusOK {
		t.Fatalf("partial %d %s", part.Code, part.Body.String())
	}
	unsafe, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PUT", "/api/v2/prompts/login/partials", map[string]any{"login": map[string]any{"form-content-start": "<script>alert(1)</script>"}}, func(w http.ResponseWriter, r *http.Request) { e.h.PutPromptPartials(w, r, "login") })
	if unsafe.Code != http.StatusBadRequest {
		t.Fatalf("unsafe partial accepted: %d", unsafe.Code)
	}
}

func TestUniversalLoginTemplateContract(t *testing.T) {
	e := newClientsEnv(t)
	source := `<html><head>{% auth0:head %}</head><body>{% auth0:widget %}</body></html>`
	put, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PUT", "/api/v2/branding/templates/universal-login", map[string]any{"template": source}, e.h.PutUniversalLoginTemplate)
	if put.Code != http.StatusOK || put.Body.Len() != 0 {
		t.Fatalf("put=%d body=%q", put.Code, put.Body.String())
	}
	get, _ := e.call(t, e.tn, m2mCaller("read:branding"), "GET", "/api/v2/branding/templates/universal-login", nil, e.h.GetUniversalLoginTemplate)
	if get.Code != http.StatusOK || get.Body.String() == "" {
		t.Fatalf("get=%d body=%q", get.Code, get.Body.String())
	}
	del, _ := e.call(t, e.tn, m2mCaller("update:branding"), "DELETE", "/api/v2/branding/templates/universal-login", nil, e.h.DeleteUniversalLoginTemplate)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete=%d", del.Code)
	}
}

func TestConcurrentTextAndBrandingWrites(t *testing.T) {
	e := newClientsEnv(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan int, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		r, _ := e.call(t, e.tn, m2mCaller("update:branding"), "PATCH", "/api/v2/branding", map[string]any{"logo_url": "https://example.test/logo.svg"}, e.h.UpdateBranding)
		results <- r.Code
	}()
	go func() {
		defer wg.Done()
		<-start
		r, _ := e.call(t, e.tn, m2mCaller("update:prompts"), "PUT", "/api/v2/prompts/login/custom-text/en", map[string]any{"login": map[string]any{"title": "Welcome"}}, func(w http.ResponseWriter, r *http.Request) { e.h.PutPromptCustomText(w, r, "login", "en") })
		results <- r.Code
	}()
	close(start)
	wg.Wait()
	close(results)
	for code := range results {
		if code != http.StatusOK {
			t.Fatalf("concurrent update=%d", code)
		}
	}
	c, err := (hostedlogin.Service{Store: e.st}).Load(context.Background(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Branding["logo_url"] != "https://example.test/logo.svg" || c.CustomText["login"]["en"]["login"]["title"] != "Welcome" {
		t.Fatalf("lost update: %+v", c)
	}
}

func TestPluginUnavailableBranding(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Store = noHostedRepository{e.st}
	response, _ := e.call(t, e.tn, m2mCaller("read:branding"), "GET", "/api/v2/branding", nil, e.h.GetBranding)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("unavailable repository returned %d: %s", response.Code, response.Body.String())
	}
}
