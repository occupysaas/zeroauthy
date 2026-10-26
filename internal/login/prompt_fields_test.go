package login

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

func setPartials(t *testing.T, e *env, partials map[string]map[string]map[string]string) {
	t.Helper()
	tn := mustTenant(t, e, "acme")
	c, err := e.st.HostedLogins().Get(context.Background(), tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Partials = partials
	if err := e.st.HostedLogins().Put(context.Background(), c, c.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestPartialFieldLifecycle(t *testing.T) {
	e := newEnv(t)
	setPartials(t, e, map[string]map[string]map[string]string{"login": {"login": {"form-content-start": `<label for="note">Note</label><input aria-label="Additional information" id="note" name="ulp-note">`, "form-footer-end": `<p>Footer copy</p>`}}})
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	body := page.Body.String()
	start, field, end := strings.Index(body, "<form"), strings.Index(body, `name="ulp-note"`), strings.Index(body, "</form>")
	if field < start || field > end || !strings.Contains(body, "Footer copy") {
		t.Fatal("partial slots misplaced")
	}
	tn := mustTenant(t, e, "acme")
	before, _ := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	wrong := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}, "ulp-note": {"<b>Private note</b>"}})
	if wrong.Code != http.StatusUnauthorized || strings.Contains(wrong.Body.String(), "<b>Private note</b>") || !strings.Contains(wrong.Body.String(), "&lt;b&gt;Private note&lt;/b&gt;") {
		t.Fatalf("redisplay=%d %s", wrong.Code, wrong.Body.String())
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if txn.HostedState.PromptFields["ulp-note"] != "<b>Private note</b>" || len(txn.HostedState.PromptFields) != 1 || !txn.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("capture=%+v", txn.HostedState)
	}
	done := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}, "ulp-note": {"done"}})
	if done.Code != http.StatusFound {
		t.Fatalf("login=%d %s", done.Code, done.Body.String())
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("completed fields remained: %v", err)
	}
	if strings.Contains(e.logs.String(), "Private note") {
		t.Fatal("captured field logged")
	}
}

func TestPartialConfigChangedBetweenGetPost(t *testing.T) {
	e := newEnv(t)
	setPartials(t, e, map[string]map[string]map[string]string{"login": {"login": {"form-content-start": `<input aria-label="Additional information" name="ulp-old">`}}})
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	revision := revisionFrom(t, page.Body.String())
	setPartials(t, e, map[string]map[string]map[string]string{"login": {"login": {"form-content-start": `<input aria-label="Additional information" name="ulp-new">`}}})
	changed := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revision}, "username": {"alice@acme.test"}, "password": {"alice password 1"}, "ulp-old": {"stale"}})
	if changed.Code != http.StatusConflict || !strings.Contains(changed.Body.String(), `name="ulp-new"`) {
		t.Fatalf("changed config=%d %s", changed.Code, changed.Body.String())
	}
	tn := mustTenant(t, e, "acme")
	txn, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(txn.HostedState.PromptFields) != 0 {
		t.Fatal("stale form captured fields")
	}
	done := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}, "ulp-new": {"fresh"}})
	if done.Code != http.StatusFound {
		t.Fatalf("fresh form=%d %s", done.Code, done.Body.String())
	}
}

func TestPartialCrossScreenOwnership(t *testing.T) {
	e := newEnv(t)
	enableIdentifier(t, e)
	setPartials(t, e, map[string]map[string]map[string]string{
		"login-id":       {"login-id": {"form-content-start": `<input aria-label="Additional information" name="ulp-first">`}},
		"login-password": {"login-password": {"form-content-start": `<input aria-label="Additional information" type="checkbox" name="ulp-second">`}},
	})
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	step := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "ulp-first": {"identifier value"}})
	if step.Code != http.StatusSeeOther {
		t.Fatalf("identifier=%d", step.Code)
	}
	b.do(t, "GET", step.Header().Get("Location"), nil)
	first := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "password": {"wrong"}, "ulp-second": {"on"}})
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("password=%d", first.Code)
	}
	second := b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "password": {"wrong"}})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("retry=%d", second.Code)
	}
	tn := mustTenant(t, e, "acme")
	txn, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if txn.HostedState.PromptFields["ulp-first"] != "identifier value" {
		t.Fatal("password screen erased identifier fields")
	}
	if _, ok := txn.HostedState.PromptFields["ulp-second"]; ok {
		t.Fatal("unchecked password field retained")
	}
	reset := b.do(t, "POST", "/u/login/identifier", url.Values{"state": {state}, "csrf": {csrf}})
	if reset.Code != http.StatusSeeOther {
		t.Fatalf("reset=%d", reset.Code)
	}
	txn, err = e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(txn.HostedState.PromptFields) != 0 {
		t.Fatal("identifier reset retained fields")
	}
}

func TestSignupPartialFieldsStayTransient(t *testing.T) {
	e := newEnv(t)
	setPartials(t, e, map[string]map[string]map[string]string{"signup": {"signup": {"form-content-end": `<label for="team">Team</label><input id="team" name="ulp-team">`}}})
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	response := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"partial@acme.test"}, "password": {"a long enough password"}, "ulp-team": {"TRANSIENT-PRIVATE-FIELD"}})
	if response.Code != http.StatusFound {
		t.Fatalf("signup=%d %s", response.Code, response.Body.String())
	}
	tn := mustTenant(t, e, "acme")
	user, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "partial@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(user.UserMetadata) != 0 || len(user.AppMetadata) != 0 {
		t.Fatal("partial fields reached user metadata")
	}
	if strings.Contains(e.logs.String(), "TRANSIENT-PRIVATE-FIELD") {
		t.Fatal("partial fields reached logs")
	}
	for _, message := range e.mail.sent {
		if strings.Contains(fmt.Sprint(message), "TRANSIENT-PRIVATE-FIELD") {
			t.Fatal("partial fields reached email")
		}
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("signup transaction retained fields")
	}
}

func TestHostedBrandingAndPartialStateAfterRestart(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "restart.db")
	first, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e := newEnvWithStore(t, first)
	enableIdentifier(t, e)
	setPartials(t, e, map[string]map[string]map[string]string{"login-id": {"login-id": {"form-content-start": `<input aria-label="Team" name="ulp-team">`}}})
	tn := mustTenant(t, e, "acme")
	config, err := first.HostedLogins().Get(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	themeID := strings.Repeat("a", 32)
	config.Themes = map[string]map[string]any{themeID: {"colors": map[string]any{"primary_button": "#123456"}}}
	config.DefaultThemeID = themeID
	if err = first.HostedLogins().Put(ctx, config, config.Revision); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	step := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "ulp-team": {"private-team"}})
	if step.Code != 303 {
		t.Fatalf("identifier=%d %s", step.Code, step.Body)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restarted := newEnvWithStore(t, second)
	b.e = restarted
	persisted, err := second.HostedLogins().Get(ctx, tn.ID)
	if err != nil || persisted.DefaultThemeID != themeID {
		t.Fatalf("lost default: %+v %v", persisted, err)
	}
	txn, err := second.AuthTransactions().Get(ctx, tn.ID, state)
	if err != nil || txn.HostedState.PromptFields["ulp-team"] != "private-team" {
		t.Fatalf("lost captured state: %+v %v", txn, err)
	}
	independent := restarted.browser("acme.example.test")
	denied := independent.do(t, "GET", step.Header().Get("Location"), nil)
	if denied.Code != 400 {
		t.Fatalf("different browser accessed persisted state: %d", denied.Code)
	}
	page := b.do(t, "GET", step.Header().Get("Location"), nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "#123456") {
		t.Fatalf("restarted theme=%d %s", page.Code, page.Body)
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"alice password 1"}}
	done := b.do(t, "POST", "/u/login/password", form)
	if done.Code != 302 {
		t.Fatalf("restarted login=%d %s", done.Code, done.Body)
	}
	replay := b.do(t, "POST", "/u/login/password", form)
	if replay.Code != 400 {
		t.Fatalf("replay=%d", replay.Code)
	}
	user, err := second.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := second.Sessions().ListByUser(ctx, tn.ID, user.UserID)
	if err != nil || len(sessions) != 1 || user.LoginsCount != 1 {
		t.Fatalf("duplicate login/session: logins=%d sessions=%d err=%v", user.LoginsCount, len(sessions), err)
	}
	if _, err := second.AuthTransactions().Get(ctx, tn.ID, state); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("captured state survived completion")
	}
}

func TestPartialInvalidStoredFragmentKeepsWidget(t *testing.T) {
	for _, source := range []string{`<textarea name="ulp-note" aria-label="Note"/>`, `<fieldset disabled></div>`} {
		e := newEnv(t)
		setPartials(t, e, map[string]map[string]map[string]string{"login": {"login": {"form-content-start": source}}})
		page, state, _ := e.browser("acme.example.test").begin(t)
		if page.Code != 200 || !strings.Contains(page.Body.String(), `id="password"`) || !strings.Contains(page.Body.String(), `<button type="submit">`) || strings.Contains(page.Body.String(), source) {
			t.Fatalf("fallback lost widget: status=%d %s", page.Code, page.Body)
		}
		txn, err := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, state)
		if err != nil || len(txn.HostedState.FormFields) != 0 {
			t.Fatalf("fallback declared controls: %+v %v", txn, err)
		}
	}
}
