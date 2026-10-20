package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// An import-mode first login whose login script accepted the old password
// while a reset completed does not overwrite the reset's hash: the reset
// wins, and the old password no longer logs in.
func TestImportLoginRacingReset(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.useImportMode(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	releaseScript := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseScript)
	le.scripts.Funcs[store.ScriptLogin] = func(args []any) (any, error) {
		out, err := legacyLogin(args)
		once.Do(func() { close(reached); <-release })
		return out, err
	}
	// The reset lookup migrates dave without a password.
	ticket := le.requestLegacyReset(t, le.browser("acme.example.test"))

	b := le.browser("acme.example.test")
	state, csrf := b.legacyBegin(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"dave@legacy.test"}, "password": {"dave legacy 1"}}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- b.send("POST", "/u/login", form) }()
	<-reached
	if rec := completeReset(t, le.browser("acme.example.test"), ticket, "new import pw 1"); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	releaseScript()
	// The old password fails as a wrong password does.
	if rec := <-done; rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Incorrect") {
		t.Fatalf("login with the old password across the reset = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}

	u, err := le.st.Users().Get(context.Background(), mustTenant(t, le.env, "acme").ID, "auth0|42")
	if err != nil {
		t.Fatal(err)
	}
	for _, try := range []struct {
		password string
		ok       bool
	}{{"dave legacy 1", false}, {"new import pw 1", true}} {
		b := le.browser("acme.example.test")
		state, csrf := b.legacyBegin(t)
		rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"dave@legacy.test"}, "password": {try.password}})
		if (rec.Code == 302) != try.ok {
			t.Errorf("login with %q after the race = %d (hash set: %v)", try.password, rec.Code, u.Identities[0].PasswordHash != "")
		}
	}
}

// Two submits of one reset ticket on a legacy connection run
// change_password once: the ticket is used before the script runs, and the
// second submit gets the used-link page.
func TestLegacyResetDoubleSubmitRunsScriptOnce(t *testing.T) {
	le := newLegacyResetEnv(t)
	reached, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseScript := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseScript)
	var mu sync.Mutex
	calls := 0
	le.scripts.Funcs[store.ScriptChangePassword] = func([]any) (any, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			close(reached)
			<-release
		}
		return true, nil
	}
	ticket := le.requestLegacyReset(t, le.browser("acme.example.test"))
	formFor := func(b *browser) url.Values {
		rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		m := csrfField.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("reset form = %d %s", rec.Code, rec.Body)
		}
		return url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {"new legacy pw 1"}, "password_confirm": {"new legacy pw 1"}}
	}
	b1, b2 := le.browser("acme.example.test"), le.browser("acme.example.test")
	f1, f2 := formFor(b1), formFor(b2)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- b1.send("POST", "/u/reset-password", f1) }()
	<-reached
	rec := b2.do(t, "POST", "/u/reset-password", f2)
	releaseScript()
	if rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Errorf("second submit = %d %s", rec.Code, rec.Body)
	}
	if rec := <-done; rec.Code != 200 {
		t.Errorf("first submit = %d %s", rec.Code, rec.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("change_password ran %d times", calls)
	}
}
