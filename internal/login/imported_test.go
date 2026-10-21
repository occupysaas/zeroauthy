package login

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/passhash/passhashtest"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// setImported replaces alice's native hash with imported.
func setImported(t *testing.T, e *env, imported string) *store.User {
	t.Helper()
	ctx := context.Background()
	tid := mustTenant(t, e, "acme").ID
	u, err := e.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	u.Identities[0].PasswordHash, u.Identities[0].ImportedHash = "", imported
	if err := e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestImportedHashHostedLogin(t *testing.T) {
	e := newEnv(t)
	u := setImported(t, e, passhashtest.PBKDF2("imported pw 12"))
	post := func(pw string) (int, string) {
		b := e.browser("acme.example.test")
		_, state, csrf := b.begin(t, "login_hint", "alice@acme.test")
		rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {pw}})
		return rec.Code, rec.Body.String()
	}
	if code, _ := post("wrong"); code != 401 {
		t.Fatalf("wrong password = %d", code)
	}
	if got, _ := e.st.Users().Get(context.Background(), u.TenantID, u.UserID); got.Identities[0].ImportedHash == "" {
		t.Fatal("a wrong password dropped the imported hash")
	}
	if code, body := post("imported pw 12"); code != 302 {
		t.Fatalf("imported password = %d %s", code, body)
	}
	got, _ := e.st.Users().Get(context.Background(), u.TenantID, u.UserID)
	if id := got.Identities[0]; id.ImportedHash != "" || !strings.HasPrefix(id.PasswordHash, "$argon2id$") {
		t.Fatalf("identity after login = %+v", id)
	}
}

func TestImportedHashUnusableHostedLogin(t *testing.T) {
	e := newEnv(t)
	setImported(t, e, passhashtest.Unusable())
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "login_hint", "alice@acme.test")
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"anything at all"}})
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "must be reset") || !strings.Contains(rec.Body.String(), "/u/reset-password/request") {
		t.Fatalf("unusable hash = %d %s", rec.Code, rec.Body)
	}
}
