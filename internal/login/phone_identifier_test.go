package login

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestLoginByPhoneAndPassword(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	_ = r
	ctx := context.Background()
	c, e := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	if e != nil {
		t.Fatal(e)
	}
	c.Extra = map[string]any{"attributes": map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}}}}
	if e = f.st.Connections().Update(ctx, c); e != nil {
		t.Fatal(e)
	}
	u, _ := f.st.Users().Get(ctx, f.tn.ID, f.uid)
	u.PhoneNumber = "+1 (415) 555-0100"
	if e = f.st.Users().Update(ctx, u); e != nil {
		t.Fatal(e)
	}
	hash, _ := secrets.Hash("A-secret-password-42")
	if e = f.st.Users().SetPasswordHash(ctx, f.tn.ID, f.uid, c.Name, hash, time.Now()); e != nil {
		t.Fatal(e)
	}
	got, e := f.h.Database.Login(ctx, c, "+1 415 555 0100", "A-secret-password-42")
	if e != nil || got.UserID != u.UserID {
		t.Fatalf("%+v %v", got, e)
	}
	_, e = f.h.Database.Login(ctx, c, "+14155550100", "wrong-password")
	if e == nil {
		t.Fatal("accepted wrong password")
	}
	c.Extra = nil
	_, e = f.h.Database.Login(ctx, c, "+14155550100", "A-secret-password-42")
	if e == nil || errors.Is(e, store.ErrPhoneUnavailable) {
		t.Fatalf("disabled phone login: %v", e)
	}
}

func phoneDatabase(t *testing.T, f *mfaFixture) *store.Connection {
	t.Helper()
	ctx := context.Background()
	c, err := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	c.Extra = map[string]any{"attributes": map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}}}}
	if err = f.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestSignupWithPhoneVerificationHosted(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	c := phoneDatabase(t, f)
	f.policy(t)
	_, state, csrf := f.b.begin(t, "screen_hint", "signup")
	form := url.Values{"state": {state}, "csrf": {csrf}, "phone_number": {"+14155550199"}, "password": {"A-secret-password-42"}}
	page := f.b.do(t, "POST", "/u/signup", form)
	if page.Code != 200 || r.count() != 1 {
		t.Fatalf("send=%d count=%d %s", page.Code, r.count(), page.Body)
	}
	users, _ := f.st.Phone().FindUsersByPhone(t.Context(), f.tn.ID, c.Name, "+14155550199")
	if len(users) != 0 {
		t.Fatal("created before verification")
	}
	form.Set("phone_code", r.last(t).Message.Code)
	page = f.b.do(t, "POST", "/u/signup", form)
	if page.Code != 302 {
		t.Fatalf("confirm=%d %s", page.Code, page.Body)
	}
	users, _ = f.st.Phone().FindUsersByPhone(t.Context(), f.tn.ID, c.Name, "+14155550199")
	if len(users) != 1 || !users[0].PhoneVerified {
		t.Fatalf("created users=%+v", users)
	}
}
func TestResetByPhoneHosted(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	c := phoneDatabase(t, f)
	f.policy(t)
	u, _ := f.st.Users().Get(t.Context(), f.tn.ID, f.uid)
	u.PhoneNumber = "+14155550100"
	if err := f.st.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	_, state, csrf := f.b.begin(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "phone_number": {"+14155550100"}}
	page := f.b.do(t, "POST", "/u/reset-password/request", form)
	if page.Code != 200 || r.count() != 1 {
		t.Fatalf("send=%d count=%d %s", page.Code, r.count(), page.Body)
	}
	// Scanner-like GET does not consume the code.
	f.b.do(t, "GET", "/u/reset-password/request?state="+state, nil)
	form.Set("phone_code", r.last(t).Message.Code)
	page = f.b.do(t, "POST", "/u/reset-password/request", form)
	if page.Code != 303 {
		t.Fatalf("code=%d %s", page.Code, page.Body)
	}
	loc, err := url.Parse(page.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	ticket := loc.Query().Get("ticket")
	page = f.b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != 200 {
		t.Fatalf("form=%d %s", page.Code, page.Body)
	}
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("missing reset csrf")
	}
	reset := url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {"short"}, "password_confirm": {"short"}}
	page = f.b.do(t, "POST", "/u/reset-password", reset)
	if page.Code != 400 {
		t.Fatalf("weak password=%d", page.Code)
	}
	reset.Set("password", "New-secret-password-42")
	reset.Set("password_confirm", "New-secret-password-42")
	page = f.b.do(t, "POST", "/u/reset-password", reset)
	if page.Code != 200 {
		t.Fatalf("reset=%d %s", page.Code, page.Body)
	}
	if _, err = f.h.Database.Login(t.Context(), c, "+14155550100", "New-secret-password-42"); err != nil {
		t.Fatal(err)
	}
	if page = f.b.do(t, "POST", "/u/reset-password", reset); page.Code != 400 {
		t.Fatal("reset ticket replayed")
	}
}

func TestPhoneIdentifierPrecedence(t *testing.T) {
	f, _ := newPhoneMFAFixture(t, "sms")
	c := phoneDatabase(t, f)
	c.RequiresUsername = true
	// Existing username is the same E.164 string as another user's phone.
	hash, _ := secrets.Hash("Username-secret-42")
	phoneHash, _ := secrets.Hash("Phone-secret-42")
	u, _ := f.st.Users().Get(t.Context(), f.tn.ID, f.uid)
	u.Username = "+14155550111"
	if e := f.st.Users().Update(t.Context(), u); e != nil {
		t.Fatal(e)
	}
	if e := f.st.Users().SetPasswordHash(t.Context(), f.tn.ID, u.UserID, c.Name, hash, time.Now()); e != nil {
		t.Fatal(e)
	}
	other := &store.User{TenantID: f.tn.ID, UserID: "auth0|other", Email: "other@example.test", PhoneNumber: "+14155550111", Identities: []store.Identity{{Provider: "auth0", Connection: c.Name, UserID: "other", PasswordHash: phoneHash}}}
	if e := f.st.Users().Create(t.Context(), other); e != nil {
		t.Fatal(e)
	}
	c.Extra["precedence"] = []any{"username", "phone_number", "email"}
	got, e := f.h.Database.Login(t.Context(), c, "+14155550111", "Username-secret-42")
	if e != nil || got.UserID != u.UserID {
		t.Fatalf("username first: %v", e)
	}
	c.Extra["precedence"] = []any{"phone_number", "username", "email"}
	got, e = f.h.Database.Login(t.Context(), c, "+14155550111", "Phone-secret-42")
	if e != nil || got.UserID != other.UserID {
		t.Fatalf("phone first: %v", e)
	}
}

func TestPhoneSignupNotAllowedSendsNothing(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	c := phoneDatabase(t, f)
	f.policy(t)
	c.Extra["attributes"].(map[string]any)["phone_number"].(map[string]any)["signup"] = map[string]any{"status": "not_allowed"}
	if e := f.st.Connections().Update(t.Context(), c); e != nil {
		t.Fatal(e)
	}
	_, state, csrf := f.b.begin(t, "screen_hint", "signup")
	rec := f.b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"signup@example.test"}, "phone_number": {"+14155550199"}, "password": {"A-secret-password-42"}})
	if rec.Code != 400 || r.count() != 0 {
		t.Fatalf("status=%d sends=%d", rec.Code, r.count())
	}
}
