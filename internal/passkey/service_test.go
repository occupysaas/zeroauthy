package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

func registration(t *testing.T, s *Service, u *store.User, kind EnrollKind) (*webauthntest.Authenticator, []byte, *Taken, webauthn.CreationOptions) {
	t.Helper()
	ctx := context.Background()
	b := hostedBinding()
	b.Purpose = PasskeyRegister
	b.UserID = u.UserID
	i, err := s.Issue(ctx, "tenant", b, 5*time.Minute)
	must(t, err)
	o, err := s.CreationOptions(ctx, "tenant", u, UserDisplay{}, b.RPID, kind, i.Challenge, i.UserHandle, 5*time.Minute)
	must(t, err)
	if !bytes.Equal(o.UserID, i.UserHandle) {
		t.Fatal("offered handle differs from issued handle")
	}
	device := webauthntest.New(webauthntest.Options{BE: true, BS: true, Attachment: "cross-platform", Transports: []string{"hybrid"}})
	raw := device.Create(o, b.Origins[0])
	taken, err := s.Take(ctx, "tenant", i.ID, b)
	must(t, err)
	if !bytes.Equal(taken.UserHandle, o.UserID) {
		t.Fatal("taken handle differs from offered handle")
	}
	return device, raw, taken, o
}
func enroll(t *testing.T, s *Service, u *store.User) (*webauthntest.Authenticator, *store.Authenticator) {
	t.Helper()
	device, raw, taken, _ := registration(t, s, u, Progressive)
	// Registration completion may land on a different replica.
	replica := &Service{Store: s.Store, Now: s.Now}
	a, err := replica.Enroll(context.Background(), "tenant", u, "user", raw, taken, "Test Browser")
	must(t, err)
	return device, a
}
func publicHandle(t *testing.T, a *store.Authenticator) []byte {
	t.Helper()
	var p struct {
		Handle string `json:"user_handle"`
	}
	must(t, json.Unmarshal(a.PublicData, &p))
	b, err := base64.RawURLEncoding.DecodeString(p.Handle)
	must(t, err)
	return b
}
func TestLoginResolvesCredentialUser(t *testing.T) {
	ctx := context.Background()
	s, u := fixture(t)
	device, a := enroll(t, s, u)
	b := hostedBinding()
	ch := bytes.Repeat([]byte{1}, 32)
	device.Opts.SignCount = 1
	raw := device.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
	got, err := s.Login(ctx, "tenant", raw, ch, b)
	must(t, err)
	if got.User.UserID != u.UserID || got.Method.ID != a.ID || got.Assertion.SignCount != 1 {
		t.Fatal("credential owner not resolved")
	}
	saved, err := s.Store.MFA().GetAuthenticator(ctx, "tenant", u.UserID, a.ID)
	must(t, err)
	if saved.SignCount != 1 || !saved.LastAuthAt.Equal(testTime) {
		t.Fatal("assertion not committed")
	}
	if _, err = s.Login(ctx, "tenant", raw, ch, b); !errors.Is(err, ErrCeremony) || webauthn.Reason(err) != "sign_count" {
		t.Fatalf("regression: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{
		{"wrong_rp", func(b *Binding) { b.RPID = "example.test" }},
		{"wrong_origin", func(b *Binding) { b.Origins = []string{"https://other.example.test"} }},
		{"wrong_client", func(b *Binding) { b.ClientID = "disabled" }},
		{"wrong_realm", func(b *Binding) { b.Realm = "Other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := b
			tc.change(&wrong)
			if _, err := s.Login(ctx, "tenant", raw, ch, wrong); !errors.Is(err, ErrCeremony) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	device.Opts.SignCount = 2
	raw = device.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
	u.Blocked = true
	must(t, s.Store.Users().Update(ctx, u))
	if _, err = s.Login(ctx, "tenant", raw, ch, b); !errors.Is(err, identity.ErrUserBlocked) {
		t.Fatalf("blocked: %v", err)
	}
	u.Blocked = false
	must(t, s.Store.Users().Update(ctx, u))
	conn, err := s.Store.Connections().Get(ctx, "tenant", "db")
	must(t, err)
	conn.Extra = nil
	must(t, s.Store.Connections().Update(ctx, conn))
	if _, err = s.Login(ctx, "tenant", raw, ch, b); !errors.Is(err, ErrCeremony) {
		t.Fatalf("disabled: %v", err)
	}
}
func TestLoginAssertionRace(t *testing.T) {
	s, u := fixture(t)
	device, _ := enroll(t, s, u)
	b := hostedBinding()
	ch := bytes.Repeat([]byte{1}, 32)
	device.Opts.SignCount = 1
	raw := device.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, err := s.Login(context.Background(), "tenant", raw, ch, b)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrCeremony) || webauthn.Reason(err) != "sign_count" {
				t.Errorf("login: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners %d", winners.Load())
	}
}
func TestEnrollLimitAndExclude(t *testing.T) {
	s, u := fixture(t)
	ctx := context.Background()
	_, first := enroll(t, s, u)
	other := *first
	other.ID = "passkey|other"
	other.CredentialID = []byte("other")
	other.RPID = "other.example.test"
	must(t, s.Store.WebAuthn().CreatePasskey(ctx, &other, 20))
	_, _, _, o := registration(t, s, u, Local)
	if len(o.Exclude) != 1 || !bytes.Equal(o.Exclude[0].ID, first.CredentialID) || !slices.Equal(o.Exclude[0].Transports, []string{"hybrid"}) || o.Attachment != "platform" {
		t.Fatal("wrong RP exclusion/local params")
	}
	for n := 2; n < 20; n++ {
		a := *first
		a.ID = "passkey|" + string(rune('a'+n))
		a.CredentialID = []byte(a.ID)
		must(t, s.Store.WebAuthn().CreatePasskey(ctx, &a, 20))
	}
	// Keep options generated before the limit was reached to prove the finish
	// path relies on the store's atomic limit, not only the options check.
	b := hostedBinding()
	b.Purpose = PasskeyRegister
	b.UserID = u.UserID
	issued, err := s.Issue(ctx, "tenant", b, time.Minute)
	must(t, err)
	o.Challenge, o.UserID = issued.Challenge, issued.UserHandle
	device := webauthntest.New(webauthntest.Options{})
	raw := device.Create(o, b.Origins[0])
	taken, err := s.Take(ctx, "tenant", issued.ID, b)
	must(t, err)
	_, err = s.Enroll(ctx, "tenant", u, "user", raw, taken, "")
	var policy *identity.PolicyError
	if !errors.As(err, &policy) || policy.Key != "passkey-enrollment-max-allowed-reached" {
		t.Fatalf("limit = %v", err)
	}
	if _, err = s.CreationOptions(ctx, "tenant", u, UserDisplay{}, o.RPID, Progressive, o.Challenge, o.UserID, time.Minute); !errors.As(err, &policy) || policy.Key != "passkey-enrollment-max-allowed-reached" {
		t.Fatalf("options limit: %v", err)
	}
}
func TestUserHandleReused(t *testing.T) {
	s, u := fixture(t)
	_, first := enroll(t, s, u)
	_, raw, taken, o := registration(t, s, u, Progressive)
	if len(o.UserID) != 32 || !bytes.Equal(o.UserID, publicHandle(t, first)) {
		t.Fatal("handle not reused")
	}
	second, err := s.Enroll(context.Background(), "tenant", u, "user", raw, taken, "")
	must(t, err)
	if !bytes.Equal(publicHandle(t, first), publicHandle(t, second)) {
		t.Fatal("stored handle changed")
	}
}
func TestConcurrentFirstEnrollmentHandle(t *testing.T) {
	s, u := fixture(t)
	_, raw1, taken1, _ := registration(t, s, u, Progressive)
	_, raw2, taken2, _ := registration(t, s, u, Progressive)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for _, v := range []struct {
		raw   []byte
		taken *Taken
	}{{raw1, taken1}, {raw2, taken2}} {
		wg.Go(func() {
			_, err := s.Enroll(context.Background(), "tenant", u, "user", v.raw, v.taken, "")
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrCeremony) {
				t.Errorf("enroll: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d", winners.Load())
	}
	as, err := s.Store.MFA().ListAuthenticators(context.Background(), "tenant", u.UserID)
	must(t, err)
	if len(as) != 1 {
		t.Fatalf("committed %d", len(as))
	}
}
func TestSignupCreatesPasswordlessUser(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	draft := &store.User{TenantID: "tenant", UserID: "auth0|new", Email: "new@example.test", Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "new", PasswordHash: "must-clear", ImportedHash: "must-clear"}}}
	_, raw, taken, o := registration(t, s, draft, Signup)
	u, a, err := s.Signup(ctx, "tenant", draft, raw, taken, "")
	must(t, err)
	stored, err := s.Store.Users().Get(ctx, "tenant", u.UserID)
	must(t, err)
	if stored.Identities[0].PasswordHash != "" || stored.Identities[0].ImportedHash != "" || !bytes.Equal(publicHandle(t, a), o.UserID) {
		t.Fatal("signup not passwordless with the offered handle")
	}
	// Duplicate credential must roll back the user insert.
	draft2 := *draft
	draft2.UserID = "auth0|rollback"
	draft2.Email = "rollback@example.test"
	draft2.Identities = []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "rollback"}}
	taken2 := *taken
	taken2.Binding.UserID = draft2.UserID
	if _, _, err = s.Signup(ctx, "tenant", &draft2, raw, &taken2, ""); err == nil {
		t.Fatal("duplicate credential accepted")
	}
	if _, err = s.Store.Users().Get(ctx, "tenant", draft2.UserID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed signup left a user")
	}
}
func TestCreationOptionsUserNames(t *testing.T) {
	s, u := fixture(t)
	u.PhoneNumber = "+15555550123"
	u.Username = "alice"
	ch := bytes.Repeat([]byte{2}, 32)
	handle := bytes.Repeat([]byte{3}, 32)
	for _, tc := range []struct{ email, phone, name, want string }{{"alice@example.test", "+15555550123", "", "alice@example.test"}, {"", "+15555550123", "", "+15555550123"}, {"", "", "", "alice"}, {"alice@example.test", "", "Alice", "alice@example.test"}} {
		u.Email, u.PhoneNumber, u.Name = tc.email, tc.phone, tc.name
		o, err := s.CreationOptions(context.Background(), "tenant", u, UserDisplay{}, "login.example.test", Signup, ch, handle, time.Minute)
		must(t, err)
		display := tc.name
		if display == "" {
			display = tc.want
		}
		if o.UserName != tc.want || o.DisplayName != display || o.UserVerification != "preferred" || o.ResidentKey != "required" || o.RPName != o.RPID {
			t.Fatalf("names/options = %s %s %s %s", o.UserName, o.DisplayName, o.UserVerification, o.ResidentKey)
		}
	}
}
func TestEffective(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	tn, err := s.Store.Tenants().Get(ctx, "tenant")
	must(t, err)
	conn, err := s.Store.Connections().Get(ctx, "tenant", "db")
	must(t, err)
	p, r, ok, err := s.Effective(ctx, "tenant", tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost}, conn)
	must(t, err)
	if !p.Effective || !ok || !r.Valid || r.RPID != "login.example.test" {
		t.Fatalf("effective = %v %v %v", p, r, ok)
	}
	_, _, ok, err = s.Effective(ctx, "other", tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost}, conn)
	if err == nil || ok {
		t.Fatal("cross-tenant effective")
	}
	s.RPID = rpid.Policy{Store: s.Store}
	_, r, ok, err = s.Effective(ctx, "tenant", tenant.Resolved{Tenant: tn, Host: "unbound.example.test"}, conn)
	must(t, err)
	if r.Valid || ok {
		t.Fatal("invalid host offered")
	}
}
func TestCeremonyErrorsHideInput(t *testing.T) {
	s, u := fixture(t)
	device, _ := enroll(t, s, u)
	b := hostedBinding()
	ch := bytes.Repeat([]byte{1}, 32)
	raw := device.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
	secret := "attacker-controlled-secret"
	var doc map[string]any
	must(t, json.Unmarshal(raw, &doc))
	doc["type"] = secret
	raw, err := json.Marshal(doc)
	must(t, err)
	_, err = s.Login(context.Background(), "tenant", raw, ch, b)
	if !errors.Is(err, ErrCeremony) || webauthn.Reason(err) != "type" || strings.Contains(err.Error(), secret) {
		t.Fatal("verification failure did not retain only a bounded reason")
	}
}

type unavailableStore struct{ store.Store }

func (unavailableStore) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
func TestEffectiveUnavailable(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	tn, err := s.Store.Tenants().Get(ctx, "tenant")
	must(t, err)
	conn, err := s.Store.Connections().Get(ctx, "tenant", "db")
	must(t, err)
	s.Store = unavailableStore{s.Store}
	_, _, offered, err := s.Effective(ctx, "tenant", tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost}, conn)
	must(t, err)
	if offered {
		t.Fatal("unavailable store offers passkeys")
	}
	if _, err = s.Issue(ctx, "tenant", hostedBinding(), time.Minute); !errors.Is(err, store.ErrWebAuthnUnavailable) {
		t.Fatalf("unavailable issue = %v", err)
	}
}
func TestEnrollmentReloadsBlockedUser(t *testing.T) {
	s, u := fixture(t)
	ctx := context.Background()
	_, raw, taken, _ := registration(t, s, u, Progressive)
	blocked := *u
	blocked.Blocked = true
	must(t, s.Store.Users().Update(ctx, &blocked))
	if _, err := s.Enroll(ctx, "tenant", u, "user", raw, taken, ""); !errors.Is(err, identity.ErrUserBlocked) {
		t.Fatalf("stale user allowed enrollment: %v", err)
	}
}
func TestCreationOptionsConnectionIdentifiers(t *testing.T) {
	s, u := fixture(t)
	ctx := context.Background()
	u.PhoneNumber = "+15555550123"
	u.Username = "alice"
	conn, err := s.Store.Connections().Get(ctx, "tenant", "db")
	must(t, err)
	conn.Extra["attributes"] = map[string]any{"email": map[string]any{"identifier": map[string]any{"active": false}}, "phone_number": map[string]any{"identifier": map[string]any{"active": true}}, "username": map[string]any{"identifier": map[string]any{"active": true}}}
	must(t, s.Store.Connections().Update(ctx, conn))
	o, err := s.CreationOptions(ctx, "tenant", u, UserDisplay{}, "login.example.test", Progressive, make([]byte, 32), make([]byte, 32), time.Minute)
	must(t, err)
	if o.UserName != "+15555550123" || o.DisplayName != "+15555550123" {
		t.Fatal("disabled email selected over phone")
	}
}

func TestCeremonySecretsMasked(t *testing.T) {
	s, u := fixture(t)
	recorder := logs.NewRecorder(s.Store, logs.Config{}, nil)
	ctx := logs.WithRecorder(context.Background(), recorder)
	b := Binding{Purpose: PasskeyRegister, RPID: "login.example.test", Origins: []string{"https://login.example.test"}, ClientID: "client", Realm: "Database", UserID: u.UserID}
	i, err := s.Issue(ctx, "tenant", b, time.Minute)
	must(t, err)
	logs.RecordEvent(ctx, recorder, logs.Event{TenantID: "tenant", Type: "f", ClientName: strings.Join([]string{i.ID, i.Session, base64.RawURLEncoding.EncodeToString(i.Challenge), base64.RawURLEncoding.EncodeToString(i.UserHandle)}, " ")})
	device, _ := enroll(t, s, u)
	ch := bytes.Repeat([]byte{1}, 32)
	device.Opts.SignCount = 1
	raw := device.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
	_, err = s.Login(ctx, "tenant", raw, ch, hostedBinding())
	must(t, err)
	c, err := webauthn.ParseCredentialJSON(raw)
	must(t, err)
	secrets := []string{base64.RawURLEncoding.EncodeToString(c.Signature), base64.RawURLEncoding.EncodeToString(c.AuthenticatorData), base64.RawURLEncoding.EncodeToString(c.ClientDataJSON), base64.RawURLEncoding.EncodeToString(c.UserHandle), base64.RawURLEncoding.EncodeToString(c.RawID)}
	logs.RecordEvent(ctx, recorder, logs.Event{TenantID: "tenant", Type: "f", ClientName: strings.Join(secrets, " ")})
	must(t, recorder.Flush(context.Background()))
	rows, _, err := s.Store.Logs().SearchLogs(context.Background(), "tenant", nil, store.LogPage{PerPage: 20, Ascending: true})
	must(t, err)
	if len(rows) != 2 {
		t.Fatalf("logs=%d", len(rows))
	}
	for _, row := range rows {
		var body map[string]any
		must(t, json.Unmarshal(row.Body, &body))
		text, _ := body["client_name"].(string)
		if strings.TrimSpace(strings.ReplaceAll(text, logscrub.Marker, "")) != "" {
			t.Fatal("ceremony values leaked into outcome attribution")
		}
	}
}

func TestLinkedAccountHandles(t *testing.T) {
	s, u := fixture(t)
	ctx := context.Background()
	firstDevice, first := enroll(t, s, u)
	secondary := &store.User{TenantID: "tenant", UserID: "auth0|linked", Email: "linked@example.test", Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "linked"}}}
	must(t, s.Store.Users().Create(ctx, secondary))
	s.Now = func() time.Time { return testTime.Add(time.Minute) }
	secondDevice, raw, taken, _ := registration(t, s, secondary, Progressive)
	second, err := s.Enroll(ctx, "tenant", secondary, "linked", raw, taken, "")
	must(t, err)
	must(t, s.Store.WebAuthn().MovePasskeys(ctx, "tenant", secondary.UserID, u.UserID, "linked"))
	must(t, s.Store.Users().Delete(ctx, "tenant", secondary.UserID))
	u.Identities = append(u.Identities, store.Identity{Connection: "Database", Provider: "auth0", UserID: "linked", ProfileData: map[string]any{"email": secondary.Email}})
	must(t, s.Store.Users().Update(ctx, u))
	s.Now = func() time.Time { return testTime.Add(2 * time.Minute) }
	_, raw, taken, _ = registration(t, s, u, Progressive)
	added, err := s.Enroll(ctx, "tenant", u, "user", raw, taken, "")
	must(t, err)
	if !bytes.Equal(publicHandle(t, added), publicHandle(t, first)) {
		t.Fatal("new passkey did not reuse the oldest existing handle")
	}
	if bytes.Equal(publicHandle(t, first), publicHandle(t, second)) {
		t.Fatal("test requires distinct pre-link handles")
	}
	// Each old authenticator retains its own handle and remains usable.
	for _, d := range []*webauthntest.Authenticator{firstDevice, secondDevice} {
		d.Opts.SignCount = 1
		b := hostedBinding()
		ch := bytes.Repeat([]byte{7}, 32)
		raw := d.Get(s.RequestOptions(b.RPID, ch, time.Minute), b.Origins[0])
		got, err := s.Login(ctx, "tenant", raw, ch, b)
		must(t, err)
		if got.User.UserID != u.UserID {
			t.Fatal("linked credential did not resolve primary user")
		}
	}
}
