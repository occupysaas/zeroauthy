package login

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A hosted enrollment transaction is decided once at /authorize. If the user
// enrolls a factor out of band before the stale transaction confirms its own
// enrollment, the stale transaction must not add a second factor and finish
// MFA with a password alone. It falls back to the challenge for the factor the
// user now has (Auth0 challenges an enrolled user; it never re-enrolls them:
// https://auth0.com/docs/secure/multi-factor-authentication/enable-mfa).
func TestMFAStaleEnrollmentFallsBackToChallenge(t *testing.T) {
	cases := []struct {
		name string
		// start opens the stale enrollment and returns the attacker's path and code.
		start func(t *testing.T, f *mfaFixture) (path, code string)
		// victim enrolls a factor out of band.
		victim func(t *testing.T, f *mfaFixture)
		typ    string
	}{
		{
			name: "otp",
			start: func(t *testing.T, f *mfaFixture) (string, string) {
				f.policy(t, "otp")
				f.begin(t)
				p := f.page(t, "/u/mfa-otp-enrollment")
				m := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
				if m == nil {
					t.Fatalf("missing secret %s", p.Body)
				}
				return "/u/mfa-otp-enrollment", m[1]
			},
			victim: func(t *testing.T, f *mfaFixture) { f.enrolled(t, "otp", false) },
			typ:    "totp",
		},
		{
			name: "email",
			start: func(t *testing.T, f *mfaFixture) (string, string) {
				f.policy(t, "email")
				f.begin(t)
				f.page(t, "/u/mfa-email-challenge")
				return "/u/mfa-email-challenge", f.mail.codes[len(f.mail.codes)-1]
			},
			victim: func(t *testing.T, f *mfaFixture) {
				*f.clock = f.clock.Add(time.Minute)
				f.enrolled(t, "email", false)
			},
			typ: "email",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAFixture(t)
			path, code := tc.start(t, f)
			tc.victim(t, f)
			if tc.typ == "totp" {
				code = otpAt(code, *f.clock)
			}
			r := f.post(t, path, url.Values{"code": {code}})
			assertStaleFallback(t, f, r, tc.typ)
		})
	}
}

// staleViewStore shows the hosted handlers the authenticators as they were
// when the page loaded, so the out-of-band enrollment lands between the
// page's own check and the confirmation transaction.
type staleViewStore struct {
	store.Store
	mfa staleViewMFA
}
type staleViewMFA struct {
	store.MFA
}

func (s staleViewStore) MFA() store.MFA { return s.mfa }
func (staleViewMFA) ListAuthenticators(context.Context, string, string) ([]store.Authenticator, error) {
	return nil, nil
}

// The confirmation itself refuses a first enrollment once the user has a
// usable factor, even when the factor appears after every earlier check.
func TestMFAEnrollmentConfirmRaceFallsBackToChallenge(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	m := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
	if m == nil {
		t.Fatalf("missing secret %s", p.Body)
	}
	f.enrolled(t, "otp", false)
	f.h.Store = staleViewStore{Store: f.st, mfa: staleViewMFA{MFA: f.st.MFA()}}
	r := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(m[1], *f.clock)}})
	f.h.Store = f.st
	assertStaleFallback(t, f, r, "totp")
}

func TestMFAConfirmFirstEnrollReportsAlreadyEnrolled(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	ctx := context.Background()
	e, err := f.h.MFA.BeginEnroll(ctx, f.tn.ID, f.uid, "otp", f.b.host)
	if err != nil {
		t.Fatal(err)
	}
	f.enrolled(t, "otp", false)
	_, err = f.h.MFA.ConfirmFirstEnroll(ctx, f.tn.ID, f.uid, e, mfa.Proof{Code: otpAt(e.Secret, *f.clock)})
	if !errors.Is(err, mfa.ErrAlreadyEnrolled) || !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("ConfirmFirstEnroll = %v, want ErrAlreadyEnrolled (an ErrInvalidCode)", err)
	}
}

func TestMFAStalePhoneEnrollmentFallsBackToChallenge(t *testing.T) {
	f, runner := newPhoneMFAFixture(t, "sms")
	f.begin(t)
	f.page(t, "/u/mfa-phone-enrollment")
	if rec := f.post(t, "/u/mfa-phone-enrollment", url.Values{"phone_number": {"+1 415 555 0199"}}); rec.Code != 303 {
		t.Fatalf("enroll number = %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-sms-challenge")
	code := runner.last(t).Message.Code
	f.enrolledPhone(t, runner, "sms")
	r := f.post(t, "/u/mfa-sms-challenge", url.Values{"code": {code}})
	assertStaleFallback(t, f, r, "phone")
}

func assertStaleFallback(t *testing.T, f *mfaFixture, r *httptest.ResponseRecorder, typ string) {
	t.Helper()
	if strings.Contains(r.Body.String(), `id="recovery-code"`) || strings.Contains(r.Header().Get("Location"), "code=") {
		t.Fatalf("stale enrollment completed: %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	if r.Code != 303 || f.location(t, r) != "/u/mfa" {
		t.Fatalf("stale enrollment = %d %s, want redirect to /u/mfa", r.Code, r.Header().Get("Location"))
	}
	aa, err := f.st.MFA().ListAuthenticators(context.Background(), f.tn.ID, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := 0
	for _, a := range aa {
		if a.Type == typ && a.Confirmed {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("confirmed %s methods = %d, want only the victim's: %+v", typ, confirmed, aa)
	}
	req := httptest.NewRequest("GET", "https://"+f.b.host+"/", nil)
	req.AddCookie(f.b.cookies[session.CookieName])
	if sess, _ := f.h.Sessions.Lookup(context.Background(), req, f.tn); sess == nil || !sess.MFAAt.IsZero() {
		t.Fatalf("session marked MFA by a stale enrollment: %+v", sess)
	}
	// The same transaction now challenges the factor the user has.
	next := f.b.do(t, "GET", r.Header().Get("Location"), nil)
	if next.Code != 303 || !strings.Contains(f.location(t, next), "challenge") {
		t.Fatalf("fallback = %d %s, want a challenge page", next.Code, next.Header().Get("Location"))
	}
	if p := f.page(t, f.location(t, next)); strings.Contains(p.Body.String(), `id="mfa-secret"`) {
		t.Fatalf("fallback still enrolls %s", p.Body)
	}
}

// Back or Refresh after MFA completed, and an expired transaction, show the
// hosted session-expired error page like the login and consent pages do,
// never a redirect to an unrouted path.
func TestMFAStalePageShowsHostedError(t *testing.T) {
	t.Run("back after completion", func(t *testing.T) {
		f := newMFAFixture(t)
		f.policy(t, "email")
		f.begin(t)
		r := f.post(t, "/u/mfa-email-challenge", url.Values{"code": {f.mail.codes[len(f.mail.codes)-1]}})
		if !strings.Contains(r.Body.String(), `id="recovery-code"`) {
			t.Fatalf("enrollment %d", r.Code)
		}
		if r = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}}); r.Code != 302 {
			t.Fatalf("ack %d %s", r.Code, r.Body)
		}
		for _, p := range []string{"/u/mfa-email-challenge", "/u/mfa-recovery-code-enrollment", "/u/mfa"} {
			assertHostedExpired(t, f.b.do(t, "GET", p+"?state="+f.state, nil))
		}
	})
	t.Run("expired transaction", func(t *testing.T) {
		f := newMFAFixture(t)
		f.policy(t, "otp")
		f.begin(t)
		*f.clock = f.clock.Add(16 * time.Minute)
		assertHostedExpired(t, f.b.do(t, "GET", "/u/mfa-otp-enrollment?state="+f.state, nil))
	})
}

func assertHostedExpired(t *testing.T, r *httptest.ResponseRecorder) {
	t.Helper()
	if r.Code != 400 || r.Header().Get("Location") != "" || !strings.Contains(strings.ToLower(r.Body.String()), "<html") {
		t.Fatalf("stale MFA page = %d %q %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}

// A factor chosen from the list on a just-switched transaction starts its
// challenge instead of restarting the list again.
func TestMFAStaleEnrollmentFactorChoice(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp", "email")
	f.begin(t)
	f.enrolled(t, "email", false)
	r := f.b.do(t, "GET", "/u/mfa?action=another&state="+f.state, nil)
	if r.Code != 200 || strings.Contains(r.Body.String(), `value="otp"`) {
		t.Fatalf("factor list = %d %s", r.Code, r.Body)
	}
	if m := csrfField.FindStringSubmatch(r.Body.String()); m != nil {
		f.csrf = m[1]
	}
	v := url.Values{"factor": {"email"}}
	if m := regexp.MustCompile(`name="hosted_revision" value="([^"]*)"`).FindStringSubmatch(r.Body.String()); m != nil {
		v.Set("hosted_revision", m[1])
	}
	r = f.post(t, "/u/mfa", v)
	if r.Code != 303 || f.location(t, r) != "/u/mfa-email-challenge" {
		t.Fatalf("choose email = %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}
