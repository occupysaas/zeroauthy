package login

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/devicecode"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const userCode = "BCDF-GHJK"

// deviceCode stores a code for the tv client. audience "" asks for no API.
func (e *env) deviceCode(t *testing.T, code string, status store.DeviceCodeStatus, expiresAt time.Time, audience string, scopes ...string) *store.DeviceCode {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	dc := &store.DeviceCode{
		TenantID: mustTenant(t, e, "acme").ID, DeviceCodeHash: secrets.HashToken(secrets.RandomString(43)),
		UserCodeHash: secrets.HashToken(devicecode.Normalize(code)), ClientID: "tv", Scopes: scopes, Audience: audience,
		Status: status, ExpiresAt: expiresAt, CreatedAt: fixedNow(),
	}
	if err := e.st.DeviceCodes().Create(context.Background(), dc); err != nil {
		t.Fatal(err)
	}
	return dc
}

func (e *env) pendingCode(t *testing.T, code string) *store.DeviceCode {
	t.Helper()
	return e.deviceCode(t, code, store.DeviceCodePending, fixedNow().Add(15*time.Minute), "")
}

func (e *env) storedCode(t *testing.T, dc *store.DeviceCode) *store.DeviceCode {
	t.Helper()
	got, err := e.st.DeviceCodes().Get(context.Background(), dc.TenantID, dc.DeviceCodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

var stateField = regexp.MustCompile(`name="state" value="([^"]+)"`)

func formValue(t *testing.T, re *regexp.Regexp, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := re.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no %s in %d page:\n%s", re, rec.Code, rec.Body)
	}
	return m[1]
}

// entry opens /activate and returns the entry form's state and CSRF token.
func (b *browser) entry(t *testing.T) (string, string) {
	t.Helper()
	rec := b.do(t, "GET", "/activate", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /activate = %d\n%s", rec.Code, rec.Body)
	}
	return formValue(t, stateField, rec), formValue(t, csrfField, rec)
}

// submitCode posts code on a fresh entry form.
func (b *browser) submitCode(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	state, csrf := b.entry(t)
	return b.do(t, "POST", "/activate", url.Values{"state": {state}, "csrf": {csrf}, "code": {code}})
}

// confirmPage follows a redirect to the confirmation page and returns it
// with its state and CSRF token.
func (b *browser) confirmPage(t *testing.T, rec *httptest.ResponseRecorder) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	loc := redirectTo(t, rec, "/device/confirmation")
	page := b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("confirmation page = %d\n%s", page.Code, page.Body)
	}
	return page, formValue(t, stateField, page), formValue(t, csrfField, page)
}

func redirectTo(t *testing.T, rec *httptest.ResponseRecorder, path string) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 to %s\n%s", rec.Code, path, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Path != path {
		t.Fatalf("Location = %q, want %s", rec.Header().Get("Location"), path)
	}
	return loc
}

func text(key string) string { return html.EscapeString(i18n.Default().T(key)) }

func entryError(t *testing.T, rec *httptest.ResponseRecorder, status int, key string) {
	t.Helper()
	if rec.Code != status || !strings.Contains(rec.Body.String(), text(key)) || !strings.Contains(rec.Body.String(), `action="/activate"`) {
		t.Fatalf("status %d, want %d entry page with %s\n%s", rec.Code, status, key, rec.Body)
	}
}

func sessionExpired(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), text(i18n.KeyErrSessionExpired)) {
		t.Fatalf("status %d, want the session-expired page\n%s", rec.Code, rec.Body)
	}
}

func TestActivateShowsEntry(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec := b.do(t, "GET", "/activate", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `type="hidden" name="state"`) {
		t.Fatalf("GET /activate = %d\n%s", rec.Code, rec.Body)
	}
	state := formValue(t, stateField, rec)
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == authz.TxnCookiePrefix+state {
			found = c.Path == "/" && c.HttpOnly && c.Secure
		}
	}
	if !found {
		t.Fatalf("no za_txn_ cookie with Path=/: %v", rec.Result().Cookies())
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, state)
	if err != nil || txn.ClientID != "" || txn.Params[authz.ParamStage] != authz.StageDeviceEntry || txn.Params[authz.ParamFlow] != authz.FlowDevice {
		t.Fatalf("entry transaction %+v, %v", txn, err)
	}
}

func TestActivateWithUserCodeGoesToConfirm(t *testing.T) {
	e := newEnv(t)
	dc := e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	rec := b.do(t, "GET", "/activate?user_code="+userCode, nil)
	page, state, _ := b.confirmPage(t, rec)
	body := page.Body.String()
	if !strings.Contains(body, userCode) || !strings.Contains(body, "Living Room TV") {
		t.Fatalf("confirmation page lacks the code or the client name:\n%s", body)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), dc.TenantID, state)
	if err != nil || txn.ClientID != "tv" || txn.Params[authz.ParamStage] != authz.StageDeviceConfirm ||
		txn.Params[authz.ParamDevice] != dc.DeviceCodeHash || txn.Params[authz.ParamUserCode] != userCode {
		t.Fatalf("confirmation transaction %+v, %v", txn, err)
	}
}

func TestDeviceSubmitAcceptsLooseFormatting(t *testing.T) {
	e := newEnv(t)
	e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	redirectTo(t, b.submitCode(t, " bcdf ghjk\n"), "/device/confirmation")
}

func TestDeviceSubmitErrors(t *testing.T) {
	e := newEnv(t)
	e.deviceCode(t, "CCCC-CCCC", store.DeviceCodePending, fixedNow(), "") // expired now
	e.deviceCode(t, "DDDD-DDDD", store.DeviceCodeApproved, fixedNow().Add(time.Hour), "")
	b := e.browser("acme.example.test")
	for _, code := range []string{"wrongcode", "CCCC-CCCC", "DDDD-DDDD"} {
		entryError(t, b.submitCode(t, code), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
	entryError(t, b.submitCode(t, ""), http.StatusBadRequest, i18n.KeyDeviceNoCode)
	entryError(t, b.submitCode(t, " - "), http.StatusBadRequest, i18n.KeyDeviceNoCode)
	// The GET form of the check gives the same answer.
	entryError(t, b.do(t, "GET", "/activate?user_code=wrongcode", nil), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
}

func TestDeviceTxnLimit(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	state, csrf := b.entry(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "code": {"wrongcode"}}
	for i := 0; i < 5; i++ {
		entryError(t, b.do(t, "POST", "/activate", form), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
	sessionExpired(t, b.do(t, "POST", "/activate", form))
	if _, err := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, state); err == nil {
		t.Fatal("the transaction was not deleted")
	}
}

func TestDeviceIPLimit(t *testing.T) {
	e := newEnv(t)
	e.h.DeviceIPThrottle = identity.NewThrottle(3, 15*time.Minute, 15*time.Minute)
	e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	for i := 0; i < 3; i++ {
		entryError(t, b.submitCode(t, "wrongcode"), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
	entryError(t, b.submitCode(t, userCode), http.StatusTooManyRequests, i18n.KeyTooManyAttempts)
	entryError(t, b.do(t, "GET", "/activate?user_code="+userCode, nil), http.StatusTooManyRequests, i18n.KeyTooManyAttempts)
}

func TestDeviceTenantLimit(t *testing.T) {
	e := newEnv(t)
	e.h.DeviceIPThrottle = nil
	e.h.DeviceTenantThrottle = identity.NewThrottle(3, 10*time.Minute, time.Minute)
	b := e.browser("acme.example.test")
	for i := 0; i < 3; i++ {
		entryError(t, b.submitCode(t, "wrongcode"), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
	entryError(t, b.submitCode(t, "wrongcode"), http.StatusTooManyRequests, i18n.KeyTooManyAttempts)
	// Another tenant is not affected.
	if rec := e.browser("globex.example.test").do(t, "GET", "/activate", nil); rec.Code != http.StatusOK {
		t.Fatalf("globex entry = %d", rec.Code)
	}
}

func TestDeviceTenantLimitOff(t *testing.T) {
	e := newEnv(t)
	e.h.DeviceIPThrottle = nil
	e.h.DeviceTenantThrottle = nil
	b := e.browser("acme.example.test")
	for i := 0; i < 20; i++ {
		entryError(t, b.submitCode(t, "wrongcode"), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
}

func TestDeviceSuccessRefunds(t *testing.T) {
	e := newEnv(t)
	e.h.DeviceIPThrottle = identity.NewThrottle(3, 15*time.Minute, 15*time.Minute)
	e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	for i := 0; i < 2; i++ {
		entryError(t, b.submitCode(t, "wrongcode"), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	}
	// The third attempt succeeds: it is refunded, and does not lock the IP.
	redirectTo(t, b.submitCode(t, userCode), "/device/confirmation")
	state, csrf := b.entry(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "code": {"wrongcode"}}
	entryError(t, b.do(t, "POST", "/activate", form), http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	// A refund undoes one attempt; it does not forget the earlier misses
	// (an attacker can mint valid codes of their own), so this is the
	// fourth miss within the limit of three.
	entryError(t, b.do(t, "POST", "/activate", form), http.StatusTooManyRequests, i18n.KeyTooManyAttempts)
}

func TestDeviceEntryChecksTransaction(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	state, csrf := b.entry(t)
	sessionExpired(t, b.do(t, "POST", "/activate", url.Values{"state": {state}, "csrf": {"wrong"}, "code": {userCode}}))
	other := e.browser("acme.example.test") // no za_txn cookie
	sessionExpired(t, other.do(t, "POST", "/activate", url.Values{"state": {state}, "csrf": {csrf}, "code": {userCode}}))
	// An entry transaction is not a confirmation transaction.
	sessionExpired(t, b.do(t, "GET", "/device/confirmation?state="+url.QueryEscape(state), nil))
	sessionExpired(t, b.do(t, "POST", "/device/confirmation", url.Values{"state": {state}, "csrf": {csrf}, "action": {"confirm"}}))
}

func TestDeviceConfirmCancel(t *testing.T) {
	e := newEnv(t)
	dc := e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	_, state, csrf := b.confirmPage(t, b.submitCode(t, userCode))
	rec := b.do(t, "POST", "/device/confirmation", url.Values{"state": {state}, "csrf": {csrf}, "action": {"cancel"}})
	redirectTo(t, rec, "/device/denied")
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeDenied {
		t.Fatalf("status = %s", got.Status)
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), dc.TenantID, state); err == nil {
		t.Fatal("the confirmation transaction was not deleted")
	}
	page := b.do(t, "GET", "/device/denied", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), text("device-flow.device-code-activation-denied.eventTitle")) {
		t.Fatalf("denied page = %d\n%s", page.Code, page.Body)
	}
}

// login signs the browser in as alice through the spa client.
func (b *browser) login(t *testing.T) {
	t.Helper()
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d\n%s", rec.Code, rec.Body)
	}
}

func TestDeviceConfirmTwice(t *testing.T) {
	e := newEnv(t)
	dc := e.pendingCode(t, userCode)
	b := e.browser("acme.example.test")
	b.login(t)
	// Two confirmation pages for the same code; the second is accepted
	// first (no consent: first-party client, no API).
	_, stateA, csrfA := b.confirmPage(t, b.submitCode(t, userCode))
	_, stateB, csrfB := b.confirmPage(t, b.submitCode(t, userCode))
	rec := b.do(t, "POST", "/device/confirmation", url.Values{"state": {stateB}, "csrf": {csrfB}, "action": {"confirm"}})
	redirectTo(t, rec, "/device/success")
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeApproved {
		t.Fatalf("status = %s", got.Status)
	}
	rec = b.do(t, "POST", "/device/confirmation", url.Values{"state": {stateA}, "csrf": {csrfA}, "action": {"confirm"}})
	entryError(t, rec, http.StatusBadRequest, i18n.KeyDeviceInvalidExpiredCode)
	// The error page is a new entry form.
	if s := formValue(t, stateField, rec); s == stateA || s == stateB {
		t.Fatalf("entry page reuses state %q", s)
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeApproved {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestDeviceFullFlowWithLogin(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t, userCode, store.DeviceCodePending, fixedNow().Add(15*time.Minute), "https://api.acme.test", "openid", "read:things")
	b := e.browser("acme.example.test")
	_, state, csrf := b.confirmPage(t, b.do(t, "GET", "/activate?user_code="+url.QueryEscape("bcdf-ghjk"), nil))
	rec := b.do(t, "POST", "/device/confirmation", url.Values{"state": {state}, "csrf": {csrf}, "action": {"confirm"}})
	loc := redirectTo(t, rec, "/u/login")

	page := b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("login page = %d\n%s", page.Code, page.Body)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {formValue(t, stateField, page)}, "csrf": {formValue(t, csrfField, page)},
		"username": {"alice@acme.test"}, "password": {"alice password 1"}})
	loc = redirectTo(t, rec, "/u/consent")

	page = b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "read:things") || !strings.Contains(page.Body.String(), "Living Room TV") {
		t.Fatalf("consent page = %d\n%s", page.Code, page.Body)
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Fatalf("consent CSP = %q", csp)
	}
	rec = b.do(t, "POST", "/u/consent", url.Values{"state": {formValue(t, stateField, page)}, "csrf": {formValue(t, csrfField, page)}, "action": {"accept"}})
	redirectTo(t, rec, "/device/success")

	got := e.storedCode(t, dc)
	if got.Status != store.DeviceCodeApproved || got.UserID == "" {
		t.Fatalf("code = %+v", got)
	}
	page = b.do(t, "GET", "/device/success", nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), text("device-flow.device-code-activation-allowed.eventTitle")) {
		t.Fatalf("success page = %d\n%s", page.Code, page.Body)
	}
}

func TestDeviceCustomText(t *testing.T) {
	e := newEnv(t)
	rec := e.browser("acme.example.test").do(t, "GET", "/activate", nil)
	if !strings.Contains(rec.Body.String(), "Link your Acme device") {
		t.Fatalf("entry page lacks the tenant's title:\n%s", rec.Body)
	}
}
