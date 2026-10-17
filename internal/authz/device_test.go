package authz

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// deviceCode stores a pending code for the tv client on the skip-consent API.
func (e *env) deviceCode(t *testing.T) *store.DeviceCode {
	t.Helper()
	dc := &store.DeviceCode{
		TenantID: e.tenant.ID, DeviceCodeHash: secrets.HashToken(secrets.RandomString(43)), UserCodeHash: secrets.HashToken(secrets.RandomString(8)),
		ClientID: "tv", Scopes: []string{"openid", "offline_access"}, Audience: "https://api.acme.test",
		Status: store.DeviceCodePending, ExpiresAt: fixedNow().Add(TxnLifetime), CreatedAt: fixedNow(),
	}
	if err := e.st.DeviceCodes().Create(context.Background(), dc); err != nil {
		t.Fatal(err)
	}
	return dc
}

func (e *env) storedCode(t *testing.T, dc *store.DeviceCode) *store.DeviceCode {
	t.Helper()
	got, err := e.st.DeviceCodes().Get(context.Background(), e.tenant.ID, dc.DeviceCodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// noSkipAPI makes the fixture's API ask first-party clients for consent.
func (e *env) noSkipAPI(t *testing.T) {
	t.Helper()
	rs, _ := e.st.ResourceServers().GetByIdentifier(context.Background(), e.tenant.ID, "https://api.acme.test")
	rs.SkipConsentForVerifiableFirstPartyClients = false
	if err := e.st.ResourceServers().Update(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
}

func (e *env) continueDevice(t *testing.T, dc *store.DeviceCode, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/device", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	e.h.ContinueDevice(rec, r, e.res(), dc, "")
	return rec
}

// txnAt loads the transaction a redirect to page?state=… names.
func (e *env) txnAt(t *testing.T, rec *httptest.ResponseRecorder, page string) *store.AuthTransaction {
	t.Helper()
	loc := location(t, rec)
	if loc.Path != page || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s, want %s?state=…", loc, page)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	return txn
}

// deviceConsentTxn walks a logged-in browser to the device consent page.
func (e *env) deviceConsentTxn(t *testing.T, dc *store.DeviceCode, ck *http.Cookie) *store.AuthTransaction {
	t.Helper()
	e.noSkipAPI(t)
	return e.txnAt(t, e.continueDevice(t, dc, ck), "/u/consent")
}

func TestContinueDeviceNoSessionStartsLogin(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	txn := e.txnAt(t, e.continueDevice(t, dc), "/u/login")
	if txn.Params[ParamFlow] != FlowDevice || txn.Params[ParamDevice] != dc.DeviceCodeHash || txn.ClientID != "tv" ||
		txn.Params["scope"] != "openid offline_access" || txn.Params["audience"] != "https://api.acme.test" {
		t.Fatalf("txn params = %v", txn.Params)
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodePending {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestContinueDeviceSessionSkipAPI(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	ck := e.login(t, fixedNow())
	loc := location(t, e.continueDevice(t, dc, ck))
	if loc.Path != "/device/success" {
		t.Fatalf("Location = %s", loc)
	}
	got := e.storedCode(t, dc)
	if got.Status != store.DeviceCodeApproved || got.UserID != e.session(t, ck).UserID || !slices.Equal(got.GrantedScopes, []string{"openid", "offline_access"}) {
		t.Fatalf("code = %+v", got)
	}
}

func TestContinueDeviceSessionShowsConsent(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	txn := e.deviceConsentTxn(t, dc, e.login(t, fixedNow()))
	if txn.Params[ParamStage] != stageConsent || txn.Params[ParamDevice] != dc.DeviceCodeHash {
		t.Fatalf("txn params = %v", txn.Params)
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodePending {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestDeviceConsentAccept(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	ck := e.login(t, fixedNow())
	loc := location(t, e.consent(t, e.deviceConsentTxn(t, dc, ck), ck, true))
	if loc.Path != "/device/success" {
		t.Fatalf("Location = %s", loc)
	}
	got := e.storedCode(t, dc)
	if got.Status != store.DeviceCodeApproved || got.UserID != e.session(t, ck).UserID || !slices.Equal(got.GrantedScopes, []string{"openid", "offline_access"}) {
		t.Fatalf("code = %+v", got)
	}
	if g := e.userGrant(t, "tv", "https://api.acme.test"); g == nil || strings.Join(g.Scopes, " ") != "openid offline_access" {
		t.Fatalf("grant = %+v", g)
	}
}

func TestDeviceConsentDecline(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	ck := e.login(t, fixedNow())
	loc := location(t, e.consent(t, e.deviceConsentTxn(t, dc, ck), ck, false))
	if loc.Path != "/device/denied" {
		t.Fatalf("Location = %s", loc)
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeDenied || got.UserID != "" {
		t.Fatalf("code = %+v", got)
	}
	if e.userGrant(t, "tv", "https://api.acme.test") != nil {
		t.Fatal("a grant was written")
	}
}

func TestDeviceResumeAfterLogin(t *testing.T) {
	e := newEnv(t)
	e.noSkipAPI(t)
	dc := e.deviceCode(t)
	txn := e.txnAt(t, e.continueDevice(t, dc), "/u/login")
	rec := httptest.NewRecorder()
	e.h.Resume(rec, httptest.NewRequest("POST", "https://acme.example.test/u/login", nil), e.res(), txn, e.session(t, e.login(t, fixedNow())))
	consent := e.txnAt(t, rec, "/u/consent")
	if consent.Params[ParamDevice] != dc.DeviceCodeHash {
		t.Fatalf("consent params = %v", consent.Params)
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txn.ID); err == nil {
		t.Fatal("login transaction not deleted")
	}
}

// sessionExpiredPage checks rec is the generic error page for a code that
// is no longer pending.
func (e *env) sessionExpiredPage(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	msg := i18n.ForRequest(e.tenant, httptest.NewRequest("GET", "/", nil), "").T(i18n.KeyErrSessionExpired)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), html.EscapeString(msg)) {
		t.Fatalf("status %d Location %q body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

func TestDeviceDecideTwiceKeepsFirst(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	ck := e.login(t, fixedNow())
	txn := e.deviceConsentTxn(t, dc, ck)
	if _, err := e.st.DeviceCodes().Decide(context.Background(), e.tenant.ID, dc.DeviceCodeHash,
		store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: "u1", GrantedScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	e.sessionExpiredPage(t, e.consent(t, txn, ck, false))
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeApproved || got.UserID != "u1" {
		t.Fatalf("code = %+v", got)
	}
}

func TestDeviceConsentViewHasNoCallback(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	ck := e.login(t, fixedNow())
	v, err := e.h.ConsentView(context.Background(), e.res(), e.deviceConsentTxn(t, dc, ck), e.session(t, ck))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Device || v.Confirmation || v.ThirdParty || v.CallbackDomain != "" || v.RedirectURI != "" || v.APIName != "API" {
		t.Fatalf("view = %+v", v)
	}
}

func TestDenyDevice(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	rec := httptest.NewRecorder()
	e.h.DenyDevice(rec, httptest.NewRequest("POST", "https://acme.example.test/device", nil), e.res(), dc, "")
	if loc := location(t, rec); loc.Path != "/device/denied" {
		t.Fatalf("Location = %s", loc)
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeDenied {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestContinueDeviceRefusesUnusableCode(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	expired := e.deviceCode(t)
	e.h.Now = func() time.Time { return expired.ExpiresAt }
	e.sessionExpiredPage(t, e.continueDevice(t, expired, ck))
	e.h.Now = fixedNow
	if got := e.storedCode(t, expired); got.Status != store.DeviceCodePending {
		t.Fatalf("status = %s", got.Status)
	}

	// The client lost the device grant after the code was issued.
	dc := e.deviceCode(t)
	c, _ := e.st.Clients().Get(context.Background(), e.tenant.ID, "tv")
	c.GrantTypes = []string{"refresh_token"}
	if err := e.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if rec := e.continueDevice(t, dc, ck); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodePending {
		t.Fatalf("status = %s", got.Status)
	}
}

// staleCodes reports every code as pending, as a read that lost a race
// with another decision would.
type staleCodes struct{ store.DeviceCodes }

func (s staleCodes) Get(ctx context.Context, tenantID, hash string) (*store.DeviceCode, error) {
	dc, err := s.DeviceCodes.Get(ctx, tenantID, hash)
	if err == nil {
		dc.Status = store.DeviceCodePending
	}
	return dc, err
}

type staleStore struct{ store.Store }

func (s staleStore) DeviceCodes() store.DeviceCodes { return staleCodes{s.Store.DeviceCodes()} }

func TestDeviceDecideRaceKeepsFirst(t *testing.T) {
	e := newEnv(t)
	dc := e.deviceCode(t)
	if _, err := e.st.DeviceCodes().Decide(context.Background(), e.tenant.ID, dc.DeviceCodeHash,
		store.DeviceDecision{Status: store.DeviceCodeDenied}); err != nil {
		t.Fatal(err)
	}
	e.h.Store = staleStore{e.st}
	e.sessionExpiredPage(t, e.continueDevice(t, dc, e.login(t, fixedNow())))
	if got := e.storedCode(t, dc); got.Status != store.DeviceCodeDenied {
		t.Fatalf("status = %s", got.Status)
	}
}
