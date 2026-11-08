package webauthn_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const (
	rpID   = "login.example.test"
	origin = "https://login.example.test"
)

var challenge = bytes.Repeat([]byte{7}, 32)

func creation() webauthn.CreationOptions {
	return webauthn.CreationOptions{Challenge: challenge, RPID: rpID, UserID: []byte("user-handle-32-bytes-------------"), UserName: "ada@example.test"}
}

func expect() webauthn.Expect {
	return webauthn.Expect{Challenge: challenge, RPID: rpID, Origins: []string{origin}}
}

func register(t *testing.T, a *webauthntest.Authenticator, e webauthn.Expect) (*webauthn.Registration, error) {
	t.Helper()
	c, err := webauthn.ParseCredentialJSON(a.Create(creation(), origin))
	if err != nil {
		return nil, err
	}
	return webauthn.VerifyRegistration(c, e)
}

func TestVerifyRegistration(t *testing.T) {
	for _, alg := range []int64{-8, -7, -257} {
		r, err := register(t, webauthntest.New(webauthntest.Options{Alg: alg, UV: true}), expect())
		if err != nil || r.Alg != alg || r.Format != "none" || !r.UV || r.SignCount != 0 || r.AAGUID != [16]byte{} {
			t.Fatalf("alg %d: %+v %v", alg, r, err)
		}
	}
	refuse := []struct {
		name   string
		opts   webauthntest.Options
		e      func(*webauthn.Expect)
		reason string
	}{
		{"alg -35 not offered", webauthntest.Options{Alg: -35}, nil, "alg"},
		{"wrong client data type", webauthntest.Options{ClientDataType: "webauthn.get"}, nil, "type"},
		{"wrong challenge", webauthntest.Options{}, func(e *webauthn.Expect) { e.Challenge = bytes.Repeat([]byte{8}, 32) }, "challenge"},
		{"wrong origin", webauthntest.Options{}, func(e *webauthn.Expect) { e.Origins = []string{"https://other.example.test"} }, "origin"},
		{"cross origin", webauthntest.Options{CrossOrigin: true}, nil, "cross_origin"},
		{"top origin", webauthntest.Options{TopOrigin: "https://frame.example.test"}, nil, "cross_origin"},
		{"wrong rpIdHash", webauthntest.Options{TamperRPIDHash: true}, nil, "rp_id"},
		{"UP clear", webauthntest.Options{NoUP: true}, nil, "user_present"},
		{"UV clear when required", webauthntest.Options{}, func(e *webauthn.Expect) { e.RequireUV = true }, "user_verified"},
		{"BS without BE", webauthntest.Options{BS: true}, nil, "backup_state"},
		{"unparsed tail", webauthntest.Options{Tail: []byte{0xaa}}, nil, "parse"},
		{"none with statement", webauthntest.Options{AttStmt: map[any]any{"sig": []byte{1}}}, nil, "attestation"},
		{"unknown format", webauthntest.Options{Format: "made-up"}, nil, "attestation"},
		{"credential ID 1024 bytes", webauthntest.Options{CredIDLen: 1024}, nil, "too_large"},
	}
	for _, c := range refuse {
		e := expect()
		if c.e != nil {
			c.e(&e)
		}
		if _, err := register(t, webauthntest.New(c.opts), e); webauthn.Reason(err) != c.reason {
			t.Errorf("%s: err %v reason %q, want %q", c.name, err, webauthn.Reason(err), c.reason)
		}
	}
	for _, f := range []string{"packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple"} {
		r, err := register(t, webauthntest.New(webauthntest.Options{Format: f}), expect())
		if err != nil || r.Format != "none" {
			t.Errorf("format %s: %+v %v", f, r, err)
		}
	}
	r, err := register(t, webauthntest.New(webauthntest.Options{BE: true, BS: true, Attachment: "platform", Transports: []string{"internal", "hybrid"}}), expect())
	if err != nil || !r.BE || !r.BS || r.Attachment != "platform" || len(r.Transports) != 2 {
		t.Fatalf("flags: %+v %v", r, err)
	}
}

func TestVerifyAssertion(t *testing.T) {
	setup := func(t *testing.T, o webauthntest.Options) (*webauthntest.Authenticator, *webauthn.Registration) {
		t.Helper()
		a := webauthntest.New(o)
		e := expect()
		e.Algs = []int64{-8, -7, -35, -36, -257, -37}
		r, err := register(t, a, e)
		if err != nil {
			t.Fatal(err)
		}
		return a, r
	}
	assert := func(a *webauthntest.Authenticator, e webauthn.Expect, s webauthn.Stored) (*webauthn.Assertion, error) {
		c, err := webauthn.ParseCredentialJSON(a.Get(webauthn.RequestOptions{Challenge: challenge, RPID: rpID}, origin))
		if err != nil {
			return nil, err
		}
		return webauthn.VerifyAssertion(c, e, s)
	}
	for _, alg := range []int64{-8, -7, -35, -36, -257, -37} {
		a, r := setup(t, webauthntest.Options{Alg: alg})
		got, err := assert(a, expect(), webauthn.Stored{PublicKeyCOSE: r.PublicKeyCOSE, UserHandle: creation().UserID})
		if err != nil || !bytes.Equal(got.CredentialID, r.CredentialID) || !bytes.Equal(got.UserHandle, creation().UserID) {
			t.Fatalf("alg %d: %+v %v", alg, got, err)
		}
	}
	a, r := setup(t, webauthntest.Options{})
	stored := webauthn.Stored{PublicKeyCOSE: r.PublicKeyCOSE, UserHandle: creation().UserID}
	other, _ := setup(t, webauthntest.Options{})
	if _, err := assert(a, expect(), webauthn.Stored{PublicKeyCOSE: mustCOSE(t, other), UserHandle: stored.UserHandle}); webauthn.Reason(err) != "signature" {
		t.Errorf("wrong key reason %q", webauthn.Reason(err))
	}
	requireHandle := expect()
	requireHandle.RequireUserHandle = true
	if _, err := assert(a, requireHandle, webauthn.Stored{PublicKeyCOSE: stored.PublicKeyCOSE, UserHandle: []byte("someone-else")}); webauthn.Reason(err) != "user_handle" {
		t.Errorf("different handle with RequireUserHandle: %q", webauthn.Reason(err))
	}
	if _, err := assert(a, expect(), webauthn.Stored{PublicKeyCOSE: stored.PublicKeyCOSE, UserHandle: []byte("someone-else")}); webauthn.Reason(err) != "user_handle" {
		t.Errorf("different handle without RequireUserHandle: %q", webauthn.Reason(err))
	}
	a.Opts.OmitUserHandle = true
	if _, err := assert(a, requireHandle, stored); webauthn.Reason(err) != "user_handle" {
		t.Errorf("nil handle with RequireUserHandle: %q", webauthn.Reason(err))
	}
	if _, err := assert(a, expect(), stored); err != nil {
		t.Errorf("nil handle without RequireUserHandle: %v", err)
	}
	a.Opts.OmitUserHandle = false
	for _, c := range []struct {
		stored, got uint32
		ok          bool
		reason      string
	}{
		{stored: 0, got: 0, ok: true}, {stored: 0, got: 5, ok: true},
		{stored: 5, got: 5, reason: "sign_count"}, {stored: 5, got: 4, reason: "sign_count"},
		{stored: 5, got: 0, reason: "sign_count"}, {stored: 5, got: 6, ok: true},
	} {
		a.Opts.SignCount = c.got
		s := stored
		s.SignCount = c.stored
		res, err := assert(a, expect(), s)
		if c.ok && (err != nil || res.SignCount != c.got) || !c.ok && webauthn.Reason(err) != c.reason {
			t.Errorf("sign count stored %d got %d: %+v %v", c.stored, c.got, res, err)
		}
	}
	a.Opts.SignCount = 0
	a.Opts.BE = true
	if _, err := assert(a, expect(), stored); webauthn.Reason(err) != "backup_eligibility" {
		t.Errorf("BE change: %q", webauthn.Reason(err))
	}
	s := stored
	s.BE = true
	a.Opts.BS = true
	if res, err := assert(a, expect(), s); err != nil || !res.BS {
		t.Errorf("BS change: %+v %v", res, err)
	}
	a.Opts.ExtraFlags = 0x02 | 0x20
	if _, err := assert(a, expect(), s); err != nil {
		t.Errorf("RFU bits: %v", err)
	}
}

func mustCOSE(t *testing.T, a *webauthntest.Authenticator) []byte {
	t.Helper()
	r, err := register(t, a, expect())
	if err != nil {
		t.Fatal(err)
	}
	return r.PublicKeyCOSE
}

func TestParseLevel2Shapes(t *testing.T) {
	a := webauthntest.New(webauthntest.Options{})
	var m map[string]any
	_ = json.Unmarshal(a.Create(creation(), origin), &m)
	delete(m, "authenticatorAttachment")
	delete(m, "clientExtensionResults")
	delete(m["response"].(map[string]any), "transports")
	b, _ := json.Marshal(m)
	c, err := webauthn.ParseCredentialJSON(b)
	if err != nil || c.Attachment != "" || c.Transports != nil {
		t.Fatalf("level 2 create: %+v %v", c, err)
	}
	if _, err := webauthn.VerifyRegistration(c, expect()); err != nil {
		t.Fatalf("level 2 verify: %v", err)
	}
	a.Opts.OmitUserHandle = true
	if c, err := webauthn.ParseCredentialJSON(a.Get(webauthn.RequestOptions{Challenge: challenge, RPID: rpID}, origin)); err != nil || c.UserHandle != nil {
		t.Fatalf("null userHandle: %+v %v", c, err)
	}
	m["id"] = "AAAA"
	b, _ = json.Marshal(m)
	if _, err := webauthn.ParseCredentialJSON(b); webauthn.Reason(err) != "parse" {
		t.Errorf("id != rawId: %q", webauthn.Reason(err))
	}
	m["id"] = m["rawId"].(string) + strings.Repeat("=", (4-len(m["rawId"].(string))%4)%4)
	m["rawId"] = m["id"]
	b, _ = json.Marshal(m)
	if _, err := webauthn.ParseCredentialJSON(b); err != nil {
		t.Errorf("padded base64url: %v", err)
	}
}

func TestOptionsJSON(t *testing.T) {
	o := creation()
	o.Timeout = 5 * time.Minute
	o.ResidentKey, o.UserVerification = "required", "preferred"
	b, err := o.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		RP     struct{ ID, Name string } `json:"rp"`
		Params []struct {
			Type string
			Alg  int64
		} `json:"pubKeyCredParams"`
		Attestation string `json:"attestation"`
		Timeout     int64  `json:"timeout"`
		Sel         struct {
			ResidentKey, UserVerification, AuthenticatorAttachment string
		} `json:"authenticatorSelection"`
	}
	_ = json.Unmarshal(b, &got)
	if got.RP.ID != rpID || got.RP.Name != rpID || got.Attestation != "none" || got.Timeout != 300000 || len(got.Params) != 3 ||
		got.Params[0].Alg != -8 || got.Params[1].Alg != -7 || got.Params[2].Alg != -257 || got.Sel.ResidentKey != "required" || got.Sel.UserVerification != "preferred" {
		t.Fatalf("creation JSON = %s", b)
	}
	rb, _ := webauthn.RequestOptions{Challenge: challenge, RPID: rpID, UserVerification: "preferred", Timeout: 60 * time.Second}.JSON()
	var req struct {
		RPID             string `json:"rpId"`
		Timeout          int64  `json:"timeout"`
		UserVerification string `json:"userVerification"`
	}
	_ = json.Unmarshal(rb, &req)
	if req.RPID != rpID || req.Timeout != 60000 || req.UserVerification != "preferred" {
		t.Fatalf("request JSON = %s", rb)
	}
	rows := []struct {
		kind               webauthn.Ceremony
		roamingUV          string
		uv, rk, attachment string
	}{
		{webauthn.CeremonyPasskeyRegister, "", "preferred", "required", ""},
		{webauthn.CeremonyLocalEnroll, "", "preferred", "required", "platform"},
		{webauthn.CeremonyPasskeyLogin, "", "preferred", "", ""},
		{webauthn.CeremonyRoaming, "", "discouraged", "discouraged", "cross-platform"},
		{webauthn.CeremonyRoaming, "preferred", "preferred", "discouraged", "cross-platform"},
		{webauthn.CeremonyRoaming, "required", "required", "discouraged", "cross-platform"},
		{webauthn.CeremonyPlatform, "", "required", "discouraged", "platform"},
	}
	for _, r := range rows {
		p := webauthn.ParamsFor(r.kind, r.roamingUV)
		if p.UserVerification != r.uv || p.ResidentKey != r.rk || p.Attachment != r.attachment {
			t.Errorf("ParamsFor(%v, %q) = %+v", r.kind, r.roamingUV, p)
		}
	}
}

func TestDeviceOf(t *testing.T) {
	ua := map[string]string{
		"winChrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"winEdge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		"macSafari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"macChrome":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"iphone":     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"ipad":       "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"android":    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"samsung":    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
		"androidFox": "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
	}
	d := func(k string) webauthn.Device { return webauthn.DeviceOf(ua[k]) }
	if d("winChrome").Key() != d("winEdge").Key() {
		t.Error("Windows Chrome and Edge should share a device key")
	}
	if d("macSafari").Key() == d("macChrome").Key() {
		t.Error("macOS Safari and Chrome should differ")
	}
	if got := d("iphone"); got.OS != "ios" || got.Class != "phone" {
		t.Errorf("iPhone = %+v", got)
	}
	if got := d("ipad"); got.OS != "ios" || got.Class != "tablet" {
		t.Errorf("iPad = %+v", got)
	}
	if got := d("android"); got.OS != "android" || got.Class != "phone" {
		t.Errorf("Android Chrome = %+v", got)
	}
	for _, k := range []string{"samsung", "androidFox"} {
		if got := d(k); got.OS != "other" {
			t.Errorf("%s = %+v, want OS other", k, got)
		}
	}
	if got := d("winChrome"); got.OS != "windows" || got.Class != "desktop" {
		t.Errorf("Windows = %+v", got)
	}
}
