package userrules

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func conn() *store.Connection {
	return &store.Connection{Name: "db", Strategy: store.StrategyDatabase}
}

func fieldErr(t *testing.T, errs []error, code, msg string) *FieldError {
	t.Helper()
	for _, e := range errs {
		var fe *FieldError
		if errors.As(e, &fe) && fe.Code == code && (msg == "" || fe.Message == msg) {
			return fe
		}
	}
	t.Fatalf("no FieldError{%q, %q} in %v", code, msg, errs)
	return nil
}

func TestCreateDefaults(t *testing.T) {
	in := &Create{Connection: "db", Email: " Bea@Example.COM ", Password: "Sup3r-secret-pw", GivenName: "Bea", FamilyName: "Obs"}
	if errs := CheckCreate(conn(), in); len(errs) != 0 {
		t.Fatal(errs)
	}
	sum := md5.Sum([]byte("bea@example.com"))
	if in.Email != "bea@example.com" || in.Name != "bea@example.com" || in.Nickname != "bea" {
		t.Fatalf("%+v", in)
	}
	if want := "https://s.gravatar.com/avatar/" + hex.EncodeToString(sum[:]) + "?s=480&r=pg&d=mp"; in.Picture != want {
		t.Fatalf("picture %q want %q", in.Picture, want)
	}
	if DefaultPicture("") != "" {
		t.Fatal("no email, no picture")
	}
}

func TestCreateKeepsGivenPicture(t *testing.T) {
	in := &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", Picture: "https://x.example/p.png", Name: "N", Nickname: "nn"}
	if errs := CheckCreate(conn(), in); len(errs) != 0 {
		t.Fatal(errs)
	}
	if in.Picture != "https://x.example/p.png" || in.Name != "N" || in.Nickname != "nn" {
		t.Fatalf("%+v", in)
	}
}

func TestCreateEmail(t *testing.T) {
	errs := CheckCreate(conn(), &Create{Connection: "db", Email: "nope", Password: "Sup3r-secret-pw"})
	fieldErr(t, errs, CodeInvalidBody, "")
}

func TestCreateUsername(t *testing.T) {
	errs := CheckCreate(conn(), &Create{Connection: "db", Email: "a@example.com", Username: "bea", Password: "Sup3r-secret-pw"})
	fieldErr(t, errs, CodeOperationNotSupported, "Cannot set username for connection without requires_username")
	c := conn()
	c.RequiresUsername = true
	in := &Create{Connection: "db", Email: "a@example.com", Username: " BeA ", Password: "Sup3r-secret-pw"}
	if errs := CheckCreate(c, in); len(errs) != 0 || in.Username != "bea" {
		t.Fatal(errs, in.Username)
	}
}

func TestCreatePhone(t *testing.T) {
	errs := CheckCreate(conn(), &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", PhoneNumber: "+15551234567"})
	fieldErr(t, errs, CodeInvalidBody, `"phone_number" is not allowed`)
}

func TestCreateUserID(t *testing.T) {
	for _, bad := range []string{"has space", "tab\there", strings.Repeat("x", 256)} {
		errs := CheckCreate(conn(), &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", UserID: bad})
		fieldErr(t, errs, CodeInvalidBody, "")
	}
	in := &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", UserID: "auth0|x"}
	if errs := CheckCreate(conn(), in); len(errs) != 0 {
		t.Fatal(errs)
	}
	if in.StoredUserID() != "auth0|auth0|x" || in.UserID != "auth0|x" {
		t.Fatalf("%q %q", in.StoredUserID(), in.UserID)
	}
	if (&Create{}).StoredUserID() != "" {
		t.Fatal("no id given, none stored")
	}
	ok := &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", UserID: strings.Repeat("x", 255)}
	if errs := CheckCreate(conn(), ok); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestCreatePassword(t *testing.T) {
	c := conn()
	errs := CheckCreate(c, &Create{Connection: "db", Email: "a@example.com", Password: "abc"})
	fe := fieldErr(t, errs, "", "PasswordStrengthError: Password is too weak")
	var pe *identity.PolicyError
	if !errors.As(fe, &pe) {
		t.Fatal("PolicyError must stay reachable")
	}
	fieldErr(t, CheckCreate(conn(), &Create{Connection: "db", Email: "a@example.com"}), CodeInvalidBody, "Missing required property: password")
}

func TestCreateCollectsAll(t *testing.T) {
	errs := CheckCreate(conn(), &Create{Connection: "db", Email: "bad", Username: "u", PhoneNumber: "1"})
	if len(errs) < 3 {
		t.Fatal(errs)
	}
}

func TestCreateMetadataLimits(t *testing.T) {
	in := &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", UserMetadata: map[string]any{"$bad": 1}}
	fieldErr(t, CheckCreate(conn(), in), CodeInvalidBody, "")
	in = &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", AppMetadata: map[string]any{"a": map[string]any{".x": 1}}}
	fieldErr(t, CheckCreate(conn(), in), CodeInvalidBody, "")
	in = &Create{Connection: "db", Email: "a@example.com", Password: "Sup3r-secret-pw", UserMetadata: map[string]any{"big": strings.Repeat("x", MetadataLimits.MaxBytes+1)}}
	fieldErr(t, CheckCreate(conn(), in), CodeInvalidBody, "")
}

func ptr[T any](v T) *T { return &v }

func existing() *store.User {
	return &store.User{UserID: "auth0|1", Email: "a@example.com", EmailVerified: true, Name: "a@example.com", Nickname: "a",
		UserMetadata: map[string]any{"keep": "1", "gone": "x", "obj": map[string]any{"a": 1.0}}}
}

func TestPatchRules(t *testing.T) {
	c := conn()
	u := existing()
	fieldErr(t, CheckPatch(c, u, &Patch{Email: ptr("b@example.com"), Password: ptr("Sup3r-secret-pw")}),
		CodeOperationNotSupported, "Cannot update password and email simultaneously")
	fieldErr(t, CheckPatch(c, u, &Patch{Username: ptr("bea")}),
		CodeOperationNotSupported, "Cannot set username for connection without requires_username or attributes")
	fieldErr(t, CheckPatch(c, u, &Patch{Email: ptr("nope")}), CodeInvalidBody, "")
	fieldErr(t, CheckPatch(c, u, &Patch{PhoneNumber: ptr("1")}), CodeInvalidBody, `"phone_number" is not allowed`)
	fieldErr(t, CheckPatch(c, u, &Patch{Password: ptr("abc")}), "", "PasswordStrengthError: Password is too weak")
	if errs := CheckPatch(conn(), u, &Patch{Name: ptr("New")}); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestApplyPatchEmail(t *testing.T) {
	u := existing()
	in := &Patch{Email: ptr(" B@Example.com ")}
	_ = CheckPatch(conn(), u, in)
	ApplyPatch(u, in)
	if u.Email != "b@example.com" || u.EmailVerified {
		t.Fatalf("%+v", u)
	}
	u = existing()
	in = &Patch{Email: ptr("b@example.com"), EmailVerified: ptr(true)}
	_ = CheckPatch(conn(), u, in)
	ApplyPatch(u, in)
	if !u.EmailVerified {
		t.Fatal("explicit email_verified wins")
	}
	u = existing()
	in = &Patch{Email: ptr("a@example.com")}
	ApplyPatch(u, in)
	if !u.EmailVerified {
		t.Fatal("unchanged email keeps verification")
	}
}

func TestApplyPatchMetadata(t *testing.T) {
	u := existing()
	ApplyPatch(u, &Patch{UserMetadata: Metadata{Set: true, Value: map[string]any{
		"gone": nil, "obj": map[string]any{"b": 2.0}, "new": "v"}}})
	want := map[string]any{"keep": "1", "obj": map[string]any{"b": 2.0}, "new": "v"}
	if len(u.UserMetadata) != 3 || u.UserMetadata["keep"] != "1" || u.UserMetadata["new"] != "v" {
		t.Fatalf("%v want %v", u.UserMetadata, want)
	}
	if o := u.UserMetadata["obj"].(map[string]any); len(o) != 1 || o["b"] != 2.0 {
		t.Fatalf("nested object must be replaced: %v", o)
	}
	ApplyPatch(u, &Patch{UserMetadata: Metadata{Set: true, Value: map[string]any{}}})
	if u.UserMetadata == nil || len(u.UserMetadata) != 0 {
		t.Fatalf("{} empties: %#v", u.UserMetadata)
	}
	u = existing()
	ApplyPatch(u, &Patch{})
	if len(u.UserMetadata) != 3 {
		t.Fatal("absent leaves metadata alone")
	}
	u = existing()
	ApplyPatch(u, &Patch{AppMetadata: Metadata{Set: true, Value: map[string]any{"plan": "pro"}}})
	if u.AppMetadata["plan"] != "pro" {
		t.Fatal(u.AppMetadata)
	}
}

func TestMetadataUnmarshal(t *testing.T) {
	var p struct{ M Metadata }
	_ = p
	var m Metadata
	if err := m.UnmarshalJSON([]byte(`{}`)); err != nil || !m.Set || m.Value == nil || len(m.Value) != 0 {
		t.Fatalf("%+v %v", m, err)
	}
	m = Metadata{}
	if err := m.UnmarshalJSON([]byte(`{"a":null}`)); err != nil || !m.Set || m.Value["a"] != nil || len(m.Value) != 1 {
		t.Fatalf("%+v %v", m, err)
	}
	if err := (&Metadata{}).UnmarshalJSON([]byte(`[1]`)); err == nil {
		t.Fatal("array is not metadata")
	}
}

func TestApplyPatchFields(t *testing.T) {
	u := existing()
	ApplyPatch(u, &Patch{Name: ptr("N"), Blocked: ptr(true), GivenName: ptr("G"), PhoneNumber: ptr("+1"), PhoneVerified: ptr(true)})
	if u.Name != "N" || !u.Blocked || u.GivenName != "G" || u.PhoneNumber != "+1" || !u.PhoneVerified {
		t.Fatalf("%+v", u)
	}
}
