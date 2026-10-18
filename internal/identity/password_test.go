package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func connWith(o store.PasswordOptions) *store.Connection {
	return &store.Connection{TenantID: "ten_a", ID: "con1", Name: "Database", PasswordOptions: o}
}

func policyKey(t *testing.T, err error) string {
	t.Helper()
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a *PolicyError", err)
	}
	return pe.Key
}

func TestComplexityRules(t *testing.T) {
	cx := func(c store.PasswordComplexity) *store.Connection {
		return connWith(store.PasswordOptions{Complexity: c})
	}
	cases := []struct {
		name string
		c    store.PasswordComplexity
		pw   string
		key  string // empty means accepted
	}{
		{"identical allowed", store.PasswordComplexity{}, "aaaabbbb", ""},
		{"identical blocked", store.PasswordComplexity{IdenticalCharacters: store.PasswordBlock}, "abbbcdef", i18n.KeyPasswordIdentical},
		{"identical pair ok", store.PasswordComplexity{IdenticalCharacters: store.PasswordBlock}, "aabbccdd", ""},
		{"identical case differs", store.PasswordComplexity{IdenticalCharacters: store.PasswordBlock}, "aAaBbBcc", ""},
		{"identical unicode", store.PasswordComplexity{IdenticalCharacters: store.PasswordBlock}, "xéééxxyy", i18n.KeyPasswordIdentical},
		{"sequential allowed", store.PasswordComplexity{}, "abcd1234", ""},
		{"sequential letters up", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "xxabcxxx", i18n.KeyPasswordSequential},
		{"sequential digits down", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "xx321xxx", i18n.KeyPasswordSequential},
		{"sequential mixed case", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "xxAbCxxx", i18n.KeyPasswordSequential},
		{"sequential pair ok", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "abxxcdxx", ""},
		{"sequential letter digit boundary ok", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "xx89:xxx", ""},
		{"sequential z a wrap ok", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "xyzzy{|}", i18n.KeyPasswordSequential},
		{"zigzag ok", store.PasswordComplexity{SequentialCharacters: store.PasswordBlock}, "abaabaab", ""},
		{"three of four ok", store.PasswordComplexity{
			CharacterTypes: store.CharacterTypes, CharacterTypeRule: store.CharacterTypeRuleThreeOfFour}, "Lower1upper", ""},
		{"three of four short", store.PasswordComplexity{
			CharacterTypes: store.CharacterTypes, CharacterTypeRule: store.CharacterTypeRuleThreeOfFour}, "lower1upper", i18n.KeyPasswordClasses},
		{"all subset missing", store.PasswordComplexity{
			CharacterTypes: []string{"uppercase", "number"}, CharacterTypeRule: "all"}, "Abcdefgh", i18n.KeyPasswordTypes},
		{"all subset satisfied", store.PasswordComplexity{
			CharacterTypes: []string{"uppercase", "number"}, CharacterTypeRule: "all"}, "Abcdefg1", ""},
		{"too long refused", store.PasswordComplexity{MaxLengthExceeded: store.MaxLengthError}, strings.Repeat("a", MaxPasswordBytes+1), i18n.KeyPasswordTooLong},
		{"too long truncated is accepted", store.PasswordComplexity{MaxLengthExceeded: store.MaxLengthTruncate}, strings.Repeat("a", MaxPasswordBytes+50), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(cx(tc.c), Person{}, tc.pw, nil)
			if tc.key == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if got := policyKey(t, err); got != tc.key {
				t.Fatalf("key = %q, want %q (%v)", got, tc.key, err)
			}
		})
	}
}

func TestComplexityMessagesNameTheRequirement(t *testing.T) {
	c := connWith(store.PasswordOptions{Complexity: store.PasswordComplexity{
		CharacterTypes: []string{"uppercase", "special"}, CharacterTypeRule: "all"}})
	err := CheckPassword(c, Person{}, "abcdefghi", nil)
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if !strings.Contains(pe.Reason, "uppercase") || !strings.Contains(pe.Reason, "symbols") || strings.Contains(pe.Reason, "at least") {
		t.Errorf("reason = %q", pe.Reason)
	}
}

func TestTruncate(t *testing.T) {
	trunc := connWith(store.PasswordOptions{Complexity: store.PasswordComplexity{MaxLengthExceeded: store.MaxLengthTruncate}})
	refuse := connWith(store.PasswordOptions{})
	long := strings.Repeat("a", MaxPasswordBytes) + "tail"
	if got := EffectivePassword(trunc, long); got != strings.Repeat("a", MaxPasswordBytes) {
		t.Errorf("truncated length = %d", len(got))
	}
	if got := EffectivePassword(refuse, long); got != long {
		t.Error("an error-mode connection must not truncate")
	}
	// Never inside a UTF-8 sequence.
	multi := strings.Repeat("a", MaxPasswordBytes-1) + "é"
	if got := EffectivePassword(trunc, multi); got != strings.Repeat("a", MaxPasswordBytes-1) {
		t.Errorf("cut inside a rune: %d bytes", len(got))
	}
	if got := EffectivePassword(trunc, "short"); got != "short" {
		t.Error("short passwords are unchanged")
	}
}

func TestDictionaryRule(t *testing.T) {
	c := connWith(store.PasswordOptions{Dictionary: store.PasswordDictionary{
		Active: true, Default: store.DictionaryEn10k, Custom: []string{"  Acme2026!  ", "acme2026!", "", "   ", "Ünïcode-Wörd"}}})
	for _, pw := range []string{"password", "PassWord", "Qwerty12", "ACME2026!", "acme2026!", "ünïcode-wörd", "ÜNÏCODE-WÖRD"} {
		if got := policyKey(t, CheckPassword(c, Person{}, pw, nil)); got != i18n.KeyPasswordDictionary {
			t.Errorf("%q: key = %q", pw, got)
		}
	}
	for _, pw := range []string{"zq7!vK2#mR9x-unlikely", "password-and-more-words", "acme2026"} {
		if err := CheckPassword(c, Person{}, pw, nil); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
	// Inactive: nothing is checked, whatever the lists hold.
	c.PasswordOptions.Dictionary.Active = false
	if err := CheckPassword(c, Person{}, "password", nil); err != nil {
		t.Errorf("inactive dictionary: %v", err)
	}
	// 100k holds words the 10k list lacks.
	c100 := connWith(store.PasswordOptions{Dictionary: store.PasswordDictionary{Active: true, Default: store.DictionaryEn100k}})
	if policyKey(t, CheckPassword(c100, Person{}, "password", nil)) != i18n.KeyPasswordDictionary {
		t.Error("en_100k does not refuse password")
	}
	// Empty default and no custom words: only the custom words apply.
	cNone := connWith(store.PasswordOptions{Dictionary: store.PasswordDictionary{Active: true}})
	if err := CheckPassword(cNone, Person{}, "password", nil); err != nil {
		t.Errorf("no default list: %v", err)
	}
}

func TestProfileDataRule(t *testing.T) {
	p := Person{
		Email: "jessica.smith@example.com", Username: "jsmith", Name: "Jessica Smith", Nickname: "Jess",
		PhoneNumber:  "+15551234567",
		UserMetadata: map[string]any{"name": "Zoë Ångström", "first": "Zoë", "last": "Ab", "other": "secretword"},
	}
	all := []string{"name", "username", "nickname", "email", "phone_number", "user_metadata.name", "user_metadata.first", "user_metadata.last", "bogus.field", "other"}
	c := connWith(store.PasswordOptions{ProfileData: store.PasswordProfileData{Active: true, BlockedFields: all}})
	refused := []string{
		"xxjessica.smith@example.comxx", // full address
		"Jessica.SMITH-1",               // local part, case-insensitive
		"my-JSMITH-pw",                  // username
		"the jessica smith pw",          // name
		"xxjessxx",                      // nickname
		"x+15551234567x",                // phone
		"zzZOË ÅNGSTRÖMzz",              // metadata name, Unicode-aware
		"abczoëabc",                     // metadata first
	}
	for _, pw := range refused {
		if got := policyKey(t, CheckPassword(c, p, pw, nil)); got != i18n.KeyPasswordPersonalInfo {
			t.Errorf("%q: key = %q", pw, got)
		}
	}
	accepted := []string{
		"unrelated-Pass-9",
		"xxxxAbxxxx",   // user_metadata.last is shorter than 3 characters
		"secretword-1", // "other" is not a field zeroauthy knows
	}
	for _, pw := range accepted {
		if err := CheckPassword(c, p, pw, nil); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
	// A field not listed as blocked is not checked.
	only := connWith(store.PasswordOptions{ProfileData: store.PasswordProfileData{Active: true, BlockedFields: []string{"nickname"}}})
	if err := CheckPassword(only, p, "jsmith-and-pw-1234", nil); err != nil {
		t.Errorf("unlisted field: %v", err)
	}
	// Inactive: nothing.
	off := connWith(store.PasswordOptions{ProfileData: store.PasswordProfileData{Active: false, BlockedFields: all}})
	if err := CheckPassword(off, p, "jsmith-jsmith", nil); err != nil {
		t.Errorf("inactive: %v", err)
	}
	// Empty values and metadata of the wrong type are ignored.
	empty := Person{UserMetadata: map[string]any{"name": 42, "first": ""}}
	if err := CheckPassword(c, empty, "anything-goes-1", nil); err != nil {
		t.Errorf("empty person: %v", err)
	}
}

func hashes(t *testing.T, pws ...string) [][]byte {
	t.Helper()
	out := make([][]byte, len(pws))
	for i, pw := range pws {
		h, err := secrets.Hash(pw)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = []byte(h)
	}
	return out
}

func TestHistoryRule(t *testing.T) {
	c := connWith(store.PasswordOptions{History: store.PasswordHistory{Active: true, Size: 2}})
	h := hashes(t, "newest-pass-1", "second-pass-2", "third-pass-3") // newest first
	if got := policyKey(t, CheckPassword(c, Person{}, "newest-pass-1", h)); got != i18n.KeyPasswordInHistory {
		t.Errorf("key = %q", got)
	}
	if err := CheckPassword(c, Person{}, "second-pass-2", h); !errors.Is(err, ErrPasswordInHistory) {
		t.Errorf("err = %v, want ErrPasswordInHistory", err)
	}
	if err := CheckPassword(c, Person{}, "third-pass-3", h); err != nil {
		t.Errorf("older than the size must pass: %v", err)
	}
	if err := CheckPassword(c, Person{}, "brand-new-pass", h); err != nil {
		t.Error(err)
	}
	c.PasswordOptions.History.Active = false
	if err := CheckPassword(c, Person{}, "newest-pass-1", h); err != nil {
		t.Errorf("inactive history checks nothing: %v", err)
	}
}

// Review focus 4: lowering the history size trims what is stored on the next
// password set and never blocks a password older than the new size; an
// inactive history checks nothing and deletes nothing.
func TestHistoryShrink(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	c := connWith(store.PasswordOptions{History: store.PasswordHistory{Active: true, Size: 5}})
	uid := "auth0|u1"
	pws := []string{"pass-one-1", "pass-two-2", "pass-three-3", "pass-four-4", "pass-five-5"}
	for _, pw := range pws {
		h, _ := secrets.Hash(pw)
		if err := RecordPassword(ctx, st, c, uid, h); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := st.PasswordHistories().List(ctx, c.TenantID, uid)
	if len(got) != 5 {
		t.Fatalf("stored %d, want 5", len(got))
	}

	// Shrink to 2: pass-three (third newest) no longer blocks.
	c.PasswordOptions.History.Size = 2
	hist, err := LoadHistory(ctx, st, c, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword(c, Person{}, "pass-three-3", hist); err != nil {
		t.Errorf("password older than the new size blocked: %v", err)
	}
	if err := CheckPassword(c, Person{}, "pass-four-4", hist); err == nil {
		t.Error("second newest must still be blocked")
	}
	// The next set trims the stored history to the new size.
	h, _ := secrets.Hash("pass-six-6")
	if err := RecordPassword(ctx, st, c, uid, h); err != nil {
		t.Fatal(err)
	}
	got, _ = st.PasswordHistories().List(ctx, c.TenantID, uid)
	if len(got) != 2 {
		t.Fatalf("after shrink stored %d, want 2", len(got))
	}

	// Inactive: checks nothing, loads nothing, deletes nothing.
	c.PasswordOptions.History.Active = false
	if hist, err := LoadHistory(ctx, st, c, uid); err != nil || len(hist) != 0 {
		t.Errorf("inactive LoadHistory = %d, %v", len(hist), err)
	}
	h, _ = secrets.Hash("pass-seven-7")
	if err := RecordPassword(ctx, st, c, uid, h); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.PasswordHistories().List(ctx, c.TenantID, uid)
	if len(got2) != 2 || string(got2[0]) != string(got[0]) {
		t.Errorf("inactive history changed storage: %d entries", len(got2))
	}
	// A size of zero with history active (never valid on the wire) also
	// deletes nothing.
	c.PasswordOptions.History = store.PasswordHistory{Active: true, Size: 0}
	if err := RecordPassword(ctx, st, c, uid, h); err != nil {
		t.Fatal(err)
	}
	got3, _ := st.PasswordHistories().List(ctx, c.TenantID, uid)
	if len(got3) != 2 {
		t.Errorf("size 0 cleared history: %d entries", len(got3))
	}
}

func TestCheckUsernameLimits(t *testing.T) {
	c := &store.Connection{UsernameMin: 3, UsernameMax: 6}
	for name, tc := range map[string]struct {
		u   string
		key string
	}{
		"ok": {"alice", ""}, "min": {"abc", ""}, "max": {"abcdef", ""},
		"short": {"ab", i18n.KeyUsernameTooShort}, "long": {"abcdefg", i18n.KeyUsernameTooLong},
	} {
		err := CheckUsername(c, tc.u)
		if tc.key == "" && err != nil {
			t.Errorf("%s: %v", name, err)
		} else if tc.key != "" && policyKey(t, err) != tc.key {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// No limits set: only the format applies.
	free := &store.Connection{}
	if err := CheckUsername(free, "a"); err != nil {
		t.Error(err)
	}
	if policyKey(t, CheckUsername(free, "has space")) != i18n.KeyInvalidUsername {
		t.Error("format not checked")
	}
	// Only a minimum, only a maximum.
	if policyKey(t, CheckUsername(&store.Connection{UsernameMin: 4}, "abc")) != i18n.KeyUsernameTooShort {
		t.Error("min only")
	}
	if policyKey(t, CheckUsername(&store.Connection{UsernameMax: 2}, "abc")) != i18n.KeyUsernameTooLong {
		t.Error("max only")
	}
}

func TestSignupRecordsHistoryAndAppliesPersonalData(t *testing.T) {
	ctx := context.Background()
	db, conn := newDB(t)
	conn.PasswordOptions = store.PasswordOptions{
		History:     store.PasswordHistory{Active: true, Size: 3},
		ProfileData: store.PasswordProfileData{Active: true, BlockedFields: []string{"email", "nickname"}},
	}
	conn.UsernameMin = 4
	conn.RequiresUsername = true
	_, err := db.Signup(ctx, conn, SignupInput{Email: "alice@example.com", Username: "abc", Password: "unrelated-Pass-9"})
	if policyKey(t, err) != i18n.KeyUsernameTooShort {
		t.Errorf("username limits: %v", err)
	}
	_, err = db.Signup(ctx, conn, SignupInput{Email: "alice@example.com", Username: "alice1", Password: "my-alice-pass"})
	if policyKey(t, err) != i18n.KeyPasswordPersonalInfo {
		t.Errorf("personal data from the email local part: %v", err)
	}
	_, err = db.Signup(ctx, conn, SignupInput{Email: "alice@example.com", Username: "alice1", Password: "unrelated-Pass-9", Nickname: "Wonderland"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := db.Store.Users().FindByLogin(ctx, conn.TenantID, conn.Name, "alice@example.com")
	hist, _ := db.Store.PasswordHistories().List(ctx, conn.TenantID, u.UserID)
	if len(hist) != 1 {
		t.Fatalf("history after signup = %d, want 1", len(hist))
	}
	if ok, _ := secrets.Verify(string(hist[0]), "unrelated-Pass-9"); !ok {
		t.Error("history holds the wrong hash")
	}
}
