package passhash

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vector struct {
	Name     string          `json:"name"`
	Task     string          `json:"task"`
	Spec     json.RawMessage `json:"spec"`
	Password string          `json:"password"`
	Match    bool            `json:"match"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestVectors(t *testing.T) {
	ran := 0
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			s, errs := ParseCustom(v.Spec)
			if len(errs) > 0 {
				t.Fatalf("ParseCustom: %v", errs)
			}
			got, err := s.Verify(v.Password)
			if errors.Is(err, ErrNotImplemented) {
				t.Skipf("later task: %v", err)
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != v.Match {
				t.Fatalf("Verify = %v, want %v", got, v.Match)
			}
			ran++
		})
	}
	if ran < 200 {
		t.Fatalf("only %d vectors ran", ran)
	}
}

func TestParseCustomErrors(t *testing.T) {
	const h = `"hash":{"value":"abc","encoding":"hex"}`
	cases := []struct {
		name, in, code, msg, path string
	}{
		{"unknown algorithm", `{"algorithm":"foo",` + h + `}`, "ENUM_MISMATCH",
			"Error in custom_password_hash.algorithm property - No enum match for: foo", "custom_password_hash.algorithm"},
		{"sha256 with utf8", `{"algorithm":"sha256","hash":{"value":"abc","encoding":"utf8"}}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"bcrypt with hex", `{"algorithm":"bcrypt",` + h + `}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"bcrypt not $2", `{"algorithm":"bcrypt","hash":{"value":"nope","encoding":"utf8"}}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"ldap CRYPT", `{"algorithm":"ldap","hash":{"value":"{CRYPT}abc","encoding":"utf8"}}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"ldap CLEARTEXT", `{"algorithm":"ldap","hash":{"value":"{CLEARTEXT}abc","encoding":"utf8"}}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"scrypt without keylen", `{"algorithm":"scrypt",` + h + `}`, "OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: keylen", "custom_password_hash"},
		{"salt on argon2", `{"algorithm":"argon2","hash":{"value":"$argon2id$x","encoding":"utf8"},"salt":{"value":"s"}}`,
			"OBJECT_ADDITIONAL_PROPERTIES", "Additional properties not allowed: salt", "custom_password_hash"},
		{"salt on pbkdf2", `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$x","encoding":"utf8"},"salt":{"value":"s"}}`,
			"OBJECT_ADDITIONAL_PROPERTIES", "Additional properties not allowed: salt", "custom_password_hash"},
		{"salt on ldap", `{"algorithm":"ldap","hash":{"value":"{SHA}x","encoding":"utf8"},"salt":{"value":"s"}}`,
			"OBJECT_ADDITIONAL_PROPERTIES", "Additional properties not allowed: salt", "custom_password_hash"},
		{"hmac without key", `{"algorithm":"hmac","hash":{"value":"abc","encoding":"hex","digest":"sha256"}}`,
			"OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: key", "custom_password_hash.hash"},
		{"hmac bad digest", `{"algorithm":"hmac","hash":{"value":"abc","encoding":"hex","digest":"crc32","key":{"value":"k"}}}`,
			"ENUM_MISMATCH", "Error in custom_password_hash.hash.digest property - No enum match for: crc32", "custom_password_hash.hash.digest"},
		{"no hash", `{"algorithm":"md5"}`, "OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: hash", "custom_password_hash"},
		{"no hash value", `{"algorithm":"md5","hash":{"encoding":"hex"}}`, "OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: value", "custom_password_hash.hash"},
		{"bad salt position", `{"algorithm":"md5",` + h + `,"salt":{"value":"s","position":"middle"}}`,
			"ENUM_MISMATCH", "Error in custom_password_hash.salt.position property - No enum match for: middle", "custom_password_hash.salt.position"},
		{"bad password encoding", `{"algorithm":"md5",` + h + `,"password":{"encoding":"ebcdic"}}`,
			"ENUM_MISMATCH", "Error in custom_password_hash.password.encoding property - No enum match for: ebcdic", "custom_password_hash.password.encoding"},
		{"scrypt cost not a power of two", `{"algorithm":"scrypt",` + h + `,"keylen":32,"cost":1000}`,
			"INVALID_FORMAT", "Error in custom_password_hash.cost property - cost must be a power of two greater than 1: 1000", "custom_password_hash.cost"},
		{"argon2 without prefix", `{"algorithm":"argon2","hash":{"value":"garbage","encoding":"utf8"}}`, "ONE_OF_MISSING", "", "custom_password_hash"},
		{"not an object", `[]`, "INVALID_TYPE", "Expected type object but found type array", "custom_password_hash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, errs := ParseCustom(json.RawMessage(c.in))
			if s != nil || len(errs) != 1 {
				t.Fatalf("got %v, %v; want one error", s, errs)
			}
			if e := errs[0]; e.Code != c.code || e.Message != c.msg || e.Path != c.path {
				t.Fatalf("got %+v, want code=%s msg=%q path=%s", e, c.code, c.msg, c.path)
			}
		})
	}
}

func TestParseCustomAccepts(t *testing.T) {
	for name, in := range map[string]string{
		"argon2 garbage after prefix": `{"algorithm":"argon2","hash":{"value":"$argon2id$garbage","encoding":"utf8"}}`,
		"pbkdf2 garbage after prefix": `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$garbage","encoding":"utf8"}}`,
		"bcrypt $2y":                  `{"algorithm":"bcrypt","hash":{"value":"$2y$10$abc","encoding":"utf8"}}`,
		"scrypt":                      `{"algorithm":"scrypt","hash":{"value":"abc","encoding":"base64"},"keylen":32,"salt":{"value":"s"}}`,
		"hmac whirlpool":              `{"algorithm":"hmac","hash":{"value":"abc","encoding":"hex","digest":"whirlpool","key":{"value":"k"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, errs := ParseCustom(json.RawMessage(in)); len(errs) > 0 {
				t.Fatal(errs)
			}
		})
	}
}

func TestParseCustomDefaults(t *testing.T) {
	s, errs := ParseCustom(json.RawMessage(
		`{"algorithm":"scrypt","hash":{"value":"abc","encoding":"hex"},"keylen":16,"salt":{"value":"s"}}`))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.Cost != 16384 || s.BlockSize != 8 || s.Parallelization != 1 || s.KeyLen != 16 {
		t.Fatalf("scrypt defaults: %+v", s)
	}
	if s.Salt.Encoding != "utf8" || s.Salt.Position != "prefix" {
		t.Fatalf("salt defaults: %+v", s.Salt)
	}
}

func TestUnusable(t *testing.T) {
	for name, in := range map[string]string{
		"bcrypt garbage":    `{"algorithm":"bcrypt","hash":{"value":"$2b$garbage","encoding":"utf8"}}`,
		"bad hex":           `{"algorithm":"md5","hash":{"value":"zz","encoding":"hex"}}`,
		"ldap bad base64":   `{"algorithm":"ldap","hash":{"value":"{SHA}!!!","encoding":"utf8"}}`,
		"ldap short salted": `{"algorithm":"ldap","hash":{"value":"{SSHA}AAAA","encoding":"utf8"}}`,
		"bad salt hex":      `{"algorithm":"md5","hash":{"value":"00","encoding":"hex"},"salt":{"value":"zz","encoding":"hex"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			s, errs := ParseCustom(json.RawMessage(in))
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if _, err := s.Verify("x"); !errors.Is(err, ErrUnusable) {
				t.Fatalf("err = %v, want ErrUnusable", err)
			}
		})
	}
}

// bcrypt of "Pa55w0rd!" generated by scripts/gen-hash-vectors.py ($2b$10).
const goodBcrypt = "$2b$10$abcdefghijklmnopqrstuuj7m4XYqbm74SxoBcXyw8to0CQ061DVG"

func TestFromBcryptPattern(t *testing.T) {
	s, errs := FromBcrypt(goodBcrypt)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if ok, err := s.Verify("pw"); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if ok, _ := s.Verify("other"); ok {
		t.Fatal("wrong password matched")
	}
	if _, errs := FromBcrypt(strings.Replace(goodBcrypt, "$2b$", "$2a$", 1)); len(errs) > 0 {
		t.Fatalf("$2a$ refused: %v", errs)
	}
	for name, h := range map[string]string{
		"2y":       strings.Replace(goodBcrypt, "$2b$", "$2y$", 1),
		"cost 12":  strings.Replace(goodBcrypt, "$10$", "$12$", 1),
		"52 chars": goodBcrypt[:len(goodBcrypt)-1],
		"empty":    "",
	} {
		t.Run(name, func(t *testing.T) {
			_, errs := FromBcrypt(h)
			want := FieldError{Code: "PATTERN", Path: "passwordHash",
				Message: `Error in passwordHash property - String does not match pattern ^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$: *****`}
			if len(errs) != 1 || errs[0] != want {
				t.Fatalf("got %+v", errs)
			}
			if strings.Contains(errs[0].Message, h) && h != "" {
				t.Fatal("message repeats the hash")
			}
		})
	}
}

func TestBcryptLongInput(t *testing.T) {
	// hash of the first 72 bytes of 70 digits + "SUFFIXSALT", from the generator
	for _, v := range loadVectors(t) {
		if v.Name == "bcrypt/long-input-truncated" {
			s, errs := ParseCustom(v.Spec)
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if len(v.Password) != 70 || s.Salt.Position != "suffix" || len(s.Salt.Value) != 10 {
				t.Fatalf("vector shape changed: %d %+v", len(v.Password), s.Salt)
			}
			if ok, err := s.Verify(v.Password); err != nil || !ok {
				t.Fatalf("Verify = %v, %v", ok, err)
			}
			// the last 8 salt bytes are cut: changing them still matches
			s.Salt.Value = "SUFFIXSAxx"
			if ok, err := s.Verify(v.Password); err != nil || !ok {
				t.Fatalf("bytes beyond 72 must not matter: %v, %v", ok, err)
			}
			s.Salt.Value = "XUFFIXSALT" // byte 71 differs
			if ok, _ := s.Verify(v.Password); ok {
				t.Fatal("byte 71 must matter")
			}
			return
		}
	}
	t.Fatal("vector missing")
}

func TestPasswordEncodings(t *testing.T) {
	cases := []struct {
		enc, in string
		want    []byte
	}{
		{"utf8", "hé", []byte{'h', 0xc3, 0xa9}},
		{"latin1", "hé", []byte{'h', 0xe9}},
		{"binary", "hé", []byte{'h', 0xe9}},
		{"ascii", "hé", []byte{'h', 0xe9}},  // Node keeps the low byte
		{"latin1", "€", []byte{0xac}},       // above U+00FF: low byte
		{"ascii", "漢字", []byte{0x22, 0x57}}, // no error, no panic
		{"utf16le", "a€", []byte{'a', 0, 0xac, 0x20}},
		{"ucs2", "a", []byte{'a', 0}},
		{"utf16le", "\U0001F600", []byte{0x3d, 0xd8, 0x00, 0xde}}, // surrogate pair
		{"latin1", "\U0001F600", []byte{0x3d, 0x00}},              // low bytes of both surrogates
	}
	for _, c := range cases {
		if got := encodePassword(c.in, c.enc); string(got) != string(c.want) {
			t.Errorf("%s %q = % x, want % x", c.enc, c.in, got, c.want)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	in := `{"algorithm":"hmac","hash":{"value":"abc","encoding":"hex","digest":"sha256","key":{"value":"k","encoding":"hex"}},` +
		`"salt":{"value":"s","encoding":"base64","position":"suffix"},"password":{"encoding":"utf16le"}}`
	s, errs := ParseCustom(json.RawMessage(in))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	back, err := Unmarshal(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if back.Marshal() != s.Marshal() || back.Hash.Key.Encoding != "hex" || back.Salt.Position != "suffix" ||
		back.Password.Encoding != "utf16le" {
		t.Fatalf("round trip: %s", back.Marshal())
	}
	if _, err := Unmarshal("{}"); err == nil {
		t.Fatal("empty spec accepted")
	}
	if _, err := Unmarshal("nope"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestMasked(t *testing.T) {
	raw := map[string]any{
		"email":         "a@b.c",
		"password_hash": goodBcrypt,
		"custom_password_hash": map[string]any{
			"algorithm": "hmac",
			"hash":      map[string]any{"value": "secret", "encoding": "hex", "key": map[string]any{"value": "k"}},
			"salt":      map[string]any{"value": "salty", "position": "suffix"},
		},
	}
	var s *Spec
	got := s.Masked(raw)
	cph := got["custom_password_hash"].(map[string]any)
	h := cph["hash"].(map[string]any)
	if got["password_hash"] != "*****" || h["value"] != "*****" || cph["salt"].(map[string]any)["value"] != "*****" ||
		h["key"].(map[string]any)["value"] != "*****" {
		t.Fatalf("not masked: %v", got)
	}
	if got["email"] != "a@b.c" || h["encoding"] != "hex" || cph["algorithm"] != "hmac" ||
		cph["salt"].(map[string]any)["position"] != "suffix" {
		t.Fatalf("over-masked: %v", got)
	}
	// the input is untouched
	orig := raw["custom_password_hash"].(map[string]any)["hash"].(map[string]any)
	if raw["password_hash"] != goodBcrypt || orig["value"] != "secret" || orig["key"].(map[string]any)["value"] != "k" {
		t.Fatalf("input modified: %v", raw)
	}
}

func TestWeak(t *testing.T) {
	cases := []struct {
		in   string
		weak bool
	}{
		{`{"algorithm":"md4","hash":{"value":"00","encoding":"hex"}}`, true},
		{`{"algorithm":"md5","hash":{"value":"00","encoding":"hex"}}`, true},
		{`{"algorithm":"sha1","hash":{"value":"00","encoding":"hex"}}`, true},
		{`{"algorithm":"md5","hash":{"value":"00","encoding":"hex"},"salt":{"value":"s"}}`, false},
		{`{"algorithm":"sha256","hash":{"value":"00","encoding":"hex"}}`, false},
		{`{"algorithm":"ldap","hash":{"value":"{MD5}AA==","encoding":"utf8"}}`, true},
		{`{"algorithm":"ldap","hash":{"value":"{sha}AA==","encoding":"utf8"}}`, true},
		{`{"algorithm":"ldap","hash":{"value":"{SSHA}AA==","encoding":"utf8"}}`, false},
		{`{"algorithm":"ldap","hash":{"value":"{SHA256}AA==","encoding":"utf8"}}`, false},
		{`{"algorithm":"bcrypt","hash":{"value":"$2b$x","encoding":"utf8"}}`, false},
	}
	for _, c := range cases {
		s, errs := ParseCustom(json.RawMessage(c.in))
		if len(errs) > 0 {
			t.Fatal(c.in, errs)
		}
		if s.Weak() != c.weak {
			t.Errorf("%s: Weak = %v", c.in, s.Weak())
		}
	}
}

func TestLaterAlgorithmsNotImplemented(t *testing.T) {
	s, errs := ParseCustom(json.RawMessage(`{"algorithm":"scrypt","hash":{"value":"00","encoding":"hex"},"keylen":16}`))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if _, err := s.Verify("x"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v", err)
	}
}
