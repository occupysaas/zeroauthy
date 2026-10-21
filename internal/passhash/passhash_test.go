package passhash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	var vs []vector
	// vectors.json is from gen-hash-vectors.py (Task 3), vectors-kdf.json from
	// gen-hash-vectors-kdf.py (Task 4).
	for _, f := range []string{"testdata/vectors.json", "testdata/vectors-kdf.json"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var part []vector
		if err := json.Unmarshal(b, &part); err != nil {
			t.Fatal(err)
		}
		vs = append(vs, part...)
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
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != v.Match {
				t.Fatalf("Verify = %v, want %v", got, v.Match)
			}
			ran++
		})
	}
	if ran < 300 {
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

// goodBcrypt is the "bcrypt/2b" vector of testdata/vectors.json, produced by
// scripts/gen-hash-vectors.py (libc crypt, $2b$10) for the password goodPassword.
const (
	goodBcrypt   = "$2b$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2"
	goodPassword = "Pa55w0rd!"
)

func TestFromBcryptPattern(t *testing.T) {
	s, errs := FromBcrypt(goodBcrypt)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if ok, err := s.Verify(goodPassword); err != nil || !ok {
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

// Hash parts of the wrong type are masked whole: a hash pasted as a plain
// string must not show in /errors.
func TestMaskedWrongShapes(t *testing.T) {
	var s *Spec
	for _, c := range []struct {
		name string
		in   map[string]any
		want string
	}{
		{"custom_password_hash string", map[string]any{"custom_password_hash": "$2b$10$secret"}, `{"custom_password_hash":"*****"}`},
		{"custom_password_hash array", map[string]any{"custom_password_hash": []any{"secret"}}, `{"custom_password_hash":"*****"}`},
		{"custom_password_hash number", map[string]any{"custom_password_hash": 5.0}, `{"custom_password_hash":"*****"}`},
		{"hash string", map[string]any{"custom_password_hash": map[string]any{"algorithm": "md5", "hash": "5f4dcc3b"}},
			`{"custom_password_hash":{"algorithm":"md5","hash":"*****"}}`},
		{"hash array", map[string]any{"custom_password_hash": map[string]any{"hash": []any{"5f4dcc3b"}}}, `{"custom_password_hash":{"hash":"*****"}}`},
		{"salt string", map[string]any{"custom_password_hash": map[string]any{"hash": map[string]any{"value": "x"}, "salt": "s3cr3t"}},
			`{"custom_password_hash":{"hash":{"value":"*****"},"salt":"*****"}}`},
		{"key string", map[string]any{"custom_password_hash": map[string]any{"hash": map[string]any{"value": "x", "key": "k3y"}}},
			`{"custom_password_hash":{"hash":{"key":"*****","value":"*****"}}}`},
		{"value object", map[string]any{"custom_password_hash": map[string]any{"hash": map[string]any{"value": map[string]any{"v": "x"}}}},
			`{"custom_password_hash":{"hash":{"value":"*****"}}}`},
		{"password_hash number", map[string]any{"password_hash": 12.0}, `{"password_hash":"*****"}`},
		{"password_hash object", map[string]any{"password_hash": map[string]any{"v": "x"}}, `{"password_hash":"*****"}`},
		{"null is kept", map[string]any{"custom_password_hash": nil}, `{"custom_password_hash":null}`},
	} {
		b, _ := json.Marshal(s.Masked(c.in))
		if string(b) != c.want {
			t.Errorf("%s: %s, want %s", c.name, b, c.want)
		}
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

func TestVectorsCoverEveryAlgorithm(t *testing.T) {
	seen := map[string]bool{}
	pbkdf2Names := map[string]bool{}
	for _, v := range loadVectors(t) {
		s, errs := ParseCustom(v.Spec)
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		seen[s.Algorithm] = true
		if s.Algorithm == "hmac" {
			seen["hmac/"+s.Hash.Digest] = true
		}
		if s.Algorithm == "pbkdf2" {
			pbkdf2Names[strings.Split(s.Hash.Value, "$")[1]] = true
		}
		if s.Algorithm == "argon2" {
			parts := strings.Split(s.Hash.Value, "$")
			seen[parts[1]] = true
			if strings.HasPrefix(parts[2], "v=") {
				seen[parts[1]+"/"+parts[2]] = true
			} else {
				seen[parts[1]+"/no-v"] = true
			}
		}
	}
	for _, a := range append(algorithms, "hmac/whirlpool", "argon2i", "argon2d", "argon2id",
		"argon2i/v=16", "argon2d/v=16", "argon2id/v=16", "argon2i/no-v", "argon2d/no-v", "argon2id/no-v",
		"argon2i/v=19", "argon2d/v=19", "argon2id/v=19") {
		if !seen[a] {
			t.Errorf("no vector for %s", a)
		}
	}
	for _, n := range []string{"pbkdf2-RSA-SHA256", "pbkdf2-sha256WithRSAEncryption", "pbkdf2-ssl3-md5", "pbkdf2-ssl3-sha1",
		"pbkdf2-RSA-SHA1-2", "pbkdf2-rmd160", "pbkdf2-ripemd", "pbkdf2-RSA-RIPEMD160", "pbkdf2-ripemd160WithRSA",
		"pbkdf2-mdc2", "pbkdf2-RSA-MDC2", "pbkdf2-mdc2WithRSA", "pbkdf2-whirlpool"} {
		found := false
		for k := range pbkdf2Names {
			found = found || strings.EqualFold(k, n)
		}
		if !found {
			t.Errorf("no pbkdf2 vector for %s", n)
		}
	}
}

func parse(t *testing.T, in string) (*Spec, []FieldError) {
	t.Helper()
	return ParseCustom(json.RawMessage(in))
}

func TestKDFCostLimits(t *testing.T) {
	maximum := func(name, in string) {
		t.Helper()
		_, errs := parse(t, in)
		if len(errs) != 1 || errs[0].Code != "MAXIMUM" || errs[0].Path != "custom_password_hash" {
			t.Errorf("%s: got %+v", name, errs)
		}
	}
	accepted := func(name, in string) {
		t.Helper()
		if _, errs := parse(t, in); len(errs) > 0 {
			t.Errorf("%s: %+v", name, errs)
		}
	}
	const hx = `"hash":{"value":"00","encoding":"hex"}`
	// N*r*128 = 1 GiB exactly is allowed (libsodium SENSITIVE: N=2^20, r=8),
	// one doubling more is not
	accepted("scrypt at cap", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":8388608,"blockSize":1}`)
	accepted("scrypt sensitive", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":1048576,"blockSize":8}`)
	maximum("scrypt over cap", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":16777216,"blockSize":1}`)
	maximum("scrypt r", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":16384,"blockSize":1000}`)
	maximum("scrypt p memory", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"parallelization":2000000000}`)
	maximum("scrypt p work", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"parallelization":2000000}`)
	maximum("scrypt int32 product", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":1073741824,"blockSize":2147483647}`)
	accepted("scrypt work at 2^30", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":1024,"blockSize":1024,"parallelization":1024}`)
	maximum("scrypt work over 2^30", `{"algorithm":"scrypt",`+hx+`,"keylen":32,"cost":2048,"blockSize":1024,"parallelization":1025}`)
	accepted("scrypt default", `{"algorithm":"scrypt",`+hx+`,"keylen":32}`)

	argon := func(m string, t ...string) string {
		pass := "1"
		if len(t) > 0 {
			pass = t[0]
		}
		return `{"algorithm":"argon2","hash":{"value":"$argon2id$v=19$m=` + m + `,t=` + pass + `,p=1$c2FsdHNhbHQ$aGFzaGhhc2g","encoding":"utf8"}}`
	}
	accepted("argon2 at cap", argon("1048576"))
	maximum("argon2 over cap", argon("1048577"))
	maximum("argon2 huge", argon("4294967295"))
	accepted("argon2 sensitive", argon("1048576", "4")) // libsodium SENSITIVE: t*m = 2^22
	accepted("argon2 work at 2^32", argon("1048576", "4096"))
	maximum("argon2 work over 2^32", argon("1048576", "4097"))
	maximum("argon2 t huge", argon("64", "4294967295"))
	const pbkdf2Val = `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$i=%s,l=%s$c2FsdA$aGFzaA","encoding":"utf8"}}`
	accepted("pbkdf2 work at 5e7", fmt.Sprintf(pbkdf2Val, "25000000", "64"))
	maximum("pbkdf2 work over 5e7", fmt.Sprintf(pbkdf2Val, "25000001", "64"))
	maximum("pbkdf2 long key", fmt.Sprintf(pbkdf2Val, "1000000", "1048576"))
	accepted("pbkdf2 realistic", fmt.Sprintf(pbkdf2Val, "1300000", "32"))
	// an argon2 value that does not parse is accepted at import (R3)
	accepted("argon2 junk", `{"algorithm":"argon2","hash":{"value":"$argon2id$junk","encoding":"utf8"}}`)
	maximum("argon2 v16 huge", `{"algorithm":"argon2","hash":{"value":"$argon2id$v=16$m=999999999,t=1,p=1$c2FsdA$aGFzaA","encoding":"utf8"}}`)
}

func TestKDFUnusable(t *testing.T) {
	for name, in := range map[string]string{
		"pbkdf2 junk":         `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$nonsense","encoding":"utf8"}}`,
		"pbkdf2 unknown hash": `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-crc32$i=1,l=4$c2FsdA$aGFzaA","encoding":"utf8"}}`,
		"pbkdf2 bad param":    `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$i=x,l=4$c2FsdA$aGFzaA","encoding":"utf8"}}`,
		"argon2 junk":         `{"algorithm":"argon2","hash":{"value":"$argon2id$junk","encoding":"utf8"}}`,
		"argon2 v20":          `{"algorithm":"argon2","hash":{"value":"$argon2id$v=20$m=64,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g","encoding":"utf8"}}`,
		"pbkdf2 duplicate i":  `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$i=1,i=2,l=4$c2FsdA$aGFzaA","encoding":"utf8"}}`,
		"argon2 no p":         `{"algorithm":"argon2","hash":{"value":"$argon2id$v=19$m=64,t=2$c2FsdHNhbHQ$aGFzaGhhc2g","encoding":"utf8"}}`,
		"scrypt bad hex":      `{"algorithm":"scrypt","hash":{"value":"zz","encoding":"hex"},"keylen":4,"cost":16}`,
	} {
		t.Run(name, func(t *testing.T) {
			s, errs := parse(t, in)
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			if _, err := s.Verify("x"); !errors.Is(err, ErrUnusable) {
				t.Fatalf("err = %v, want ErrUnusable", err)
			}
		})
	}
}

// A spec read back from storage may carry any case; Unmarshal normalises it,
// and Verify never panics on a spec that was not normalised.
func TestUnmarshalNormalisesAndVerifyNeverPanics(t *testing.T) {
	// md5("Pa55w0rd!") and HMAC-SHA256("k", "Pa55w0rd!") are checked here with
	// upper-case names.
	md5sum := md5.Sum([]byte("Pa55w0rd!"))
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte("Pa55w0rd!"))
	s, err := Unmarshal(`{"algorithm":"MD5","hash":{"value":"` + hex.EncodeToString(md5sum[:]) + `","encoding":"hex"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Algorithm != "md5" {
		t.Fatalf("algorithm = %q", s.Algorithm)
	}
	h, err := Unmarshal(`{"algorithm":"HMAC","hash":{"value":"` + hex.EncodeToString(mac.Sum(nil)) +
		`","encoding":"hex","digest":"SHA256","key":{"value":"k"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if h.Hash.Digest != "sha256" {
		t.Fatalf("digest = %q", h.Hash.Digest)
	}
	for name, spec := range map[string]*Spec{"md5": s, "hmac": h} {
		if ok, err := spec.Verify("Pa55w0rd!"); err != nil || !ok {
			t.Errorf("%s: right password: %v, %v", name, ok, err)
		}
		if ok, err := spec.Verify("wrong"); err != nil || ok {
			t.Errorf("%s: wrong password: %v, %v", name, ok, err)
		}
	}
	// Specs that bypass Unmarshal: unknown names give ErrUnusable, never a panic.
	for name, spec := range map[string]*Spec{
		"unknown algorithm": {Algorithm: "NOPE"},
		"upper-case md5":    {Algorithm: "MD5", Hash: HashPart{Value: "00", Encoding: "hex"}},
		"unknown digest":    {Algorithm: "hmac", Hash: HashPart{Value: "00", Encoding: "hex", Digest: "SHA256", Key: &KeyPart{Value: "k"}}},
	} {
		if _, err := spec.Verify("x"); !errors.Is(err, ErrUnusable) {
			t.Errorf("%s: err = %v, want ErrUnusable", name, err)
		}
	}
}

func TestBase64LikeNode(t *testing.T) {
	want := []byte{0xfb, 0xff, 0xfe, 0xfa, 0x01}
	for name, in := range map[string]string{
		"standard padded":   "+//++gE=",
		"standard unpadded": "+//++gE",
		"url padded":        "-__--gE=",
		"url unpadded":      "-__--gE",
		"whitespace":        " +//+\n+gE\t= ",
		"crlf inside":       "+//+\r\n+gE",
		"stops at padding":  "+//++gE=garbage",
		"mixed alphabets":   "+__-+gE",
		"skips other chars": "+//+*+gE",
	} {
		if got := decodeBase64(in); string(got) != string(want) {
			t.Errorf("%s: %q -> % x", name, in, got)
		}
	}
	// "YQ" and "YQ==" are "a"; a single dangling character adds nothing
	for _, in := range []string{"YQ", "YQ==", "YQ=", "YQ\n=="} {
		if got := decodeBase64(in); string(got) != "a" {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if got := decodeBase64("YWJjZ"); string(got) != "abc" {
		t.Errorf("dangling char: %q", got)
	}
	if got := decodeBase64(""); len(got) != 0 {
		t.Errorf("empty: %q", got)
	}
}

// A stored key whose length differs from l can never match: no derivation is
// done (i here would take minutes).
func TestPBKDF2LengthMismatchSkipsWork(t *testing.T) {
	s, errs := parse(t, `{"algorithm":"pbkdf2","hash":{"value":"$pbkdf2-sha256$i=40000000,l=32$c2FsdA$aGFzaA","encoding":"utf8"}}`)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if ok, err := s.Verify("x"); ok || err != nil {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

// Verify re-checks the budgets for a spec that did not come through ParseCustom.
func TestVerifyBudgetsBackstop(t *testing.T) {
	for name, v := range map[string]string{
		"pbkdf2": "$pbkdf2-sha256$i=99999999,l=32$c2FsdA$" + strings.Repeat("A", 43),
		"argon2": "$argon2id$v=19$m=1048576,t=4097,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
	} {
		s := &Spec{Algorithm: strings.SplitN(name, "-", 2)[0], Hash: HashPart{Value: v, Encoding: "utf8"}}
		if _, err := s.Verify("x"); !errors.Is(err, ErrUnusable) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	s := &Spec{Algorithm: "scrypt", Hash: HashPart{Value: "00", Encoding: "hex"}, KeyLen: 32, Cost: 2048, BlockSize: 1024, Parallelization: 1025}
	if _, err := s.Verify("x"); !errors.Is(err, ErrUnusable) {
		t.Errorf("scrypt: err = %v", err)
	}
}
