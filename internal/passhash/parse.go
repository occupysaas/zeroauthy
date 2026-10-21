package passhash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

const (
	pathCPH  = "custom_password_hash"
	pathHash = "custom_password_hash.hash"
)

var algorithms = []string{"argon2", "bcrypt", "hmac", "ldap", "md4", "md5", "sha1", "sha256", "sha512", "pbkdf2", "scrypt"}

// hashEncodings is which hash.encoding values each algorithm takes.
var hashEncodings = map[string][]string{
	"argon2": {"utf8"}, "bcrypt": {"utf8"}, "ldap": {"utf8"}, "pbkdf2": {"utf8"},
	"hmac": {"hex", "base64"}, "md4": {"hex", "base64"}, "md5": {"hex", "base64"},
	"sha1": {"hex", "base64"}, "sha256": {"hex", "base64"}, "sha512": {"hex", "base64"},
	"scrypt": {"hex", "base64"},
}

var (
	valueEncodings    = []string{"base64", "hex", "utf8"}
	saltPositions     = []string{"prefix", "suffix"}
	passwordEncodings = []string{"ascii", "utf8", "utf16le", "ucs2", "latin1", "binary"}
	hmacDigests       = []string{"md4", "md5", "ripemd160", "sha1", "sha224", "sha256", "sha384", "sha512", "whirlpool"}
)

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ParseCustom validates a custom_password_hash object and returns the spec
// with Auth0's defaults filled in. It reports the first problem it finds, as
// one FieldError, using the codes, messages and paths observed on Auth0 (J5);
// where Auth0's wording was not observed the message is our own and says so in
// the comment beside it. Properties it does not know are ignored.
func ParseCustom(raw json.RawMessage) (*Spec, []FieldError) {
	fail := func(code, msg, path string) (*Spec, []FieldError) {
		return nil, []FieldError{{Code: code, Message: msg, Path: path}}
	}
	missing := func(name, path string) (*Spec, []FieldError) {
		return fail("OBJECT_MISSING_REQUIRED_PROPERTY", "Missing required property: "+name, path)
	}
	oneOf := func() (*Spec, []FieldError) { return fail("ONE_OF_MISSING", "", pathCPH) }

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top any
	if err := dec.Decode(&top); err != nil {
		return fail("INVALID_TYPE", "Expected type object but found type invalid", pathCPH)
	}
	m, ok := top.(map[string]any)
	if !ok {
		return fail("INVALID_TYPE", "Expected type object but found type "+jsonType(top), pathCPH)
	}

	// algorithm
	av, ok := m["algorithm"]
	if !ok {
		return missing("algorithm", pathCPH)
	}
	alg, ok := av.(string)
	if !ok {
		return typeErr("string", av, pathCPH+".algorithm")
	}
	if !contains(algorithms, alg) {
		return fail("ENUM_MISMATCH", "Error in custom_password_hash.algorithm property - No enum match for: "+alg,
			pathCPH+".algorithm")
	}

	s := &Spec{Algorithm: alg}

	// Properties an algorithm does not take.
	if _, has := m["salt"]; has && (alg == "argon2" || alg == "pbkdf2" || alg == "ldap") {
		return fail("OBJECT_ADDITIONAL_PROPERTIES", "Additional properties not allowed: salt", pathCPH)
	}

	// hash
	hv, ok := m["hash"]
	if !ok {
		return missing("hash", pathCPH)
	}
	hm, ok := hv.(map[string]any)
	if !ok {
		return typeErr("object", hv, pathHash)
	}
	val, ok := hm["value"]
	if !ok {
		return missing("value", pathHash)
	}
	if s.Hash.Value, ok = val.(string); !ok {
		return typeErr("string", val, pathHash+".value")
	}
	if ev, has := hm["encoding"]; has {
		if s.Hash.Encoding, ok = ev.(string); !ok {
			return typeErr("string", ev, pathHash+".encoding")
		}
	}
	if !contains(hashEncodings[alg], s.Hash.Encoding) {
		return oneOf()
	}

	switch alg {
	case "hmac":
		if f, e := parseHMAC(s, hm); e != nil {
			return f, e
		}
	case "scrypt":
		if f, e := parseScrypt(s, m); e != nil {
			return f, e
		}
	}

	if f, e := parseSalt(s, m); e != nil {
		return f, e
	}
	if pv, has := m["password"]; has {
		pm, ok := pv.(map[string]any)
		if !ok {
			return typeErr("object", pv, pathCPH+".password")
		}
		if ev, has := pm["encoding"]; has {
			enc, ok := ev.(string)
			if !ok {
				return typeErr("string", ev, pathCPH+".password.encoding")
			}
			if !contains(passwordEncodings, enc) {
				return enumErr(pathCPH+".password.encoding", enc)
			}
			s.Password = &PassPart{Encoding: enc}
		}
	}

	// The value itself: only its shape is checked here.
	v := s.Hash.Value
	switch alg {
	case "bcrypt":
		if !strings.HasPrefix(v, "$2") {
			return oneOf()
		}
	case "argon2":
		if !strings.HasPrefix(v, "$argon2") {
			return oneOf()
		}
		// A value that does not parse is accepted and unusable (R3); one
		// that does is held to the memory cap.
		if p, err := parseArgon2(v); err == nil && p.memory() > maxKDFMemory {
			return nil, []FieldError{memoryTooBig("MAXIMUM")}
		}
	case "pbkdf2":
		if !strings.HasPrefix(v, "$pbkdf2-") {
			return oneOf()
		}
	case "ldap":
		// {CRYPT} and {CLEARTEXT} (accepted by Auth0 but unusable, D-0044
		// refuses them) and anything that is not an RFC 2307 scheme.
		name, _ := ldapScheme(v)
		if _, ok := ldapKinds[name]; !ok {
			return oneOf()
		}
	}
	return s, nil
}

func parseHMAC(s *Spec, hm map[string]any) (*Spec, []FieldError) {
	dv, ok := hm["digest"]
	if !ok {
		return nil, []FieldError{{Code: "OBJECT_MISSING_REQUIRED_PROPERTY", Message: "Missing required property: digest", Path: pathHash}}
	}
	d, ok := dv.(string)
	if !ok {
		return typeErr("string", dv, pathHash+".digest")
	}
	if !contains(hmacDigests, d) {
		return enumErr(pathHash+".digest", d)
	}
	s.Hash.Digest = d

	kv, ok := hm["key"]
	if !ok {
		return nil, []FieldError{{Code: "OBJECT_MISSING_REQUIRED_PROPERTY", Message: "Missing required property: key", Path: pathHash}}
	}
	km, ok := kv.(map[string]any)
	if !ok {
		return typeErr("object", kv, pathHash+".key")
	}
	val, ok := km["value"]
	if !ok {
		return nil, []FieldError{{Code: "OBJECT_MISSING_REQUIRED_PROPERTY", Message: "Missing required property: value", Path: pathHash + ".key"}}
	}
	key := &KeyPart{Encoding: "utf8"}
	if key.Value, ok = val.(string); !ok {
		return typeErr("string", val, pathHash+".key.value")
	}
	if ev, has := km["encoding"]; has {
		if key.Encoding, ok = ev.(string); !ok {
			return typeErr("string", ev, pathHash+".key.encoding")
		}
		if !contains(valueEncodings, key.Encoding) {
			return enumErr(pathHash+".key.encoding", key.Encoding)
		}
	}
	s.Hash.Key = key
	return nil, nil
}

func parseSalt(s *Spec, m map[string]any) (*Spec, []FieldError) {
	sv, has := m["salt"]
	if !has {
		return nil, nil
	}
	const p = pathCPH + ".salt"
	sm, ok := sv.(map[string]any)
	if !ok {
		return typeErr("object", sv, p)
	}
	val, ok := sm["value"]
	if !ok {
		return nil, []FieldError{{Code: "OBJECT_MISSING_REQUIRED_PROPERTY", Message: "Missing required property: value", Path: p}}
	}
	salt := &SaltPart{Encoding: "utf8", Position: "prefix"}
	if salt.Value, ok = val.(string); !ok {
		return typeErr("string", val, p+".value")
	}
	if ev, has := sm["encoding"]; has {
		if salt.Encoding, ok = ev.(string); !ok {
			return typeErr("string", ev, p+".encoding")
		}
		if !contains(valueEncodings, salt.Encoding) {
			return enumErr(p+".encoding", salt.Encoding)
		}
	}
	if pv, has := sm["position"]; has {
		if salt.Position, ok = pv.(string); !ok {
			return typeErr("string", pv, p+".position")
		}
		if !contains(saltPositions, salt.Position) {
			return enumErr(p+".position", salt.Position)
		}
	}
	s.Salt = salt
	return nil, nil
}

// parseScrypt reads keylen (required), cost (default 16384, a power of two
// above 1), blockSize (default 8) and parallelization (default 1). The error
// codes for out-of-range values are ours; Auth0's were not observed.
func parseScrypt(s *Spec, m map[string]any) (*Spec, []FieldError) {
	kl, ok, fe := intProp(m, "keylen")
	if fe != nil {
		return nil, fe
	}
	if !ok {
		return nil, []FieldError{{Code: "OBJECT_MISSING_REQUIRED_PROPERTY", Message: "Missing required property: keylen", Path: pathCPH}}
	}
	s.KeyLen = kl
	s.Cost, s.BlockSize, s.Parallelization = 16384, 8, 1
	for _, p := range []struct {
		name string
		dst  *int
	}{{"cost", &s.Cost}, {"blockSize", &s.BlockSize}, {"parallelization", &s.Parallelization}} {
		n, ok, fe := intProp(m, p.name)
		if fe != nil {
			return nil, fe
		}
		if ok {
			*p.dst = n
		}
	}
	for _, p := range []struct {
		name string
		v    int
	}{{"keylen", s.KeyLen}, {"blockSize", s.BlockSize}, {"parallelization", s.Parallelization}} {
		if p.v < 1 {
			return nil, []FieldError{{Code: "MINIMUM", Message: fmt.Sprintf("Value %d is less than minimum 1", p.v), Path: pathCPH + "." + p.name}}
		}
	}
	if scryptMemory(uint64(s.Cost), uint64(s.BlockSize), uint64(s.Parallelization)) > maxKDFMemory {
		return nil, []FieldError{memoryTooBig("MAXIMUM")}
	}
	if s.Cost < 2 || s.Cost&(s.Cost-1) != 0 {
		return nil, []FieldError{{Code: "INVALID_FORMAT", Message: fmt.Sprintf("Error in custom_password_hash.cost property - cost must be a power of two greater than 1: %d", s.Cost), Path: pathCPH + ".cost"}}
	}
	return nil, nil
}

// intProp reads an integer property; ok is false when it is absent. Integers
// outside int32 are reported as MAXIMUM; that is zeroauthy's choice, as Auth0's
// code for them was not observed (it is the code for a value above a declared
// maximum, here the int32 range).
func intProp(m map[string]any, name string) (n int, ok bool, fe []FieldError) {
	v, has := m[name]
	if !has {
		return 0, false, nil
	}
	num, isNum := v.(json.Number)
	if isNum {
		i, err := num.Int64()
		if err == nil && i >= math.MinInt32 && i <= math.MaxInt32 {
			return int(i), true, nil
		}
		if err != nil {
			return 0, false, []FieldError{{Code: "INVALID_TYPE", Message: "Expected type integer but found type number", Path: pathCPH + "." + name}}
		}
		return 0, false, []FieldError{{Code: "MAXIMUM", Message: fmt.Sprintf("Value %d is out of range", i), Path: pathCPH + "." + name}}
	}
	_, fe = typeErr("integer", v, pathCPH+"."+name)
	return 0, false, fe
}

func typeErr(want string, got any, path string) (*Spec, []FieldError) {
	return nil, []FieldError{{Code: "INVALID_TYPE", Message: "Expected type " + want + " but found type " + jsonType(got), Path: path}}
}

func enumErr(path, got string) (*Spec, []FieldError) {
	return nil, []FieldError{{Code: "ENUM_MISMATCH", Message: "Error in " + path + " property - No enum match for: " + got, Path: path}}
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	}
	return "object"
}

var bcryptPattern = regexp.MustCompile(`^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$`)

// FromBcrypt checks an Auth0 password_hash and returns the spec for it. The
// PATTERN message ends in "*****" where Auth0 repeats the hash (D-0044).
func FromBcrypt(passwordHash string) (*Spec, []FieldError) {
	if !bcryptPattern.MatchString(passwordHash) {
		return nil, []FieldError{{
			Code:    "PATTERN",
			Message: `Error in passwordHash property - String does not match pattern ^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$: ` + masked,
			Path:    "passwordHash",
		}}
	}
	return &Spec{Algorithm: "bcrypt", Hash: HashPart{Value: passwordHash, Encoding: "utf8"}}, nil
}
