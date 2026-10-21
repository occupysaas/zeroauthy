package passhash

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/argon2"
)

// argon2PHC is a parsed `$argon2i|argon2d|argon2id$v=19$m=…,t=…,p=…$salt$hash`.
type argon2PHC struct {
	variant string
	m, t, p uint64
	salt    []byte
	key     []byte
}

// parseArgon2 reads the PHC string. Only version 19 (0x13) can be computed
// with the vendored implementation, so v=16 (Argon2 1.0) is refused as
// unusable. A string without v= is read as 19: encoders that omit it are
// mostly current ones, and if it was 1.0 it simply does not verify.
func parseArgon2(v string) (*argon2PHC, error) {
	parts := strings.Split(v, "$")
	if len(parts) == 6 && strings.HasPrefix(parts[2], "v=") {
		if parts[2] != "v=19" {
			return nil, fmt.Errorf("%w: argon2 version %q", ErrUnusable, parts[2])
		}
		parts = append(parts[:2], parts[3:]...)
	}
	if len(parts) != 5 || parts[0] != "" {
		return nil, fmt.Errorf("%w: not an argon2 PHC string", ErrUnusable)
	}
	p := &argon2PHC{variant: parts[1]}
	switch p.variant {
	case "argon2i", "argon2d", "argon2id":
	default:
		return nil, fmt.Errorf("%w: argon2 variant %q", ErrUnusable, p.variant)
	}
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[2], ",") {
		k, val, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(val, 10, 32)
		if !ok || err != nil || seen[k] {
			return nil, fmt.Errorf("%w: argon2 parameter %q", ErrUnusable, kv)
		}
		seen[k] = true
		switch k {
		case "m":
			p.m = n
		case "t":
			p.t = n
		case "p":
			p.p = n
		default:
			return nil, fmt.Errorf("%w: argon2 parameter %q", ErrUnusable, k)
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] {
		return nil, fmt.Errorf("%w: argon2 parameters", ErrUnusable)
	}
	var err error
	if p.salt, err = decodeBase64(parts[3]); err != nil {
		return nil, err
	}
	if p.key, err = decodeBase64(parts[4]); err != nil {
		return nil, err
	}
	return p, nil
}

// memory is the memory in bytes the parameters need: m KiB.
func (p *argon2PHC) memory() uint64 { return p.m * 1024 }

func (s *Spec) verifyArgon2(pw []byte) (bool, error) {
	p, err := parseArgon2(s.Hash.Value)
	if err != nil {
		return false, err
	}
	if p.t < 1 || p.t > maxArgon2Passes || p.p < 1 || p.p > maxArgon2Threads || p.m < 8*p.p ||
		p.memory() > maxKDFMemory || len(p.key) < 4 || len(p.key) > maxKDFKeyLen {
		return false, fmt.Errorf("%w: argon2 parameters", ErrUnusable)
	}
	derive := argon2.IDKey
	switch p.variant {
	case "argon2i":
		derive = argon2.Key
	case "argon2d":
		derive = argon2.DKey
	}
	got := derive(pw, p.salt, uint32(p.t), uint32(p.m), uint8(p.p), uint32(len(p.key)))
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}
