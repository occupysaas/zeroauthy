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
	version uint32
	m, t, p uint64
	salt    []byte
	key     []byte
}

// parseArgon2 reads the PHC string. Version 16 (Argon2 1.0) and 19 (1.3) are
// supported. A string without v= is Argon2 1.0, as the reference decoder and
// node-argon2 read it: the v= field was added with 1.3.
func parseArgon2(v string) (*argon2PHC, error) {
	parts := strings.Split(v, "$")
	version := uint32(argon2.Version10)
	if len(parts) == 6 && strings.HasPrefix(parts[2], "v=") {
		switch parts[2] {
		case "v=19":
			version = argon2.Version
		case "v=16":
		default:
			return nil, fmt.Errorf("%w: argon2 version %q", ErrUnusable, parts[2])
		}
		parts = append(parts[:2], parts[3:]...)
	}
	if len(parts) != 5 || parts[0] != "" {
		return nil, fmt.Errorf("%w: not an argon2 PHC string", ErrUnusable)
	}
	p := &argon2PHC{variant: parts[1], version: version}
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
	p.salt = decodeBase64(parts[3])
	p.key = decodeBase64(parts[4])
	return p, nil
}

// memory is the memory in bytes the parameters need: m KiB.
func (p *argon2PHC) memory() uint64 { return p.m * 1024 }

// work is t·m, in KiB-passes.
func (p *argon2PHC) work() uint64 { return p.t * p.m }

func (s *Spec) verifyArgon2(pw []byte) (bool, error) {
	p, err := parseArgon2(s.Hash.Value)
	if err != nil {
		return false, err
	}
	if p.t < 1 || p.p < 1 || p.p > maxArgon2Threads || p.m < 8*p.p || p.memory() > maxKDFMemory ||
		p.work() > maxArgon2Work || len(p.key) < 4 || len(p.key) > maxKDFKeyLen {
		return false, fmt.Errorf("%w: argon2 parameters", ErrUnusable)
	}
	got := argon2.KeyVersion(p.variant, p.version, pw, p.salt, uint32(p.t), uint32(p.m), uint8(p.p), uint32(len(p.key)))
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}
