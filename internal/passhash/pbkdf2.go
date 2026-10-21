package passhash

import (
	"crypto/pbkdf2"
	"crypto/subtle"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// pbkdf2Digests maps the digest names a `$pbkdf2-<digest>$` hash may carry to
// hashes. They are OpenSSL's digest names and aliases, which is what the
// Node crypto.pbkdf2 behind Auth0 accepts.
var pbkdf2Digests = func() map[string]func() hash.Hash {
	m := map[string]func() hash.Hash{"mdc2": newMDC2}
	for n, c := range digests {
		m[n] = c
	}
	alias := func(c func() hash.Hash, names ...string) {
		for _, n := range names {
			m[n] = c
		}
	}
	for _, n := range []string{"md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"} {
		alias(digests[n], "rsa-"+n, n+"withrsaencryption")
	}
	alias(digests["md5"], "ssl3-md5")
	alias(digests["sha1"], "ssl3-sha1", "rsa-sha1-2")
	alias(digests["ripemd160"], "rmd160", "ripemd", "rsa-ripemd160", "ripemd160withrsa")
	alias(newMDC2, "rsa-mdc2", "mdc2withrsa")
	return m
}()

// pbkdf2PHC is a parsed `$pbkdf2-<digest>$i=<n>,l=<bytes>$<salt>$<key>` value.
type pbkdf2PHC struct {
	digest func() hash.Hash
	iter   int
	keyLen int
	salt   []byte
	key    []byte
}

// parsePBKDF2 reads the PHC string. Salt and key are base64 without padding;
// i defaults to 100000 and l to 64.
func parsePBKDF2(v string) (*pbkdf2PHC, error) {
	parts := strings.Split(v, "$")
	if len(parts) != 5 || parts[0] != "" || !strings.HasPrefix(parts[1], "pbkdf2-") {
		return nil, fmt.Errorf("%w: not a pbkdf2 PHC string", ErrUnusable)
	}
	ctor, ok := pbkdf2Digests[strings.ToLower(strings.TrimPrefix(parts[1], "pbkdf2-"))]
	if !ok {
		return nil, fmt.Errorf("%w: pbkdf2 digest %q", ErrUnusable, parts[1])
	}
	p := &pbkdf2PHC{digest: ctor, iter: 100000, keyLen: 64}
	if parts[2] != "" {
		seen := map[string]bool{}
		for _, kv := range strings.Split(parts[2], ",") {
			k, val, ok := strings.Cut(kv, "=")
			n, err := strconv.Atoi(val)
			if !ok || err != nil || n < 1 || seen[k] {
				return nil, fmt.Errorf("%w: pbkdf2 parameter %q", ErrUnusable, kv)
			}
			seen[k] = true
			switch k {
			case "i":
				p.iter = n
			case "l":
				p.keyLen = n
			default:
				return nil, fmt.Errorf("%w: pbkdf2 parameter %q", ErrUnusable, k)
			}
		}
	}
	p.salt = decodeBase64(parts[3])
	p.key = decodeBase64(parts[4])
	return p, nil
}

func (s *Spec) verifyPBKDF2(pw []byte) (bool, error) {
	p, err := parsePBKDF2(s.Hash.Value)
	if err != nil {
		return false, err
	}
	if p.keyLen > maxKDFKeyLen || p.work() > maxPBKDF2Work {
		return false, fmt.Errorf("%w: pbkdf2 cost", ErrUnusable)
	}
	if len(p.key) != p.keyLen {
		return false, nil // a key of another length can never match: skip the work
	}
	got, err := pbkdf2.Key(p.digest, string(pw), p.salt, p.iter, p.keyLen)
	if err != nil {
		return false, fmt.Errorf("%w: pbkdf2: %v", ErrUnusable, err)
	}
	return subtle.ConstantTimeCompare(got, p.key) == 1, nil
}

// work is the number of HMAC block computations: rounds × ceil(l / digest size).
func (p *pbkdf2PHC) work() uint64 {
	size := p.digest().Size()
	return uint64(p.iter) * uint64((p.keyLen+size-1)/size)
}
