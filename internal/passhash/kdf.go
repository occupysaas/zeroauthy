package passhash

import (
	"math/bits"
)

// maxKDFMemory is the most memory a scrypt or argon2 import hash may ask for
// (D-0044, ruling R9): 1 GiB, so libsodium's MEMLIMIT_SENSITIVE argon2 and
// scrypt N=2^20, r=8 verify. A hostile file must not be able to exhaust a worker.
const maxKDFMemory = 1 << 30

// Work budgets bound the time one login can spend on an imported hash. They
// are zeroauthy's own (Auth0's limits were not observed) and sit well above
// real-world settings:
//
//	pbkdf2: rounds × ceil(l / digest size) <= 50,000,000 HMAC blocks
//	        (600,000 rounds of SHA-256 with l=32 is 600,000)
//	argon2: t × m (KiB) <= 2^32 (libsodium SENSITIVE, t=4 at 1 GiB, is 2^22)
//	scrypt: N × r × p <= 2^30 (N=2^20, r=8, p=1 is 2^23)
//
// They are checked at parse (MAXIMUM) and again in Verify (ErrUnusable).
const (
	maxPBKDF2Work = 50_000_000
	maxArgon2Work = 1 << 32
	maxScryptWork = 1 << 30
)

// Limits on the other inputs; they only guard Verify against absurd stored
// values.
const (
	maxKDFKeyLen     = 1 << 20
	maxArgon2Threads = 255
)

// scryptMemory is the memory scrypt needs for N, r and p, in bytes, saturated
// at math.MaxUint64: N·r·128 for the V array and p·r·128 for the blocks.
func scryptMemory(n, r, p uint64) uint64 {
	big := func(a, b uint64) uint64 {
		hi, lo := bits.Mul64(a, b)
		hi2, lo2 := bits.Mul64(lo, 128)
		if hi != 0 || hi2 != 0 {
			return ^uint64(0)
		}
		return lo2
	}
	return max(big(n, r), big(p, r))
}

// scryptWork is N·r·p, saturated at math.MaxUint64.
func scryptWork(n, r, p uint64) uint64 {
	hi, lo := bits.Mul64(n, r)
	hi2, lo2 := bits.Mul64(lo, p)
	if hi != 0 || hi2 != 0 {
		return ^uint64(0)
	}
	return lo2
}

// costTooBig is the parse error for a cost over a memory or work limit.
func costTooBig(what string) FieldError {
	return FieldError{Code: "MAXIMUM", Message: "The " + what + " cost is above the maximum", Path: pathCPH}
}
