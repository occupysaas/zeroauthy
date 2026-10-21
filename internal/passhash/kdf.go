package passhash

import (
	"fmt"
	"math/bits"
)

// maxKDFMemory is the most memory a scrypt or argon2 import hash may ask for
// (D-0044): a hostile file must not be able to stall or exhaust a worker.
const maxKDFMemory = 256 << 20

// Limits on the other cost inputs. They only guard Verify against absurd
// stored values; Auth0's documented defaults are far below them.
const (
	maxKDFKeyLen     = 1 << 20
	maxPBKDF2Rounds  = 50_000_000
	maxArgon2Passes  = 1 << 20
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

func memoryTooBig(code string) FieldError {
	return FieldError{Code: code, Message: fmt.Sprintf("Value exceeds the maximum memory cost of %d bytes", maxKDFMemory), Path: pathCPH}
}
