package logstream

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// xxhash64 is XXH64 with seed zero, implemented locally to keep module pins.
// Arithmetic intentionally wraps modulo 2^64.
func xxhash64(b []byte) uint64 {
	const p1 uint64 = 11400714785074694791
	const p2 uint64 = 14029467366897019727
	const p3 uint64 = 1609587929392839161
	const p4 uint64 = 9650029242287828579
	const p5 uint64 = 2870177450012600261
	round := func(v, n uint64) uint64 { return bits.RotateLeft64(v+n*p2, 31) * p1 }
	n := len(b)
	var h uint64
	if len(b) >= 32 {
		v1 := uint64(p1)
		v1 += p2
		v2 := uint64(p2)
		v3 := uint64(0)
		v4 := uint64(0)
		v4 -= p1
		for len(b) >= 32 {
			v1 = round(v1, binary.LittleEndian.Uint64(b))
			v2 = round(v2, binary.LittleEndian.Uint64(b[8:]))
			v3 = round(v3, binary.LittleEndian.Uint64(b[16:]))
			v4 = round(v4, binary.LittleEndian.Uint64(b[24:]))
			b = b[32:]
		}
		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) + bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		for _, v := range []uint64{v1, v2, v3, v4} {
			h ^= round(0, v)
			h = h*p1 + p4
		}
	} else {
		h = p5
	}
	h += uint64(n)
	for len(b) >= 8 {
		h ^= round(0, binary.LittleEndian.Uint64(b))
		h = bits.RotateLeft64(h, 27)*p1 + p4
		b = b[8:]
	}
	if len(b) >= 4 {
		h ^= uint64(binary.LittleEndian.Uint32(b)) * p1
		h = bits.RotateLeft64(h, 23)*p2 + p3
		b = b[4:]
	}
	for _, v := range b {
		h ^= uint64(v) * p5
		h = bits.RotateLeft64(h, 11) * p1
	}
	h ^= h >> 33
	h *= p2
	h ^= h >> 29
	h *= p3
	h ^= h >> 32
	return h
}
func hashPII(s string) string { return fmt.Sprintf("%016x", xxhash64([]byte(s))) }
