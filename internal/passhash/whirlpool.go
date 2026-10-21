package passhash

import (
	"hash"
)

// Whirlpool, ISO/IEC 10118-3 (the final, 2003 version), written from the
// published specification: a 512-bit Miyaguchi-Preneel hash over the 10-round
// block cipher W. The 8x8 state is a matrix of bytes over GF(2^8) with the
// reduction polynomial x^8+x^4+x^3+x^2+1; byte i of a block is row i/8,
// column i%8.

const (
	whirlpoolSize   = 64
	whirlpoolRounds = 10
)

var (
	// whirlpoolT[k][x] is row k of the diffusion step applied to a state whose
	// only non-zero byte is x in column k: S(x) times row k of the circulant
	// matrix cir(1, 1, 4, 1, 8, 5, 2, 9), packed big-endian into a uint64.
	whirlpoolT [8][256]uint64
	// whirlpoolRC[r] is the round constant of round r+1: row 0 holds
	// S[8r..8r+7], the other rows are zero.
	whirlpoolRC [whirlpoolRounds]uint64
)

func init() {
	// The S-box is built from three 4-bit mini-boxes, as the specification
	// describes: E, its inverse and R.
	e := [16]byte{0x1, 0xB, 0x9, 0xC, 0xD, 0x6, 0xF, 0x3, 0xE, 0x8, 0x7, 0x4, 0xA, 0x2, 0x5, 0x0}
	r := [16]byte{0x7, 0xC, 0xB, 0xD, 0xE, 0x4, 0x9, 0xF, 0x6, 0x3, 0x8, 0xA, 0x2, 0x5, 0x1, 0x0}
	var einv [16]byte
	for i, v := range e {
		einv[v] = byte(i)
	}
	var sbox [256]byte
	for u := 0; u < 256; u++ {
		a := e[u>>4]
		b := einv[u&0xf]
		m := r[a^b]
		sbox[u] = e[a^m]<<4 | einv[b^m]
	}

	mul := func(a, b byte) byte { // multiplication in GF(2^8), polynomial 0x11D
		var p byte
		for ; b != 0; b >>= 1 {
			if b&1 != 0 {
				p ^= a
			}
			hi := a & 0x80
			a <<= 1
			if hi != 0 {
				a ^= 0x1D
			}
		}
		return p
	}
	c := [8]byte{1, 1, 4, 1, 8, 5, 2, 9}
	for k := 0; k < 8; k++ {
		for x := 0; x < 256; x++ {
			s := sbox[x]
			var row uint64
			for j := 0; j < 8; j++ {
				// entry (k, j) of the circulant matrix is c[(j-k) mod 8]
				row = row<<8 | uint64(mul(s, c[(j-k+8)&7]))
			}
			whirlpoolT[k][x] = row
		}
	}
	for i := 0; i < whirlpoolRounds; i++ {
		var row uint64
		for j := 0; j < 8; j++ {
			row = row<<8 | uint64(sbox[8*i+j])
		}
		whirlpoolRC[i] = row
	}
}

// whirlpoolRound is one round rho[k]: substitute every byte, cyclically shift
// column j down by j rows, multiply by the circulant matrix and add the key k.
func whirlpoolRound(a, k *[8]uint64) [8]uint64 {
	var out [8]uint64
	for i := 0; i < 8; i++ {
		v := k[i]
		for c := 0; c < 8; c++ {
			// after the shift, row i column c comes from row (i-c) mod 8
			v ^= whirlpoolT[c][byte(a[(i-c+8)&7]>>(56-8*uint(c)))]
		}
		out[i] = v
	}
	return out
}

type whirlpool struct {
	h   [8]uint64
	buf [64]byte
	n   int    // bytes in buf
	len uint64 // total bytes written
}

// newWhirlpool returns a Whirlpool hash.Hash.
func newWhirlpool() hash.Hash { return &whirlpool{} }

func (w *whirlpool) Size() int      { return whirlpoolSize }
func (w *whirlpool) BlockSize() int { return 64 }
func (w *whirlpool) Reset()         { *w = whirlpool{} }

func (w *whirlpool) Write(p []byte) (int, error) {
	total := len(p)
	w.len += uint64(total)
	if w.n > 0 {
		c := copy(w.buf[w.n:], p)
		w.n += c
		p = p[c:]
		if w.n < 64 {
			return total, nil
		}
		w.block(w.buf[:])
		w.n = 0
	}
	for len(p) >= 64 {
		w.block(p[:64])
		p = p[64:]
	}
	w.n = copy(w.buf[:], p)
	return total, nil
}

// block is the compression function: H' = W_H(m) xor H xor m.
func (w *whirlpool) block(m []byte) {
	var msg, state [8]uint64
	for i := 0; i < 8; i++ {
		var v uint64
		for j := 0; j < 8; j++ {
			v = v<<8 | uint64(m[8*i+j])
		}
		msg[i] = v
		state[i] = v ^ w.h[i]
	}
	key := w.h
	for r := 0; r < whirlpoolRounds; r++ {
		key = whirlpoolRound(&key, &[8]uint64{whirlpoolRC[r]})
		state = whirlpoolRound(&state, &key)
	}
	for i := range w.h {
		w.h[i] ^= state[i] ^ msg[i]
	}
}

func (w *whirlpool) Sum(in []byte) []byte {
	c := *w // Sum does not change the running state
	// Padding: a 1 bit, zeros up to 32 bytes short of a block boundary, then
	// the message length in bits as a 256-bit big-endian integer.
	pad := make([]byte, 0, 128)
	pad = append(pad, 0x80)
	for (c.n+len(pad))%64 != 32 {
		pad = append(pad, 0)
	}
	var l [32]byte
	bits := c.len * 8
	hi := c.len >> 61
	for i := 0; i < 8; i++ {
		l[31-i] = byte(bits >> (8 * uint(i)))
		l[23-i] = byte(hi >> (8 * uint(i)))
	}
	pad = append(pad, l[:]...)
	c.len = 0 // the padding is not part of the length
	c.Write(pad)
	for _, v := range c.h {
		for s := 56; s >= 0; s -= 8 {
			in = append(in, byte(v>>uint(s)))
		}
	}
	return in
}
