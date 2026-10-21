package passhash

import (
	"crypto/des"
	"hash"
)

// MDC-2, ISO/IEC 10118-2 with DES as the block cipher, computed the way
// `openssl dgst -mdc2` does (padding type 1): the input is cut into 8-byte
// blocks, the last one zero-padded, and nothing is appended. The state is two
// 8-byte DES keys, h and hh, starting at 0x52.. and 0x25..; each block X gives
// A = DES_h(X) xor X and B = DES_hh(X) xor X, and the halves are swapped
// across the two keys. The digest is h || hh (16 bytes).

type mdc2 struct {
	h, hh [8]byte
	buf   [8]byte
	n     int
}

func newMDC2() hash.Hash {
	m := &mdc2{}
	m.Reset()
	return m
}

func (m *mdc2) Size() int      { return 16 }
func (m *mdc2) BlockSize() int { return 8 }

func (m *mdc2) Reset() {
	*m = mdc2{}
	for i := range m.h {
		m.h[i] = 0x52
		m.hh[i] = 0x25
	}
}

func (m *mdc2) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		c := copy(m.buf[m.n:], p)
		m.n += c
		p = p[c:]
		if m.n == 8 {
			m.block(m.buf)
			m.n = 0
		}
	}
	return total, nil
}

func (m *mdc2) block(x [8]byte) {
	// Bits 2 and 3 of the first key byte are forced to 10 for h and 01 for hh.
	m.h[0] = m.h[0]&0x9f | 0x40
	m.hh[0] = m.hh[0]&0x9f | 0x20
	var a, b [8]byte
	k1, _ := des.NewCipher(m.h[:]) // 8-byte keys: cannot fail
	k2, _ := des.NewCipher(m.hh[:])
	k1.Encrypt(a[:], x[:])
	k2.Encrypt(b[:], x[:])
	for i := range a {
		a[i] ^= x[i]
		b[i] ^= x[i]
	}
	copy(m.h[:4], a[:4])
	copy(m.h[4:], b[4:])
	copy(m.hh[:4], b[:4])
	copy(m.hh[4:], a[4:])
}

func (m *mdc2) Sum(in []byte) []byte {
	c := *m
	if c.n > 0 {
		for i := c.n; i < 8; i++ {
			c.buf[i] = 0
		}
		c.block(c.buf)
	}
	in = append(in, c.h[:]...)
	return append(in, c.hh[:]...)
}
