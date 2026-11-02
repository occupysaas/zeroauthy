package mgmt

import "encoding/binary"

// validStoredCOSE checks the bounded public COSE_Key shape. These keys are
// stored for Plan 33b; this does not implement WebAuthn verification.
func validStoredCOSE(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 16384 {
		return false
	}
	value, rest, ok := readCOSEItem(raw, 0)
	if !ok || len(rest) != 0 {
		return false
	}
	m, ok := value.(map[int64]any)
	if !ok {
		return false
	}
	// Public credentials must never contain private key parameters. Reject
	// unknown labels too, rather than reflecting opaque key material back out.
	allowed := map[int64]bool{1: true, 3: true, -1: true, -2: true}
	if kind, ok := m[1].(int64); ok && kind == 2 {
		allowed[-3] = true
	}
	for key := range m {
		if !allowed[key] {
			return false
		}
	}
	integer := func(k int64) int64 { v, _ := m[k].(int64); return v }
	size := func(k int64) int { v, _ := m[k].([]byte); return len(v) }
	switch integer(1) {
	case 1:
		return integer(3) == -8 && integer(-1) == 6 && size(-2) == 32
	case 2:
		n := 0
		switch integer(-1) {
		case 1:
			if integer(3) != -7 {
				return false
			}
			n = 32
		case 2:
			if integer(3) != -35 {
				return false
			}
			n = 48
		case 3:
			if integer(3) != -36 {
				return false
			}
			n = 66
		}
		return n > 0 && size(-2) == n && size(-3) == n
	case 3:
		return (integer(3) == -257 || integer(3) == -37) && size(-1) >= 256 && size(-1) <= 1024 && size(-2) > 0 && size(-2) <= 8
	}
	return false
}
func readCOSEItem(raw []byte, depth int) (any, []byte, bool) {
	if len(raw) == 0 || depth > 2 {
		return nil, nil, false
	}
	head := raw[0]
	raw = raw[1:]
	n := uint64(head & 31)
	switch n {
	case 24:
		if len(raw) < 1 {
			return nil, nil, false
		}
		n = uint64(raw[0])
		raw = raw[1:]
	case 25:
		if len(raw) < 2 {
			return nil, nil, false
		}
		n = uint64(binary.BigEndian.Uint16(raw))
		raw = raw[2:]
	case 26:
		if len(raw) < 4 {
			return nil, nil, false
		}
		n = uint64(binary.BigEndian.Uint32(raw))
		raw = raw[4:]
	case 27:
		if len(raw) < 8 {
			return nil, nil, false
		}
		n = binary.BigEndian.Uint64(raw)
		raw = raw[8:]
	case 28, 29, 30, 31:
		return nil, nil, false
	}
	switch head >> 5 {
	case 0:
		if n > 1<<31 {
			return nil, nil, false
		}
		return int64(n), raw, true
	case 1:
		if n > 1<<31 {
			return nil, nil, false
		}
		return -1 - int64(n), raw, true
	case 2:
		if n > uint64(len(raw)) {
			return nil, nil, false
		}
		return raw[:n], raw[n:], true
	case 5:
		if n > 32 {
			return nil, nil, false
		}
		m := map[int64]any{}
		for range n {
			k, r, ok := readCOSEItem(raw, depth+1)
			if !ok {
				return nil, nil, false
			}
			key, ok := k.(int64)
			if !ok {
				return nil, nil, false
			}
			if _, exists := m[key]; exists {
				return nil, nil, false
			}
			v, r, ok := readCOSEItem(r, depth+1)
			if !ok {
				return nil, nil, false
			}
			m[key] = v
			raw = r
		}
		return m, raw, true
	}
	return nil, nil, false
}
