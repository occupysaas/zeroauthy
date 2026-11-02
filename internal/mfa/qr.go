package mfa

import (
	"fmt"
	"strings"
)

// QR byte mode, level M. Entries describe short blocks, long blocks, their
// data lengths, and the number of error-correction bytes per block.
var qrBlocks = [10][5]int{{1, 0, 16, 0, 10}, {1, 0, 28, 0, 16}, {1, 0, 44, 0, 26}, {2, 0, 32, 0, 18}, {2, 0, 43, 0, 24}, {4, 0, 27, 0, 16}, {4, 0, 31, 0, 18}, {2, 2, 38, 39, 22}, {3, 2, 36, 37, 22}, {4, 1, 43, 44, 26}}
var qrAlign = [][]int{nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}

// QRSVG returns nil when text exceeds the capacity of version 10 at level M.
func QRSVG(text string) []byte {
	data := []byte(text)
	version := 0
	for i, b := range qrBlocks {
		cap := b[0]*b[2] + b[1]*b[3]
		countBits := 8
		if i == 9 {
			countBits = 16
		}
		if len(data) < 1<<countBits && 4+countBits+len(data)*8 <= cap*8 {
			version = i + 1
			break
		}
	}
	if version == 0 {
		return nil
	}
	b := qrBlocks[version-1]
	cap := b[0]*b[2] + b[1]*b[3]
	bits := make([]bool, 0, cap*8)
	add := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (v>>i)&1 != 0)
		}
	}
	add(4, 4)
	countBits := 8
	if version == 10 {
		countBits = 16
	}
	add(len(data), countBits)
	for _, v := range data {
		add(int(v), 8)
	}
	for i := 0; i < 4 && len(bits) < cap*8; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	words := make([]byte, 0, cap)
	for i := 0; i < len(bits); i += 8 {
		v := byte(0)
		for j := 0; j < 8; j++ {
			v <<= 1
			if bits[i+j] {
				v |= 1
			}
		}
		words = append(words, v)
	}
	for len(words) < cap {
		if (len(words)-(len(bits)/8))%2 == 0 {
			words = append(words, 0xec)
		} else {
			words = append(words, 0x11)
		}
	}
	blocks := make([][]byte, 0, b[0]+b[1])
	ecc := make([][]byte, 0, cap)
	pos := 0
	for i := 0; i < b[0]+b[1]; i++ {
		n := b[2]
		if i >= b[0] {
			n = b[3]
		}
		block := words[pos : pos+n]
		pos += n
		blocks = append(blocks, block)
		ecc = append(ecc, qrRemainder(block, b[4]))
	}
	stream := make([]byte, 0)
	for i := 0; i < b[3] || i < b[2]; i++ {
		for _, block := range blocks {
			if i < len(block) {
				stream = append(stream, block[i])
			}
		}
	}
	for i := 0; i < b[4]; i++ {
		for _, e := range ecc {
			stream = append(stream, e[i])
		}
	}
	size := 17 + 4*version
	grid := make([][]bool, size)
	used := make([][]bool, size)
	for i := range grid {
		grid[i] = make([]bool, size)
		used[i] = make([]bool, size)
	}
	set := func(x, y int, v bool) {
		if x >= 0 && x < size && y >= 0 && y < size {
			grid[y][x] = v
			used[y][x] = true
		}
	}
	finder := func(cx, cy int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				d := max(abs(dx), abs(dy))
				set(cx+dx, cy+dy, d != 2 && d != 4)
			}
		}
	}
	finder(3, 3)
	finder(size-4, 3)
	finder(3, size-4)
	for i := 8; i < size-8; i++ {
		set(i, 6, i%2 == 0)
		set(6, i, i%2 == 0)
	}
	for _, y := range qrAlign[version-1] {
		for _, x := range qrAlign[version-1] {
			if (x == 6 && (y == 6 || y == size-7)) || (x == size-7 && y == 6) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	// Reserve and write the two copies of the format information: M, mask 0.
	format := 0x5412
	bit := func(i int) bool { return (format>>i)&1 != 0 }
	for i := 0; i <= 5; i++ {
		set(8, i, bit(i))
	}
	set(8, 7, bit(6))
	set(8, 8, bit(7))
	set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		set(size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		set(8, size-15+i, bit(i))
	}
	set(8, size-8, true)
	if version >= 7 {
		v := version << 12
		rem := v
		for i := 17; i >= 12; i-- {
			if rem>>i&1 != 0 {
				rem ^= 0x1f25 << (i - 12)
			}
		}
		v |= rem
		for i := 0; i < 18; i++ {
			on := v>>i&1 != 0
			a := size - 11 + i%3
			c := i / 3
			set(a, c, on)
			set(c, a, on)
		}
	}
	idx := 0
	up := true
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right--
		}
		for vert := 0; vert < size; vert++ {
			y := vert
			if up {
				y = size - 1 - vert
			}
			for k := 0; k < 2; k++ {
				x := right - k
				if used[y][x] {
					continue
				}
				on := false
				if idx < len(stream)*8 {
					on = (stream[idx/8]>>uint(7-idx%8))&1 != 0
				}
				idx++
				if (x+y)%2 == 0 {
					on = !on
				}
				grid[y][x] = on
			}
		}
		up = !up
	}
	var s strings.Builder
	fmt.Fprintf(&s, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="white"/><path d="`, size+8, size+8)
	for y := range grid {
		for x, on := range grid[y] {
			if on {
				fmt.Fprintf(&s, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	s.WriteString(`" fill="black"/></svg>`)
	return []byte(s.String())
}
func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func qrMul(a, b byte) byte {
	r := 0
	x := int(a)
	for b > 0 {
		if b&1 != 0 {
			r ^= x
		}
		x <<= 1
		if x&256 != 0 {
			x ^= 0x11d
		}
		b >>= 1
	}
	return byte(r)
}
func qrRemainder(data []byte, n int) []byte {
	gen := []byte{1}
	root := byte(1)
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		for j, v := range gen {
			next[j] ^= v
			next[j+1] ^= qrMul(v, root)
		}
		gen = next
		root = qrMul(root, 2)
	}
	r := make([]byte, n)
	for _, v := range data {
		factor := v ^ r[0]
		copy(r, r[1:])
		r[n-1] = 0
		for j := 0; j < n; j++ {
			r[j] ^= qrMul(gen[j+1], factor)
		}
	}
	return r
}
