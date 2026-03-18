package flashsign

import (
	"strconv"
	"time"
)

const (
	// defaultContentsPlaceholderLen is a conservative upper bound that fits
	// large production cert chains.
	defaultContentsPlaceholderLen = 16384
	minContentsPlaceholderLen     = 3072
	placeholderSafetyMarginHex    = 1024
	placeholderRoundUpHex         = 1024

	// byteRangePlaceholder is written into the signature dictionary initially with
	// zero offsets. It gets patched in-place after the increment is built.
	byteRangePlaceholder = "/ByteRange [0 0000000000 0000000000 0000000000]"
)

// upperHexChars is a lookup table for uppercase hex encoding.
const upperHexChars = "0123456789ABCDEF"

// appendZeroPad10 appends a 10-digit zero-padded decimal representation of n to dst.
func appendZeroPad10(dst []byte, n int64) []byte {
	var tmp [10]byte
	v := n
	for i := 9; i >= 0; i-- {
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, tmp[:]...)
}

// formatByteRange formats the ByteRange string directly into dst starting at pos.
func formatByteRange(dst []byte, pos int, a, b, c int64) {
	copy(dst[pos:], "/ByteRange [0 ")
	p := pos + 14
	var tmp [10]byte
	for _, v := range [3]int64{a, b, c} {
		for i := 9; i >= 0; i-- {
			tmp[i] = byte('0' + v%10)
			v /= 10
		}
		copy(dst[p:], tmp[:])
		p += 10
		if p-pos < len(byteRangePlaceholder) {
			dst[p] = ' '
			p++
		}
	}
	dst[p-1] = ']'
}

// encodeUpperHex encodes src into uppercase hex and writes into dst.
func encodeUpperHex(dst, src []byte) {
	for i, b := range src {
		dst[i*2] = upperHexChars[b>>4]
		dst[i*2+1] = upperHexChars[b&0x0f]
	}
}

// appendInt appends the decimal string of n to buf.
func appendInt(buf []byte, n int) []byte {
	return strconv.AppendInt(buf, int64(n), 10)
}

// appendInt64 appends the decimal string of n to buf.
func appendInt64(buf []byte, n int64) []byte {
	return strconv.AppendInt(buf, n, 10)
}

// appendFloat appends a float with minimal formatting to buf.
func appendFloat(buf []byte, f float64) []byte {
	return strconv.AppendFloat(buf, f, 'g', -1, 64)
}

// appendPDFDate appends a PDF date string (D:YYYYMMDDHHmmSS+00'00') to buf.
// Zero allocations (replaces time.Format which allocates).
func appendPDFDate(buf []byte, t time.Time) []byte {
	t = t.UTC()
	y, mo, d := t.Date()
	hh, mm, ss := t.Clock()
	buf = append(buf, 'D', ':')
	buf = append(buf, byte('0'+y/1000), byte('0'+(y/100)%10), byte('0'+(y/10)%10), byte('0'+y%10))
	buf = append(buf, byte('0'+int(mo)/10), byte('0'+int(mo)%10))
	buf = append(buf, byte('0'+d/10), byte('0'+d%10))
	buf = append(buf, byte('0'+hh/10), byte('0'+hh%10))
	buf = append(buf, byte('0'+mm/10), byte('0'+mm%10))
	buf = append(buf, byte('0'+ss/10), byte('0'+ss%10))
	buf = append(buf, "+00'00'"...)
	return buf
}

// appendPDFEscaped appends s to buf, escaping \, (, ) for PDF string literals.
// Zero allocations.
func appendPDFEscaped(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			buf = append(buf, '\\', '\\')
		case '(':
			buf = append(buf, '\\', '(')
		case ')':
			buf = append(buf, '\\', ')')
		default:
			buf = append(buf, s[i])
		}
	}
	return buf
}

// patchDecimal writes a left-aligned decimal number into buf[pos:pos+width],
// padding with spaces. Used for /Length placeholder patching.
func patchDecimal(buf []byte, pos, width, val int) {
	var tmp [10]byte
	n := 0
	if val == 0 {
		tmp[0] = '0'
		n = 1
	} else {
		v := val
		for v > 0 {
			tmp[n] = byte('0' + v%10)
			v /= 10
			n++
		}
		for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
			tmp[i], tmp[j] = tmp[j], tmp[i]
		}
	}
	copy(buf[pos:], tmp[:n])
	for i := n; i < width; i++ {
		buf[pos+i] = ' '
	}
}
