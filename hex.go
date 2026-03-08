package flashsign

import (
	"strconv"
	"strings"
)

const (
	// contentsPlaceholderLen is the number of hex characters reserved for the
	// PKCS#7 DER-encoded signature. 16384 hex chars = 8192 bytes.
	// Large enough for RSA-4096 signatures with multi-cert chains (e.g. Zerodha production PFX).
	contentsPlaceholderLen = 16384

	// byteRangePlaceholder is written into the signature dictionary initially with
	// zero offsets. It gets patched in-place after the increment is built.
	byteRangePlaceholder = "/ByteRange [0 0000000000 0000000000 0000000000]"
)

// Pre-computed zeros placeholder.
var contentsZeros = strings.Repeat("0", contentsPlaceholderLen)

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
