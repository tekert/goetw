package hexf

// Faster hex->String conversions with "0x" prefixes and trims, fewer allocations too.
// Convenient functions to convert integers to hex strings with "0x" prefixes
// or trimmed zeroes on high frequency paths.

import (
	"encoding/binary"
	"unsafe"
)

// const hextableUpper = "0123456789ABCDEF"
// const hextableLower = "0123456789abcdef"

var hextableUpper = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}
var hextableLower = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

// --- Core Encoding Functions (write to a slice) ---

// Ported from the hex package to print uppercase hex efficiently
//
// Encode encodes src into [EncodedLen](len(src))
// bytes of dst. As a convenience, it returns the number
// of bytes written to dst, but this value is always [EncodedLen](len(src)).
// Encode implements hexadecimal encoding.
func EncodeU(dst, src []byte) int {
	return encode(dst, src, &hextableUpper)
}

// Ported from the hex package to print lowercase hex just for convenience.
//
// Encode encodes src into [EncodedLen](len(src))
// bytes of dst. As a convenience, it returns the number
// of bytes written to dst, but this value is always [EncodedLen](len(src)).
// Encode implements hexadecimal encoding.
func Encode(dst, src []byte) int {
	return encode(dst, src, &hextableLower)
}

// Ported this from the hex package to handle upper and lowercase efficiently
func encode(dst, src []byte, hexTable *[16]byte) int {
	j := 0
	for _, v := range src {
		dst[j] = hexTable[v>>4]
		dst[j+1] = hexTable[v&0x0f]
		j += 2
	}
	return len(src) * 2
}

// Efficiently removing leading zeroes while converting to hex.
// The fastest performing one i could do.
func encodeTrim(dst, src []byte, hexTable *[16]byte) int {
	// Handle nil/empty case
	if len(src) == 0 {
		return 0
	}

	// Handle empty or a single zero byte
	if len(src) == 1 && src[0] == 0 {
		dst[0] = '0'
		return 1
	}

	// Skip leading zeros
	i := 0
	for ; i < len(src) && src[i] == 0; i++ {
	}
	// If all zeros, return "0"
	if i == len(src) {
		dst[0] = '0'
		return 1
	}

	// Encode the first nonzero byte carefully, Example:
	// If v = 0x05, it goes through the single nibble path → "5"
	// If v = 0x4F, it goes through the two nibbles path → "4F"
	v := src[i]
	j := 0
	if v < 0x10 {
		// Single nibble
		dst[j] = hexTable[v]
		j++
	} else {
		// Two nibbles
		dst[j] = hexTable[v>>4]
		dst[j+1] = hexTable[v&0x0f]
		j += 2
	}
	i++

	// Encode remaining bytes with two nibbles each
	for ; i < len(src); i++ {
		v = src[i]
		dst[j] = hexTable[v>>4]
		dst[j+1] = hexTable[v&0x0f]
		j += 2
	}

	return j
}

//go:inline
func EncodeTrim(dst, src []byte) int {
	return encodeTrim(dst, src, &hextableLower)
}

//go:inline
func EncodeUTrim(dst, src []byte) int {
	return encodeTrim(dst, src, &hextableUpper)
}

// --- Allocating Convenience Functions (return string) ---

// EncodeToString returns the hexadecimal lowercase encoding of src.
func EncodeToString(src []byte) string {
	dst := make([]byte, len(src)*2)
	Encode(dst, src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToStringU returns the hexadecimal UPPERCASE encoding of src.
func EncodeToStringU(src []byte) string {
	dst := make([]byte, len(src)*2)
	EncodeU(dst, src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToStringPrefix returns the hexadecimal lowercase encoding
// of src with a "0x" prefix.
func EncodeToStringPrefix(src []byte) string {
	dst := make([]byte, 2+len(src)*2)
	dst[0] = '0'
	dst[1] = 'x'
	Encode(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToStringUPrefix returns the hexadecimal UPPERCASE encoding
// of src with a "0x" prefix.
func EncodeToStringUPrefix(src []byte) string {
	dst := make([]byte, 2+len(src)*2)
	dst[0] = '0'
	dst[1] = 'x'
	EncodeU(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToStringPrefixTrim returns the hexadecimal lowercase encoding of src
// with leading 0s trimmed and a "0x" prefix.
func EncodeToStringPrefixTrim(src []byte) string {
	dst := make([]byte, 2+len(src)*2)
	dst[0] = '0'
	dst[1] = 'x'
	n := EncodeTrim(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), n+2)
}

// EncodeToStringUPrefixTrim returns the hexadecimal uppercase encoding of src
// with leading 0s trimmed and a "0x" prefix.
func EncodeToStringUPrefixTrim(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	n := EncodeUTrim(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), n+2)
}

// --- Integer Interfaces ---

type Uint64Like interface{ ~uint64 | ~int64 }
type Uint32Like interface{ ~uint32 | ~int32 }
type Uint16Like interface{ ~uint16 | ~int16 }
type Uint8Like interface{ ~uint8 | ~int8 }

// --- Allocating ToString for Numbers (Uppercase) ---

// Uppercase
func NUm64[T Uint64Like](n T) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return EncodeToStringU(b[:])
}

// Uppercase with 0x prefix
func NUm64p[T Uint64Like](n T, trim bool) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// Uppercase
func NUm32[T Uint32Like](n T) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return EncodeToStringU(b[:])
}

// Uppercase with 0x prefix
func NUm32p[T Uint32Like](n T, trim bool) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// Uppercase
func NUm16[T Uint16Like](n T) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return EncodeToStringU(b[:])
}

// Uppercase with 0x prefix
func NUm16p[T Uint16Like](n T, trim bool) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// Uppercase
func NUm8[T Uint8Like](n T) string {
	return EncodeToStringU([]byte{byte(n)})
}

// Uppercase with 0x prefix
func NUm8p[T Uint8Like](n T, trim bool) string {
	var b [1]byte
	b[0] = byte(n)
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// --- Allocating ToString for Numbers (Lowercase) ---

// lowercase
func Num64[T Uint64Like](n T) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return EncodeToString(b[:])
}

// lowercase with 0x prefix
func Num64p[T Uint64Like](n T, trim bool) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	if trim {
		return EncodeToStringPrefixTrim(b[:])
	}
	return EncodeToStringPrefix(b[:])
}

// lowercase
func Num32[T Uint32Like](n T) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return EncodeToString(b[:])
}

// lowercase with 0x prefix
func Num32p[T Uint32Like](n T, trim bool) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	if trim {
		return EncodeToStringPrefixTrim(b[:])
	}
	return EncodeToStringPrefix(b[:])
}

// lowercase
func Num16[T Uint16Like](n T) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return EncodeToString(b[:])
}

// lowercase with 0x prefix
func Num16p[T Uint16Like](n T, trim bool) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	if trim {
		return EncodeToStringPrefixTrim(b[:])
	}
	return EncodeToStringPrefix(b[:])
}

// lowercase
func Num8[T Uint8Like](n T) string {
	return EncodeToString([]byte{byte(n)})
}

// lowercase with 0x prefix
func Num8p[T Uint8Like](n T, trim bool) string {
	var b [1]byte
	b[0] = byte(n)
	if trim {
		return EncodeToStringPrefixTrim(b[:])
	}
	return EncodeToStringPrefix(b[:])
}

// --- Zero-Allocation Append for Numbers (Uppercase) ---

// AppendUPrefix appends the uppercase hex of src to dst with a "0x" prefix.
func AppendEncodeToStringUPrefix(dst, src []byte) []byte {
    dst = append(dst, '0', 'x')
    n := len(dst)
    // Grow the slice to accommodate the new hex characters
    dst = append(dst, make([]byte, len(src)*2)...)
    EncodeU(dst[n:], src)
    return dst
}

// AppendNUm64p appends the uppercase, '0x' prefixed hex representation of a 64-bit integer.
func AppendNUm64p[T Uint64Like](dst []byte, n T, trim bool) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	dst = append(dst, '0', 'x')
	var tempBuf [16]byte
	if trim {
		written := EncodeUTrim(tempBuf[:], b[:])
		return append(dst, tempBuf[:written]...)
	}
	EncodeU(tempBuf[:], b[:])
	return append(dst, tempBuf[:]...)
}

// AppendNUm32p appends the uppercase, '0x' prefixed hex representation of a 32-bit integer.
func AppendNUm32p[T Uint32Like](dst []byte, n T, trim bool) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	dst = append(dst, '0', 'x')
	var tempBuf [8]byte
	if trim {
		written := EncodeUTrim(tempBuf[:], b[:])
		return append(dst, tempBuf[:written]...)
	}
	EncodeU(tempBuf[:], b[:])
	return append(dst, tempBuf[:]...)
}

// AppendNUm16p appends the uppercase, '0x' prefixed hex representation of a 16-bit integer.
func AppendNUm16p[T Uint16Like](dst []byte, n T, trim bool) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	dst = append(dst, '0', 'x')
	var tempBuf [4]byte
	if trim {
		written := EncodeUTrim(tempBuf[:], b[:])
		return append(dst, tempBuf[:written]...)
	}

	EncodeU(tempBuf[:], b[:])
	return append(dst, tempBuf[:]...)
}

// AppendNUm8p appends the uppercase, '0x' prefixed hex representation of an 8-bit integer.
func AppendNUm8p[T Uint8Like](dst []byte, n T, trim bool) []byte {
	var b [1]byte
	b[0] = byte(n)
	dst = append(dst, '0', 'x')
	var tempBuf [2]byte
	if trim {
		written := EncodeUTrim(tempBuf[:], b[:])
		return append(dst, tempBuf[:written]...)
	}
	EncodeU(tempBuf[:], b[:])
	return append(dst, tempBuf[:]...)
}

// encodeUintPadded writes the zero-padded, uppercase hex representation of n
// into dst. len(dst) must be sizeof(n) * 2.
//
//go:inline
func encodeUintPadded(dst []byte, n uint64, size int) {
	hexLen := size * 2
	for i := hexLen - 1; i >= 0; i -= 2 {
		val := byte(n)
		dst[i-1] = hextableUpper[val>>4]
		dst[i] = hextableUpper[val&0x0F]
		n >>= 8
	}
}

// AppendUint64PaddedU appends the hexadecimal representation of a uint64 to a byte slice,
// zero-padded to 16 characters (8 bytes). This version is optimized to process
// one byte (two hex chars) per loop iteration.
func AppendUint64PaddedU(dst []byte, n uint64) []byte {
	var b [16]byte
	encodeUintPadded(b[:], n, 8)
	return append(dst, b[:]...)
}

// AppendUint32PaddedU appends the hexadecimal representation of a uint32 to a byte slice,
// zero-padded to 8 characters (4 bytes).
func AppendUint32PaddedU(dst []byte, n uint32) []byte {
	var b [8]byte
	encodeUintPadded(b[:], uint64(n), 4)
	return append(dst, b[:]...)
}

// AppendUint16PaddedU appends the hexadecimal representation of a uint16 to a byte slice,
// zero-padded to 4 characters (2 bytes).
func AppendUint16PaddedU(dst []byte, n uint16) []byte {
	var b [4]byte
	encodeUintPadded(b[:], uint64(n), 2)
	return append(dst, b[:]...)
}

// AppendUint8PaddedU appends the hexadecimal representation of a uint8 to a byte slice,
// zero-padded to 2 characters (1 byte).
func AppendUint8PaddedU(dst []byte, n uint8) []byte {
	var b [2]byte // 1 byte * 2 hex chars/byte
	encodeUintPadded(b[:], uint64(n), 1)
	return append(dst, b[:]...)
}
