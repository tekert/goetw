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

// EncodeToString returns the hexadecimal lowercase encoding of src.
// with prefix 0x as prefix.
// Way more efficient than 2 allocations of the hex package.
func EncodeToStringPrefix(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	Encode(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// EncodeToString returns the hexadecimal UPPERCASE encoding of src.
// with prefix 0x as prefix.
// Way more efficient than 2 allocations of the hex package.
func EncodeToStringUPrefix(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	EncodeU(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// Ported from the hex package to print lowercase hex just for convenience.
//
// EncodeToString returns the hexadecimal encoding of src.
func EncodeToString(src []byte) string {
	dst := make([]byte, len(src)*2)
	Encode(dst, src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// Ported from the hex package to print UPPERCASE hex just for convenience.
//
// EncodeToString returns the hexadecimal encoding of src.
func EncodeToStringU(src []byte) string {
	dst := make([]byte, len(src)*2) // 1 byte = 2 hex chars
	EncodeU(dst, src)
	return unsafe.String(unsafe.SliceData(dst), len(dst))
}

// Checking len() is costly, so no optional parameters with ... slice

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
		i++
	} else {
		// Two nibbles
		dst[j] = hexTable[v>>4]
		dst[j+1] = hexTable[v&0x0f]
		j += 2
		i++
	}

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

// EncodeToString returns the hexadecimal lowercase encoding of src.
// with leading 0 trimmed and 0x as prefix.
func EncodeToStringPrefixTrim(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	n := EncodeTrim(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), n+2) // Use trimmed length + prefix
}

// EncodeToString returns the hexadecimal uppercase encoding of src.
// with leading 0 trimmed and 0x as prefix.
func EncodeToStringUPrefixTrim(src []byte) string {
	dst := make([]byte, 2+len(src)*2) // 1 byte = 2 hex chars
	dst[0] = '0'
	dst[1] = 'x'
	n := EncodeUTrim(dst[2:], src)
	return unsafe.String(unsafe.SliceData(dst), n+2) // Use trimmed  length + prefix
}

//
// Append to buffer
//

// AppendUint64 appends the hexadecimal representation of a uint64 to a byte slice,
// zero-padded to 16 characters (8 bytes). This version is optimized to process
// one byte (two hex chars) per loop iteration.
func AppendUint64(dst []byte, n uint64) []byte {
	var b [16]byte
	for i := 15; i >= 1; i -= 2 {
		val := byte(n)
		b[i-1] = hextableUpper[val>>4]
		b[i] = hextableUpper[val&0x0F]
		n >>= 8
	}
	return append(dst, b[:]...)
}

// AppendUint32 appends the hexadecimal representation of a uint32 to a byte slice,
// zero-padded to 8 characters (4 bytes).
func AppendUint32(dst []byte, n uint32) []byte {
	var b [8]byte
	for i := 7; i >= 1; i -= 2 {
		val := byte(n)
		b[i-1] = hextableUpper[val>>4]
		b[i] = hextableUpper[val&0x0F]
		n >>= 8
	}
	return append(dst, b[:]...)
}

// AppendUint16 appends the hexadecimal representation of a uint16 to a byte slice,
// zero-padded to 4 characters (2 bytes).
func AppendUint16(dst []byte, n uint16) []byte {
	var b [4]byte
	val := byte(n >> 8)
	b[0] = hextableUpper[val>>4]
	b[1] = hextableUpper[val&0x0F]
	val = byte(n)
	b[2] = hextableUpper[val>>4]
	b[3] = hextableUpper[val&0x0F]
	return append(dst, b[:]...)
}

// AppendUint8 appends the hexadecimal representation of a uint8 to a byte slice,
// zero-padded to 2 characters (1 byte).
func AppendUint8(dst []byte, n uint8) []byte {
	var b [2]byte // 1 byte * 2 hex chars/byte
	b[0] = hextableUpper[n>>4]
	b[1] = hextableUpper[n&0xF]
	return append(dst, b[:]...)
}

//
// Numbers
//

// Number represents any integer type
type Number interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// Separate interfaces by size for better performance
type Uint64Like interface {
	~uint64 | ~int64
}

type Uint32Like interface {
	~uint32 | ~int32
}

type Uint16Like interface {
	~uint16 | ~int16
}

type Uint8Like interface {
	~uint8 | ~int8
}

// uppercase
func NUm64[T Uint64Like](n T) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return EncodeToStringU(b[:])
}

// uppercase with 0x prefix
func NUm64p[T Uint64Like](n T, trim bool) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// uppercase
func NUm32[T Uint32Like](n T) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return EncodeToStringU(b[:])
}

// uppercase with 0x prefix
func NUm32p[T Uint32Like](n T, trim bool) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// uppercase
func NUm16[T Uint16Like](n T) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return EncodeToStringU(b[:])
}

// uppercase with 0x prefix
func NUm16p[T Uint16Like](n T, trim bool) string {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	if trim {
		return EncodeToStringUPrefixTrim(b[:])
	}
	return EncodeToStringUPrefix(b[:])
}

// uppercase
func NUm8[T Uint8Like](n T) string {
	return EncodeToStringU([]byte{byte(n)})
}

// uppercase with 0x prefix
func NUm8p[T Uint8Like](n T, trim bool) string {
	if trim {
		return EncodeToStringUPrefixTrim([]byte{uint8(n)})
	}
	return EncodeToStringUPrefix([]byte{uint8(n)})
}

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
	if trim {
		return EncodeToStringPrefixTrim([]byte{uint8(n)})
	}
	return EncodeToStringPrefix([]byte{uint8(n)})
}
