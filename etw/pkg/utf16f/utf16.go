package utf16f

import (
	"runtime"
	"unsafe"
)

const rune1Max = 1<<7 - 1
const rune2Max = 1<<11 - 1

//go:nosplit
//go:nocheckptr
func DecodeWtf8(src []uint16) string {
	// Pre-calculate max size
	maxLen := 0
	for i, v := range src {
		if v == 0 {
			src = src[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}

	if len(src) == 0 {
		return ""
	}

	// Single allocation for buffer
	buf := make([]byte, maxLen)

	// Get raw pointers
	srcPtr := unsafe.SliceData(src)
	dstPtr := unsafe.SliceData(buf)
	written := utf16_convert_nobounds(dstPtr, srcPtr, len(src))

	// Zero-allocation string conversion
	return unsafe.String(dstPtr, written)
}

//go:nosplit
//go:nocheckptr
func DecodeWtf8_SliceVer(src []uint16) string {
	// Pre-calculate max size
	maxLen := 0
	for i, v := range src {
		if v == 0 {
			src = src[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}

	if len(src) == 0 {
		return ""
	}

	// Pre-allocate max possible size
	buf := make([]byte, maxLen)
	written := utf16_convert_slice(buf, src)
	return unsafe.String(unsafe.SliceData(buf), written)
}

//go:inline
func isASCII(w uint64) bool {
	return (w & 0xFF80FF80FF80FF80) == 0
}

// 5-20% faster depending on string size (larger ones run faster), omits bound checking.
//
// utf16_convert_nobounds converts UTF-16 encoded text to UTF-8 using direct pointer access.
// It processes text in 8-character blocks for ASCII and handles UTF-16 surrogate pairs.
//
// Parameters:
//   - dst: Pointer to pre-allocated destination buffer for UTF-8 output
//   - src: Pointer to source UTF-16 encoded text
//   - srcLen: Number of UTF-16 code units in source
//
// Returns:
//   - int: Number of bytes written to dst
//
// Safety requirements:
//   - dst must have enough space (caller must ensure this)
//   - src must be valid for srcLen*2 bytes
//   - Memory must be properly aligned
//
// Notes:
//   - No bounds checking for maximum performance
//   - Uses 8-byte word alignment for fast ASCII processing
//   - Handles UTF-16 surrogate pairs correctly
//   - Supports WTF-8 encoding for unpaired surrogates
//   - Uses //go:nosplit and //go:nocheckptr for performance
//
//go:nosplit
//go:nocheckptr
func utf16_convert_nobounds(dst *byte, src *uint16, srcLen int) int {
	var i, j int

	// Fast path: process 8 UTF-16 codes at once
	for i+8 <= srcLen {
		chunks := *(*[2]uint64)(unsafe.Add(unsafe.Pointer(src), uintptr(i)*2))
		if isASCII(chunks[0]) && isASCII(chunks[1]) {
			// Check for surrogate at block boundary
			lastWord := *(*uint16)(unsafe.Add(unsafe.Pointer(src), uintptr(i+7)*2))
			if lastWord >= 0xD800 && lastWord <= 0xDFFF {
				break
			}

			// Process ASCII block - simple copy
			for k := 0; k < 8; k++ {
				*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+k))) =
					byte(*(*uint16)(unsafe.Add(unsafe.Pointer(src), uintptr(i+k)*2)))
			}
			i += 8
			j += 8
			continue
		}
		break
	}

	// Process remaining chars
	for i < srcLen {
		word := *(*uint16)(unsafe.Add(unsafe.Pointer(src), uintptr(i)*2))

		switch {
		case word < 0x80:
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j))) = byte(word)
			j++
			i++

		case word < 0x800:
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j))) = byte((word >> 6) | 0xC0)
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+1))) = byte((word & 0x3F) | 0x80)
			j += 2
			i++

		case word >= 0xD800 && word <= 0xDFFF:
			if word <= 0xDBFF && i+1 < srcLen {
				nextWord := *(*uint16)(unsafe.Add(unsafe.Pointer(src), uintptr(i+1)*2))
				if nextWord >= 0xDC00 && nextWord <= 0xDFFF {
					r := (uint32(word-0xD800)<<10 | uint32(nextWord-0xDC00)) + 0x10000
					*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j))) = byte((r >> 18) | 0xF0)
					*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+1))) = byte(((r >> 12) & 0x3F) | 0x80)
					*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+2))) = byte(((r >> 6) & 0x3F) | 0x80)
					*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+3))) = byte((r & 0x3F) | 0x80)
					j += 4
					i += 2
					continue
				}
			}
			// Math explanation for surrogate encoding:
			// Using 0xD800 base works for both high/low surrogates:
			// High (0xD800): (0xD800-0xD800)>>6 = 0 -> 0xA0|0 = 0xA0
			// Low (0xDC00):  (0xDC00-0xD800)>>6 = 0x10 -> 0xA0|0x10 = 0xB0
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j))) = 0xED
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+1))) = 0xA0 | byte((word-0xD800)>>6)
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+2))) = 0x80 | byte(word&0x3F)
			j += 3
			i++

		default:
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j))) = byte((word >> 12) | 0xE0)
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+1))) = byte(((word >> 6) & 0x3F) | 0x80)
			*(*byte)(unsafe.Add(unsafe.Pointer(dst), uintptr(j+2))) = byte((word & 0x3F) | 0x80)
			j += 3
			i++
		}
	}

	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	return j
}

// 10-20% slower because of bound-cheking, use any go run or test with
//	-gcflags="-d=ssa/check_bce/debug=1" to check wich lines are bound checked.
//
// utf16_convert_slice converts UTF-16 encoded text to UTF-8.
// It processes text in 8-character blocks for ASCII and handles UTF-16 surrogate pairs.
//
// Parameters:
//   - dst: Destination byte slice for UTF-8 output (must be pre-allocated)
//   - src: Source UTF-16 encoded slice
//
// Returns:
//   - int: Number of bytes written to dst
//
// Notes:
//   - Uses 8-byte word alignment for fast ASCII processing
//   - Assumes dst has enough space (caller must ensure this)
//   - Uses //go:nosplit and //go:nocheckptr for performance
//
//go:nosplit
//go:nocheckptr
func utf16_convert_slice(dst []byte, src []uint16) int {
	var i, j int
	srcLen := len(src)

	// Fast path: process 8 UTF-16 codes at once
	// Checks if 8 consecutive characters are ASCII using 64-bit word
	for i+8 <= srcLen {
		chunks := *(*[2]uint64)(unsafe.Pointer(&src[i]))
		if isASCII(chunks[0]) && isASCII(chunks[1]) {
			// Check if last character in block is a surrogate
			// If true, exit fast path to handle properly
			lastWord := src[i+7]
			if lastWord >= 0xD800 && lastWord <= 0xDFFF {
				break
			}

			// Fast copy ASCII block (8 bytes at once)
			for k := 0; k < 8; k++ {
				dst[j+k] = byte(src[i+k])
			}
			i += 8
			j += 8
			continue
		}
		break
	}

	// Process remaining characters one by one
	// Handles: ASCII, 2-byte UTF-8, surrogate pairs, and 3-byte UTF-8
	for i < srcLen {
		word := src[i]

		switch {
		case word < 0x80:
			// ASCII character (0xxxxxxx)
			dst[j] = byte(word)
			j++
			i++
		case word < 0x800:
			// 2-byte UTF-8 (110xxxxx 10xxxxxx)
			dst[j] = byte((word >> 6) | 0xC0)
			dst[j+1] = byte((word & 0x3F) | 0x80)
			j += 2
			i++
		case word >= 0xD800 && word <= 0xDFFF:
			// UTF-16 surrogate pair handling
			if word <= 0xDBFF && i+1 < srcLen {
				// Check for valid low surrogate
				nextWord := src[i+1]
				if nextWord >= 0xDC00 && nextWord <= 0xDFFF {
					// Convert surrogate pair to Unicode codepoint
					r := (uint32(word-0xD800)<<10 | uint32(nextWord-0xDC00)) + 0x10000
					// Write 4-byte UTF-8 sequence
					dst[j] = byte((r >> 18) | 0xF0)
					dst[j+1] = byte(((r >> 12) & 0x3F) | 0x80)
					dst[j+2] = byte(((r >> 6) & 0x3F) | 0x80)
					dst[j+3] = byte((r & 0x3F) | 0x80)
					j += 4
					i += 2
					continue
				}
			}
			// Math explanation for surrogate encoding:
			// For high surrogates (0xD800-0xDBFF):
			//   word = 0xD800, base = 0xD800
			//   (word-base)>>6 = 0 -> 0xA0|0 = 0xA0 (correct high prefix)
			//
			// For low surrogates (0xDC00-0xDFFF):
			//   word = 0xDC00, base = 0xD800
			//   (0xDC00-0xD800)>>6 = 0x400>>6 = 0x10
			//   0xA0|0x10 = 0xB0 (correct low prefix)
			//
			// Therefore using 0xD800 as base works for both cases
			// Invalid/unpaired surrogate - encode as WTF-8
			dst[j] = 0xED
			dst[j+1] = 0xA0 | byte((word-0xD800)>>6)
			dst[j+2] = 0x80 | byte(word&0x3F)
			j += 3
			i++
		default:
			// 3-byte UTF-8 sequence (1110xxxx 10xxxxxx 10xxxxxx)
			dst[j] = byte((word >> 12) | 0xE0)
			dst[j+1] = byte(((word >> 6) & 0x3F) | 0x80)
			dst[j+2] = byte((word & 0x3F) | 0x80)
			j += 3
			i++
		}
	}

	return j
}
