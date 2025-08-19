//go:build windows

package etw

import (
	"unsafe"

	"github.com/tekert/goetw/internal/utf16f"
)

const maxUtf16CachedLength = 256 // Maximum string length to cache (prevents cache pollution from large strings)

// utf16Convert performs a cache lookup for a given string slice and its hash.
// On a cache miss, it calls the final utf16 conversion function and stores the result in the cache.
//
//go:inline
func utf16Convert(s []uint16, h uint64, n int) string {
	// For long strings, convert directly without caching to avoid polluting the cache.
	if n >= maxUtf16CachedLength {
		return utf16f.DecodeWtf8(s)
	}
	// If the hash wasn't pre-computed (e.g., from a slice), calculate it now.
	if h == 0 {
		h = fnvHash(s)
	}

	// The converter function is only executed on a cache miss.
	return globalUtf16Cache.lookupOrConvert(h, func() string {
		return utf16f.DecodeWtf8(s)
	})
}

// fnvHash calculates the FNV-1a hash for a UTF-16 slice.
//
//go:inline
func fnvHash(data []uint16) uint64 {
	h := uint64(fnvOffset64)
	for _, v := range data {
		h ^= uint64(v)
		h *= fnvPrime64
	}
	return h
}

// UTF16PtrToString is the most performant way to convert a null-terminated
// UTF-16 pointer to a Go string. It finds the string length and calculates
// its hash in a single pass to optimize cache lookups.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	// Calculate string length and FNV-1a hash in a single loop for optimal performance.
	// This specialized loop is the key to this function's efficiency.
	h := uint64(fnvOffset64) // FNV-1a offset basis
	end := unsafe.Pointer(p)
	n := 0
	for {
		char := *(*uint16)(end)
		if char == 0 {
			break // Null terminator found
		}
		h ^= uint64(char) // XOR with character value
		h *= fnvPrime64   // Multiply by FNV prime

		end = unsafe.Pointer(uintptr(end) + 2) // 2 bytes per uint16
		n++
	}

	if n == 0 {
		return ""
	}
	s := unsafe.Slice(p, n)

	return utf16Convert(s, h, n)
}

// UTF16SliceToString converts a UTF-16 slice to a string, using a cache for performance.
// For best performance, use UTF16PtrToString2 when you have a pointer.
func UTF16SliceToString(s []uint16) string {
	if len(s) == 0 {
		return ""
	}
	// Pass h=0 to signal that the hash needs to be computed inside the helper function.
	return utf16Convert(s, 0, len(s))
}

// UTF16AtOffsetToString converts a UTF-16 string at a given offset from a pointer.
func UTF16AtOffsetToString(pstruct uintptr, offset uintptr) string {
	ptr := (*uint16)(unsafe.Pointer(pstruct + offset))
	return UTF16PtrToString(ptr)
}

// UTF16BytesToString transforms a byte slice of UTF16 encoded characters to a Go string.
func UTF16BytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// This re-slice is safe because we calculate the correct length in uint16 chars.
	s := unsafe.Slice((*uint16)(unsafe.Pointer(unsafe.SliceData(b))), len(b)/2)
	return UTF16SliceToString(s)
}

// Wcslen finds the length of a null-terminated UTF-16 string in characters.
func Wcslen(p *uint16) (length int) {
	if p == nil {
		return 0
	}
	end := unsafe.Pointer(p)
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + 2) // 2 bytes per uint16
		length++
	}
	return
}

// CopyUTF16Ptr Copies a null terminated UTF16 string from a pointer to a
// new allocated memory
func CopyUTF16Ptr(src *uint16) *uint16 {
	if src == nil {
		return nil
	}
	length := Wcslen(src)
	if length == 0 {
		// Return a pointer to a null terminator, consistent with some Windows API behavior.
		return &[]uint16{0}[0]
	}
	dst := make([]uint16, length+1) // +1 for null terminator
	copy(dst, unsafe.Slice(src, length+1))
	return &dst[0]
}
