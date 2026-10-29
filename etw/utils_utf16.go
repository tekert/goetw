package etw

import (
	"unsafe"

	"github.com/tekert/goetw/internal/utf16f"
)

// FromUTF16PointerN is a variant of FromUTF16Pointer that also returns the
// length of the string in characters. This is useful for iterating over lists of
// null-terminated strings without rescanning to find the length.
func FromUTF16PointerN(p *uint16) (string, int) {
	n := Wcslen(p) // handles nil
	if n == 0 {
		return "", 0
	}
	return utf16f.DecodeWtf8(unsafe.Slice(p, n)), n
}

// FromUTF16Pointer converts a null-terminated UTF-16 pointer to a Go string.
func FromUTF16Pointer(p *uint16) string {
	str, _ := FromUTF16PointerN(p)
	return str
}

// FromUTF16Slice converts a UTF-16 slice to a Go string.
func FromUTF16Slice(s []uint16) string {
	if len(s) == 0 {
		return ""
	}
	return utf16f.DecodeWtf8(s)
}

// AppendFromUTF16Slice decodes a UTF-16 slice and appends the resulting
// UTF-8 bytes to the destination buffer, grows the destination buffer as needed.
func AppendFromUTF16Slice(dst []byte, s []uint16) []byte {
    return utf16f.AppendWtf8(dst, s)
}


// FromUTF16AtOffset converts a UTF-16 string at a given offset from a pointer.
func FromUTF16AtOffset(pstruct uintptr, offset uintptr) string {
	ptr := (*uint16)(unsafe.Pointer(pstruct + offset))
	return FromUTF16Pointer(ptr)
}

// FromUTF16Bytes transforms a byte slice of UTF16 encoded characters to a Go string.
func FromUTF16Bytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// This re-slice is safe because we calculate the correct length in uint16 chars.
	s := unsafe.Slice((*uint16)(unsafe.Pointer(unsafe.SliceData(b))), len(b)/2)
	return FromUTF16Slice(s)
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
