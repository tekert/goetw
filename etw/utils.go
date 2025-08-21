//go:build windows

package etw

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// noCopy may be added to structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
//
// Note that it must not be embedded, due to the Lock and Unlock methods.
//
//lint:ignore U1000 explanation
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Windows FILETIME constants
const (
	WINDOWS_TICK     = 100         // 100-nanosecond intervals
	EPOCH_DIFF       = 11644473600 // seconds between Windows epoch (1601) and Unix epoch (1970)
	TICKS_PER_SECOND = 10000000    // 1 second = 10,000,000 ticks
)


// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unixtime.Time, This is wrapper for UnixTimeStampU who uses the correct unsigned form.
// Microsoft documentation uses signed int for FILETIME but it can never be negative...
//
//go:inline
func UnixFiletime(fileTime int64) time.Time {
	return UnixTimeStampU(uint64(fileTime))
}

// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unixtime.Time, This is wrapper for UnixTimeStampU who uses the correct unsigned form.
// Microsoft documentation uses signed int for FILETIME but it can never be negative...
//
//go:inline
func UnixTimeStamp(fileTime int64) time.Time {
	return UnixTimeStampU(uint64(fileTime))
}

// Faster than syscall.Filetime.Nanoseconds() on edge cases.
// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unixtime.Time
func UnixTimeStampU(fileTime uint64) time.Time {
	// Convert to Unix epoch
	unixTime := fileTime - (EPOCH_DIFF * TICKS_PER_SECOND)

	// Calculate seconds and remaining ticks
	seconds := unixTime / TICKS_PER_SECOND
	remaining := unixTime % TICKS_PER_SECOND

	// Convert remaining ticks to nanoseconds (multiply by 100)
	nanos := remaining * WINDOWS_TICK

	return time.Unix(int64(seconds), int64(nanos))
}

// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix UTC time.Time
func UTCTimeStamp(ft *syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

func max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

// // UTF16PtrToString transforms a *uint16 to a Go string
// DEPRECATED the one ported from go syscall package is 48% faster than this
// wich uses UTF16AtOffsetToString_slow
// func UTF16PtrToString(utf16 *uint16) string {
// 	return UTF16AtOffsetToString_slow(uintptr(unsafe.Pointer(utf16)), 0)
// }

// too many allocations - DEPRECATED
// func UTF16AtOffsetToString_slow(pstruct uintptr, offset uintptr) string {
// 	out := make([]uint16, 0, 64)
// 	wc := (*uint16)(unsafe.Pointer(pstruct + offset))
// 	for i := uintptr(2); *wc != 0; i += 2 {
// 		out = append(out, *wc)
// 		wc = (*uint16)(unsafe.Pointer(pstruct + offset + i))
// 	}
// 	return syscall.UTF16ToString(out)
// }

func CopyData(pointer unsafe.Pointer, size int) []byte {
	if size <= 0 {
		return nil
	}
	// Create a slice from the pointer without copying memory
	src := unsafe.Slice((*byte)(pointer), size)
	dst := make([]byte, size)
	copy(dst, src)
	return dst
}

// inneficient - delete 3x slower than CopyData and a bit unsafe with uintptr.
// func CopyData_old(pointer uintptr, size int) []byte {
// 	out := make([]byte, 0, size)
// 	for it := pointer; it != pointer+uintptr(size); it++ {
// 		b := (*byte)(unsafe.Pointer(it))
// 		out = append(out, *b)
// 	}
// 	return out
// }

// UUID is a simple UUIDgenerator
func UUID() (uuid string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	uuid = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return
}

// ConvertSidToStringSidGO converts a SID structure to its string representation.
// This version is optimized to reduce memory allocations by using a byte buffer
// and strconv.AppendUint.
// No cgo/syscalls needed
// replaces ConvertSidToStringSidW from Windows API
func ConvertSidToStringSidGO(sid *SID) (string, error) {
	if sid == nil {
		return "", nil
	}

	// Validate SID structure // SID_MAX_SUB_AUTHORITIES = 15
	if sid.Revision != 1 || sid.SubAuthorityCount > 15 {
		return "", fmt.Errorf("the SID is not valid")
	}

	// A typical SID string is around 40-70 chars. Pre-allocating a buffer of
	// 64 bytes is a good starting point to avoid reallocations.
	buf := make([]byte, 0, 64)

	buf = append(buf, 'S', '-')
	buf = strconv.AppendUint(buf, uint64(sid.Revision), 10)

	// Format IdentifierAuthority. It's a 6-byte big-endian value.
	var authority uint64
	// Using range on a fixed-size array is safe and clean.
	for i := range sid.IdentifierAuthority.Value {
		authority = (authority << 8) | uint64(sid.IdentifierAuthority.Value[i])
	}
	buf = append(buf, '-')
	buf = strconv.AppendUint(buf, authority, 10)

	// Format SubAuthorities
	subAuthorities := sid.SubAuthorities()
	for _, subAuth := range subAuthorities {
		buf = append(buf, '-')
		buf = strconv.AppendUint(buf, uint64(subAuth), 10)
	}

	return string(buf), nil
}

func isETLFile(path string) bool {
	// Convert to clean Windows path
	clean := filepath.Clean(path)
	if !strings.EqualFold(filepath.Ext(clean), ".etl") {
		return false
	}
	// Check if absolute path or UNC
	return filepath.IsAbs(clean) || strings.HasPrefix(clean, "\\\\")
}

func getGoroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	id := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	val, _ := strconv.ParseInt(id, 10, 64)
	return val
}

func stackUsage() {
	buf := make([]byte, 64)
	for {
		n := runtime.Stack(buf, false)
		// If trace fits in buffer
		if n < len(buf) {
			fmt.Printf("stack: %d bytes", n)
			return
		}
		buf = make([]byte, 2*len(buf))
	}
}
