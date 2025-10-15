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

const FiletimeEpoch = 116444736000000000

// Faster than syscall.Filetime.Nanoseconds() on edge cases.
// UTCTimeStamp converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unixtime.Time
//
//go:inline
func FromFiletime(fileTime int64) time.Time {
	return time.Unix(0, (fileTime-FiletimeEpoch)*100)
}

// FromFiletimeNanos converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix time in nanoseconds since epoch
//
//go:inline
func FromFiletimeNanos(fileTime int64) int64 {
	return (fileTime - FiletimeEpoch) * 100
}

// FromFiletimeUTC converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix UTC time.Time
//
//go:inline
func FromFiletimeUTC(fileTime int64) time.Time {
	return time.Unix(0, (fileTime-FiletimeEpoch)*100).UTC()
}

// FromSyscallFiletime converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix time.Time
//
//go:inline
func FromSyscallFiletime(ft *syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}

// FromSyscallFiletimeUCT converts a Windows FILETIME (100-nanosecond intervals since 1601)
// to a Unix UTC time.Time
//
//go:inline
func FromSyscallFiletimeUCT(ft *syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

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

func (sid *SID) AppendText(buf []byte) ([]byte, error) {
	if sid == nil {
		return buf, nil
	}

	// Validate SID structure // SID_MAX_SUB_AUTHORITIES = 15
	if sid.Revision != 1 || sid.SubAuthorityCount > 15 {
		return buf, fmt.Errorf("the SID is not valid")
	}

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

	return buf, nil
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
	var err error
		// A typical SID string is around 40-70 chars. Pre-allocating a buffer of
	// 64 bytes is a good starting point to avoid reallocations.
	buf := make([]byte, 0, 64)
	buf, err = sid.AppendText(buf)

	return string(buf), err
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
