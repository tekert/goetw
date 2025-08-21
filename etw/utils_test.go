package etw

import (
	crand "crypto/rand"
	"fmt"
	"hash/fnv"
	"hash/maphash"
	"runtime" // <-- Import runtime
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/tekert/goetw/internal/test"
)

func TestUtils(t *testing.T) {

	tt := test.FromT(t)

	s := "this is a utf16 string"
	sutf16, err := syscall.UTF16PtrFromString(s)
	tt.CheckErr(err)

	tt.Assert(UTF16PtrToString(sutf16) == s)
	tt.Assert(Wcslen(sutf16) == len(s))

	// we have to double the length because we are in utf16
	butf16 := CopyData(unsafe.Pointer(sutf16), len(s)*2)

	tt.Assert(len(butf16) == len(s)*2)
	tt.Assert(UTF16BytesToString(butf16) == s)

	uuid, err := UUID()
	tt.CheckErr(err)
	t.Log(uuid)
}

// Helper
// Allocate SID with proper SubAuthority array size
func allocSID(t testing.TB, subAuthorityCount uint8) *SID {
	t.Helper()
	// Calculate total size needed
	sidSize := unsafe.Sizeof(SID{}) - unsafe.Sizeof([1]uint32{}) +
		uintptr(subAuthorityCount)*unsafe.Sizeof(uint32(0))

	newSID := make([]byte, sidSize)
	sid := (*SID)(unsafe.Pointer(&newSID[0])) // Get SID pointer

	sid.Revision = 1
	sid.SubAuthorityCount = subAuthorityCount

	return sid
}

func TestSIDConversion(t *testing.T) {
	tt := test.FromT(t)

	tests := []struct {
		name     string
		subAuths []uint32 // SubAuthorities to set
		auth     [6]byte  // IdentifierAuthority value
		want     string   // Expected SID string
	}{
		{
			name:     "System SID",
			subAuths: []uint32{18},
			auth:     [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want:     "S-1-5-18",
		},
		{
			name:     "Local Admin SID",
			subAuths: []uint32{32, 544},
			auth:     [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want:     "S-1-5-32-544",
		},
		{
			name: "Domain User SID",
			subAuths: []uint32{
				21,         // SECURITY_NT_NON_UNIQUE
				1068291655, // Domain ID part 1
				1087365685, // Domain ID part 2
				3231394758, // Domain ID part 3
				1001,       // User RID
			},
			auth: [6]byte{0, 0, 0, 0, 0, 5}, // NT Authority
			want: "S-1-5-21-1068291655-1087365685-3231394758-1001",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create SID with proper memory layout
			sid := allocSID(t, uint8(len(tc.subAuths)))
			tt.Assert(sid != nil, "AllocSID failed")

			sid.Revision = 1
			sid.IdentifierAuthority.Value = tc.auth

			// Set SubAuthorities
			subAuth := sid.SubAuthorities()
			copy(subAuth, tc.subAuths)

			// Test Windows API
			gotAPI, err := ConvertSidToStringSidW(sid)
			tt.CheckErr(err)

			// Test GO implementation
			gotGO, err := ConvertSidToStringSidGO(sid)
			tt.CheckErr(err)

			// Compare results
			tt.Assert(gotAPI == tc.want,
				"API result mismatch: got "+gotAPI+", want "+tc.want)
			tt.Assert(gotGO == tc.want,
				"GO result mismatch: got "+gotGO+", want "+tc.want)
			tt.Assert(gotAPI == gotGO,
				"Results differ: API="+gotAPI+", GO="+gotGO)
		})
	}
}

// write a benchmark comparing the SID conversion functions
func BenchmarkSIDConversion(b *testing.B) {
	// Test data for SID conversion
	sid := allocSID(b, 3)
	sid.Revision = 1
	sid.IdentifierAuthority.Value = [6]byte{0, 0, 0, 0, 0, 5} // NT Authority
	subAuth := sid.SubAuthorities()
	subAuth[0] = 21         // SECURITY_NT_NON_UNIQUE
	subAuth[1] = 1068291655 // Domain ID part 1
	subAuth[2] = 1087365685 // Domain ID part 2

	b.Run("ConvertSidToStringSidW", func(b *testing.B) {
		for b.Loop() {
			_, err := ConvertSidToStringSidW(sid)
			if err != nil {
				b.Fatalf("ConvertSidToStringSidW failed: %v", err)
			}
		}
	})

	b.Run("ConvertSidToStringSidGO", func(b *testing.B) {
		for b.Loop() {
			_, err := ConvertSidToStringSidGO(sid)
			if err != nil {
				b.Fatalf("ConvertSidToStringSidGO failed: %v", err)
			}
		}
	})
}

func BenchmarkUTF16Conversion(b *testing.B) {
	// Test strings of various lengths, including some realistic examples
	testStrings := []string{
		"short",
		"a medium length string for testing",
		"a much longer string to test performance characteristics with more data and see how the functions handle larger inputs",
		"Kernel/Trace/Provider",
		`C:\Windows\System32\ntdll.dll`,
	}

	// Prepare test data outside the benchmark loops
	var testData []*uint16
	for _, s := range testStrings {
		p, err := syscall.UTF16PtrFromString(s)
		if err != nil {
			b.Fatalf("Failed to create test string: %v", err)
		}
		testData = append(testData, p)
	}

	// Benchmark UTF16PtrToString
	for i, p := range testData {
		b.Run("UTF16PtrToString/len_"+strconv.Itoa(len(testStrings[i])), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = UTF16PtrToString(p)
			}
		})
	}

	// Benchmark UTF16AtOffsetToString
	// We'll create a buffer and place the string at an offset to simulate reading from a struct
	const offset = 128 // An arbitrary offset
	for i, p := range testData {
		strLenChars := len(testStrings[i])
		// Create a buffer large enough for the offset and the null-terminated string
		buf := make([]uint16, (offset/2)+strLenChars+1)
		structPtr := uintptr(unsafe.Pointer(&buf[0]))
		targetPtr := (*uint16)(unsafe.Pointer(structPtr + offset))

		// Copy the test string into the buffer at the specified offset
		copy(unsafe.Slice(targetPtr, strLenChars+1), unsafe.Slice(p, strLenChars+1))

		b.Run("UTF16AtOffsetToString/len_"+strconv.Itoa(strLenChars), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = UTF16AtOffsetToString(structPtr, offset)
			}
			// This is critical: it ensures the buf and its underlying memory
			// are not garbage collected before the benchmark loop finishes.
			runtime.KeepAlive(buf)
		})

	}
}

// BenchmarkHash compares the performance of different non-cryptographic hashing
// algorithms on strings of various lengths.
func BenchmarkHash(b *testing.B) {
	// A single seed for maphash is created once for all benchmarks.
	var hashSeed = maphash.MakeSeed()

	// Test strings of various lengths, typical for error messages.
	sizes := []int{16, 32, 64, 128, 256, 512}
	testStrings := make(map[int]string)

	for _, size := range sizes {
		data := make([]byte, size)
		if _, err := crand.Read(data); err != nil {
			b.Fatalf("failed to generate random test data: %v", err)
		}
		testStrings[size] = string(data)
	}

	for _, size := range sizes {
		data := testStrings[size]
		dataBytes := []byte(data)

		b.Run(fmt.Sprintf("FNV-1a_FullString/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(dataBytes)))
			b.ResetTimer()
			for b.Loop() {
				h := fnv.New64a()
				h.Write(dataBytes)
				_ = h.Sum64()
			}
		})

		// FNV-1a inline
		b.Run("FNV-1a_FullString_inline/"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(dataBytes)))
			b.ResetTimer()
			for b.Loop() {
				h := uint64(14695981039346656037)
				for _, v := range data {
					h ^= uint64(v)
					h *= 1099511628211
				}
			}
		})

		// djb2
		b.Run("djb2/"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(dataBytes)))
			b.ResetTimer()
			for b.Loop() {
				var h uint64 = 5381
				for _, v := range data {
					h = ((h << 5) + h) + uint64(v)
				}
			}
		})

		b.Run(fmt.Sprintf("MapHash_FullString/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(dataBytes)))
			b.ResetTimer()
			// maphash.Hash is a struct designed to be used by value to avoid allocations.
			var h maphash.Hash
			h.SetSeed(hashSeed)
			for b.Loop() {
				h.Reset() // Reset is very cheap.
				h.WriteString(data)
				_ = h.Sum64()
			}
		})

		b.Run(fmt.Sprintf("DJB2_FullString/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(dataBytes)))
			b.ResetTimer()
			for b.Loop() {
				var hash uint64 = 5381
				for _, c := range data {
					hash = ((hash << 5) + hash) + uint64(c) // hash * 33 + c
				}
				_ = hash
			}
		})
	}
}

// TestUTF16PtrToStringConcurrent tests the UTF16PtrToString function
// in a concurrent environment to ensure it handles multiple goroutines
// accessing the cache without issues.
func TestUTF16PtrToStringConcurrent(t *testing.T) {
	// Reset the global cache for a clean test run.
	globalUtf16Cache = newClockCache(128)

	var wg sync.WaitGroup
	// Tested a bug with this, min 100/10000 for consistent detection
	numGoroutines := 100 // use min of 100
	iterations := 10000  // use at least 10000 to get consisnt results

	// Prepare test data
	testStrings := make([]string, numGoroutines)
	testPtrs := make([]*uint16, numGoroutines)
	for i := range numGoroutines {
		testStrings[i] = fmt.Sprintf("concurrent-string-%d", i)
		ptr, err := syscall.UTF16PtrFromString(testStrings[i])
		if err != nil {
			t.Fatalf("Failed to create test string: %v", err)
		}
		testPtrs[i] = ptr
	}

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range iterations {
				// Access different strings to stress the cache's read/write paths
				index := (id + j) % numGoroutines
				s := testStrings[index]
				p := testPtrs[index]

				res := UTF16PtrToString(p)
				if res != s {
					t.Errorf("goroutine %d: expected '%s', got '%s'", id, s, res)
				}
			}
		}(i)
	}

	wg.Wait()
}
