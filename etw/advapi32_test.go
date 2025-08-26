//go:build windows

package etw

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/tekert/goetw/internal/test"
)

func TestAccessString(t *testing.T) {

	tt := test.FromT(t)

	//systemSID := "S-1-5-18"

	for _, p := range EnumerateProviders() {

		_, err := GetAccessString(&p.GUID)

		tt.CheckErr(err)

		/*err = AddProviderAccess(p.GUID, systemSID, 0x120fff)
		// we might have some access denied sometimes
		if err == ERROR_ACCESS_DENIED {
			continue
		}

		tt.CheckErr(err)*/

	}
}

// TestEventRecordLayout verifies that the memory layout of the Go EventRecord struct
// matches the C layout of EVENT_RECORD, which is critical for C interop.
func TestEventRecordLayout(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Skipping layout test on non-64-bit architecture")
	}

	// Expected offsets and size for EVENT_RECORD on a 64-bit system.
	// EVENT_HEADER        (size 80) -> offset 0
	// ETW_BUFFER_CONTEXT  (size 4)  -> offset 80
	// ExtendedDataCount   (size 2)  -> offset 84
	// UserDataLength      (size 2)  -> offset 86
	// ExtendedData        (ptr 8)   -> offset 88
	// UserData            (ptr 8)   -> offset 96
	// UserContext         (ptr 8)   -> offset 104
	// Total size = 112 bytes
	expectedSize := uintptr(112)
	expectedOffsets := map[string]uintptr{
		"EventHeader":       0,
		"BufferContext":     80,
		"ExtendedDataCount": 84,
		"UserDataLength":    86,
		"ExtendedData":      88,
		"UserData":          96,
		"UserContext":       104,
	}

	var record EventRecord

	// 1. Check the total size of the struct.
	actualSize := unsafe.Sizeof(record)
	if actualSize != expectedSize {
		t.Errorf("EventRecord size mismatch: got %d, want %d", actualSize, expectedSize)
	}

	// 2. Check the offset of each field within the struct.
	t.Run("FieldOffsets", func(t *testing.T) {
		check := func(name string, actual, expected uintptr) {
			if actual != expected {
				t.Errorf("Offset of %s mismatch: got %d, want %d", name, actual, expected)
			}
		}
		check("EventHeader", unsafe.Offsetof(record.EventHeader), expectedOffsets["EventHeader"])
		check("BufferContext", unsafe.Offsetof(record.BufferContext), expectedOffsets["BufferContext"])
		check("ExtendedDataCount", unsafe.Offsetof(record.ExtendedDataCount), expectedOffsets["ExtendedDataCount"])
		check("UserDataLength", unsafe.Offsetof(record.UserDataLength), expectedOffsets["UserDataLength"])
		check("ExtendedData", unsafe.Offsetof(record.ExtendedData), expectedOffsets["ExtendedData"])
		check("UserData", unsafe.Offsetof(record.UserData), expectedOffsets["UserData"])
		check("UserContext", unsafe.Offsetof(record.UserContext), expectedOffsets["UserContext"])
	})
}
