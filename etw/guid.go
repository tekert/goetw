//go:build windows

package etw

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/tekert/goetw/internal/hexf"
)

const (
	nullGUIDStr = "{00000000-0000-0000-0000-000000000000}"
)

var (
	nullGUID = GUID{}
)

// GUID represents a Windows GUID (Globally Unique Identifier) structure.
// GUIDs are 128-bit values used throughout Windows APIs to uniquely identify
// objects, interfaces, and other entities.
//
// The structure matches the Windows GUID layout:
// - Data1: 32-bit value
// - Data2: 16-bit value
// - Data3: 16-bit value
// - Data4: 8-byte array
//
// String format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// Example: {9E814AAD-3204-11D2-9A82-006008A86939}
//
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
type GUID struct {
	Data1 uint32    // First 32 bits of the GUID
	Data2 uint16    // Next 16 bits of the GUID
	Data3 uint16    // Next 16 bits of the GUID
	Data4 [8]byte   // Final 64 bits of the GUID as 8 bytes
}

// IsZero checks if GUID is all zeros
func (g *GUID) IsZero() bool {
	return g.Equals(&nullGUID)
}

// StringU returns the uppercase string representation of the GUID in standard format.
// The format is: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
//
// This implementation is ~10x faster than using fmt.Sprintf by avoiding
// allocations and using optimized hex encoding.
func (g *GUID) StringU() string {
	var b [38]byte
	b[0] = '{'
	b[37] = '}'

	// Avoid slice allocations
	var d1 [4]byte
	d1[0] = byte(g.Data1 >> 24)
	d1[1] = byte(g.Data1 >> 16)
	d1[2] = byte(g.Data1 >> 8)
	d1[3] = byte(g.Data1)

	var d2 [2]byte
	d2[0] = byte(g.Data2 >> 8)
	d2[1] = byte(g.Data2)

	var d3 [2]byte
	d3[0] = byte(g.Data3 >> 8)
	d3[1] = byte(g.Data3)

	hexf.EncodeU(b[1:9], d1[:])
	b[9] = '-'
	hexf.EncodeU(b[10:14], d2[:])
	b[14] = '-'
	hexf.EncodeU(b[15:19], d3[:])
	b[19] = '-'
	hexf.EncodeU(b[20:24], g.Data4[:2])
	b[24] = '-'
	hexf.EncodeU(b[25:37], g.Data4[2:])

	return unsafe.String(unsafe.SliceData(b[:]), len(b))
}

// String returns the lowercase string representation of the GUID in standard format.
// The format is: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
//
// This implementation is ~10x faster than using fmt.Sprintf by avoiding
// allocations and using optimized hex encoding.
func (g *GUID) String() string {
	var b [38]byte
	b[0] = '{'
	b[37] = '}'

	// Avoid slice allocations
	var d1 [4]byte
	d1[0] = byte(g.Data1 >> 24)
	d1[1] = byte(g.Data1 >> 16)
	d1[2] = byte(g.Data1 >> 8)
	d1[3] = byte(g.Data1)

	var d2 [2]byte
	d2[0] = byte(g.Data2 >> 8)
	d2[1] = byte(g.Data2)

	var d3 [2]byte
	d3[0] = byte(g.Data3 >> 8)
	d3[1] = byte(g.Data3)

	hexf.Encode(b[1:9], d1[:])
	b[9] = '-'
	hexf.Encode(b[10:14], d2[:])
	b[14] = '-'
	hexf.Encode(b[15:19], d3[:])
	b[19] = '-'
	hexf.Encode(b[20:24], g.Data4[:2])
	b[24] = '-'
	hexf.Encode(b[25:37], g.Data4[2:])

	return unsafe.String(unsafe.SliceData(b[:]), len(b))
}

// Equals compares this GUID with another GUID for equality.
// Returns true if all fields of both GUIDs are identical.
func (g *GUID) Equals(other *GUID) bool {
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4[0] == other.Data4[0] &&
		g.Data4[1] == other.Data4[1] &&
		g.Data4[2] == other.Data4[2] &&
		g.Data4[3] == other.Data4[3] &&
		g.Data4[4] == other.Data4[4] &&
		g.Data4[5] == other.Data4[5] &&
		g.Data4[6] == other.Data4[6] &&
		g.Data4[7] == other.Data4[7]
}

var (
	guidRE = regexp.MustCompile(`^\{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}?$`)
)

// MustParseGUID parses a guid string into a GUID struct or panics
func MustParseGUID(sguid string) (guid *GUID) {
	var err error
	if guid, err = ParseGUID(sguid); err != nil {
		panic(err)
	}
	return
}

// ParseGUID parses a guid string into a GUID structure
func ParseGUID(guid string) (g *GUID, err error) {
	var u uint64

	g = &GUID{}
	guid = strings.ToUpper(guid)
	if !guidRE.MatchString(guid) {
		return nil, fmt.Errorf("bad GUID format")
	}
	guid = strings.Trim(guid, "{}")
	sp := strings.Split(guid, "-")

	if u, err = strconv.ParseUint(sp[0], 16, 32); err != nil {
		return
	}
	g.Data1 = uint32(u)
	if u, err = strconv.ParseUint(sp[1], 16, 16); err != nil {
		return
	}
	g.Data2 = uint16(u)
	if u, err = strconv.ParseUint(sp[2], 16, 16); err != nil {
		return
	}
	g.Data3 = uint16(u)
	if u, err = strconv.ParseUint(sp[3], 16, 16); err != nil {
		return
	}
	g.Data4[0] = uint8(u >> 8)
	g.Data4[1] = uint8(u & 0xff)
	if u, err = strconv.ParseUint(sp[4], 16, 64); err != nil {
		return
	}
	g.Data4[2] = uint8((u >> 40))
	g.Data4[3] = uint8((u >> 32) & 0xff)
	g.Data4[4] = uint8((u >> 24) & 0xff)
	g.Data4[5] = uint8((u >> 16) & 0xff)
	g.Data4[6] = uint8((u >> 8) & 0xff)
	g.Data4[7] = uint8(u & 0xff)

	return
}

func (g GUID) MarshalJSON() ([]byte, error) {
	s := g.StringU()
	buf := make([]byte, 0, len(s)+2) // +2 for quotes
	buf = append(buf, '"')
	buf = append(buf, s...)
	buf = append(buf, '"')
	return buf, nil
}
