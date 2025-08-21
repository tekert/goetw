//go:build windows

package etw

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tekert/goetw/internal/test"
)

func TestGUID(t *testing.T) {
	t.Parallel()

	var g *GUID
	var err error

	tt := test.FromT(t)

	// with curly brackets
	guid := "{45d8cccd-539f-4b72-a8b7-5c683142609a}"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(!g.IsZero())
	tt.Assert(strings.EqualFold(guid, g.StringU()))

	guid = "54849625-5478-4994-a5ba-3e3b0328c30d"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(!g.IsZero())
	tt.Assert(strings.EqualFold(fmt.Sprintf("{%s}", guid), g.StringU()))

	guid = "00000000-0000-0000-0000-000000000000"
	g, err = ParseGUID(guid)
	tt.CheckErr(err)
	tt.Assert(g.IsZero())
	tt.Assert(strings.EqualFold(fmt.Sprintf("{%s}", guid), g.StringU()))
}

func TestGUIDEquality(t *testing.T) {
	t.Parallel()

	tt := test.FromT(t)
	p := MustParseProvider("Microsoft-Windows-Kernel-File")
	g1 := p.GUID
	g2 := p.GUID

	tt.Assert(g1.Equals(&g2))

	// testing Data1
	g2.Data1++
	tt.Assert(!g1.Equals(&g2))

	// testing Data2
	g2 = p.GUID
	g2.Data2++
	tt.Assert(!g1.Equals(&g2))

	// testing Data3
	g2 = p.GUID
	g2.Data3++
	tt.Assert(!g1.Equals(&g2))

	// testing Data4
	for i := range 8 {
		g2 = p.GUID
		g2.Data4[i]++
		tt.Assert(!g1.Equals(&g2))
	}
}

func TestGUIDStringConversion(t *testing.T) {
	tests := []struct {
		name string
		guid GUID
		want string
	}{
		{
			name: "Standard GUID",
			guid: GUID{
				Data1: 0x12345678,
				Data2: 0x9ABC,
				Data3: 0xDEF0,
				Data4: [8]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			},
			want: "{12345678-9ABC-DEF0-1234-56789ABCDEF0}",
		},
		{
			name: "Zero GUID",
			guid: GUID{},
			want: "{00000000-0000-0000-0000-000000000000}",
		},
		{
			name: "All Fs GUID",
			guid: GUID{
				Data1: 0xFFFFFFFF,
				Data2: 0xFFFF,
				Data3: 0xFFFF,
				Data4: [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
			want: "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1 := tt.guid.StringU()
			v2 := tt.guid.String()

			if !strings.EqualFold(v1, tt.want) {
				t.Errorf("String() = %v, want %v", v1, tt.want)
			}
			if !strings.EqualFold(v2, v1) {
				t.Errorf("String() = %v, want %v", v1, tt.want)
			}
		})
	}
}
