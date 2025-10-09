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

func TestParseGUID_ErrorCases(t *testing.T) {
	t.Parallel()

	// These test cases cover various invalid formats. The test only asserts
	// that an error is returned, not what the specific error message is.
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Empty String",
			input: "",
		},
		{
			name:  "Incorrect Length (Short)",
			input: "54849625-5478-4994-a5ba-3e3b0328c30",
		},
		{
			name:  "Incorrect Length (Long)",
			input: "54849625-5478-4994-a5ba-3e3b0328c30dd",
		},
		{
			name:  "Mismatched Braces (Missing Closing)",
			input: "{45d8cccd-539f-4b72-a8b7-5c683142609a",
		},
		{
			name:  "Mismatched Braces (Missing Opening)",
			input: "45d8cccd-539f-4b72-a8b7-5c683142609a}",
		},
		{
			name:  "Invalid Separator (Correct Length)",
			input: "45d8cccd-539f-4b72-a8b7 5c683142609a",
		},
		{
			name:  "Missing Hyphens (Incorrect Length)",
			input: "45d8cccd539f4b72a8b75c683142609a",
		},
		{
			name:  "Invalid Hex Character",
			input: "{45d8cccd-539f-4b72-a8b7-5c683142609g}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseGUID(tt.input)
			if err == nil {
				t.Fatalf("ParseGUID(%q) succeeded, want error", tt.input)
			}
		})
	}
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

// --- Benchmark for Equals method ---

var (
	guid1 = MustParseGUID("{13D70263-4226-42DB-9EEF-43D052A43822}")
	guid2 = MustParseGUID("{13D70263-4226-42DB-9EEF-43D052A43822}")
	guid3 = MustParseGUID("{E752D673-035F-422D-833E-262651098568}")
)

func BenchmarkGUIDEquals(b *testing.B) {
	// Manual field-by-field comparison for benchmarking against.
	equalsManual := func(g, other *GUID) bool {
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

	b.Run("ManualCompare_Equal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = equalsManual(guid1, guid2)
		}
	})

	b.Run("DirectCompare_Equal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = guid1.Equals(guid2)
		}
	})

	b.Run("ManualCompare_NotEqual", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = equalsManual(guid1, guid3)
		}
	})

	b.Run("DirectCompare_NotEqual", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = guid1.Equals(guid3)
		}
	})
}

// --- Benchmark for String methods ---

func BenchmarkGUIDString(b *testing.B) {
	guid := MustParseGUID("{13D70263-4226-42DB-9EEF-43D052A43822}")

	// Sprintf version for comparison.
	stringSprintf := func(g *GUID) string {
		return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			g.Data1, g.Data2, g.Data3,
			g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
			g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
	}

	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = guid.String()
		}
	})

	b.Run("Sprintf", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = stringSprintf(guid)
		}
	})
}

// --- Benchmark for ParseGUID method ---

func BenchmarkParseGUID(b *testing.B) {
	guidStr := "{13D70263-4226-42DB-9EEF-43D052A43822}"

	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = ParseGUID(guidStr)
		}
	})

	b.Run("RegexpAndSplit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = parseGUID_old(guidStr)
		}
	})
}
