package hexf

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

type testCase struct {
	expectedReg    string // For Regular encode (lower)
	expectedUp     string // For uppercase encode
	expectedTrim   string // For trimming functions (lower)
	expectedUpTrim string // For uppercase trimming
}

// Helper function to generate test case strings from a hex value
func makeTestCase(hex string) testCase {
	// Remove 0x prefix if present
	hex = strings.TrimPrefix(hex, "0x")

	// Handle empty cases specially
	if hex == "" {
		return testCase{"", "", "", ""}
	}

	// Handle empty/zero cases
	if hex == "0" {
		return testCase{"00", "00", "0", "0"}
	}

	// Generate variants
	reg := strings.ToLower(hex)
	up := strings.ToUpper(hex)
	trim := strings.TrimLeft(reg, "0")
	if trim == "" {
		trim = "0"
	}
	upTrim := strings.TrimLeft(up, "0")
	if upTrim == "" {
		upTrim = "0"
	}
	return testCase{reg, up, trim, upTrim}
}

func TestEncode(t *testing.T) {
	// Test cases with expected outputs
	tests := []struct {
		name  string
		input []byte
		testCase
	}{
		{"Empty", []byte{}, makeTestCase("")},
		{"Nil", nil, makeTestCase("")},

		{"SingleZero", []byte{0}, makeTestCase("00")},
		{"SingleDigit", []byte{5}, makeTestCase("05")},
		{"TwoDigits", []byte{0x3f}, makeTestCase("3f")},
		{"AllZeros4", []byte{0, 0, 0, 0}, makeTestCase("00000000")},
		{"LeadingZeros", []byte{0, 0, 0x0a, 0x7b}, makeTestCase("00000a7b")},
		{"NoZeros", []byte{0xde, 0xad, 0xbe, 0xef}, makeTestCase("deadbeef")},
		{"MixedZeros", []byte{0, 0xab, 0, 0xcd}, makeTestCase("00ab00cd")},
		{"MaxValue", []byte{0xff, 0xff}, makeTestCase("ffff")},
		{"LeadingSingle", []byte{0, 0xf}, makeTestCase("000f")},
		{"LeadingDouble", []byte{0, 0xff}, makeTestCase("00ff")},
		{"LastF", []byte{0, 0x0f}, makeTestCase("000f")},
		{"SingleDigits", []byte{1}, makeTestCase("01")},
		{"SingleF", []byte{0xf}, makeTestCase("0f")},
		{"LeadingF", []byte{0, 0xf}, makeTestCase("000f")},
		{"DoubleF", []byte{0xff}, makeTestCase("ff")},
		{"LeadingDoubleF", []byte{0, 0xff}, makeTestCase("00ff")},
		{"MixedSingle", []byte{0, 1, 0, 2}, makeTestCase("00010002")},
		{"AlternateZeros", []byte{0, 0xa, 0, 0xb}, makeTestCase("000a000b")},
		{"LongLeadingZeros", []byte{0, 0, 0, 0, 0, 0, 0, 1}, makeTestCase("0000000000000001")},
		{"LongTrailingZeros", []byte{1, 0, 0, 0, 0, 0, 0, 0}, makeTestCase("0100000000000000")},
		{"SingleNibbles", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			makeTestCase("000102030405060708090a0b0c0d0e0f")},
		{"AllNonZero", []byte{0x1, 0x23, 0x45}, makeTestCase("012345")},
		{"NonZeroDoubleFirst", []byte{0xab, 0x0c}, makeTestCase("ab0c")},
		{"LongArray", []byte{0, 0, 0, 0, 0, 0, 0xff, 0, 0xaa}, makeTestCase("000000000000ff00aa")},
		{"NonZeroLeadingWithZerosAfter", []byte{0x0a, 0, 0, 0x1}, makeTestCase("0a000001")},
		{"RandomMixed", []byte{0, 6, 0, 255, 0, 12}, makeTestCase("000600ff000c")},
		{"AllZerosOdd", []byte{0, 0, 0, 0, 0}, makeTestCase("0000000000")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			func() {
				defer func() {
					if r := recover(); r != nil {
						if tt.name != "Nil" && tt.name != "Empty" {
							panic(r)
						}
						// For nil/empty, we expect a panic and empty result
						return
					}
				}()

				// Always allocate at least 2 bytes for dst
				dstSize := 2
				if tt.input != nil {
					dstSize = len(tt.input) * 2
				}
				dst := make([]byte, dstSize)

				// Test lowercase no trim
				n := Encode(dst, tt.input)
				got := string(dst[:n])
				if got != tt.expectedReg {
					t.Errorf("Encode(%v) = %q, want %q", tt.input, got, tt.expectedReg)
				}

				// Test uppercase no trim
				n = EncodeU(dst, tt.input)
				got = string(dst[:n])
				if got != tt.expectedUp {
					t.Errorf("EncodeU(%x) = %s, want %s", tt.input, got, tt.expectedUp)
				}

				// Test lowercase with trim
				n = EncodeTrim(dst, tt.input)
				got = string(dst[:n])
				if got != tt.expectedTrim {
					t.Errorf("EncodeTrim(%x) = %s, want %s", tt.input, got, tt.expectedTrim)
				}

				// Test uppercase with trim
				n = EncodeUTrim(dst, tt.input)
				got = string(dst[:n])
				if got != tt.expectedUpTrim {
					t.Errorf("EncodeUTrim(%x) = %s, want %s", tt.input, got, tt.expectedUpTrim)
				}
			}()
		})
	}
}

// Add a new helper to generate test cases with 0x prefix.
func makePrefixTestCase(hex string) testCase {
	// Use our existing makeTestCase helper to generate the variants...
	tc := makeTestCase(hex)
	// And add the "0x" prefix to each output.
	return testCase{
		expectedReg:    "0x" + tc.expectedReg,
		expectedUp:     "0x" + tc.expectedUp,
		expectedTrim:   "0x" + tc.expectedTrim,
		expectedUpTrim: "0x" + tc.expectedUpTrim,
	}
}

func TestEncodePrefix(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		tc    testCase
	}{
		// Test empty/nil cases first
		{"Nil", nil, testCase{"0x", "0x", "0x", "0x"}},
		{"Empty", []byte{}, testCase{"0x", "0x", "0x", "0x"}},

		// Test zero cases
		{"Zero", []byte{0}, makePrefixTestCase("00")},
		{"ZeroDouble", []byte{0, 0}, makePrefixTestCase("0000")},

		{"SingleDigit", []byte{5}, makePrefixTestCase("05")},
		{"TwoDigits", []byte{0x3f}, makePrefixTestCase("3f")},
		{"LeadingZeros", []byte{0, 0, 0x0a, 0x7b}, makePrefixTestCase("00000a7b")},
		{"NoLeadingZeros", []byte{0xde, 0xad, 0xbe, 0xef}, makePrefixTestCase("deadbeef")},
		{"MixedZeros", []byte{0, 0xab, 0, 0xcd}, makePrefixTestCase("00ab00cd")},
		{"SingleF", []byte{0xf}, makePrefixTestCase("0f")},
		{"LeadingF", []byte{0, 0xf}, makePrefixTestCase("000f")},
		{"LongZeros", []byte{0, 0, 0, 0, 0, 0, 0, 0}, makePrefixTestCase("0000000000000000")},
		{"LongMixed", []byte{0, 0, 0, 1, 0, 0, 0, 0}, makePrefixTestCase("0000000100000000")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap each test in a sub-function to catch panics for nil/empty cases.
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Only ignore panics for nil/empty tests.
						if tt.name != "Nil" && tt.name != "Empty" {
							panic(r)
						}
					}
				}()

				// Test lowercase no trim.
				got := EncodeToStringPrefix(tt.input)
				if got != tt.tc.expectedReg {
					t.Errorf("EncodeToStringPrefix(%x) = %s, want %s", tt.input, got, tt.tc.expectedReg)
				}

				// Test lowercase with trim.
				got = EncodeToStringPrefixTrim(tt.input)
				if got != tt.tc.expectedTrim {
					t.Errorf("EncodeToStringPrefixTrim(%x) = %s, want %s", tt.input, got, tt.tc.expectedTrim)
				}

				// Test uppercase no trim.
				got = EncodeToStringUPrefix(tt.input)
				if got != tt.tc.expectedUp {
					t.Errorf("EncodeToStringUPrefix(%x) = %s, want %s", tt.input, got, tt.tc.expectedUp)
				}

				// Test uppercase with trim.
				got = EncodeToStringUPrefixTrim(tt.input)
				if got != tt.tc.expectedUpTrim {
					t.Errorf("EncodeToStringUPrefixTrim(%x) = %s, want %s", tt.input, got, tt.tc.expectedUpTrim)
				}
			}()
		})
	}
}

func TestNumEncodePrefix(t *testing.T) {
	numTests := []struct {
		name    string
		noTrim  string            // Expected output without trim
		trimmed string            // Expected output with trim
		fn      func(bool) string // Function (test with trim or without)
	}{
		// 64-bit tests
		{"Uint64_Zero", "0x0000000000000000", "0x0", func(trim bool) string { return Num64p(uint64(0), trim) }},
		{"Uint64_Mid", "0x0000000000001234", "0x1234", func(trim bool) string { return Num64p(uint64(0x1234), trim) }},
		{"Uint64_Max", "0xffffffffffffffff", "0xffffffffffffffff", func(trim bool) string { return Num64p(uint64(0xFFFFFFFFFFFFFFFF), trim) }},

		{"Int64_NegZero", "0x0000000000000000", "0x0", func(trim bool) string { return Num64p(int64(0), trim) }},
		{"Int64_Min", "0x8000000000000000", "0x8000000000000000", func(trim bool) string { return Num64p(int64(-9223372036854775808), trim) }},
		{"Int64_MidNeg", "0xfffffffffffff000", "0xfffffffffffff000", func(trim bool) string { return Num64p(int64(-4096), trim) }},
		{"Int64_MidPos", "0x0000000000001234", "0x1234", func(trim bool) string { return Num64p(int64(0x1234), trim) }},
		{"Int64_Pos", "0x0000000000000042", "0x42", func(trim bool) string { return Num64p(int64(66), trim) }},

		// 32-bit tests
		{"Uint32_Zero", "0x00000000", "0x0", func(trim bool) string { return Num32p(uint32(0), trim) }},
		{"Uint32_Mid", "0x00001234", "0x1234", func(trim bool) string { return Num32p(uint32(0x1234), trim) }},
		{"Uint32_Max", "0xffffffff", "0xffffffff", func(trim bool) string { return Num32p(uint32(0xFFFFFFFF), trim) }},

		{"Int32_NegZero", "0x00000000", "0x0", func(trim bool) string { return Num32p(int32(0), trim) }},
		{"Int32_Min", "0x80000000", "0x80000000", func(trim bool) string { return Num32p(int32(-2147483648), trim) }},
		{"Int32_MidNeg", "0xfffff000", "0xfffff000", func(trim bool) string { return Num32p(int32(-4096), trim) }},
		{"Int32_MidPos", "0x00001234", "0x1234", func(trim bool) string { return Num32p(int32(0x1234), trim) }},
		{"Int32_Pos", "0x00000042", "0x42", func(trim bool) string { return Num32p(int32(66), trim) }},

		// 16-bit tests
		{"Uint16_Zero", "0x0000", "0x0", func(trim bool) string { return Num16p(uint16(0), trim) }},
		{"Uint16_Mid", "0x0123", "0x123", func(trim bool) string { return Num16p(uint16(0x123), trim) }},
		{"Uint16_Max", "0xffff", "0xffff", func(trim bool) string { return Num16p(uint16(0xFFFF), trim) }},

		{"Int16_NegZero", "0x0000", "0x0", func(trim bool) string { return Num16p(int16(0), trim) }},
		{"Int16_Min", "0x8000", "0x8000", func(trim bool) string { return Num16p(int16(-32768), trim) }},
		{"Int16_MidNeg", "0xf000", "0xf000", func(trim bool) string { return Num16p(int16(-4096), trim) }},
		{"Int16_MidPos", "0x0123", "0x123", func(trim bool) string { return Num16p(int16(0x123), trim) }},
		{"Int16_Pos", "0x0042", "0x42", func(trim bool) string { return Num16p(int16(66), trim) }},

		// 8-bit tests
		{"Uint8_Zero", "0x00", "0x0", func(trim bool) string { return Num8p(uint8(0), trim) }},
		{"Uint8_Mid", "0x09", "0x9", func(trim bool) string { return Num8p(uint8(0x09), trim) }},
		{"Uint8_Max", "0xff", "0xff", func(trim bool) string { return Num8p(uint8(0xFF), trim) }},

		{"Int8_NegZero", "0x00", "0x0", func(trim bool) string { return Num8p(int8(-0), trim) }},
		{"Int8_Min", "0x80", "0x80", func(trim bool) string { return Num8p(int8(-128), trim) }},
		{"Int8_MidNeg", "0xf0", "0xf0", func(trim bool) string { return Num8p(int8(-16), trim) }},
		{"Int8_MidPos", "0x12", "0x12", func(trim bool) string { return Num8p(int8(0x12), trim) }},
		{"Int8_Pos", "0x42", "0x42", func(trim bool) string { return Num8p(int8(66), trim) }},
	}

	for _, tt := range numTests {
		t.Run(tt.name, func(t *testing.T) {
			// Test without trim
			got := tt.fn(false)
			if got != tt.noTrim {
				t.Errorf("%s (no trim) = %s, want %s", tt.name, got, tt.noTrim)
			}

			// Test with trim
			got = tt.fn(true)
			if got != tt.trimmed {
				t.Errorf("%s (trimmed) = %s, want %s", tt.name, got, tt.trimmed)
			}
		})
	}
}

func BenchmarkEncodeCompare(b *testing.B) {
	sizes := []int{4, 8, 16, 32}
	patterns := []struct {
		name string
		gen  func(size int) []byte
	}{
		{"Sequential", func(size int) []byte {
			b := make([]byte, size)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}},
		{"AllZeros", func(size int) []byte {
			return make([]byte, size)
		}},
		{"AllFF", func(size int) []byte {
			b := make([]byte, size)
			for i := range b {
				b[i] = 0xFF
			}
			return b
		}},
		{"Random", func(size int) []byte {
			b := make([]byte, size)
			for i := range b {
				b[i] = byte(i * 7)
			}
			return b
		}},
	}

	for _, pat := range patterns {
		for _, size := range sizes {
			data := pat.gen(size)
			dst := make([]byte, size*2)

			b.Run(fmt.Sprintf("hexf_Encode_%s_%d", pat.name, size), func(b *testing.B) {
				b.ResetTimer()
				for b.Loop() {
					Encode(dst, data)
				}
			})

			b.Run(fmt.Sprintf("hex.Encode_%s_%d", pat.name, size), func(b *testing.B) {
				b.ResetTimer()
				for b.Loop() {
					hex.Encode(dst, data)
				}
			})

			b.Run(fmt.Sprintf("hex.EncodeTrim_%s_%d", pat.name, size), func(b *testing.B) {
				b.ResetTimer()
				for b.Loop() {
					EncodeTrim(dst, data)
				}
			})
		}
	}
}

// func BenchmarkHexConversions(b *testing.B) {
//     testCases := []struct {
//         name string
//         fn   func(b *testing.B)
//     }{
//         {
//             name: "Uint64U_Direct",
//             fn: func(b *testing.B) {
//                 n := uint64(0xDEADBEEF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = Uint64U(n)
//                 }
//             },
//         },
//         {
//             name: "NumberToHexU_Generic_Uint64",
//             fn: func(b *testing.B) {
//                 n := uint64(0xDEADBEEF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = NumberToHexU(n)
//                 }
//             },
//         },
//         {
//             name: "Uint64UPrefix_Direct",
//             fn: func(b *testing.B) {
//                 n := uint64(0xDEADBEEF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = Uint64UPrefix(n, true)
//                 }
//             },
//         },
//         {
//             name: "NumberToHexUPrefix_Generic_Uint64",
//             fn: func(b *testing.B) {
//                 n := uint64(0xDEADBEEF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = NumberToHexUPrefix(n, true)
//                 }
//             },
//         },
//         {
//             name: "Uint8U_Direct",
//             fn: func(b *testing.B) {
//                 n := uint8(0xFF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = Uint8U(n)
//                 }
//             },
//         },
//         {
//             name: "NumberToHexU_Generic_Uint8",
//             fn: func(b *testing.B) {
//                 n := uint8(0xFF)
//                 b.ResetTimer()
//                 for i := 0; i < b.N; i++ {
//                     _ = NumberToHexU(n)
//                 }
//             },
//         },
//     }

//     for _, tc := range testCases {
//         b.Run(tc.name, tc.fn)
//     }
// }
