package utf16f

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
)

func TestUTF16_To_WTF8(t *testing.T) {
	tests := []struct {
		name  string
		input []uint16
		want  []byte
	}{
		// --- Basic ASCII ---

		// "EmptyInput": Tests handling of an empty slice.
		{"EmptyInput", []uint16{}, []byte{}},
		// "SingleASCII": Tests a single ASCII character 'A'.
		{"SingleASCII", []uint16{0x41}, []byte("A")},
		// "ASCII": Tests a simple string of ASCII characters "ABC".
		{"ASCII", []uint16{0x41, 0x42, 0x43}, []byte("ABC")},

		// --- SIMD Block Alignment ---
		// These tests ensure the SIMD fast path for ASCII works correctly with various block sizes.

		// "8CharsASCII": "ABCDEFGH". Tests a full 8-char block.
		{"8CharsASCII", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
			[]byte("ABCDEFGH")},
		// "15CharsASCII": "ABCDEFGHIJKLMNO". Tests a nearly full 16-char (2x8) block.
		{"15CharsASCII", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		}, []byte("ABCDEFGHIJKLMNO")},
		// "16CharsASCII": "ABCDEFGHIJKLMNOP". Tests exactly two 8-char blocks.
		{"16CharsASCII", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		}, []byte("ABCDEFGHIJKLMNOP")},
		// "32CharsASCII": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef". Tests multiple full blocks.
		{"32CharsASCII", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		}, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")},

		// --- Basic Multilingual Plane (BMP) ---
		// These tests cover characters that encode to 2 or 3 bytes in UTF-8.

		// "SingleBMP": "£" (U+00A3). A single 2-byte UTF-8 character.
		{"SingleBMP", []uint16{0x00A3}, []byte{0xC2, 0xA3}},
		// "BMP": "你好" (U+4F60, U+597D). A common CJK string using 3-byte UTF-8 characters.
		{"BMP", []uint16{0x4F60, 0x597D}, []byte{0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD}},
		// "BMPAtBlockBoundary": "ABCDEFGH你好". Tests transitioning from ASCII fast path to BMP characters.
		{"BMPAtBlockBoundary", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // ABCDEFGH
			0x4F60, 0x597D, // 你好
		}, []byte{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // ABCDEFGH
			0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD, // 你好
		}},

		// --- Valid Surrogate Pairs (4-byte UTF-8) ---

		// "SingleSurrogatePair": "𝄞" (U+1D11E). A single valid surrogate pair.
		{"SingleSurrogatePair", []uint16{0xD834, 0xDD1E}, []byte{0xF0, 0x9D, 0x84, 0x9E}},
		// "SurrogateAtBlockBoundary": "ABCDEFGH😀AB". A surrogate pair starting exactly at a SIMD block boundary.
		{"SurrogateAtBlockBoundary", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0xD83D, 0xDE00, // 😀 at boundary
			0x41, 0x42,
		}, []byte{65, 66, 67, 68, 69, 70, 71, 72, 240, 159, 152, 128, 65, 66}},
		// "MultipleSurrogates": "😀👍". Multiple consecutive surrogate pairs.
		{"MultipleSurrogates", []uint16{
			0xD83D, 0xDE00, 0xD83D, 0xDC4D},
			[]byte{240, 159, 152, 128, 240, 159, 145, 141}},
		// "AlternatingSurrogates": "𐀀𐄁". Two valid surrogate pairs, U+10000 and U+10101.
		{"AlternatingSurrogates", []uint16{
			0xD800, 0xDC00, 0xD801, 0xDC01},
			[]byte{0xF0, 0x90, 0x80, 0x80, 0xF0, 0x90, 0x90, 0x81}},
		// "ValidSurrogatePairExtremes": "𐀀𴿿". The first (U+10000) and last (U+10FFFF) possible Unicode code points represented by surrogate pairs.
		// Note: This test was previously misnamed "MixedUnpairedSurrogates".
		{"ValidSurrogatePairExtremes", []uint16{
			0xD800, 0xDC00, 0xDBFF, 0xDFFF},
			[]byte{
				0xF0, 0x90, 0x80, 0x80, // Valid pair D800,DC00 -> U+10000
				0xF4, 0x8F, 0xBF, 0xBF, // Valid pair DBFF,DFFF -> U+10FFFF
			}},

		// --- Unpaired Surrogates (WTF-8) ---
		// These tests ensure that lone high or low surrogates are encoded correctly according to the WTF-8 spec.

		// "HighSurrogateOnly": A lone high surrogate U+D800.
		{"HighSurrogateOnly", []uint16{0xD800}, []byte{0xED, 0xA0, 0x80}},
		// "LowSurrogateOnly": A lone low surrogate U+DC00.
		{"LowSurrogateOnly", []uint16{0xDC00}, []byte{0xED, 0xB0, 0x80}},
		// "UnpairedHighFollowedByASCII": A lone high surrogate followed by 'A'.
		{"UnpairedHighFollowedByASCII", []uint16{0xD800, 0x0041}, []byte{237, 160, 128, 65}},
		// "UnpairedHighFollowedByBMP": A lone high surrogate followed by "你".
		{"UnpairedHighFollowedByBMP", []uint16{0xD800, 0x4F60}, []byte{237, 160, 128, 228, 189, 160}},
		// "UnpairedLowFollowedBySurrogate": A lone low surrogate followed by a valid surrogate pair "😀".
		{"UnpairedLowFollowedBySurrogate", []uint16{
			0xDC00, 0xD83D, 0xDE00},
			[]byte{237, 176, 128, 240, 159, 152, 128}},
		// "UnpairedSurrogateAtBlockEnd": "ABCDEFG" followed by a lone high surrogate, ending on a SIMD block boundary.
		{"UnpairedSurrogateAtBlockEnd", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0xD800, // Unpaired at 8-char boundary
		}, []byte{65, 66, 67, 68, 69, 70, 71, 237, 160, 128}},
		// "HighSurrogateRange": Tests the first, second, and last possible high surrogates (U+D800, U+D801, U+DBFF).
		{"HighSurrogateRange", []uint16{
			0xD800, 0xD801, 0xDBFF},
			[]byte{
				0xED, 0xA0, 0x80, // First high surrogate
				0xED, 0xA0, 0x81, // Second high surrogate
				0xED, 0xAF, 0xBF, // Last high surrogate
			}},
		// "LowSurrogateRange": Tests a few low surrogates across the valid range (U+DC00, U+DC01, U+DCFF).
		{"LowSurrogateRange", []uint16{
			0xDC00, 0xDC01, 0xDCFF},
			[]byte{0xED, 0xB0, 0x80, 0xED, 0xB0, 0x81, 0xED, 0xB3, 0xBF}},
		// "LowSurrogateEdgeCases": Tests the absolute first (U+DC00) and last (U+DFFF) low surrogates.
		{"LowSurrogateEdgeCases", []uint16{
			0xDC00, 0xDFFF},
			[]byte{
				0xED, 0xB0, 0x80, // First low (DC00)
				0xED, 0xBF, 0xBF, // Last low (DFFF)
			}},
		// "LowSurrogateBytePatterns": Tests specific low surrogates to verify correct byte pattern generation.
		{"LowSurrogateBytePatterns", []uint16{
			0xDC01, 0xDC20, 0xDC7F},
			[]byte{
				0xED, 0xB0, 0x81, // Check B0 prefix
				0xED, 0xB0, 0xA0, // Check middle bits
				0xED, 0xB1, 0xBF, // Check high bits
			}},
		// "TrulyUnpairedSurrogates": "A" and "B" interspersed with unpaired high and low surrogates.
		{"TrulyUnpairedSurrogates", []uint16{
			0xD800, 0x0041, 0xDFFF, 0x0042},
			[]byte{
				0xED, 0xA0, 0x80, // High surrogate D800
				0x41,             // ASCII 'A'
				0xED, 0xBF, 0xBF, // Low surrogate DFFF
				0x42, // ASCII 'B'
			}},

		// --- Conformance & Edge Cases (from WTF-8 Spec) ---

		// "ReversedSurrogatePair": A low surrogate U+DC00 followed by a high surrogate U+D800. Must be treated as two unpaired surrogates.
		{"ReversedSurrogatePair",
			[]uint16{0xDC00, 0xD800},
			[]byte{0xED, 0xB0, 0x80, 0xED, 0xA0, 0x80}},
		// "CodePointBeforeSurrogates": U+D7FF, the code point just before the high surrogate range. Must be a normal 3-byte sequence.
		{"CodePointBeforeSurrogates",
			[]uint16{0xD7FF},
			[]byte{0xED, 0x9F, 0xBF}},
		// "CodePointAfterSurrogates": U+E000, the code point just after the low surrogate range. Must be a normal 3-byte sequence.
		{"CodePointAfterSurrogates",
			[]uint16{0xE000},
			[]byte{0xEE, 0x80, 0x80}},
		// "TwoHighSurrogates": Two consecutive high surrogates. Must be treated as two unpaired surrogates.
		{"TwoHighSurrogates",
			[]uint16{0xD800, 0xD801},
			[]byte{0xED, 0xA0, 0x80, 0xED, 0xA0, 0x81}},
		// "TwoLowSurrogates": Two consecutive low surrogates. Must be treated as two unpaired surrogates.
		{"TwoLowSurrogates",
			[]uint16{0xDC00, 0xDC01},
			[]byte{0xED, 0xB0, 0x80, 0xED, 0xB0, 0x81}},
		// "HighSurrogateAtEnd": "AB" followed by a lone high surrogate at the end of the string.
		{"HighSurrogateAtEnd", []uint16{
			0x41, 0x42, 0xD800}, []byte{65, 66, 237, 160, 128}},
		// "LowSurrogateAtStart": A lone low surrogate at the start of the string, followed by "AB".
		{"LowSurrogateAtStart", []uint16{
			0xDC00, 0x41, 0x42}, []byte{237, 176, 128, 65, 66}},

		// --- Mixed Content & Complex Cases ---

		// "MixedAllTypes": "A你😀[unpaired]B". A mix of ASCII, BMP, a valid surrogate pair, an unpaired surrogate, and more ASCII.
		{"MixedAllTypes", []uint16{
			0x41,           // ASCII
			0x4F60,         // BMP
			0xD83D, 0xDE00, // Valid surrogate pair
			0xD800, // Unpaired high surrogate
			0x42,   // ASCII
		}, []byte{
			65,            // A
			228, 189, 160, // 你
			240, 159, 152, 128, // 😀
			237, 160, 128, // Unpaired high surrogate
			66, // B
		}},
		// "SurrogatePairSpanningBlocks": A 16-char string where a surrogate pair is split across two 8-char SIMD blocks.
		{"SurrogatePairSpanningBlocks", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0xD83D,
			0xDE00, // Second part of surrogate in next block
		}, []byte{
			65, 66, 67, 68, 69, 70, 71, 72,
			73, 74, 75, 76, 77, 78, 79, 240, 159, 152, 128,
		}},
		// "FullBMPBlock16": Full block of 16 3-byte BMP characters to test non-ASCII performance.
		{"FullBMPBlock16", []uint16{
			0x4E00, 0x4E01, 0x4E02, 0x4E03, 0x4E04, 0x4E05, 0x4E06, 0x4E07,
			0x4E08, 0x4E09, 0x4E0A, 0x4E0B, 0x4E0C, 0x4E0D, 0x4E0E, 0x4E0F,
		}, []byte{
			0xE4, 0xB8, 0x80, 0xE4, 0xB8, 0x81, 0xE4, 0xB8, 0x82, 0xE4, 0xB8, 0x83,
			0xE4, 0xB8, 0x84, 0xE4, 0xB8, 0x85, 0xE4, 0xB8, 0x86, 0xE4, 0xB8, 0x87,
			0xE4, 0xB8, 0x88, 0xE4, 0xB8, 0x89, 0xE4, 0xB8, 0x8A, 0xE4, 0xB8, 0x8B,
			0xE4, 0xB8, 0x8C, 0xE4, 0xB8, 0x8D, 0xE4, 0xB8, 0x8E, 0xE4, 0xB8, 0x8F,
		}},
		// "FullBMPBlock8": Full block of 8 3-byte BMP characters.
		{"FullBMPBlock8", []uint16{
			0x4E00, 0x4E01, 0x4E02, 0x4E03, 0x4E04, 0x4E05, 0x4E06, 0x4E07,
		}, []byte{
			0xE4, 0xB8, 0x80, 0xE4, 0xB8, 0x81, 0xE4, 0xB8, 0x82, 0xE4, 0xB8, 0x83,
			0xE4, 0xB8, 0x84, 0xE4, 0xB8, 0x85, 0xE4, 0xB8, 0x86, 0xE4, 0xB8, 0x87,
		}},
		// "MixedBMPAndASCII": An alternating sequence of BMP and ASCII characters.
		{"MixedBMPAndASCII", []uint16{
			0x4E00, 0x0041, 0x4E01, 0x0042, 0x4E02, 0x0043, 0x4E03, 0x0044,
		}, []byte{
			0xE4, 0xB8, 0x80, 0x41, 0xE4, 0xB8, 0x81, 0x42,
			0xE4, 0xB8, 0x82, 0x43, 0xE4, 0xB8, 0x83, 0x44,
		}},

		// --- Accented Characters (2-byte UTF-8) ---

		// "SingleAccent": "ó" (U+00F3).
		{name: "SingleAccent",
			input: []uint16{0x00F3},
			want:  []byte{0xC3, 0xB3}},
		// "MoreAccents": "áéíóúñÁÉÍÓÚÑ". A string of common accented characters.
		{name: "MoreAccents",
			input: []uint16{0x00E1, 0x00E9, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00C1, 0x00C9, 0x00CD, 0x00D3, 0x00DA, 0x00D1},
			want:  []byte{0xC3, 0xA1, 0xC3, 0xA9, 0xC3, 0xAD, 0xC3, 0xB3, 0xC3, 0xBA, 0xC3, 0xB1, 0xC3, 0x81, 0xC3, 0x89, 0xC3, 0x8D, 0xC3, 0x93, 0xC3, 0x9A, 0xC3, 0x91}},

		// --- NULL Termination Handling ---
		// These tests are important for C-style string interoperability.

		// "NullTerminated": "AB\x00CD". The string should be truncated at the first NULL.
		{"NullTerminated", []uint16{
			0x41, 0x42, 0x00, 0x43, 0x44}, []byte("AB")},
		// "StartWithNull": "\x00ABC". An empty string should be returned.
		{"StartWithNull", []uint16{
			0x00, 0x41, 0x42, 0x43}, []byte{}},
		// "NullAtBlockBoundary": "ABCDEFGH\x00IJ". A NULL character appearing at a SIMD block boundary.
		{"NullAtBlockBoundary", []uint16{
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x00, 0x49, 0x4A, // NULL at boundary
		}, []byte("ABCDEFGH")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeSIMD(tt.input, utf16ToStringSSE2_v3)
			if string(got) != string(tt.want) {
				t.Errorf("DecodeSIMD(%v) = [% X], want [% X]", tt.input,
					[]byte(got), tt.want)
			}
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeSIMD(tt.input, utf16ToStringSSE2_v4)
			if string(got) != string(tt.want) {
				t.Errorf("DecodeSIMDv4(%v) = [% X], want [% X]", tt.input,
					[]byte(got), tt.want)
			}
		})
	}

	// // ! TESTING
	// for _, tt := range tests {
	// 	t.Run(tt.name, func(t *testing.T) {
	// 		got := DecodeSIMD(tt.input, utf16ToWTF8_simdutf_scalar)
	// 		if string(got) != string(tt.want) {
	// 			t.Errorf("DecodeSIMD_SIMDUTF_TEST(%v) = [% X], want [% X]", tt.input,
	// 				[]byte(got), tt.want)
	// 		}
	// 	})
	// }
	// // ! TESTING
	// for _, tt := range tests {
	// 	t.Run(tt.name, func(t *testing.T) {
	// 		got := DecodeSIMD(tt.input, utf16ToWTF8_webkit)
	// 		if string(got) != string(tt.want) {
	// 			t.Errorf("DecodeSIMD_WEBKIT_TEST(%v) = [% X], want [% X]", tt.input,
	// 				[]byte(got), tt.want)
	// 		}
	// 	})
	// }
	// // ! TESTING
	// for _, tt := range tests {
	// 	t.Run(tt.name, func(t *testing.T) {
	// 		got := DecodeSIMD(tt.input, utf16ToWTF8_v8)
	// 		if string(got) != string(tt.want) {
	// 			t.Errorf("DecodeSIMD_V8_TEST(%v) = [% X], want [% X]", tt.input,
	// 				[]byte(got), tt.want)
	// 		}
	// 	})
	// }

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscall.UTF16ToString(tt.input)
			if string(got) != string(tt.want) {
				//t.Errorf("syscall.UTF16ToString(%v) = %v, want %v", tt.input, got, tt.want)
				t.Errorf("syscall.UTF16ToString(%v) = [% X], want [% X]", tt.input,
					[]byte(got), tt.want)
			}
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeWtf8(tt.input)
			if string(got) != string(tt.want) {
				//t.Errorf("DecodeWtf8(%v) = %v, want %v", tt.input, got, tt.want)
				t.Errorf("DecodeWtf8(%v) = [% X], want [% X]", tt.input,
					[]byte(got), tt.want)
			}
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeWtf8_SliceVer(tt.input)
			if string(got) != string(tt.want) {
				//t.Errorf("DecodeWtf8_SliceVer(%v) = %v, want %v", tt.input, got, tt.want)
				t.Errorf("DecodeWtf8_SliceVer(%v) = [% X], want [% X]", tt.input,
					[]byte(got), tt.want)
			}
		})
	}
}

// go test -run=^$ -bench='BenchmarkDecodeUTF16/(SIMDv[23456]|SIMD_|DecodeWtf8.*|Syscall|utf16Package)/./(16|65536)(-.*)?$' ./etw/pkg/utf16f

func BenchmarkDecodeUTF16(b *testing.B) {
	cases := []struct {
		name string
		gen  func(n int) ([]uint16, int) // Returns input and expected output size
	}{
		{"ASCII", func(n int) ([]uint16, int) {
			s := make([]uint16, n)
			for i := range n {
				s[i] = uint16((i % 127) + 1) // Start from 1 to avoid NUL
			}
			return s, n
		}},
		// Uses Basic Multilingual Plane characters (Asian characters)
		{"BMP", func(n int) ([]uint16, int) {
			s := make([]uint16, n)
			for i := range n {
				s[i] = 0x4E00 + uint16(i%20940)
			}
			return s, n * 3
		}},
		{"Mixed", func(n int) ([]uint16, int) {
			s := make([]uint16, n)
			outSize := 0
			i := 0
			for i < n {
				switch i % 4 {

				case 0: // ASCII (1 byte)
					s[i] = uint16((i % 127) + 1) // ASCII but avoid NUL
					outSize++
					i++

				case 1: // Asian characters (3 bytes)
					s[i] = 0x4E00 + uint16(i%20940)
					outSize += 3
					i++

				case 2: // Emoji surrogate pairs (4 bytes)
					if i+1 < n {
						s[i] = 0xD83D
						s[i+1] = 0xDE00
						outSize += 4
						i += 2
					} else {
						s[i] = uint16((i % 127) + 1)
						outSize++
						i++
					}

				case 3: // Unpaired surrogate (3 bytes WTF-8)
					s[i] = 0xD800 // Unpaired surrogate
					outSize += 3
					i++
				}
			}
			return s, outSize
		}},
	}

	//sizes := []int{16, 256, 4096, 65536}

	sizes := []int{4, 8, 16, 32, 256, 65536}

	for _, size := range sizes {
		for _, tc := range cases {
			input, outSize := tc.gen(size)

			// Print header to stderr before each test category
			fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
				strings.Repeat("=", 15),
				tc.name,
				strings.Repeat("=", 15))

			b.Run(fmt.Sprintf("SIMDv4/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := DecodeSIMD(input, utf16ToStringSSE2_v4)
					if len(s) != outSize {
						b.Fatalf("ConvertUTF16_SIMDv4(%v) = %v, want %v", input, s, outSize)
					}
				}
			})

			b.Run(fmt.Sprintf("SIMDv3/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := DecodeSIMD(input, utf16ToStringSSE2_v3)
					if len(s) != outSize {
						b.Fatalf("ConvertUTF16_SIMDv3(%v) = %v, want %v", input, s, outSize)
					}
				}
			})

			// // ! TESTING
			// b.Run(fmt.Sprintf("SIMD_SIMDUTF/%s/%d", tc.name, size), func(b *testing.B) {
			// 	b.SetBytes(int64(outSize))
			// 	for i := 0; i < b.N; i++ {
			// 		s := DecodeSIMD(input, utf16ToWTF8_simdutf_scalar)
			// 		if len(s) != outSize {
			// 			b.Fatalf("utf16ToWTF8_simdutf_scalar(%v) = %v, want %v", input, s, outSize)
			// 		}
			// 	}
			// })
			// // ! TESTING
			// b.Run(fmt.Sprintf("SIMD_webkit/%s/%d", tc.name, size), func(b *testing.B) {
			// 	b.SetBytes(int64(outSize))
			// 	for i := 0; i < b.N; i++ {
			// 		s := DecodeSIMD(input, utf16ToWTF8_webkit)
			// 		if len(s) != outSize {
			// 			b.Fatalf("utf16ToWTF8_webkit(%v) = %v, want %v", input, s, outSize)
			// 		}
			// 	}
			// })
			// // ! TESTING
			// b.Run(fmt.Sprintf("SIMD_JavascriptV8/%s/%d", tc.name, size), func(b *testing.B) {
			// 	b.SetBytes(int64(outSize))
			// 	for i := 0; i < b.N; i++ {
			// 		s := DecodeSIMD(input, utf16ToWTF8_v8)
			// 		if len(s) != outSize {
			// 			b.Fatalf("utf16ToWTF8_v8(%v) = %v, want %v", input, s, outSize)
			// 		}
			// 	}
			// })

			// b.Run(fmt.Sprintf("SIMDv2/%s/%d", tc.name, size), func(b *testing.B) {
			// 	b.SetBytes(int64(outSize))
			// 	for i := 0; i < b.N; i++ {
			// 		s := DecodeSIMD_v2(input)
			// 		if len(s) != outSize {
			// 			b.Fatalf("ConvertUTF16_SSE2_v2(%v) = %v, want %v", input, s, outSize)
			// 		}
			// 	}
			// })

			// b.Run(fmt.Sprintf("SIMDv1/%s/%d", tc.name, size), func(b *testing.B) {
			// 	b.SetBytes(int64(outSize))
			// 	for i := 0; i < b.N; i++ {
			// 		s := DecodeSIMD_v1(input)
			// 		if len(s) != outSize {
			// 			b.Fatalf("ConvertUTF16_SSE2_v1(%v) = %v, want %v", input, s, outSize)
			// 		}
			// 	}
			// })

			// uses unsafe pointer instead of slice to omit bound cheking. (why is go so inneficient)
			b.Run(fmt.Sprintf("DecodeWtf8/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := DecodeWtf8(input)
					if len(s) != outSize {
						b.Fatalf("DecodeWtf8(%v) = %v, want %v", input, s, outSize)
					}
				}
			})

			b.Run(fmt.Sprintf("DecodeWtf8_SliceVer/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := DecodeWtf8_SliceVer(input)
					if len(s) != outSize {
						b.Fatalf("DecodeWtf8_SliceVer(%v) = %v, want %v", input, s, outSize)
					}
				}
			})

			b.Run(fmt.Sprintf("Syscall/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := syscall.UTF16ToString(input)
					if len(s) != outSize {
						b.Fatalf("ConvertUTF16_SSE2(%v) = %v, want %v", input, s, outSize)
					}
				}
			})

			b.Run(fmt.Sprintf("utf16Package/%s/%d", tc.name, size), func(b *testing.B) {
				b.SetBytes(int64(outSize))
				for b.Loop() {
					s := uf16PackageWrapper(input)
					// decodes to utf8 instead of wtf8, different output for invalid surrogates
					if len(s) != outSize {
						//b.Fatalf("utf16.Decode(%v) = %v, want %v", input, s, outSize)
						_ = s
					}
				}
			})

		}

		fmt.Println()
	}
}

func uf16PackageWrapper(s []uint16) []rune {
	for i, v := range s {
		if v == 0 {
			s = s[0:i]
			break
		}
	}

	return utf16.Decode(s)
}
