package mofgen

import (
	"fmt"
	"regexp"
	"strings"
)

// parseType analyzes property type and qualifiers to determine TDH input/output types
// Parameters:
//   - typeName: MOF type (uint32, char16, etc)
//   - qualifiers: Property qualifiers like format("x"), WmiSizeIs("Count"), pointer, read
//   - idMap: Maps property names to their WmiDataId values for array size refs
//
// Type mapping examples:
//
//	uint32               -> InType: TDH_INTYPE_UINT32
//	[MAX(16)] char16     -> InType: TDH_INTYPE_UNICODESTRING, IsArray: true, ArraySize: 16
//	[WmiSizeIs("Count")] uint32  -> InType: TDH_INTYPE_UINT32, SizeFromID: <Count property ID>
//	[StringTermination("NullTerminated")] string -> TDH_INTYPE_UNICODESTRING
func (p *mofParsedProperty) parseType(typeName, qualifiers string, idMap map[string]string) {
	// Check for WmiSizeIs first - look up referenced property name ID
	if sizeRef := p.extractWmiSizeIs(qualifiers); sizeRef != "" {
		if id, ok := idMap[sizeRef]; ok {
			p.SizeFromID = id
		}
	}

	// Handle string types based on MOF specification
	// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers
	// String properties can have:
	//   - Format("w") -> wide-character string
	//   - Format("s") -> null-terminated string (default)
	//   - StringTermination("Counted") -> length prefix as USHORT
	//   - StringTermination("ReverseCounted") -> length prefix as big-endian USHORT
	//   - StringTermination("NotCounted") -> raw string data
	//   - StringTermination("NullTerminated") -> null terminated (default)
	if strings.ToLower(typeName) == "string" {
		// Default to ANSI string unless format("w") is specified
		p.InType = "TDH_INTYPE_ANSISTRING"

		// Format("w") indicates wide-character string
		// Example: [WmiDataId(6), StringTermination("NullTerminated"), format("w"), read] string ProcessName;
		if strings.Contains(qualifiers, `format("w")`) {
			p.InType = "TDH_INTYPE_UNICODESTRING"
		}

		// Handle StringTermination variants
		// Example: [WmiDataId(3), StringTermination("Counted")] string Path;
		if strings.Contains(qualifiers, "StringTermination(\"Counted\")") {
			p.InType = "TDH_INTYPE_COUNTEDSTRING"
		} else if strings.Contains(qualifiers, "StringTermination(\"ReverseCounted\")") {
			p.InType = "TDH_INTYPE_REVERSEDCOUNTEDSTRING"
		} else if strings.Contains(qualifiers, "StringTermination(\"NotCounted\")") {
			// For NotCounted strings, the length is the remaining bytes in the event
			// Wide strings if format("w"), ANSI strings otherwise
			if strings.Contains(qualifiers, `format("w")`) {
				p.InType = "TDH_INTYPE_NONNULLTERMINATEDSTRING" // Wide chars
			} else {
				p.InType = "TDH_INTYPE_NONNULLTERMINATEDANSISTRING" // ANSI chars
			}
		}
		// Note: NullTerminated is default

		// All strings use string output type regardless of input format
		p.OutType = "TDH_OUTTYPE_STRING"
		p.GoType = "uintptr" // Strings in structs are offsets.
		return
	}

	// Set base TDH type and Go type first
	if baseType, ok := typeMap[strings.ToLower(typeName)]; ok {
		p.InType = baseType
	}
	if goType, ok := goTypeMap[strings.ToLower(typeName)]; ok {
		p.GoType = goType
	}

	// Handle qualifiers that override the base type
	if strings.Contains(strings.ToLower(qualifiers), "pointer") {
		p.InType = "TDH_INTYPE_POINTER"
		p.GoType = "uintptr"
		return // Pointer qualifier overrides everything else
	}

	// Process format qualifier to determine output type:
	// - format("w") -> TDH_OUTTYPE_UNICODE_STRING    // Unicode string
	// - format("s") -> TDH_OUTTYPE_STRING            // ANSI string
	// - format("x") -> TDH_OUTTYPE_HEXINTxx         // Hex format (32/64 bit)
	if format := p.parseOutputFormatQualifier(qualifiers); format != "" {
		if outType, ok := formatMap[format]; ok {
			p.OutType = outType
		}
		if format == "x" {
			// For hex format, output type depends on input type size
			switch p.InType {
			case "TDH_INTYPE_UINT32", "TDH_INTYPE_INT32":
				p.OutType = "TDH_OUTTYPE_HEXINT32"
			case "TDH_INTYPE_UINT64", "TDH_INTYPE_INT64":
				p.OutType = "TDH_OUTTYPE_HEXINT64"
			}
		}
	}

	// Handle extension qualifier
	if ext := p.parseExtensionQualifier(qualifiers); ext != "" {
		p.Extension = ext // Store the raw extension name
		if types, ok := extensionMap[ext]; ok {
			p.InType = types[0]
			if types[1] != "" {
				p.OutType = types[1]
			}
		}
		if goType, ok := goExtensionTypeMap[ext]; ok {
			p.GoType = goType
		}
	}

	// Handle array size with ID map
	isArray, arraySize, sizeFromID := p.parseArraySize(qualifiers, idMap)
	if isArray {
		p.IsArray = "true"
		p.ArraySize = arraySize
		p.GoType = fmt.Sprintf("[%s]%s", arraySize, p.GoType)
	} else if sizeFromID != "" {
		p.SizeFromID = sizeFromID
		p.GoType = "uintptr" // Variable-size array is a pointer/offset.
	}
}

// extractWmiSizeIs parses the WmiSizeIs qualifier to get the property name that defines array size
// Input format: WmiSizeIs("PropertyName")
// Returns the property name or empty string if not found
func (p *mofParsedProperty) extractWmiSizeIs(qualifiers string) string {
	re := regexp.MustCompile(`WmiSizeIs\s*\(\s*"(\w+)"\s*\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}
	return ""
}

// parseOutputFormatQualifier extracts the format type from format qualifier
// Input format: format("x") where x can be: w (unicode), s (string), x (hex), c (ascii)
// Returns the format character or empty string if not found
func (p *mofParsedProperty) parseOutputFormatQualifier(qualifiers string) string {
	re := regexp.MustCompile(`format\s*\(\s*"(\w)"\s*\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}
	return ""
}

// parseExtensionQualifier extracts the extension type from extension qualifier
// Input format: extension("ExtensionName")
// Returns the extension name or empty string if not found
func (p *mofParsedProperty) parseExtensionQualifier(qualifiers string) string {
	re := regexp.MustCompile(`extension\s*\(\s*"(\w+)"\s*\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}
	return ""
}

// parseArraySize determines if property is an array and its size from qualifiers
// Checks for:
// - WmiSizeIs("PropName") -> dynamic size from other property
// - MAX(n) -> fixed size array of n elements
// Returns isArray flag, arraySize (if fixed), and sizeFromID (if dynamic)
func (p *mofParsedProperty) parseArraySize(qualifiers string, idMap map[string]string) (isArray bool, arraySize string, sizeFromID string) {
	// Check for WmiSizeIs first
	// Extract property name from WmiSizeIs("PropName")
	re := regexp.MustCompile(`WmiSizeIs\s*\(\s*"(\w+)"\s*\)`)

	// Match groups for: WmiSizeIs("Count")
	// m[0] = WmiSizeIs("Count")    - Full match
	// m[1] = Count                 - Property name
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		propName := m[1]
		// Look up property ID from name->ID map
		// e.g., if Count has WmiDataId(3), returns "3" (ids saved on Idmap when parsing properties)
		if id, ok := idMap[propName]; ok {
			return false, "", id // Return the actual property ID
		}
	}

	// Check for MAX size - fixed array
	re = regexp.MustCompile(`MAX\s*\(\s*(\d+)\s*\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return true, m[1], ""
	}

	return false, "", ""
}
