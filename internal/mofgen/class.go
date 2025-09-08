package mofgen

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// stringToUint16SliceLiteral converts a string to a Go literal for a null-terminated []uint16 slice.
func stringToUint16SliceLiteral(s string) string {
	if s == "" {
		return "nil"
	}
	var builder strings.Builder
	builder.WriteString("[]uint16{")
	for i, r := range s {
		if i > 0 {
			builder.WriteString(", ")
		}
		 if r < 128 && r >= 32 { // printable ASCII
            builder.WriteString(fmt.Sprintf("'%c'", r))
        } else {
            builder.WriteString(fmt.Sprintf("%d", r))
        }
	}
	builder.WriteString(", 0}") // Null terminator
	return builder.String()
}

// parseClass parses a MOF class definition by analyzing regex matches that capture
// different parts of the class structure. The match array contains:
//
// match[0]: Full class definition - Complete MOF class text including qualifiers,
//
//	name, base class and property block
//
// match[1]: Qualifiers block - Contains class metadata like:
//   - GUID in format "guid(12345678-1234-1234-1234-123456789012)"
//   - Version as "EventVersion(1)"
//   - Event types as "EventType{1,2,3}" or "EventType(1)"
//
// match[2]: Class name - The identifier for this class (e.g. "FileIo_V2")
//
// match[3]: Base class name - The class this one inherits from (e.g. "MSNT_SystemTrace")
//
// match[4]: Property definitions block - Contains all class properties with their
//
//	qualifiers, types and names. Can be empty for classes without properties.
//
// Returns nil if the match array doesn't contain all required parts (len < 5)
func parseClass(match []string) *mofParsedClass {
	if len(match) < 5 {
		return nil
	}

	class := &mofParsedClass{
		Name:          match[2],
		Base:          match[3],
		Properties:    make([]mofParsedProperty, 0),
		MofDefinition: match[0], // Store complete MOF definition
	}

	// Extract format: guid("12345678-1234-1234-1234-123456789012")
	// Returns GUID string or empty if not found
	if guid := class.parseGUIDQualifier(match[1]); guid != "" {
		class.GUID = guid
		class.InheritsGUID = false
	}

	// Extract format: EventVersion(1) or EventVersion("2.0")
	// Returns version string or empty if not found
	if ver := class.parseVersionQualifier(match[1]); ver != "" {
		class.Version = ver
		class.InheritsVersion = false
	}

	// Extract format: EventType(1) or EventType{1,2,3}
	// Returns event types string or empty if not found
	if events := class.parseEventTypesQualifier(match[1]); events != "" {
		class.EventTypes = events
	}

	// parseProperties parses all property definitions from match[4] text block
	// Each property must have WmiDataId(n), type and name, like:
	// [WmiDataId(1)] uint32 ProcessId;
	class.parseProperties(match[4])

	return class
}

// parseProperties processes the property definitions block of a MOF class to extract
// individual property definitions and their metadata.
//
// The body parameter contains raw text of property definitions in this format:
//
//	[Qualifiers] Type PropertyName;
//
// Property Format:
//   - Qualifiers: Must include WmiDataId(n), may have others
//   - Type: Data type like uint32, string
//   - Name: Property identifier
//   - Must end with semicolon
//
// Example property definitions:
//
//	[WmiDataId(1)] uint32 ProcessId;               // Simple numeric property
//	[WmiDataId(2), format("w")] string Name;       // Unicode string
//	[WmiDataId(3), MAX(256)] char16 ServiceName;   // Fixed size array
//	[WmiDataId(4), WmiSizeIs("TimeStampCount"), read ] uint64 TimeStamp;  // Dynamic array
//
// Processing Flow:
//  1. Build ID map from WmiDataId(n) values
//  2. For each property:
//     - Extract WmiDataId, type, name
//     - Parse qualifiers (format, size, etc)
//     - Determine TDH input/output types
//     - Add to class's Properties list
//
// Invalid properties (missing required parts) are skipped with a warning.
func (c *mofParsedClass) parseProperties(body string) {
	// Match property patterns including multi-line properties
	propPattern := regexp.MustCompile(`\[\s*WmiDataId\((\d+)\)(.*?)\]\s*(\w+)\s+(\w+)\s*;`)

	// Replace newlines with spaces to handle multi-line properties
	body = strings.ReplaceAll(body, "\n", " ")

	// First pass - build map of property names to their WmiDataId values
	// The regex match groups contain:          Example property:
	//   match[0] = full property definition    // [WmiDataId(6), format("s"), read, MAX(4)] char16 DriveLetterString;
	//   match[1] = WmiDataId value             // 6
	//   match[2] = other qualifiers            // , format("s"), read, MAX(4)
	//   match[3] = type                        // char16
	//   match[4] = property name               // DriveLetterString
	propertyMatches := propPattern.FindAllStringSubmatch(body, -1)

	idMap := make(map[string]string) // map[PropertyName]PropertyID
	for _, match := range propertyMatches {
		if len(match) < 5 {
			continue
		}
		idMap[match[4]] = match[1] // Store name->ID mapping
	}

	// Second pass - parse properties with ID map available
	for _, match := range propertyMatches {
		// Each property regex match should have 5 groups:
		if len(match) < 5 {
			log.Printf("Warning: Invalid property definition in class %s: %s", c.Name, match[0])
			continue
		}

		// Validate property has required parts
		if match[1] == "" {
			log.Printf("Warning: Missing type in property definition: %s", match[0])
			continue
		}
		if match[2] == "" {
			log.Printf("Warning: Missing name in property definition: %s", match[0])
			continue
		}

		prop := mofParsedProperty{
			ID:   match[1],
			Name: match[4],
		}

		// Parse type and qualifiers
		typeName := match[3]
		qualifiers := match[2]

		prop.parseType(typeName, qualifiers, idMap)
		c.Properties = append(c.Properties, prop)
	}
}

// processInheritance sets inherited metadata from the immediate base class.
// If the current class doesn't define its own GUID or Version, it will
// inherit these values from its base class.
//
// Parameters:
//   - baseClass: Immediate parent class to inherit from
//
// Example:
//
//	Child (no GUID defined) inherits from Parent (GUID=123) -> Child.GUID = 123
func (c *mofParsedClass) processInheritance(baseClass *mofParsedClass) {
	// Only inherit GUID if not explicitly defined
	if c.GUID == "" {
		c.GUID = baseClass.GUID
		c.InheritsGUID = true
	}

	// Only inherit version if not explicitly defined
	if c.Version == "" {
		c.Version = baseClass.Version
		c.InheritsVersion = true
	}
}

// parseGUIDQualifier extracts the GUID from a qualifiers block.
// Input format: ", Guid(\"{90cbdc39-4a3e-11d1-84f4-0000f80464e3}\"),\r\n         EventVersion(2)"
// Returns: extracted GUID string or empty if not found/invalid
// Examples:
//
//	returns:  "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}"
//	- No GUID -> "" (inherits from base class)
func (c *mofParsedClass) parseGUIDQualifier(qualifiers string) string {
	re := regexp.MustCompile(`Guid\("({[0-9A-Fa-f-]+})"\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}
	return ""
}

// parseVersionQualifier extracts the version from a qualifiers block.
// Input format: "<....qualifiers....>  EventVersion(1)"
// Returns: extracted version string or empty if not found/invalid
// Examples:
//   - "EventVersion(1)" -> returns "1"
//   - No version -> "" (inherits from base class)
func (c *mofParsedClass) parseVersionQualifier(qualifiers string) string {
	re := regexp.MustCompile(`EventVersion\((\d+)\)`)
	if m := re.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}
	return ""
}

// parseEventTypesQualifier extracts event types from a qualifiers block.
// Input formats:
//   - Single: EventType(1)
//   - Multiple: EventType{1,2,3}
//
// Returns: extracted event types string or empty if not found
// Examples:
//   - "EventType(1)" -> "1"
//   - "EventType{1,2,3}" -> "1,2,3"
//   - No event types -> ""
func (c *mofParsedClass) parseEventTypesQualifier(qualifiers string) string {
	// Try array format first: EventType{1, 2, 3}
	arrayRe := regexp.MustCompile(`EventType\s*{\s*([\d\s,]+)\s*}`)
	if m := arrayRe.FindStringSubmatch(qualifiers); len(m) > 1 {
		return strings.Join(strings.Split(m[1], ","), ", ")
	}

	// Try single format: EventType(1)
	singleRe := regexp.MustCompile(`EventType\s*\((\d+)\)`)
	if m := singleRe.FindStringSubmatch(qualifiers); len(m) > 1 {
		return m[1]
	}

	return ""
}
