package mofgen

type mofParsedProperty struct {
	ID         string // WmiDataId
	Name       string
	NameW      string // Go literal for []uint16
	InType     string // string constant
	OutType    string // string constant
	IsArray    string // "true" if is array.
	ArraySize  string // MAX(n)
	SizeFromID string // WmiSizeIs property ID
}

type mofParsedClass struct {
	Name            string
	NameW           string // Go literal for []uint16
	Base            string
	BaseW           string // Go literal for []uint16
	GUID            string
	Version         string
	EventTypes      string
	Properties      []mofParsedProperty
	InheritsGUID    bool
	InheritsVersion bool
	MofDefinition   string // Original MOF class definition text
	GUIDFirst32Bits string // First 32 bits of GUID for mapping
}

// Mappings from MOF types to ETW types
var typeMap = map[string]string{
	"uint8":   "TDH_INTYPE_UINT8",
	"uint16":  "TDH_INTYPE_UINT16",
	"uint32":  "TDH_INTYPE_UINT32",
	"uint64":  "TDH_INTYPE_UINT64",
	"sint8":   "TDH_INTYPE_INT8",
	"sint16":  "TDH_INTYPE_INT16",
	"sint32":  "TDH_INTYPE_INT32",
	"sint64":  "TDH_INTYPE_INT64",
	"pointer": "TDH_INTYPE_POINTER",
	"string":  "TDH_INTYPE_UNICODESTRING",
	"object":  "TDH_INTYPE_POINTER",
	"char16":  "TDH_INTYPE_UNICODECHAR",
	"boolean": "TDH_INTYPE_BOOLEAN",
}

// Mappings for format qualifiers
var formatMap = map[string]string{
	"x": "TDH_OUTTYPE_HEXINT32", // Display as hex (pointers will not use this)
	"w": "TDH_OUTTYPE_STRING",   // Wide string
	"c": "TDH_OUTTYPE_STRING",   // ASCII character
	"s": "TDH_OUTTYPE_STRING",   // Null-terminated string
}

// Mappings for extension qualifiers
// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers
var extensionMap = map[string][2]string{
	"Port":     {"TDH_INTYPE_UINT16", "TDH_OUTTYPE_PORT"},
	"IPAddrV6": {"TDH_INTYPE_BINARY", "TDH_OUTTYPE_IPV6"},
	"IPAddrV4": {"TDH_INTYPE_UINT32", "TDH_OUTTYPE_IPV4"},
	"IPAddr":   {"TDH_INTYPE_UINT32", "TDH_OUTTYPE_IPV4"},
	"SizeT":    {"TDH_INTYPE_POINTER", "TDH_OUTTYPE_NULL"}, // instad of deprecated TDH_INTYPE_SIZET
	"Sid":      {"TDH_INTYPE_SID", "TDH_OUTTYPE_STRING"},
	"GUID":     {"TDH_INTYPE_GUID", "TDH_OUTTYPE_GUID"},
	"WmiTime":  {"TDH_INTYPE_UINT64", "TDH_OUTTYPE_DATETIME"},
	// Special cases, not used for kernel MOFs.
	"NoPrint":  {"TDH_INTYPE_BINARY", "TDH_OUTTYPE_NULL"},
	"RString":  {"TDH_INTYPE_ANSISTRING", "TDH_OUTTYPE_STRING"},
	"RWString": {"TDH_INTYPE_UNICODESTRING", "TDH_OUTTYPE_STRING"},
	"Variant":  {"TDH_INTYPE_BINARY", "TDH_OUTTYPE_NULL"},
}
