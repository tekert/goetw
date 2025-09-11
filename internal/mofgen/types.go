package mofgen

type mofParsedProperty struct {
	ID                string // WmiDataId
	Name              string
	InType            string // string constant
	OutType           string // string constant
	Extension         string // e.g., "SizeT", "IPAddr"
	IsArray           string // "true" if is array.
	ArraySize         string // MAX(n)
	SizeFromID        string // WmiSizeIs property ID
	GoType            string // Go type for struct generation
	QualifiersComment string // Formatted qualifiers for comments
}

type mofParsedClass struct {
	Name            string
	Base            string
	GUID            string
	Version         string
	EventTypes      string
	Properties      []mofParsedProperty
	InheritsGUID    bool
	InheritsVersion bool
	MofDefinition   string // Original MOF class definition text
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

// Mappings from MOF types to Go types for struct generation
var goTypeMap = map[string]string{
	"uint8":   "uint8",
	"uint16":  "uint16",
	"uint32":  "uint32",
	"uint64":  "uint64",
	"sint8":   "int8",
	"sint16":  "int16",
	"sint32":  "int32",
	"sint64":  "int64",
	"pointer": "uintptr",
	"string":  "uintptr", // Strings are represented as an offset within UserData.
	"object":  "uintptr",
	"char16":  "uint16",
	"boolean": "uint32", // TDH_INTYPE_BOOLEAN is 4 bytes.
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
	"IPAddrV4": {"TDH_INTYPE_UINT32", "TDH_OUTTYPE_IPV4"}, // unsigned long is uint32 for the microsoft compiler
	"IPAddr":   {"TDH_INTYPE_UINT32", "TDH_OUTTYPE_IPV4"},
	"SizeT":    {"TDH_INTYPE_POINTER", "TDH_OUTTYPE_NULL"},   // instad of deprecated TDH_INTYPE_SIZET
	"Sid":      {"TDH_INTYPE_WBEMSID", "TDH_OUTTYPE_STRING"}, // Sid are TDH_INTYPE_WBEMSID isntead of TDH_INTYPE_SID in MOF according to doc.
	"GUID":     {"TDH_INTYPE_GUID", "TDH_OUTTYPE_GUID"},
	"WmiTime":  {"TDH_INTYPE_UINT64", "TDH_OUTTYPE_DATETIME"}, // This one is the resolution of the WnodeHeader.ClientContext of the session.
	// Special cases, not used for kernel MOFs.
	"NoPrint":  {"TDH_INTYPE_BINARY", "TDH_OUTTYPE_NULL"},
	"RString":  {"TDH_INTYPE_ANSISTRING", "TDH_OUTTYPE_STRING"},
	"RWString": {"TDH_INTYPE_UNICODESTRING", "TDH_OUTTYPE_STRING"},
	"Variant":  {"TDH_INTYPE_BINARY", "TDH_OUTTYPE_NULL"},
}

// Mappings for extension qualifiers to Go types
var goExtensionTypeMap = map[string]string{
	"Port":     "uint16",   // big endian need convert
	"IPAddrV6": "[16]byte", // IPAddrV6 is a 16-byte array IN6_ADDR
	"IPAddrV4": "[4]byte",   // IPAddrV4 is a uint32
	"IPAddr":   "[4]byte",   // IPAddr is a uint32
	"SizeT":    "uintptr",
	"Sid":      "uintptr", // SIDs are variable length with USER_TOKEN and are represented as an offset.
	"GUID":     "GUID",    // Assumes etw.GUID is available in the generated code's package
	"WmiTime":  "uint64",  // FILETIME or session Wnode.ClientContext resolution if raw timestamps
}
