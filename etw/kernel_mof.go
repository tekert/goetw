//go:build windows

package etw

import (
	"fmt"
	"sync"
	"unsafe"
)

type MofKernelNames struct {
	// Class name
	Name string
	// Serves as base to compute event id
	BaseId uint16
}

var (
	// The final event id of Mof Events is computed
	// by BaseId + Opcode. As Opcode is uint8 we jump
	// BaseIds every 0xff so that we do not overlap event
	// ids between classes
	MofClassMapping = map[uint32]MofKernelNames{
		guidToUint("45d8cccd-539f-4b72-a8b7-5c683142609a"): {Name: "ALPC", BaseId: /*0*/ calcBaseId(0)},
		guidToUint("78d14f17-0105-46d7-bfff-6fbea2f3f358"): {Name: "ApplicationVerifier", BaseId: /*255*/ calcBaseId(1)},
		guidToUint("13976d09-a327-438c-950b-7f03192815c7"): {Name: "DbgPrint", BaseId: /*510*/ calcBaseId(2)},
		guidToUint("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "DiskIo", BaseId: /*765*/ calcBaseId(3)},
		guidToUint("bdd865d1-d7c1-11d0-a501-00a0c9062910"): {Name: "DiskPerf", BaseId: /*1020*/ calcBaseId(4)},
		guidToUint("d56ca431-61bf-4904-a621-00e0381e4dde"): {Name: "DriverVerifier", BaseId: /*1275*/ calcBaseId(5)},
		guidToUint("b16f9f5e-b3da-4027-9318-adf2b79df73b"): {Name: "EventLog", BaseId: /*1530*/ calcBaseId(6)},
		guidToUint("01853a65-418f-4f36-aefc-dc0f1d2fd235"): {Name: "EventTraceConfig", BaseId: /*1785*/ calcBaseId(7)},
		guidToUint("90cbdc39-4a3e-11d1-84f4-0000f80464e3"): {Name: "FileIo", BaseId: /*2040*/ calcBaseId(8)},
		guidToUint("8d40301f-ab4a-11d2-9a93-00805f85d7c6"): {Name: "GenericMessage", BaseId: /*2295*/ calcBaseId(9)},
		guidToUint("e8908abc-aa84-11d2-9a93-00805f85d7c6"): {Name: "GlobalLogger", BaseId: /*2550*/ calcBaseId(10)},
		guidToUint("3d6fa8d2-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "HardFault", BaseId: /*2805*/ calcBaseId(11)},
		guidToUint("2cb15d1d-5fc1-11d2-abe1-00a0c911f518"): {Name: "ImageLoad", BaseId: /*3060*/ calcBaseId(12)},
		guidToUint("98a2b9d7-94dd-496a-847e-67a5557a59f2"): {Name: "MsSystemInformation", BaseId: /*3315*/ calcBaseId(13)},
		guidToUint("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "PageFault", BaseId: /*3570*/ calcBaseId(14)},
		guidToUint("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"): {Name: "PerfInfo", BaseId: /*3825*/ calcBaseId(15)},
		guidToUint("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "Process", BaseId: /*4080*/ calcBaseId(16)},
		guidToUint("ae53722e-c863-11d2-8659-00c04fa321a1"): {Name: "Registry", BaseId: /*4335*/ calcBaseId(17)},
		guidToUint("d837ca92-12b9-44a5-ad6a-3a65b3578aa8"): {Name: "SplitIo", BaseId: /*4590*/ calcBaseId(18)},
		guidToUint("9a280ac0-c8e0-11d1-84e2-00c04fb998a2"): {Name: "TcpIp", BaseId: /*4845*/ calcBaseId(19)},
		guidToUint("a1bc18c0-a7c8-11d1-bf3c-00a0c9062910"): {Name: "ThermalZone", BaseId: /*5100*/ calcBaseId(20)},
		guidToUint("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "Thread", BaseId: /*5355*/ calcBaseId(21)},
		guidToUint("398191dc-2da7-11d3-8b98-00805f85d7c6"): {Name: "TraceError", BaseId: /*5610*/ calcBaseId(22)},
		guidToUint("bf3a50c5-a9c9-4988-a005-2df0b7c80f80"): {Name: "UdpIp", BaseId: /*5865*/ calcBaseId(23)},
		guidToUint("44608a51-1851-4456-98b2-b300e931ee41"): {Name: "WmiEventLogger", BaseId: /*6120*/ calcBaseId(24)},
		guidToUint("68fdd900-4a3e-11d1-84f4-0000f80464e3"): {Name: "EventTraceEvent", BaseId: /*6375*/ calcBaseId(25)},
	}

	// Pre-converted UTF-16 string for "MSNT_SystemTrace" to avoid runtime allocations.
	// TODO: put this in generator?
	utf16MSNT_SystemTrace = []uint16{'M', 'S', 'N', 'T', '_', 'S', 'y', 's', 't', 'e', 'm', 'T', 'r', 'a', 'c', 'e', 0}
)

func calcBaseId(index int) uint16 {
	return uint16(index * 0xFF)
}

func guidToUint(guid string) uint32 {
	u := MustParseGUID(guid)
	// Take first 4 bytes of GUID and convert to uint32
	return u.Data1
}

var (
	mofClassLookupMap = make(map[uint64]*MofClassDef) // Lookup by packed key
	MofClassQueryMap  = make(map[string]*MofClassDef) // Lookup by class name

	mofKernelClassLoaded = false
)

// Represents a MOF property definition
type MofPropertyDef struct {
	ID         uint16 // WmiDataId
	Name       string
	NameW      []uint16   // UTF-16 null-terminated name
	InType     TdhInType  // How to read the raw data
	OutType    TdhOutType // How to represent in Go
	Extension  string     // From extension("...") qualifier
	IsArray    bool
	ArraySize  uint32 // MAX(n)
	SizeFromID uint32 // WmiSizeIs("PropName") - ID of property that holds array size
}

// MofClassDef represents a complete MOF class definition
type MofClassDef struct {
	Name       string           // Class name (e.g. "Process_V2_TypeGroup1")
	NameW      []uint16         // UTF-16 null-terminated name
	Base       string           // Base class name (e.g. "Process_V2")
	BaseW      []uint16         // UTF-16 null-terminated base name
	GUID       GUID             // From parent class
	Version    uint8            // From parent class
	EventTypes []uint8          // List of event types this class handles
	Properties []MofPropertyDef // Property definitions

	// --- Caching for buildTraceInfoFromMof ---
	// buildOnce ensures the property template is built only once.
	buildOnce sync.Once
	// propertyInfos contains the pre-built EventPropertyInfo array.
	propertyInfos []byte
	// propertyNamesBlock contains the pre-built concatenated property name strings.
	propertyNamesBlock []byte
}

// MofRegister adds a MOF class definition to the global MofClassQueryMap
// and mofClassLookupMap maps.
// The expensive work of building the property template is deferred until the
// first time the event is actually encountered.
func MofRegister(class *MofClassDef) {
	for _, eventType := range class.EventTypes {
		key := MofPackKey(class.GUID.Data1, class.GUID.Data2, eventType, class.Version)
		mofClassLookupMap[key] = class
	}

	// Register for lookup by name
	MofClassQueryMap[class.Name] = class
}

// MofErLookup finds a MOF class definition by its event record
// A MOF event record is uniquely identified by its provider GUID, event type, and version
func MofErLookup(er *EventRecord) *MofClassDef {
	key := MofPackKey(er.EventHeader.ProviderId.Data1, // guid first 32 bits
		er.EventHeader.ProviderId.Data2,        // guid second 16 bits
		er.EventHeader.EventDescriptor.Opcode,  // EventType 8 bytes
		er.EventHeader.EventDescriptor.Version) // EventVersion 8 bytes

	class, exists := mofClassLookupMap[key]

	if !exists {
		return nil
	}
	return class
}

// MofLookup finds a MOF class definition by its identifiers
// A MOF event record is uniquely identified by its provider GUID, event type, and version
func MofLookup(guid GUID, eventType uint8, version uint8) *MofClassDef {
	key := MofPackKey(guid.Data1, guid.Data2, eventType, version)
	class, exists := mofClassLookupMap[key]
	if !exists {
		return nil
	}
	return class
}

// Bit positions for packing/unpacking
const (
	bGUID_DATA1_SHIFT = 32 // ProviderId (Data1) uses bits 32-63
	bGUID_DATA2_SHIFT = 16 // ProviderId (Data2) uses bits 16-31
	bOPCODE_SHIFT     = 8  // Opcode uses bits 8-15
	bVERSION_SHIFT    = 0  // Version uses lower 8 bits
)

// Pack event identifiers into single uint64
func MofPackKey(providerId uint32, data2 uint16, opcode uint8, version uint8) uint64 {
	return uint64(providerId)<<bGUID_DATA1_SHIFT |
		uint64(data2)<<bGUID_DATA2_SHIFT |
		uint64(opcode)<<bOPCODE_SHIFT |
		uint64(version)<<bVERSION_SHIFT
}

// Unpack for debugging/display
func MofUnpackKey(key uint64) (providerId uint32, data2 uint16, opcode uint8, version uint8) {
	providerId = uint32(key >> bGUID_DATA1_SHIFT)
	data2 = uint16((key >> bGUID_DATA2_SHIFT) & 0xFFFF)
	opcode = uint8((key >> bOPCODE_SHIFT) & 0xFF)
	version = uint8(key & 0xFF)
	return
}

func getTdhInTypeFixedSize(inType TdhInType, er *EventRecord) uint16 {
	switch inType {
	case TDH_INTYPE_INT8, TDH_INTYPE_UINT8, TDH_INTYPE_ANSICHAR:
		return 1
	case TDH_INTYPE_INT16, TDH_INTYPE_UINT16, TDH_INTYPE_UNICODECHAR:
		return 2
	case TDH_INTYPE_INT32, TDH_INTYPE_UINT32, TDH_INTYPE_HEXINT32, TDH_INTYPE_FLOAT, TDH_INTYPE_BOOLEAN:
		return 4
	case TDH_INTYPE_INT64, TDH_INTYPE_UINT64, TDH_INTYPE_HEXINT64, TDH_INTYPE_DOUBLE, TDH_INTYPE_FILETIME:
		return 8
	case TDH_INTYPE_GUID:
		return 16
	case TDH_INTYPE_SYSTEMTIME:
		return 16
	case TDH_INTYPE_POINTER, TDH_INTYPE_SIZET:
		if er != nil {
			return uint16(er.PointerSize())
		}
		// Fallback if er is nil, though it shouldn't be.
		if unsafe.Sizeof(uintptr(0)) == 8 {
			return 8
		}
		return 4
	default:
		return 0 // Variable size
	}
}

const (
	// MismatchNone indicates no differences were found.
	MismatchNone = 0
	// MismatchClassName indicates a difference in TaskName or OpcodeName.
	MismatchClassName = 1
	// MismatchOutTypeStringNull indicates a specific, often benign, difference where one OutType is STRING and the other is NULL.
	MismatchOutTypeStringNull = 2
	// MismatchOther indicates any other difference in headers or properties.
	MismatchOther = 4
)

// buildMofPropertyTemplate is called once per MOF class to pre-build the expensive-to-create
// property information block. It generates a byte slice containing ONLY the EventPropertyInfo
// array. It also pre-calculates the total size of all property name strings.
func (mofClass *MofClassDef) buildMofPropertyTemplate(er *EventRecord) {
	propCount := len(mofClass.Properties)
	if propCount == 0 {
		return
	}

	// --- Pre-calculate sizes and mappings ---
	propInfosSize := propCount * int(unsafe.Sizeof(EventPropertyInfo{}))
	wmiIDToIndex := make(map[uint16]uint16, propCount)
	var totalPropNamesSize int
	for i, prop := range mofClass.Properties {
		wmiIDToIndex[prop.ID] = uint16(i)
		totalPropNamesSize += len(prop.NameW) * 2
	}

	// --- Create and populate the property names block ---
	// This block concatenates all property name strings into a single byte slice.
	mofClass.propertyNamesBlock = make([]byte, totalPropNamesSize)
	currentNameOffset := 0
	for _, propDef := range mofClass.Properties {
		nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&propDef.NameW[0])), len(propDef.NameW)*2)
		copy(mofClass.propertyNamesBlock[currentNameOffset:], nameBytes)
		currentNameOffset += len(nameBytes)
	}

	// --- Create and populate the property info block ---
	mofClass.propertyInfos = make([]byte, propInfosSize)
	eventProperties := unsafe.Slice((*EventPropertyInfo)(unsafe.Pointer(&mofClass.propertyInfos[0])), propCount)

	// This is the exact logic from the original, working buildTraceInfoFromMof function.
	// It populates the `eventProperties` slice.
	// IMPORTANT: Explicitly zero the memory for the property slice.
	clear(eventProperties)

	for i, propDef := range mofClass.Properties {
		epi := &eventProperties[i]

		// NOTE: NameOffset is NOT set here. It must be calculated at runtime
		// relative to the final buffer layout.

		// --- Transform types to mimic TdhGetEventInformation for classic MOF events ---
		finalInType := propDef.InType
		finalOutType := propDef.OutType

		// The API tends to use older, deprecated WBEM types for classic events.
		// We transform our modern MOF definitions to match this legacy behavior,
		// guided by the deprecation comments in tdh.h and observed API behavior.
		switch finalInType {
		case TDH_INTYPE_SID:
			// "TDH_INTYPE_WBEMSID: Deprecated. Prefer TDH_INTYPE_SID."
			// The API provides the deprecated type for classic events.
			finalInType = TDH_INTYPE_WBEMSID
		case TDH_INTYPE_BINARY:
			// "TDH_INTYPE_HEXDUMP: Deprecated. Prefer TDH_INTYPE_BINARY."
			// This transformation is generally correct for HEXBINARY output.
			if finalOutType == TDH_OUTTYPE_HEXBINARY {
				finalInType = TDH_INTYPE_HEXDUMP
			}
		case TDH_INTYPE_POINTER:
			// Use the explicit Extension field set by the generator, which is more reliable
			// than checking the property name.
			if propDef.Extension == "SizeT" {
				finalInType = TDH_INTYPE_SIZET
			}
		case TDH_INTYPE_UINT16:
			// "TDH_INTYPE_UNICODECHAR: Deprecated. Prefer TDH_INTYPE_UINT16 with TDH_OUTTYPE_STRING."
			if finalOutType == TDH_OUTTYPE_STRING {
				finalInType = TDH_INTYPE_UNICODECHAR
			}
		case TDH_INTYPE_UINT8:
			// "TDH_INTYPE_ANSICHAR: Deprecated. Prefer TDH_INTYPE_UINT8 with TDH_OUTTYPE_STRING."
			if finalOutType == TDH_OUTTYPE_STRING {
				finalInType = TDH_INTYPE_ANSICHAR
			}
		}

		// The API often uses a NULL OutType for strings and GUIDs, relying on the InType.
		if propDef.InType == TDH_INTYPE_UNICODESTRING ||
			propDef.InType == TDH_INTYPE_ANSISTRING ||
			propDef.InType == TDH_INTYPE_GUID {
			finalOutType = TDH_OUTTYPE_NULL
		}
		// --- End of transformation ---

		// Set types
		epi.SetInType(finalInType)
		epi.SetOutType(finalOutType)

		// Set fixed length for scalar types
		if !propDef.IsArray && propDef.SizeFromID == 0 {
			if fixedSize := getTdhInTypeFixedSize(propDef.InType, er); fixedSize > 0 {
				epi.SetLength(fixedSize)
				// epi.Flags |= PropertyParamFixedLength // This flag should not be set for implicitly sized MOF types.
			} else if propDef.InType == TDH_INTYPE_BINARY && propDef.OutType == TDH_OUTTYPE_IPV6 {
				// Special case for IPV6 addresses, which have a fixed length of 16
				// but are of InType BINARY (which is normally variable length).
				epi.SetLength(16)
				epi.Flags |= PropertyParamFixedLength
			}
		}

		// Set length/count for arrays
		if propDef.IsArray {
			epi.SetCount(uint16(propDef.ArraySize))
			// For legacy MOF events, the API doesn't seem to set PropertyParamFixedCount.
			// The presence of a Count > 1 is enough to indicate an array.
			// epi.Flags |= PropertyParamFixedCount

			// The API also sets the Length to the size of a single array element.
			if elementSize := getTdhInTypeFixedSize(propDef.InType, er); elementSize > 0 {
				epi.SetLength(elementSize)
			}
		} else {
			epi.SetCount(1) // For non-array properties, count is 1.
		}
	}

	// Second pass to resolve dynamic array counts (WmiSizeIs)
	for i, propDef := range mofClass.Properties {
		if propDef.SizeFromID != 0 {
			// Use the locally-calculated map.
			if countPropIndex, ok := wmiIDToIndex[uint16(propDef.SizeFromID)]; ok {
				eventProperties[i].Flags |= PropertyParamCount
				eventProperties[i].SetCountPropertyIndex(countPropIndex)
			}
		}
	}
}

// buildTraceInfoFromMof constructs a TRACE_EVENT_INFO structure from a registered MOF class definition.
// This serves as a fallback when TdhGetEventInformation fails for classic kernel events.
// It reuses the provided teiBuffer to avoid allocations.
func buildTraceInfoFromMof(er *EventRecord, teiBuffer *[]byte) (tei *TraceEventInfo, err error) {
	mofClass := MofErLookup(er)
	if mofClass == nil {
		return nil,
			fmt.Errorf("MOF class definition not found for event with GUID %s, Opcode %d, Version %d : %v",
				er.EventHeader.ProviderId.String(),
				er.EventHeader.EventDescriptor.Opcode,
				er.EventHeader.EventDescriptor.Version,
				ErrBuildTraceInfoFromMof)
	}

	// On the first encounter with this event type, run the expensive template generation.
	// sync.Once ensures this happens safely and only one time across all goroutines.
	mofClass.buildOnce.Do(func() {
		mofClass.buildMofPropertyTemplate(er)
	})

	// The layout of our buffer will be:
	// 1. TRACE_EVENT_INFO struct
	// 2. Array of EVENT_PROPERTY_INFO structs
	// 3. All strings (Provider, Task, Opcode, then all property names)

	propCount := len(mofClass.Properties)
	propInfosSize := len(mofClass.propertyInfos)
	propNamesSize := len(mofClass.propertyNamesBlock)

	// --- Calculate required buffer size ---
	providerNameSize := len(utf16MSNT_SystemTrace) * 2
	taskNameSize := len(mofClass.BaseW) * 2
	opcodeNameSize := len(mofClass.NameW) * 2

	traceEventInfoBaseSize := int(unsafe.Offsetof(TraceEventInfo{}.EventPropertyInfoArray))
	requiredSize := traceEventInfoBaseSize +
		propInfosSize +
		providerNameSize +
		taskNameSize +
		opcodeNameSize +
		propNamesSize

	// Resize the provided buffer if it's too small.
	if cap(*teiBuffer) < requiredSize {
		*teiBuffer = make([]byte, requiredSize)
	}
	*teiBuffer = (*teiBuffer)[:requiredSize]
	buffer := *teiBuffer // Use a local variable for convenience.

	// 1. Populate the TRACE_EVENT_INFO header.
	tei = (*TraceEventInfo)(unsafe.Pointer(&buffer[0]))
	tei.ProviderGUID = *systemTraceControlGuid
	tei.EventGUID = mofClass.GUID
	tei.EventDescriptor = er.EventHeader.EventDescriptor
	tei.DecodingSource = DecodingSourceWbem
	tei.PropertyCount = uint32(propCount)
	tei.TopLevelPropertyCount = uint32(propCount) // MOF properties are flat.
	tei.Flags = TEMPLATE_EVENT_DATA

	// 2. Copy the pre-built property info block into the correct location.
	propInfoArrayStartOffset := traceEventInfoBaseSize
	copy(buffer[propInfoArrayStartOffset:], mofClass.propertyInfos)

	// 3. Define the starting point for all strings, which is right after the property array.
	currentStringOffset := propInfoArrayStartOffset + propInfosSize

	// 4. Write metadata strings and set their absolute offsets.
	tei.ProviderNameOffset = uint32(currentStringOffset)
	copy(buffer[currentStringOffset:], unsafe.Slice((*byte)(unsafe.Pointer(&utf16MSNT_SystemTrace[0])), providerNameSize))
	currentStringOffset += providerNameSize

	tei.TaskNameOffset = uint32(currentStringOffset)
	copy(buffer[currentStringOffset:], unsafe.Slice((*byte)(unsafe.Pointer(&mofClass.BaseW[0])), taskNameSize))
	currentStringOffset += taskNameSize

	tei.OpcodeNameOffset = uint32(currentStringOffset)
	copy(buffer[currentStringOffset:], unsafe.Slice((*byte)(unsafe.Pointer(&mofClass.NameW[0])), opcodeNameSize))
	currentStringOffset += opcodeNameSize

	// 5. Copy the entire block of pre-built property names. This replaces the slow loop.
	copy(buffer[currentStringOffset:], mofClass.propertyNamesBlock)

	// 6. Get a slice to the property array we just copied into the buffer.
	eventProperties := unsafe.Slice((*EventPropertyInfo)(unsafe.Pointer(&buffer[propInfoArrayStartOffset])), propCount)

	// 7. Fix up the NameOffset for each property.
	for i, propDef := range mofClass.Properties {
		eventProperties[i].NameOffset = uint32(currentStringOffset)
		currentStringOffset += len(propDef.NameW) * 2
	}

	return tei, nil
}

// Loads custom kernel MOF classes into the global registry (only for parsing purposes)
func init() {

	// Event 84 is not defined in the kernel MOF classes or the web, but maybe it's a special event
	// from the hex data, the only similar event is FileIo_Info
	/* UsarData Memory Dump examples (40 bytes):
	f810d5710ad2ffff 5037b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 dc700000 00000000
	38717b760ad2ffff d043b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 a42d0000 00000000
	f8403a7b0ad2ffff a064b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 94760000 00000000
	f8708f6d0ad2ffff d043b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 4c550000 00000000
	f8403a7b0ad2ffff a064b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 94760000 00000000
	f810d5710ad2ffff c035b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 dc700000 00000000
	IrpPtr           FileObject  	  FileKey          ?                TTID?    InfoClass?
	*/
	// TODO(tekert): Find the correct definition for this event
	var FileIo_V3_Type8X = &MofClassDef{
		Name:       "FileIo_V3_TypeX",
		NameW:      []uint16{'F', 'i', 'l', 'e', 'I', 'o', '_', 'T', 'y', 'p', 'e', '8', '4', 0},
		Base:       "FileIo",
		BaseW:      []uint16{'F', 'i', 'l', 'e', 'I', 'o', 0},
		GUID:       *MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}"), // FileIo GUID
		Version:    3,
		EventTypes: []uint8{83, 84},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "IrpPtr", NameW: []uint16{'I', 'r', 'p', 'P', 't', 'r', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 2, Name: "FileObject", NameW: []uint16{'F', 'i', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 3, Name: "FileKey", NameW: []uint16{'F', 'i', 'l', 'e', 'K', 'e', 'y', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 4, Name: "ExtraInfo", NameW: []uint16{'E', 'x', 't', 'r', 'a', 'I', 'n', 'f', 'o', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 5, Name: "TTID", NameW: []uint16{'T', 'T', 'I', 'D', 0}, InType: TDH_INTYPE_UINT32},
			{ID: 6, Name: "InfoClass", NameW: []uint16{'I', 'n', 'f', 'o', 'C', 'l', 'a', 's', 's', 0}, InType: TDH_INTYPE_UINT32},
		},
	}

	// FileIo, Version 3, Opcodes 37 (MapFile) and 38 (UnmapFile) are not in the system manifest.
	// The structure is similar to FileIo_V2_MapFile but with an extra 4-byte field at the end.
	// UserData is 44 bytes.
	/*
	   Example UserData (Opcode 37):
	   0000d9aff77f0000 7011969a85e6ffff 0000000000004700 0010050000000000 0040040000000000 00000000
	   FileObject (ptr) ImageBase (ptr)  ViewBase (ptr)   PageProtection   ProcessId        FileKey (ptr)    Reserved
	*/
	// TODO(tekert): Find the correct definition for this event
	var FileIo_V3_MapFile = &MofClassDef{
		Name:       "FileIo_V3_MapFile",
		NameW:      []uint16{'F', 'i', 'l', 'e', 'I', 'o', '_', 'V', '3', '_', 'M', 'a', 'p', 'F', 'i', 'l', 'e', 0},
		Base:       "FileIo",
		BaseW:      []uint16{'F', 'i', 'l', 'e', 'I', 'o', 0},
		GUID:       *MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}"), // FileIo GUID
		Version:    3,
		EventTypes: []uint8{37, 38, 39},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "FileObject", NameW: []uint16{'F', 'i', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 2, Name: "ImageBase", NameW: []uint16{'I', 'm', 'a', 'g', 'e', 'B', 'a', 's', 'e', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 3, Name: "ViewBase", NameW: []uint16{'V', 'i', 'e', 'w', 'B', 'a', 's', 'e', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 4, Name: "PageProtection", NameW: []uint16{'P', 'a', 'g', 'e', 'P', 'r', 'o', 't', 'e', 'c', 't', 'i', 'o', 'n', 0}, InType: TDH_INTYPE_UINT32},
			{ID: 5, Name: "ProcessId", NameW: []uint16{'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', 0}, InType: TDH_INTYPE_UINT32},
			{ID: 6, Name: "FileKey", NameW: []uint16{'F', 'i', 'l', 'e', 'K', 'e', 'y', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 7, Name: "Reserved", NameW: []uint16{'R', 'e', 's', 'e', 'r', 'v', 'e', 'd', 0}, InType: TDH_INTYPE_UINT32},
		},
	}

	// ALPC, Version 2, Opcodes 38 and 41 are not in the system manifest.
	// UserData is 4 bytes.
	/*
		Example UserData (Opcode 38): 88200100
		Example UserData (Opcode 41): 1c230100
		Example UserData (Opcode 39): b8250100
		Likely a single UINT32 field.
	*/
	// TODO(tekert): Find the correct definition for this event
	var ALPC_V2_Type3X = &MofClassDef{
		Name:       "ALPC_V2_Type38",
		NameW:      []uint16{'A', 'L', 'P', 'C', '_', 'V', '2', '_', 'T', 'y', 'p', 'e', '3', '8', 0},
		Base:       "ALPC",
		BaseW:      []uint16{'A', 'L', 'P', 'C', 0},
		GUID:       *MustParseGUID("{45d8cccd-539f-4b72-a8b7-5c683142609a}"), // ALPC GUID
		Version:    2,
		EventTypes: []uint8{38, 39, 41},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "Data", NameW: []uint16{'D', 'a', 't', 'a', 0}, InType: TDH_INTYPE_UINT32},
		},
	}

	// Event 33 is not defined in the kernel MOF classes or the web, but maybe it's a special event
	// ?                 ?                  KeyHandle        KeyName
	// 00000000 00000000 00000000 00000000  605c8bda8cbeffff <unicode string>
	// TODO(tekert): Find the correct definition for this event
	var Registry_V2_Type33 = &MofClassDef{
		Name:       "Registry_Type33",
		NameW:      []uint16{'R', 'e', 'g', 'i', 's', 't', 'r', 'y', '_', 'T', 'y', 'p', 'e', '3', '3', 0},
		Base:       "Registry",
		BaseW:      []uint16{'R', 'e', 'g', 'i', 's', 't', 'r', 'y', 0},
		GUID:       *MustParseGUID("{ae53722e-c863-11d2-8659-00c04fa321a1}"), // Registry
		Version:    2,
		EventTypes: []uint8{33},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "InitialTime", NameW: []uint16{'I', 'n', 'i', 't', 'i', 'a', 'l', 'T', 'i', 'm', 'e', 0}, InType: TDH_INTYPE_INT64},
			{ID: 2, Name: "Status", NameW: []uint16{'S', 't', 'a', 't', 'u', 's', 0}, InType: TDH_INTYPE_UINT32},
			{ID: 3, Name: "Index", NameW: []uint16{'I', 'n', 'd', 'e', 'x', 0}, InType: TDH_INTYPE_UINT32},
			{ID: 4, Name: "KeyHandle", NameW: []uint16{'K', 'e', 'y', 'H', 'a', 'n', 'd', 'l', 'e', 0}, InType: TDH_INTYPE_POINTER},
			{ID: 5, Name: "KeyName", NameW: []uint16{'K', 'e', 'y', 'N', 'a', 'm', 'e', 0}, InType: TDH_INTYPE_UNICODESTRING, OutType: TDH_OUTTYPE_STRING},
		},
	}

	MofRegister(FileIo_V3_Type8X)
	MofRegister(FileIo_V3_MapFile)
	MofRegister(Registry_V2_Type33)
	MofRegister(ALPC_V2_Type3X)
}
