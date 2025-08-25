//go:build windows

package etw

import (
	"fmt"
	"strings"
	"unsafe"
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-tdh_context
// v10.0.19041.0 /tdh.h
/*
	Decoding configuration parameters used with TdhGetDecodingParameter,
	TdhSetDecodingParameter, TdhGetEventInformation, TdhGetProperty,
	TdhGetPropertySize, and TdhEnumerateProviderFilters.

	Note that the TDH_CONTEXT_WPP_GMT and TDH_CONTEXT_PDB_PATH parameter types are
	only used by TdhGetDecodingParameter and TdhSetDecodingParameter. They are
	ignored by TdhGetEventInformation and TdhGetProperty.
*/
// typedef struct _TDH_CONTEXT {
//     ULONGLONG ParameterValue; /* For GMT or POINTERSIZE, directly stores the
//         parameter's integer value. For other types, stores an LPCWSTR pointing
//         to a nul-terminated string with the parameter value. */
//     TDH_CONTEXT_TYPE ParameterType;
//     ULONG ParameterSize; /* Reserved. Set to 0. */
// } TDH_CONTEXT;
type TdhContext struct {
	// For GMT or POINTERSIZE, directly stores the
	// parameter's integer value. For other types, stores an LPCWSTR pointing
	// to a nul-terminated string with the parameter value.
	ParameterValue uint64
	ParameterType  TdhContextType
	ParameterSize  uint32 // Reserved. Set to 0.
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-tdh_context_type
// v10.0.19041.0 /tdh.h
/*
typedef enum _TDH_CONTEXT_TYPE {
	TDH_CONTEXT_WPP_TMFFILE,
	TDH_CONTEXT_WPP_TMFSEARCHPATH,
	TDH_CONTEXT_WPP_GMT,
	TDH_CONTEXT_POINTERSIZE,
	TDH_CONTEXT_PDB_PATH,
	TDH_CONTEXT_MAXIMUM
} TDH_CONTEXT_TYPE;
*/
type TdhContextType int32

// Defines the context type.
const (
	/* LPCWSTR path to the TMF file for a WPP event. */
	TDH_CONTEXT_WPP_TMFFILE = TdhContextType(0)

	/* LPCWSTR semicolon-separated list of
	   directories to search for the TMF file for a WPP event. Only files
	   with the name [ProviderId].TMF will be found during the search. */
	TDH_CONTEXT_WPP_TMFSEARCHPATH = TdhContextType(1)

	/* Integer value. If set to 1, the TdhGetWppProperty
	   and TdhGetWppMessage functions will format a WPP event's timestamp in
	   UTC (GMT). By default, the timestamp is formatted in local time. */
	TDH_CONTEXT_WPP_GMT = TdhContextType(2)

	/* Integer value, set to 4 or 8. Used when
	   decoding POINTER or SIZE_T fields on WPP events that do not set a
	   pointer size in the event header. If the event does not set a pointer
	   size in the event header and this context is not set, the decoder will
	   use the pointer size of the current process. */
	TDH_CONTEXT_POINTERSIZE = TdhContextType(3)

	/* LPCWSTR semicolon-separated list of PDB files
	to be search for decoding information when decoding an event using
	TdhGetWppProperty or TdhGetWppMessage. (Not used by TdhGetProperty
	or TdhGetEventInformation.) */
	TDH_CONTEXT_PDB_PATH = TdhContextType(4)

	TDH_CONTEXT_MAXIMUM = TdhContextType(5)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-property_data_descriptor
// v10.0.19041.0 /tdh.h
/*
typedef struct _PROPERTY_DATA_DESCRIPTOR {
    ULONGLONG PropertyName;                // Pointer to property name.
    ULONG ArrayIndex;                      // Array Index.
    ULONG Reserved;
} PROPERTY_DATA_DESCRIPTOR;
*/

// Defines the property to retrieve.
type PropertyDataDescriptor struct {
	PropertyName uint64 // Pointer to property name.
	ArrayIndex   uint32 // Array Index.
	Reserved     uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_field_infoarray
// v10.0.19041.0 /tdh.h
/*
typedef struct _PROVIDER_FIELD_INFOARRAY {
    ULONG NumberOfElements;
    EVENT_FIELD_TYPE FieldType;
    PROVIDER_FIELD_INFO FieldInfoArray[ANYSIZE_ARRAY];
} PROVIDER_FIELD_INFOARRAY;
*/

// Defines metadata information about the requested field.
type ProviderFieldInfoArray struct {
	NumberOfElements uint32
	FieldType        EventFieldType       // This field is initially an enum so I guess it has the size of an int; NOTE(tekert): correct
	FieldInfoArray   [1]ProviderFieldInfo // This is a variable size array in C
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_field_info
// v10.0.19041.0 /tdh.h
/*
typedef struct _PROVIDER_FIELD_INFO {
    ULONG NameOffset;                  // English only.
    ULONG DescriptionOffset;           // Localizable String.
    ULONGLONG Value;
} PROVIDER_FIELD_INFO;
*/

// Defines the field information.
type ProviderFieldInfo struct {
	NameOffset        uint32 // English only.
	DescriptionOffset uint32 // Localizable String.
	Value             uint64
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-event_field_type
// v10.0.19041.0 /tdh.h (expanded with numbers)
/*
typedef enum _EVENT_FIELD_TYPE {
  EventKeywordInformation   = 0,
  EventLevelInformation     = 1,
  EventChannelInformation   = 2,
  EventTaskInformation      = 3,
  EventOpcodeInformation    = 4,
  EventInformationMax       = 5
} EVENT_FIELD_TYPE;
*/
type EventFieldType int32

// Defines the provider information to retrieve.
const (
	EventKeywordInformation = EventFieldType(0)
	EventLevelInformation   = EventFieldType(1)
	EventChannelInformation = EventFieldType(2)
	EventTaskInformation    = EventFieldType(3)
	EventOpcodeInformation  = EventFieldType(4)
	EventInformationMax     = EventFieldType(5)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_enumeration_info
// v10.0.19041.0 /tdh.h
/*
typedef struct _PROVIDER_ENUMERATION_INFO {
    ULONG NumberOfProviders;
    ULONG Reserved;
    _Field_size_(NumberOfProviders) TRACE_PROVIDER_INFO TraceProviderInfoArray[ANYSIZE_ARRAY];
} PROVIDER_ENUMERATION_INFO;
*/

// Defines the array of providers that have registered a MOF or manifest on the computer.
type ProviderEnumerationInfo struct {
	NumberOfProviders      uint32
	Reserved               uint32
	TraceProviderInfoArray [1]TraceProviderInfo // This is a variable size array in C
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_provider_info
// v10.0.19041.0 /tdh.h
/*
typedef struct _TRACE_PROVIDER_INFO {
    GUID ProviderGuid;
    ULONG SchemaSource;
    ULONG ProviderNameOffset;
} TRACE_PROVIDER_INFO;
*/

// Defines the GUID and name for a provider.
type TraceProviderInfo struct {
	ProviderGuid       GUID
	SchemaSource       uint32
	ProviderNameOffset uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info
// v10.0.19041.0 /tdh.h (comments from source where moved to go interface,
// and some remarks from lean.microsoft where put on this C interface)
//
// sizeof(TRACE_EVENT_INFO) = 136 bytes
//
/*
typedef struct _TRACE_EVENT_INFO {
  GUID                ProviderGuid;
  GUID                EventGuid;
  EVENT_DESCRIPTOR    EventDescriptor;
  DECODING_SOURCE     DecodingSource;
  ULONG               ProviderNameOffset;
  ULONG               LevelNameOffset;
  ULONG               ChannelNameOffset;
  ULONG               KeywordsNameOffset;
  ULONG               TaskNameOffset;
  ULONG               OpcodeNameOffset;
  ULONG               EventMessageOffset;
  ULONG               ProviderMessageOffset;
  ULONG               BinaryXMLOffset;
  ULONG               BinaryXMLSize;
  union {
    ULONG EventNameOffset;
    ULONG ActivityIDNameOffset; // Supported for classic ETW events only. // MOF and WPP?
  };
  union {
    ULONG EventAttributesOffset;
    ULONG RelatedActivityIDNameOffset; //  Supported for legacy (broader term) ETW events only. // MOF and WPP
  };
  ULONG               PropertyCount;
  ULONG               TopLevelPropertyCount;
  union {
    TEMPLATE_FLAGS Flags;
    struct {
      ULONG Reserved : 4;
      ULONG Tags : 28;
    };
  };
  EVENT_PROPERTY_INFO EventPropertyInfoArray[ANYSIZE_ARRAY];
} TRACE_EVENT_INFO;
*/
// Defines the information about the event.
type TraceEventInfo struct {

	/* The meaning of this field depends on DecodingSource.
	   - XMLFile: ProviderGuid contains the decode GUID (the provider GUID of
	     the manifest).
	   - Wbem: If EventGuid is GUID_NULL, ProviderGuid contains the decode
	     GUID. Otherwise, ProviderGuid contains the control GUID.
	   - WPP: ProviderGuid is not used (always GUID_NULL).
	   - Tlg: ProviderGuid contains the control GUID. */
	ProviderGUID GUID

	/* The meaning of this field depends on DecodingSource.
	   - XMLFile: If the provider specifies a controlGuid, EventGuid contains
	     the controlGuid and Flags contains TEMPLATE_CONTROL_GUID. Otherwise,
	     if the event's Task specifies an eventGUID, EventGuid contains the
	     eventGUID. Otherwise, EventGuid is GUID_NULL.
	   - Wbem: If EventGuid is not GUID_NULL, it is the decode GUID.
	   - WPP: EventGuid contains the decode GUID.
	   - Tlg: EventGuid is not used (always GUID_NULL). */
	EventGUID GUID

	EventDescriptor    EventDescriptor
	DecodingSource     DecodingSource
	ProviderNameOffset uint32
	LevelNameOffset    uint32
	ChannelNameOffset  uint32
	KeywordsNameOffset uint32

	/* Meaning of this field depends on DecodingSource.
	   - XMLFile: The offset to the name of the associated task.
	   - Wbem: The offset to the event's MOF "DisplayName" property. For many
	     Wbem providers, ProviderName is a provider category and TaskName is
	     the provider subcategory.
	   - WPP: Not used.
	   - Tlg: The offset to the name of the event. */
	TaskNameOffset uint32

	/* Meaning of this field depends on DecodingSource.
	   - XMLFile: The offset to the name of the associated opcode.
	   - Wbem: The offset to the event's MOF "EventTypeName" property. For
	     many Wbem providers, OpcodeName is the event's name.
	   - WPP: Not used.
	   - Tlg: The offset to the name of the associated opcode. */
	OpcodeNameOffset uint32

	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32 // reserved
	BinaryXMLSize         uint32 // reserved

	/* - EventNameOffset */
	/* Event name for manifest-based events.
	This field is valid only if DecodingSource is set to
	DecodingSourceXMLFile or DecodingSourceTlg.

	EventNameOffset contains the offset from the beginning of this
	structure to a nul-terminated Unicode string that contains the
	event's name.

	This field will be 0 if the event does not have an assigned name or
	if this event is decoded on a system that does not support decoding
	manifest event names. Event name decoding is supported on Windows
	10 Fall Creators Update (2017) and later. */
	// OR
	/* - ActivityIDNameOffset */
	/* Activity ID name for WBEM events.
	This field is valid only if DecodingSource is set to
	DecodingSourceWbem.

	ActivityIDNameOffset contains the offset from the beginning of this
	structure to a nul-terminated Unicode string that contains the
	property name of the activity identifier in the MOF class. */
	Union1 uint32 // (EventNameOffset | ActivityIDNameOffset)

	/* - EventAttributesOffset */
	/* Attributes for manifest-based events.
	This field is valid only if DecodingSource is set to
	DecodingSourceXMLFile.

	EventAttributesOffset contains the offset from the beginning of
	this structure to a nul-terminated Unicode string that contains a
	semicolon-separated list of name=value attributes associated with
	the event.

	This field will be 0 if the event does not have attributes or if
	this event is decoded on a system that does not support decoding
	manifest event attributes. Attribute decoding is supported on
	Windows 10 Fall Creators Update (2017) and later.

	Defined attributes include:
	FILE=Filename of source code associated with event;
	LINE=Line number of source code associated with event;
	COL=Column of source code associated with event;
	FUNC=Function name associated with event;
	MJ=Major component associated with event;
	MN=Minor component associated with event.

	Values containing semicolons or double-quotes should be quoted
	using double-quotes. Double-quotes within the value should be
	doubled. Example string:
	FILE=source.cpp;LINE=123;MJ="Value; ""Quoted""" */
	// OR
	/* - RelatedActivityIDNameOffset */
	/* Related activity ID name (WBEM).
	This field is valid only if DecodingSource is set to
	DecodingSourceWbem.

	RelatedActivityIDNameOffset contains the offset from the beginning
	of this structure to a nul-terminated Unicode string that contains
	the property name of the related activity identifier in the MOF
	class. */
	Union2 uint32 // (EventAttributesOffset | RelatedActivityIDNameOffset)

	PropertyCount         uint32 // Number of properties in the event.
	TopLevelPropertyCount uint32 // This number does not include members of structures

	Flags                  TemplateFlags
	EventPropertyInfoArray [1]EventPropertyInfo // This is a variable size array
	// This means that in memory after this struct ends there can be
	// 0 to n EventPropertyInfo{} structs, the first one is always on
	// the struct itself.
}

func (t *TraceEventInfo) pointer() uintptr {
	return uintptr(unsafe.Pointer(t))
}

func (t *TraceEventInfo) pointerOffset(offset uintptr) uintptr {
	return t.pointer() + offset
}

func (t *TraceEventInfo) stringAt(offset uintptr) string {
	if offset > 0 {
		return FromUTF16AtOffset(t.pointer(), offset)
	}
	return ""
}

func (t *TraceEventInfo) cleanStringAt(offset uintptr) string {
	if offset > 0 {
		return strings.Trim(t.stringAt(offset), " ")
	}
	return ""
}

func (t *TraceEventInfo) EventID() uint16 {
	if t.IsXML() {
		return t.EventDescriptor.Id
	} else if t.IsMof() {
		if c, ok := MofClassMapping[t.EventGUID.Data1]; ok {
			return c.BaseId + uint16(t.EventDescriptor.Opcode)
		}
	}
	// not meaningful, cannot be used to identify event
	return 0
}

func (t *TraceEventInfo) EventMessage() string {
	return t.cleanStringAt(uintptr(t.EventMessageOffset))
}
func (t *TraceEventInfo) ProviderMessage() string {
	return t.cleanStringAt(uintptr(t.ProviderMessageOffset))
}

func (t *TraceEventInfo) ProviderName() string {
	return t.cleanStringAt(uintptr(t.ProviderNameOffset))
}

func (t *TraceEventInfo) LevelName() string {
	return t.cleanStringAt(uintptr(t.LevelNameOffset))
}

/*
Meaning of this field depends on DecodingSource.
  - XMLFile: The offset to the name of the associated task.
  - Wbem: The offset to the event's MOF "DisplayName" property. For many
    Wbem providers, ProviderName is a provider category and TaskName is
    the provider subcategory.
  - WPP: Not used.
  - Tlg: The offset to the name of the event.
*/
func (t *TraceEventInfo) TaskName() string {
	return t.cleanStringAt(uintptr(t.TaskNameOffset))
}

// Source docs:
/* Meaning of this field depends on DecodingSource.
- XMLFile: The offset to the name of the associated opcode.
- Wbem: The offset to the event's MOF "EventTypeName" property. For
	many Wbem providers, OpcodeName is the event's name.
- WPP: Not used.
- Tlg: The offset to the name of the associated opcode. */
func (t *TraceEventInfo) OpcodeName() string {
	return t.cleanStringAt(uintptr(t.OpcodeNameOffset))
}

// Returs a list of keyword names [DELETE]
// func (t *TraceEventInfo) KeywordsName_inneficient() []string {
// 	var names []string
// 	var offset = t.KeywordsNameOffset
// 	for str := t.cleanStringAt(uintptr(offset)); str != ""; {
// 		names = append(names, str)
// 		offset += uint32(len(str)+1)*2 // *2 for UTF16
// 	}
// 	return names
// }

// Returs a list of keyword names (2x faster)
func (t *TraceEventInfo) KeywordsName() []string {
	var names []string
	if t.KeywordsNameOffset > 0 {
		var pKeyword = (*uint16)(unsafe.Add(unsafe.Pointer(t), t.KeywordsNameOffset))
		// The list is terminated with two null characters.
		for *pKeyword != 0 {
			utf8Key := FromUTF16Pointer(pKeyword)
			names = append(names, utf8Key)
			// Advance pointer by string length + 1 (null terminator)
			strLen := uintptr(Wcslen(pKeyword)+1) * 2 // *2 for UTF16
			pKeyword = (*uint16)(unsafe.Add(unsafe.Pointer(pKeyword), strLen))
		}
	}
	return names
}

func (t *TraceEventInfo) ChannelName() string {
	return t.cleanStringAt(uintptr(t.ChannelNameOffset))
}

// Seems to be always empty
// *NOTE(tekert): thats because this is supported for classic (MOF) ETW events only.
//
// Source docs:
/*  Activity ID name for WBEM events.
This field is valid only if DecodingSource is set to
DecodingSourceWbem.

ActivityIDNameOffset contains the offset from the beginning of this
structure to a nul-terminated Unicode string that contains the
property name of the activity identifier in the MOF class.
Supported for classic ETW events only. */
func (t *TraceEventInfo) ActivityIDName() string {
	if t.IsMof() {
		return t.stringAt(uintptr(t.Union1))
	}
	// not meaningful, cannot be used to identify event
	return ""
}

//
// Source docs:
/*
Event name for manifest-based events.
This field is valid only if DecodingSource is set to
DecodingSourceXMLFile or DecodingSourceTlg.

EventNameOffset contains the offset from the beginning of this
structure to a nul-terminated Unicode string that contains the
event's name.

This field will be 0 if the event does not have an assigned name or
if this event is decoded on a system that does not support decoding
manifest event names. Event name decoding is supported on Windows
10 Fall Creators Update (2017) and later.
*/
func (t *TraceEventInfo) EventName() string {
	if (t.DecodingSource == DecodingSourceXMLFile) ||
		(t.DecodingSource == DecodingSourceTlg) {
		return t.stringAt(uintptr(t.Union1))
	}
	// not meaningful, cannot be used to identify event
	return ""
}

// Seems to be always empty
// *NOTE(tekert): that is because is Supported for legacy ETW events only.
//
// Source docs:
/*
Related activity ID name (WBEM).
This field is valid only if DecodingSource is set to
DecodingSourceWbem.

RelatedActivityIDNameOffset contains the offset from the beginning
of this structure to a nul-terminated Unicode string that contains
the property name of the related activity identifier in the MOF
class. */
func (t *TraceEventInfo) RelatedActivityIDName() string {
	if t.IsMof() {
		return t.stringAt(uintptr(t.Union2))
	}
	// not meaningful, cannot be used to identify event
	return ""
}

// Source docs:
/*
	Attributes for manifest-based events.
	This field is valid only if DecodingSource is set to
	DecodingSourceXMLFile.

	EventAttributesOffset contains the offset from the beginning of
	this structure to a nul-terminated Unicode string that contains a
	semicolon-separated list of name=value attributes associated with
	the event.

	This field will be 0 if the event does not have attributes or if
	this event is decoded on a system that does not support decoding
	manifest event attributes. Attribute decoding is supported on
	Windows 10 Fall Creators Update (2017) and later.

	Defined attributes include:
	FILE=Filename of source code associated with event;
	LINE=Line number of source code associated with event;
	COL=Column of source code associated with event;
	FUNC=Function name associated with event;
	MJ=Major component associated with event;
	MN=Minor component associated with event.

	Values containing semicolons or double-quotes should be quoted
	using double-quotes. Double-quotes within the value should be
	doubled. Example string:
	FILE=source.cpp;LINE=123;MJ="Value; ""Quoted"""
*/
func (t *TraceEventInfo) EventAttributes() string {
	if t.IsXML() {
		return t.stringAt(uintptr(t.Union2))
	}
	// not meaningful, cannot be used to identify event
	return ""
}

// Is Classic ETW event
func (t *TraceEventInfo) IsMof() bool {
	return t.DecodingSource == DecodingSourceWbem
}

// Is Modern ETW event
func (t *TraceEventInfo) IsXML() bool {
	return t.DecodingSource == DecodingSourceXMLFile
}

// Is Classic ETW event
func (t *TraceEventInfo) IsWPP() bool {
	return t.DecodingSource == DecodingSourceWPP
}

// Access the EventPropertyInfo block at index i (they are contiguous in memory)
func (t *TraceEventInfo) GetEventPropertyInfoAt(i uint32) *EventPropertyInfo {
	if i < t.PropertyCount {
		pEpi := uintptr(unsafe.Pointer(&t.EventPropertyInfoArray[0]))
		pEpi += uintptr(i) * unsafe.Sizeof(EventPropertyInfo{})
		// this line triggers checkptr
		// I guess that is because TraceInfo is variable size C
		// struct we had to hack with to make it compatible with Go
		return ((*EventPropertyInfo)(unsafe.Pointer(pEpi)))
	}
	panic(fmt.Errorf("index out of range"))
}

func (t *TraceEventInfo) PropertyNamePointer(i uint32) uintptr {
	return t.pointer() + uintptr(t.GetEventPropertyInfoAt(i).NameOffset)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source
// v10.0.19041.0 /tdh.h
/*
typedef enum _DECODING_SOURCE {
  DecodingSourceXMLFile   = 0,
  DecodingSourceWbem      = 1,
  DecodingSourceWPP       = 2,
  DecodingSourceTlg       = 3,
  DecodingSourceMax       = 4
} DECODING_SOURCE;
*/
// Defines the source of the event data.
type DecodingSource int32

const (
	DecodingSourceXMLFile = DecodingSource(0)
	DecodingSourceWbem    = DecodingSource(1)
	DecodingSourceWPP     = DecodingSource(2)
	DecodingSourceTlg     = DecodingSource(3)
	DecodingSourceMax     = DecodingSource(4)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-template_flags
// v10.0.19041.0 /tdh.h (comments from source where moved to go interface)
/*
typedef enum _TEMPLATE_FLAGS {
  TEMPLATE_EVENT_DATA = 1,
  TEMPLATE_USER_DATA = 2,
  TEMPLATE_CONTROL_GUID = 4
} TEMPLATE_FLAGS;
*/
// Defines constant values that indicates the layout of the event data.
type TemplateFlags int32

const (
	TEMPLATE_EVENT_DATA   = TemplateFlags(1) // Used when custom xml is not specified.
	TEMPLATE_USER_DATA    = TemplateFlags(2) // Used when custom xml is specified.
	TEMPLATE_CONTROL_GUID = TemplateFlags(4) // EventGuid contains the manifest control GUID.
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_map_info
// v10.0.19041.0 /tdh.h
// sizeof(EVENT_MAP_INFO): 24 bytes
/*
typedef struct _EVENT_MAP_INFO {
    ULONG NameOffset;
    MAP_FLAGS Flag;
    ULONG EntryCount;
    union {
        MAP_VALUETYPE MapEntryValueType;
        ULONG FormatStringOffset;
    };
    _Field_size_(EntryCount) EVENT_MAP_ENTRY MapEntryArray[ANYSIZE_ARRAY];
} EVENT_MAP_INFO;
typedef EVENT_MAP_INFO *PEVENT_MAP_INFO;
*/

// Defines the metadata about the event map.
type EventMapInfo struct {
	NameOffset    uint32
	Flag          MapFlags
	EntryCount    uint32
	Union         uint32           // Not sure about size of union depends on size of enum MAP_VALUETYPE
	MapEntryArray [1]EventMapEntry // This is a variable size array in C
}

func (e *EventMapInfo) GetEventMapEntryAt(i int) *EventMapEntry {
	if uint32(i) < e.EntryCount {
		pEmi := uintptr(unsafe.Pointer(&e.MapEntryArray[0]))
		pEmi += uintptr(i) * unsafe.Sizeof(EventMapEntry{})
		return ((*EventMapEntry)(unsafe.Pointer(pEmi)))
	}
	panic(fmt.Errorf("index out of range"))
}

/*
// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    SIZE_T ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}
*/

func (e *EventMapInfo) RemoveTrailingSpace() {
	for i := uint32(0); i < e.EntryCount; i++ {
		me := e.GetEventMapEntryAt(int(i))
		pStr := uintptr(unsafe.Pointer(e)) + uintptr(me.OutputOffset)
		byteLen := (Wcslen(((*uint16)(unsafe.Pointer(pStr)))) - 1) * 2
		*((*uint16)(unsafe.Pointer(pStr + uintptr(byteLen)))) = 0
	}
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-map_flags
// v10.0.19041.0 /tdh.h
/*
typedef enum _MAP_FLAGS {
    EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP = 0x1,
    EVENTMAP_INFO_FLAG_MANIFEST_BITMAP = 0x2,
    EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP = 0x4,
    EVENTMAP_INFO_FLAG_WBEM_VALUEMAP = 0x8,
    EVENTMAP_INFO_FLAG_WBEM_BITMAP = 0x10,
    EVENTMAP_INFO_FLAG_WBEM_FLAG = 0x20,
    EVENTMAP_INFO_FLAG_WBEM_NO_MAP = 0x40
} MAP_FLAGS;
*/
// Defines constant values that indicate if the map is a value map, bitmap, or pattern map.
type MapFlags int32

const (
	EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP   = MapFlags(1)
	EVENTMAP_INFO_FLAG_MANIFEST_BITMAP     = MapFlags(2)
	EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP = MapFlags(4)
	EVENTMAP_INFO_FLAG_WBEM_VALUEMAP       = MapFlags(8)
	EVENTMAP_INFO_FLAG_WBEM_BITMAP         = MapFlags(16)
	EVENTMAP_INFO_FLAG_WBEM_FLAG           = MapFlags(32)
	EVENTMAP_INFO_FLAG_WBEM_NO_MAP         = MapFlags(64)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-map_valuetype
// v10.0.19041.0 /tdh.h
/*
typedef enum _MAP_VALUETYPE
{
  EVENTMAP_ENTRY_VALUETYPE_ULONG  = 0,
  EVENTMAP_ENTRY_VALUETYPE_STRING = 1
} MAP_VALUETYPE;
*/
// Defines if the value map value is in a ULONG data type or a string.
type MapValueType int32

const (
	EVENTMAP_ENTRY_VALUETYPE_ULONG  = MapValueType(0)
	EVENTMAP_ENTRY_VALUETYPE_STRING = MapValueType(1)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_map_entry
// v10.0.19041.0 /tdh.h
/*
typedef struct _EVENT_MAP_ENTRY {
    ULONG OutputOffset;
    union {
        ULONG Value;        // For ULONG value (valuemap and bitmap).
        ULONG InputOffset;  // For String value (patternmap or valuemap in WBEM).
    };
} EVENT_MAP_ENTRY;
*/
// Defines a single value map entry.
type EventMapEntry struct {
	OutputOffset uint32
	Union        uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-property_flags
// v10.0.19041.0 /tdh.h
/*
typedef enum _PROPERTY_FLAGS {
  PropertyStruct = 0x1,
  PropertyParamLength = 0x2,
  PropertyParamCount = 0x4,
  PropertyWBEMXmlFragment = 0x8,
  PropertyParamFixedLength = 0x10,
  PropertyParamFixedCount = 0x20,
  PropertyHasTags = 0x40,
  PropertyHasCustomSchema = 0x80
} PROPERTY_FLAGS;
*/
// Defines if the property is contained in a structure or array.
type PropertyFlags int32

const (
	// Type is struct.
	//
	// The property information is contained in the structType member of the EVENT_PROPERTY_INFO structure.
	PropertyStruct = PropertyFlags(0x1)

	// Length field is index of param with length.
	//
	// Use the lengthPropertyIndex member of the EVENT_PROPERTY_INFO structure to locate
	// the property that contains the length value of the property.
	PropertyParamLength = PropertyFlags(0x2)

	// Count field is index of param with count.
	//
	// Use the countPropertyIndex member of the EVENT_PROPERTY_INFO structure to locate
	// the property that contains the size of the array.
	PropertyParamCount = PropertyFlags(0x4)

	// WBEM extension flag for property.
	//
	// Indicates that the MOF data is in XML format (the event data contains within itself a fully-rendered XML description).
	// This flag is set if the MOF property contains the XMLFragment qualifier.
	PropertyWBEMXmlFragment = PropertyFlags(0x8)

	// Length of the parameter is fixed.
	//
	// Indicates that the length member of the EVENT_PROPERTY_INFO structure contains a fixed length,
	// e.g. as specified in the provider manifest with <data length="12" … />.
	// This flag will not be set for a variable-length field, e.g. <data length="LengthField" … />,
	// nor will this flag be set for fields where the length is not specified in the manifest,
	// e.g. int32 or null-terminated string. As an example, if PropertyParamLength is unset,
	// length is 0, and InType is TDH_INTYPE_UNICODESTRING, we must check the PropertyParamFixedLength
	// flag to determine the length of the string. If PropertyParamFixedLength is set, the string length is fixed at 0.
	// If PropertyParamFixedLength is unset, the string is null-terminated.
	PropertyParamFixedLength = PropertyFlags(0x10)

	// Count of the parameter is fixed.
	//
	// Indicates that the count member of the EVENT_PROPERTY_INFO structure contains a fixed array count,
	// e.g. as specified in the provider manifest with <data count="12" … />.
	// This flag will not be set for a variable-length array, e.g. <data count="ArrayCount" … />,
	// nor will this flag be set for non-array fields. As an example, if PropertyParamCount is unset and count is 1,
	// PropertyParamFixedCount flag must be checked to determine whether the field is a scalar value or a single-element array.
	// If PropertyParamFixedCount is set, the field is a single-element array. If PropertyParamFixedCount is unset,
	// the field is a scalar value, not an array.
	//
	// Caution  This flag is new in the Windows 10 SDK. Earlier versions of the manifest compiler did not set this flag.
	// For compatibility with manifests compiled with earlier versions of the compiler,
	// event processing tools should only use this flag when determining whether to present a field with a
	// fixed count of 1 as an array or a scalar.
	PropertyParamFixedCount = PropertyFlags(0x20)

	// The Tags field has been initialized.
	//
	// Indicates that the Tags field contains valid field tag data.
	PropertyHasTags = PropertyFlags(0x40)

	// Indicates that the Type is described with a custom schema.
	//
	// NOTE  This flag is new in the Windows 10 SDK.
	PropertyHasCustomSchema = PropertyFlags(0x80)
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info
// v10.0.19041.0 /tdh.h
// sizeof(EVENT_PROPERTY_INFO): 24 bytes
/*
typedef struct _EVENT_PROPERTY_INFO {
    PROPERTY_FLAGS Flags;
    ULONG NameOffset;
    union {
        struct _nonStructType {
            USHORT InType;
            USHORT OutType;
            ULONG MapNameOffset;
        } nonStructType;
        struct _structType {
            USHORT StructStartIndex;
            USHORT NumOfStructMembers;
            ULONG padding;
        } structType;
        struct _customSchemaType { */
// Data of this field is described by a user-defined serialization
// protocol such as Bond or Protocol Buffers. InType and OutType
// should be set for best-effort decoding by decoders that do not
// understand the schema, e.g. InType could be set to
// TDH_INTYPE_BINARY so that a decoder can properly extract or skip
// the raw serialized data even if it can't parse it. The
// CustomSchemaOffset points at a structure laid out as:
// UINT16 Protocol; // User-defined value from 5..31
// UINT16 Length;
// BYTE SchemaData[Length];
/*          USHORT InType;
            USHORT OutType;
            ULONG CustomSchemaOffset;
        } customSchemaType;
    };
    union {
        USHORT count;
        USHORT countPropertyIndex;
    };
    union {
        USHORT length;
        USHORT lengthPropertyIndex;
    };
    union {
        ULONG Reserved;
        struct {
            ULONG Tags : 28;
        };
    };
} EVENT_PROPERTY_INFO;
typedef EVENT_PROPERTY_INFO *PEVENT_PROPERTY_INFO;
*/

// Provides information about a single property of the event or filter.
type EventPropertyInfo struct {
	Flags      PropertyFlags
	NameOffset uint32
	TypeUnion  struct {
		u1 uint16 // InType() | StructStartIndex()
		u2 uint16 // OutType() | NumOfStructMembers() | padding [NOT USED]
		u3 uint32 // MapNameOffset() | CustomSchemaOffset()
	}
	CountUnion  uint16 // Count() | CountPropertyIndex()
	LengthUnion uint16 // LengthPropertyIndex() | Length()
	ResTagUnion uint32
}

// SetInType sets the InType for the property.
func (i *EventPropertyInfo) SetInType(inType TdhInType) {
	i.TypeUnion.u1 = uint16(inType)
}

// SetOutType sets the OutType for the property.
func (i *EventPropertyInfo) SetOutType(outType TdhOutType) {
	i.TypeUnion.u2 = uint16(outType)
}

// SetCount sets the fixed count for the property.
func (i *EventPropertyInfo) SetCount(count uint16) {
	i.CountUnion = count
}

// SetCountPropertyIndex sets the index of the property that contains the count.
func (i *EventPropertyInfo) SetCountPropertyIndex(index uint16) {
	i.CountUnion = index
}

// SetLength sets the fixed length for the property.
func (i *EventPropertyInfo) SetLength(length uint16) {
	i.LengthUnion = length
}

// Zero-based index to the element of the property array that contains the first member of the structure.
func (i *EventPropertyInfo) StructStartIndex() uint16 {
	return i.TypeUnion.u1
}

// Data type of this property on input. For a description of these types, see Remarks in InputType.
//
// For descriptions of these types, see [Event Tracing MOF Qualifiers].
//
// [TdhGetPropertySize] [TdhGetPropertySize]
//
// [Event Tracing MOF Qualifiers]: https://learn.microsoft.com/en-us/windows/desktop/ETW/event-tracing-mof-qualifiers
// [TdhGetPropertySize]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/nf-tdh-tdhgetpropertysize
//
// [TdhGetPropertySize]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/nf-tdh-tdhgetpropertysize
func (i *EventPropertyInfo) InType() TdhInType {
	return TdhInType(i.TypeUnion.u1)
}

// Output format for this property.
//
// If the value is TDH_OUTTYPE_NULL, use the in type as the output format. For a description of these types, see [Remarks in InputType].
//
// For descriptions of these types, see [Event Tracing MOF Qualifiers].
//
// [Remarks in InputType]: https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-inputtype-complextype#remarks
// [Event Tracing MOF Qualifiers]: https://learn.microsoft.com/en-us/windows/desktop/ETW/event-tracing-mof-qualifiers
func (i *EventPropertyInfo) OutType() TdhOutType {
	return TdhOutType(i.TypeUnion.u2)
}

// Number of members in the structure.
func (i *EventPropertyInfo) NumOfStructMembers() uint16 {
	return i.TypeUnion.u2
}

// Offset from the beginning of the [TRACE_EVENT_INFO] structure to a null-terminated Unicode string that contains the name of the map attribute value.
//
// You can pass this string to [TdhGetEventMapInformation] to retrieve information about the value map.
//
// [TdhGetEventMapInformation]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/nf-tdh-tdhgeteventmapinformation
// [TRACE_EVENT_INFO]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/ns-tdh-trace_event_info
func (i *EventPropertyInfo) MapNameOffset() uint32 {
	return i.TypeUnion.u3
}

// Offset (in bytes) from the beginning of the TRACE_EVENT_INFO structure to the custom schema information.
//
// The custom schema information will contain a 2-byte protocol identifier, followed by a 2-byte schema length, followed by the schema.
func (i *EventPropertyInfo) CustomSchemaOffset() uint32 {
	return i.TypeUnion.u3
}

// Number of elements in the array. Note that this value is 1 for properties that are not defined as an array.
func (i *EventPropertyInfo) Count() uint16 {
	return i.CountUnion
}

// Zero-based index to the element of the property array that contains the number of elements in the array.
//
// Use this member if the [PropertyParamCount] flag in Flags is set; otherwise, use the count member.
//
// [PropertyParamCount]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/ne-tdh-property_flags
func (i *EventPropertyInfo) CountPropertyIndex() uint16 {
	return i.CountUnion
}

// Zero-based index to the element of the property array that contains the size value of this property.
//
// Use this member if the [PropertyParamLength] flag in Flags is set; otherwise, use the length member.
//
// [PropertyParamLength]: https://learn.microsoft.com/en-us/windows/desktop/api/tdh/ne-tdh-property_flags
func (i *EventPropertyInfo) LengthPropertyIndex() uint16 {
	return i.LengthUnion
}

// Size of the property, in bytes.
//
// Note that variable-sized types such as strings and binary data have a length of zero unless the property has
// length attribute to explicitly indicate its real length. Structures have a length of zero.
func (i *EventPropertyInfo) Length() uint16 {
	return i.LengthUnion
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_in_type
// The relevant info is inside tdh.h on WinSDK
// Here are the comments from the header file. v10.0.19041.0 /tdh.h ported to golang
//
/*
	InType provides basic information about the raw encoding of the data in the
	field of an ETW event. An event field's InType tells the event decoder how to
	determine the size of the field. In the case that a field's OutType is
	NULL/unspecified/unrecognized, the InType also provides a default OutType for
	the data (an OutType refines how the data should be interpreted). For example,
	InType = INT32 indicates that the field's data is 4 bytes in length. If the
	field's OutType is NULL/unspecified/unrecognized, the InType of INT32 also
	provides the default OutType, TDH_OUTTYPE_INT, indicating that the field's data
	should be interpreted as a Win32 INT value.

	Note that there are multiple ways for the size of a field to be determined.

	- Some InTypes have a fixed size. For example, InType UINT16 is always 2 bytes.
	For these fields, the length property of the EVENT_PROPERTY_INFO structure
	can be ignored by decoders.
	- Some InTypes support deriving the size from the data content. For example,
	the size of a COUNTEDSTRING field is determined by reading the first 2 bytes
	of the data, which contain the size of the remaining string. For these
	fields, the length property of the EVENT_PROPERTY_INFO structure must be
	ignored.
	- Some InTypes use the Flags and length properties of the EVENT_PROPERTY_INFO
	structure associated with the field. Details on how to do this are provided
	for each type.

	For ETW InType values, the corresponding default OutType and the list of
	applicable OutTypes can be found in winmeta.xml. For legacy WBEM InType values
	(i.e. values not defined in winmeta.xml), the details for each InType are
	included below.
*/
type TdhInType uint16

func (t TdhInType) V() uint16 {
	return uint16(t)
}

const (
	TDH_INTYPE_NULL          = TdhInType(iota) /* Invalid InType value. */
	TDH_INTYPE_UNICODESTRING                   /*
		Field size depends on the Flags and length fields of the corresponding
		EVENT_PROPERTY_INFO structure (epi) as follows:
		- If ((epi.Flags & PropertyParamLength) != 0), the
		epi.lengthPropertyIndex field contains the index of the property that
		contains the number of WCHARs in the string.
		- Else if ((epi.Flags & PropertyLength) != 0 || epi.length != 0), the
		epi.length field contains number of WCHARs in the string.
		- Else the string is nul-terminated (terminated by (WCHAR)0).
		Note that some event providers do not correctly nul-terminate the last
		string field in the event. While this is technically invalid, event
		decoders may silently tolerate such behavior instead of rejecting the
		event as invalid. */
	TDH_INTYPE_ANSISTRING /*
		Field size depends on the Flags and length fields of the corresponding
		EVENT_PROPERTY_INFO structure (epi) as follows:
		- If ((epi.Flags & PropertyParamLength) != 0), the
		epi.lengthPropertyIndex field contains the index of the property that
		contains the number of BYTEs in the string.
		- Else if ((epi.Flags & PropertyLength) != 0 || epi.length != 0), the
		epi.length field contains number of BYTEs in the string.
		- Else the string is nul-terminated (terminated by (CHAR)0).
		Note that some event providers do not correctly nul-terminate the last
		string field in the event. While this is technically invalid, event
		decoders may silently tolerate such behavior instead of rejecting the
		event as invalid. */
	TDH_INTYPE_INT8    /* Field size is 1 byte. */
	TDH_INTYPE_UINT8   /* Field size is 1 byte. */
	TDH_INTYPE_INT16   /* Field size is 2 bytes. */
	TDH_INTYPE_UINT16  /* Field size is 2 bytes. */
	TDH_INTYPE_INT32   /* Field size is 4 bytes. */
	TDH_INTYPE_UINT32  /* Field size is 4 bytes. */
	TDH_INTYPE_INT64   /* Field size is 8 bytes. */
	TDH_INTYPE_UINT64  /* Field size is 8 bytes. */
	TDH_INTYPE_FLOAT   /* Field size is 4 bytes. */
	TDH_INTYPE_DOUBLE  /* Field size is 8 bytes. */
	TDH_INTYPE_BOOLEAN /* Field size is 4 bytes. */ /* note: not 1 */
	TDH_INTYPE_BINARY  /*
		Field size depends on the OutType, Flags, and length fields of the
		corresponding EVENT_PROPERTY_INFO structure (epi) as follows:
		- If ((epi.Flags & PropertyParamLength) != 0), the
		epi.lengthPropertyIndex field contains the index of the property that
		contains the number of BYTEs in the field.
		- Else if ((epi.Flags & PropertyLength) != 0 || epi.length != 0), the
		epi.length field contains number of BYTEs in the field.
		- Else if (epi.OutType == IPV6), the field size is 16 bytes.
		- Else the field is incorrectly encoded. */
	TDH_INTYPE_GUID    /* Field size is 16 bytes. */
	TDH_INTYPE_POINTER /*
		Field size depends on the eventRecord.EventHeader.Flags value. If the
		EVENT_HEADER_FLAG_32_BIT_HEADER flag is set, the field size is 4 bytes.
		If the EVENT_HEADER_FLAG_64_BIT_HEADER flag is set, the field size is 8
		bytes. Default OutType is HEXINT64. Other usable OutTypes include
		CODE_POINTER, LONG, UNSIGNEDLONG.
	*/
	TDH_INTYPE_FILETIME   /* Field size is 8 bytes. */
	TDH_INTYPE_SYSTEMTIME /* Field size is 16 bytes. */
	TDH_INTYPE_SID        /*
		Field size is determined by reading the first few bytes of the field
		value to determine the number of relative IDs. */
	TDH_INTYPE_HEXINT32               /* Field size is 4 bytes. */
	TDH_INTYPE_HEXINT64               /* Field size is 8 bytes. */
	TDH_INTYPE_MANIFEST_COUNTEDSTRING /*
	   Supported in Windows 2018 Fall Update or later. This is the same as
	   TDH_INTYPE_COUNTEDSTRING, but can be used in manifests.
	   Field contains a little-endian 16-bit bytecount followed by a WCHAR
	   (16-bit character) string. Default OutType is STRING. Other usable
	   OutTypes include XML, JSON. Field size is determined by reading the
	   first two bytes of the payload, which are then interpreted as a
	   little-endian 16-bit integer which gives the number of additional bytes
	   (not characters) in the field. */
	TDH_INTYPE_MANIFEST_COUNTEDANSISTRING /*
	   Supported in Windows 2018 Fall Update or later. This is the same as
	   TDH_INTYPE_COUNTEDANSISTRING, but can be used in manifests.
	   Field contains a little-endian 16-bit bytecount followed by a CHAR
	   (8-bit character) string. Default OutType is STRING. Other usable
	   OutTypes include XML, JSON, UTF8. Field size is determined by reading
	   the first two bytes of the payload, which are then interpreted as a
	   little-endian 16-bit integer which gives the number of additional bytes
	   (not characters) in the field. */
	TDH_INTYPE_RESERVED24
	TDH_INTYPE_MANIFEST_COUNTEDBINARY /*
	   Supported in Windows 2018 Fall Update or later.
	   Field contains a little-endian 16-bit bytecount followed by binary
	   data. Default OutType is HEXBINARY. Other usable
	   OutTypes include IPV6, SOCKETADDRESS, PKCS7_WITH_TYPE_INFO. Field size
	   is determined by reading the first two bytes of the payload, which are
	   then interpreted as a little-endian 16-bit integer which gives the
	   number of additional bytes in the field. */

	// End of winmeta intypes.
)

const (
	// Start of TDH intypes for WBEM. These types cannot be used in manifests.

	TDH_INTYPE_COUNTEDSTRING = TdhInType(iota + 300) /*
		Field contains a little-endian 16-bit bytecount followed by a WCHAR
		(16-bit character) string. Default OutType is STRING. Other usable
		OutTypes include XML, JSON. Field size is determined by reading the
		first two bytes of the payload, which are then interpreted as a
		little-endian 16-bit integer which gives the number of additional bytes
		(not characters) in the field. */
	TDH_INTYPE_COUNTEDANSISTRING /*
		Field contains a little-endian 16-bit bytecount followed by a CHAR
		(8-bit character) string. Default OutType is STRING. Other usable
		OutTypes include XML, JSON, UTF8. Field size is determined by reading
		the first two bytes of the payload, which are then interpreted as a
		little-endian 16-bit integer which gives the number of additional bytes
		(not characters) in the field. */
	TDH_INTYPE_REVERSEDCOUNTEDSTRING /*
		Deprecated. Prefer TDH_INTYPE_COUNTEDSTRING.
		Field contains a big-endian 16-bit bytecount followed by a WCHAR
		(16-bit little-endian character) string. Default OutType is STRING.
		Other usable OutTypes include XML, JSON. Field size is determined by
		reading the first two bytes of the payload, which are then interpreted
		as a big-endian 16-bit integer which gives the number of additional
		bytes (not characters) in the field. */
	TDH_INTYPE_REVERSEDCOUNTEDANSISTRING /*
		Deprecated. Prefer TDH_INTYPE_COUNTEDANSISTRING.
		Field contains a big-endian 16-bit bytecount followed by a CHAR (8-bit
		character) string. Default OutType is STRING. Other usable OutTypes
		include XML, JSON, UTF8. Field size is determined by reading the first
		two bytes of the payload, which are then interpreted as a big-endian
		16-bit integer which gives the number of additional bytes in the
		field. */
	TDH_INTYPE_NONNULLTERMINATEDSTRING /*
		Deprecated. Prefer TDH_INTYPE_COUNTEDSTRING.
		Field contains a WCHAR (16-bit character) string. Default OutType is
		STRING. Other usable OutTypes include XML, JSON. Field size is the
		remaining bytes of data in the event. */
	TDH_INTYPE_NONNULLTERMINATEDANSISTRING /*
		Deprecated. Prefer TDH_INTYPE_COUNTEDANSISTRING.
		Field contains a CHAR (8-bit character) string. Default OutType is
		STRING. Other usable OutTypes include XML, JSON, UTF8. Field size is
		the remaining bytes of data in the event. */
	TDH_INTYPE_UNICODECHAR /*
		Deprecated. Prefer TDH_INTYPE_UINT16 with TDH_OUTTYPE_STRING.
		Field contains a WCHAR (16-bit character) value. Default OutType is
		STRING. Field size is 2 bytes. */
	TDH_INTYPE_ANSICHAR /*
		Deprecated. Prefer TDH_INTYPE_UINT8 with TDH_OUTTYPE_STRING.
		Field contains a CHAR (8-bit character) value. Default OutType is
		STRING. Field size is 1 byte. */
	TDH_INTYPE_SIZET /*
		Deprecated. Prefer TDH_INTYPE_POINTER with TDH_OUTTYPE_UNSIGNEDLONG.
		Field contains a SIZE_T (UINT_PTR) value. Default OutType is HEXINT64.
		Field size depends on the eventRecord.EventHeader.Flags value. If the
		EVENT_HEADER_FLAG_32_BIT_HEADER flag is set, the field size is 4 bytes.
		If the EVENT_HEADER_FLAG_64_BIT_HEADER flag is set, the field size is
		8 bytes. */
	TDH_INTYPE_HEXDUMP /*
		Deprecated. Prefer TDH_INTYPE_BINARY.
		Field contains binary data. Default OutType is HEXBINARY. Field size is
		determined by reading the first four bytes of the payload, which are
		then interpreted as a little-endian UINT32 which gives the number of
		additional bytes in the field. */
	TDH_INTYPE_WBEMSID /*
		Deprecated. Prefer TDH_INTYPE_SID.
		Field contains an SE_TOKEN_USER (security identifier) value. Default
		OutType is STRING (i.e. the SID will be converted to a string during
		decoding using ConvertSidToStringSid or equivalent). Field size is
		determined by reading the first few bytes of the field value to
		determine the number of relative IDs. Because the SE_TOKEN_USER
		structure includes pointers, decoding this structure requires accurate
		knowledge of the event provider's pointer size (i.e. from
		eventRecord.EventHeader.Flags). */
)

/*
OutType describes how to interpret a field's data. If a field's OutType is
not specified in the manifest, it defaults to TDH_OUTTYPE_NULL. If the field's
OutType is NULL, decoding should use the default OutType associated with the
field's InType.

Not all combinations of InType and OutType are valid, and event decoding tools
will only recognize a small set of InType+OutType combinations. If an
InType+OutType combination is not recognized by a decoder, the decoder should
use the default OutType associated with the field's InType (i.e. the decoder
should behave as if the OutType were NULL).
*/
type TdhOutType uint16

func (t TdhOutType) V() uint16 {
	return uint16(t)
}

const (
	TDH_OUTTYPE_NULL = TdhOutType(iota) /*
		Default OutType value. If a field's OutType is set to this value, the
		decoder should determine the default OutType corresponding to the
		field's InType and use that OutType when decoding the field. */
	TDH_OUTTYPE_STRING /*
		Implied by the STRING, CHAR, and SID InType values. Applicable to the
		INT8, UINT8, UINT16 InType values. Specifies that the field should be
		decoded as text. Decoding depends on the InType. For INT8, UINT8, and
		ANSISTRING InTypes, the data is decoded using the ANSI code page of the
		event provider. For UINT16 and UNICODESTRING InTypes, the data is
		decoded as UTF-16LE. For SID InTypes, the data is decoded using
		ConvertSidToStringSid or equivalent. */
	TDH_OUTTYPE_DATETIME /*
		Implied by the FILETIME and SYSTEMTIME InType values. Data is decoded
		as a date/time. FILETIME is decoded as a 64-bit integer representing
		the number of 100-nanosecond intervals since January 1, 1601.
		SYSTEMTIME is decoded as the Win32 SYSTEMTIME structure. In both cases,
		the time zone must be determined using other methods. (FILETIME is
		usually but not always UTC.) */
	TDH_OUTTYPE_BYTE /*
		Implied by the INT8 InType value. Data is decoded as a signed integer. */
	TDH_OUTTYPE_UNSIGNEDBYTE /*
		Implied by the UINT8 InType value. Data is decoded as an unsigned
		integer. */
	TDH_OUTTYPE_SHORT /*
		Implied by the INT16 InType value. Data is decoded as a signed
		little-endian integer. */
	TDH_OUTTYPE_UNSIGNEDSHORT /*
		Implied by the UINT16 InType value. Data is decoded as an unsigned
		little-endian integer. */
	TDH_OUTTYPE_INT /*
		Implied by the INT32 InType value. Data is decoded as a signed
		little-endian integer. */
	TDH_OUTTYPE_UNSIGNEDINT /*
		Implied by the UINT32 InType value. Data is decoded as an unsigned
		little-endian integer. */
	TDH_OUTTYPE_LONG /*
		Implied by the INT64 InType value. Applicable to the INT32 InType value
		(i.e. to distinguish between the C data types "long int" and "int").
		Data is decoded as a signed little-endian integer. */
	TDH_OUTTYPE_UNSIGNEDLONG /*
		Implied by the UINT64 InType value. Applicable to the UINT32 InType
		value (i.e. to distinguish between the C data types "long int" and
		"int"). Data is decoded as an unsigned little-endian integer. */
	TDH_OUTTYPE_FLOAT /*
		Implied by the FLOAT InType value. Data is decoded as a
		single-precision floating-point number. */
	TDH_OUTTYPE_DOUBLE /*
		Implied by the DOUBLE InType value. Data is decoded as a
		double-precision floating-point number. */
	TDH_OUTTYPE_BOOLEAN /*
		Implied by the BOOL InType value. Applicable to the UINT8 InType value.
		Data is decoded as a Boolean (false if zero, true if non-zero). */
	TDH_OUTTYPE_GUID /*
		Implied by the GUID InType value. Data is decoded as a GUID. */
	TDH_OUTTYPE_HEXBINARY /*
		Not commonly used. Implied by the BINARY and HEXDUMP InType values. */
	TDH_OUTTYPE_HEXINT8 /*
		Specifies that the field should be formatted as a hexadecimal integer.
		Applicable to the UINT8 InType value. */
	TDH_OUTTYPE_HEXINT16 /*
		Specifies that the field should be formatted as a hexadecimal integer.
		Applicable to the UINT16 InType value. */
	TDH_OUTTYPE_HEXINT32 /*
		Not commonly used. Implied by the HEXINT32 InType value. Applicable to
		the UINT32 InType value. */
	TDH_OUTTYPE_HEXINT64 /*
		Not commonly used. Implied by the HEXINT64 InType value. Applicable to
		the UINT64 InType value. */
	TDH_OUTTYPE_PID /*
		Specifies that the field is a process identifier. Applicable to the
		UINT32 InType value. */
	TDH_OUTTYPE_TID /*
		Specifies that the field is a thread identifier. Applicable to the
		UINT32 InType value. */
	TDH_OUTTYPE_PORT /*
		Specifies that the field is an Internet Protocol port number, specified
		in network byte order (big-endian). Applicable to the UINT16 InType
		value. */
	TDH_OUTTYPE_IPV4 /*
		Specifies that the field is an Internet Protocol V4 address. Applicable
		to the UINT32 InType value. */
	TDH_OUTTYPE_IPV6 /*
		Specifies that the field is an Internet Protocol V6 address. Applicable
		to the BINARY InType value. If the length of a field is unspecified in
		the EVENT_PROPERTY_INFO but the field's InType is BINARY and its
		OutType is IPV6, the field's length should be assumed to be 16 bytes. */
	TDH_OUTTYPE_SOCKETADDRESS /*
		Specifies that the field is a SOCKADDR structure. Applicable to the
		BINARY InType value. Note that different address types have different
		sizes. */
	TDH_OUTTYPE_CIMDATETIME /*
		Not commonly used. */
	TDH_OUTTYPE_ETWTIME /*
		Not commonly used. Applicable to the UINT32 InType value. */
	TDH_OUTTYPE_XML /*
		Specifies that the field should be treated as XML text. Applicable to
		the *STRING InType values. When this OutType is used, decoders should
		use standard XML decoding rules (i.e. assume a Unicode encoding unless
		the document specifies a different encoding in its encoding
		attribute). */
	TDH_OUTTYPE_ERRORCODE /*
		Not commonly used. Specifies that the field is an error code of
		some type. Applicable to the UINT32 InType value. */
	TDH_OUTTYPE_WIN32ERROR /*
		Specifies that the field is a Win32 error code. Applicable to the
		UINT32 and HEXINT32 InType values. */
	TDH_OUTTYPE_NTSTATUS /*
		Specifies that the field is an NTSTATUS code. Applicable to the UINT32
		and HEXINT32 InType values. */
	TDH_OUTTYPE_HRESULT /*
		Specifies that the field is an HRESULT error code. Applicable to the
		INT32 InType value. */
	TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME /*
		Specifies that a date/time value should be formatted in a
		locale-invariant format. Applicable to the FILETIME and SYSTEMTIME
		InType values. */
	TDH_OUTTYPE_JSON /*
		Specifies that the field should be treated as JSON text. Applicable to
		the *STRING InType values. When this OutType is used with the ANSI
		string InType values, decoders should decode the data as UTF-8. */
	TDH_OUTTYPE_UTF8 /*
		Specifies that the field should be treated as UTF-8 text. Applicable to
		the *ANSISTRING InType values. */
	TDH_OUTTYPE_PKCS7_WITH_TYPE_INFO /*
		Specifies that the field should be treated as a PKCS#7 message (e.g.
		encrypted and/or signed). Applicable to the BINARY InType value. One
		or more bytes of TraceLogging-compatible type information (providing
		the type of the inner content) may optionally be appended immediately
		after the PKCS#7 message. For example, the byte 0x01
		(TlgInUNICODESTRING = 0x01) might be appended to indicate that the
		inner content is to be interpreted as InType = UNICODESTRING; the bytes
		0x82 0x22 (TlgInANSISTRING + TlgInChain = 0x82, TlgOutJSON = 0x22)
		might be appended to indicate that the inner content is to be
		interpreted as InType = ANSISTRING, OutType = JSON. */
	TDH_OUTTYPE_CODE_POINTER /*
		Specifies that the field should be treated as an address that can
		potentially be decoded into a symbol name. Applicable to InTypes
		UInt32, UInt64, HexInt32, HexInt64, and Pointer. */
	TDH_OUTTYPE_DATETIME_UTC /*
		Usable with the FILETIME and SYSTEMTIME InType values. Data is decoded
		as a date/time. FILETIME is decoded as a 64-bit integer representing
		the number of 100-nanosecond intervals since January 1, 1601.
		SYSTEMTIME is decoded as the Win32 SYSTEMTIME structure. In both cases,
		the time zone is assumed to be UTC.) */

	// End of winmeta outtypes.
)

const (
	// Start of TDH outtypes for WBEM.
	TDH_OUTTYPE_REDUCEDSTRING = TdhOutType(iota + 300) /*
		Not commonly used. */
	TDH_OUTTYPE_NOPRINT /*
		Not commonly used. Specifies that the field should not be shown in the
		output of the decoding tool. This might be applied to a Count or a
		Length field. Applicable to all InType values. Most decoders ignore
		this value. */
)
