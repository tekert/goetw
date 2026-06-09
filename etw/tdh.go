//go:build windows

package etw

import (
	"syscall"
	"unsafe"
)

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhenumerateproviderfieldinformation
/*
TdhEnumerateProviderFieldInformation API wrapper generated from prototype
ULONG __stdcall TdhEnumerateProviderFieldInformation(
	 LPGUID pGuid,
	 EVENT_FIELD_TYPE EventFieldType,
	 PPROVIDER_FIELD_INFOARRAY pBuffer,
	 ULONG *pBufferSize );

Tested: NOK
*/

// Retrieves the specified field metadata for a given provider.
func TdhEnumerateProviderFieldInformation(
	pGuid *GUID,
	eventFieldType int,
	pBuffer *ProviderFieldInfoArray,
	pBufferSize *uint32) error {
	r1, _, _ := tdhEnumerateProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(pGuid)),
		uintptr(eventFieldType),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhenumerateproviderfilters
/*
	TDHSTATUS TdhEnumerateProviderFilters(
		[in]            LPGUID                Guid,
		[in]            ULONG                 TdhContextCount,
		[in, optional]  PTDH_CONTEXT          TdhContext,
		[in]            ULONG                 *FilterCount,
		[out, optional] PPROVIDER_FILTER_INFO *Buffer,
		[in, out]       ULONG                 *BufferSize
	);
*/
// The TdhEnumerateProviderFilters function enumerates the filters
// that the specified provider defined in the manifest.
func TdhEnumerateProviderFilters(
	pGuid *GUID,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	filterCount *uint32,
	pBuffer *ProviderFilterBuffer,
	pBufferSize *uint32) error {

	var pBufferPtr uintptr
	if pBuffer != nil {
		pBufferPtr = uintptr(unsafe.Pointer(&pBuffer.Ptr))
	}

	r1, _, _ := tdhEnumerateProviderFilters.Call(
		uintptr(unsafe.Pointer(pGuid)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(unsafe.Pointer(filterCount)),
		pBufferPtr,
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhcreatepayloadfilter
/*
	TDHSTATUS TdhCreatePayloadFilter(
	[in]  LPCGUID                   ProviderGuid,
	[in]  PCEVENT_DESCRIPTOR        EventDescriptor,
	[in]  BOOLEAN                   EventMatchANY,
	[in]  ULONG                     PayloadPredicateCount,
	[in]  PPAYLOAD_FILTER_PREDICATE PayloadPredicates,
	[out] PVOID                     *PayloadFilter
	);
*/
// The TdhCreatePayloadFilter function creates a single filter
// for a single payload to be used with the EnableTraceEx2 function.
func TdhCreatePayloadFilter(
	providerGuid *GUID,
	eventDescriptor *EventDescriptor,
	eventMatchANY bool,
	payloadPredicateCount uint32,
	payloadPredicates *PayloadFilterPredicate,
	payloadFilter *unsafe.Pointer) error {

	var val uint8
	if eventMatchANY {
		val = 1
	} else {
		val = 0
	}

	r1, _, _ := tdhCreatePayloadFilter.Call(
		uintptr(unsafe.Pointer(providerGuid)),
		uintptr(unsafe.Pointer(eventDescriptor)),
		uintptr(val),
		uintptr(payloadPredicateCount),
		uintptr(unsafe.Pointer(payloadPredicates)),
		uintptr(unsafe.Pointer(payloadFilter)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhaggregatepayloadfilters
/*
	TDHSTATUS TdhAggregatePayloadFilters(
					ULONG                    PayloadFilterCount,
					PVOID                    *PayloadFilterPtrs,
	[in, optional] PBOOLEAN                 EventMatchALLFlags,
	[out]          PEVENT_FILTER_DESCRIPTOR EventFilterDescriptor
	);
*/
// The TdhAggregatePayloadFilters function aggregates multiple payload filters for a single
// provider into a single data structure for use with the EnableTraceEx2 function.
func TdhAggregatePayloadFilters(
	payloadFilterCount uint32,
	payloadFilterPtrs *unsafe.Pointer,
	eventMatchALLFlags *bool,
	eventFilterDescriptor *EventFilterDescriptor) error {

	var pBoolean uintptr
	if eventMatchALLFlags != nil {
		b := uint8(0)
		if *eventMatchALLFlags {
			b = 1
		}
		pBoolean = uintptr(unsafe.Pointer(&b))
	}

	r1, _, _ := tdhAggregatePayloadFilters.Call(
		uintptr(payloadFilterCount),
		uintptr(unsafe.Pointer(payloadFilterPtrs)),
		pBoolean,
		uintptr(unsafe.Pointer(eventFilterDescriptor)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhcleanuppayloadeventfilterdescriptor
/*
  TDHSTATUS TdhCleanupPayloadEventFilterDescriptor(
	[in, out] PEVENT_FILTER_DESCRIPTOR EventFilterDescriptor
	);
*/
// The TdhCleanupPayloadEventFilterDescriptor function frees the aggregated structure of
// payload filters created using the TdhAggregatePayloadFilters function.
func TdhCleanupPayloadEventFilterDescriptor(
	eventFilterDescriptor *EventFilterDescriptor) error {
	r1, _, _ := tdhCleanupPayloadEventFilterDescriptor.Call(
		uintptr(unsafe.Pointer(eventFilterDescriptor)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhdeletepayloadfilter
/*
	TDHSTATUS TdhDeletePayloadFilter(
	  [in, out] PVOID *PayloadFilter
	);
*/
// The TdhDeletePayloadFilter function frees the memory allocated for a single payload filter
// by the TdhCreatePayloadFilter function.
func TdhDeletePayloadFilter(payloadFilter *unsafe.Pointer) error {
	r1, _, _ := tdhDeletePayloadFilter.Call(uintptr(unsafe.Pointer(payloadFilter)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhenumerateproviders
/*
TdhEnumerateProviders API wrapper generated from prototype
	TDHSTATUS TdhEnumerateProviders(
		[out]     PPROVIDER_ENUMERATION_INFO pBuffer,
		[in, out] ULONG                      *pBufferSize
	);

	Tested: NOK
*/
// Retrieves a list of all providers that have registered on the computer.
func TdhEnumerateProviders(
	pBuffer *ProviderEnumerationInfo,
	pBufferSize *uint32) error {
	r1, _, _ := tdhEnumerateProviders.Call(
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation
/*
TdhGetEventInformation API wrapper generated from prototype
ULONG __stdcall TdhGetEventInformation(
	 PEVENT_RECORD pEvent,
	 ULONG TdhContextCount,
	 PTDH_CONTEXT pTdhContext,
	 PTRACE_EVENT_INFO pBuffer,
	 ULONG *pBufferSize );

Tested: OK
*/

// Retrieves metadata about an event using the Windows TdhGetEventInformation API.
//
// This function uses syscall.SyscallN instead of Proc.Call to avoid unnecessary heap allocations
// for pointer arguments (such as &bufferSize). Proc.Call is annotated with //go:uintptrescapes,
// which forces all arguments to escape to the heap for safety, but this can cause significant
// performance overhead in high-frequency scenarios (e.g., hundreds of thousands of calls per second).
//
// By using syscall.SyscallN, arguments remain on the stack, reducing memory allocations and GC pressure.
// This is safe in this context because:
//   - The pointer arguments (e.g., &bufferSize) are stack-allocated and their lifetime is managed.
//   - No operations that could trigger stack growth or GC occur between pointer creation and the syscall.
//   - The function does not perform actions that would invalidate pointers during the call.
//
// https://github.com/golang/go/issues/42680 and https://github.com/golang/go/issues/34684
// For more details, see Go issue #42680 and related discussions on pointer escape analysis and Windows DLL calls.
func TdhGetEventInformation(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	pBuffer *TraceEventInfo,
	pBufferSize *uint32) error {
	//r1, _, _ := tdhGetEventInformation.Call(
	r1, _, _ := syscall.SyscallN(tdhGetEventInformation.Addr(), // Improves performance by 15%
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventmapinformation
/*
TdhGetEventMapInformation API wrapper generated from prototype
ULONG __stdcall TdhGetEventMapInformation(
	 PEVENT_RECORD pEvent,
	 LPWSTR pMapName,
	 PEVENT_MAP_INFO pBuffer,
	 ULONG *pBufferSize );

Tested: OK
*/

// Retrieves information about the event map contained in the event.
func TdhGetEventMapInformation(pEvent *EventRecord,
	pMapName *uint16,
	pBuffer *EventMapInfo,
	pBufferSize *uint32) error {
	r1, _, _ := tdhGetEventMapInformation.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(unsafe.Pointer(pMapName)),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty
/*
TdhGetProperty API wrapper generated from prototype
ULONG __stdcall TdhGetProperty(
	 PEVENT_RECORD pEvent,
	 ULONG TdhContextCount,
	 PTDH_CONTEXT pTdhContext,
	 ULONG PropertyDataCount,
	 PPROPERTY_DATA_DESCRIPTOR pPropertyData,
	 ULONG BufferSize,
	 PBYTE pBuffer );

Tested: OK
*/

// [Deprecated] Dont use this. Use TdhFormatProperty instead.
//
//	Retrieves a property value from the event data.
func TdhGetProperty(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	propertyDataCount uint32,
	pPropertyData *PropertyDataDescriptor,
	bufferSize uint32,
	pBuffer *byte) error {
	r1, _, _ := tdhGetProperty.Call(
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(propertyDataCount),
		uintptr(unsafe.Pointer(pPropertyData)),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(pBuffer)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetpropertysize
/*
TdhGetPropertySize API wrapper generated from prototype
ULONG __stdcall TdhGetPropertySize(
	 PEVENT_RECORD pEvent,
	 ULONG TdhContextCount,
	 PTDH_CONTEXT pTdhContext,
	 ULONG PropertyDataCount,
	 PPROPERTY_DATA_DESCRIPTOR pPropertyData,
	 ULONG *pPropertySize );

Tested: OK
*/

// Retrieves the size of one or more property values in the event data.
// Uses Syscall.SyscallN instead of Proc.Call to avoid heap allocations.
func TdhGetPropertySize(pEvent *EventRecord,
	tdhContextCount uint32,
	pTdhContext *TdhContext,
	propertyDataCount uint32,
	pPropertyData *PropertyDataDescriptor,
	pPropertySize *uint32) error {
	//r1, _, _ := tdhGetPropertySize.Call(
	r1, _, _ := syscall.SyscallN(tdhGetPropertySize.Addr(),
		uintptr(unsafe.Pointer(pEvent)),
		uintptr(tdhContextCount),
		uintptr(unsafe.Pointer(pTdhContext)),
		uintptr(propertyDataCount),
		uintptr(unsafe.Pointer(pPropertyData)),
		uintptr(unsafe.Pointer(pPropertySize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhqueryproviderfieldinformation
/*
TdhQueryProviderFieldInformation API wrapper generated from prototype
ULONG __stdcall TdhQueryProviderFieldInformation(
	 LPGUID pGuid,
	 ULONGLONG EventFieldValue,
	 EVENT_FIELD_TYPE EventFieldType,
	 PPROVIDER_FIELD_INFOARRAY pBuffer,
	 ULONG *pBufferSize );

Tested: NOK
*/

// Retrieves information for the specified field from the event descriptions for those field values that match the given value.
func TdhQueryProviderFieldInformation(
	pGuid *GUID,
	eventFieldValue uint64,
	eventFieldType int,
	pBuffer *ProviderFieldInfoArray,
	pBufferSize *uint32) error {
	r1, _, _ := tdhQueryProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(pGuid)),
		uintptr(eventFieldValue),
		uintptr(eventFieldType),
		uintptr(unsafe.Pointer(pBuffer)),
		uintptr(unsafe.Pointer(pBufferSize)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty
/*
TdhFormatProperty API wrapper generated from prototype
TDHSTATUS TdhFormatProperty(
	 PTRACE_EVENT_INFO EventInfo,
	 PEVENT_MAP_INFO MapInfo,
	 ULONG PointerSize,
	 USHORT PropertyInType,
	 USHORT PropertyOutType,
	 USHORT PropertyLength,
	 USHORT UserDataLength,
	 PBYTE UserData,
	 PULONG BufferSize,
	 PWCHAR Buffer,
	 PUSHORT UserDataConsumed );

Tested: OK
*/

// Using Syscall.SyscallN instead of Proc.Call to avoid heap allocations
// Formats a property value for display.
func TdhFormatProperty(
	eventInfo *TraceEventInfo,
	mapInfo *EventMapInfo,
	pointerSize uint32,
	propertyInType uint16,
	propertyOutType uint16,
	propertyLength uint16,
	userDataLength uint16,
	userData *byte,
	bufferSize *uint32,
	buffer *uint16,
	userDataConsumed *uint16) error {
	r1, _, _ := syscall.SyscallN(tdhFormatProperty.Addr(),
		//r1, _, _ := tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(eventInfo)),
		uintptr(unsafe.Pointer(mapInfo)),
		uintptr(pointerSize),
		uintptr(propertyInType),
		uintptr(propertyOutType),
		uintptr(propertyLength),
		uintptr(userDataLength),
		uintptr(unsafe.Pointer(userData)),
		uintptr(unsafe.Pointer(bufferSize)),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(userDataConsumed)))
	if r1 == 0 {
		return nil
	}
	return syscall.Errno(r1)
}
