//go:build windows

package etw

import (
	"bytes" // also slow but not used much here.
	"fmt"

	"math"
	"os"
	"sync"
	"time"
	"unsafe"
)

const (
	StructurePropertyName = "Structures"
)

// Global Memory Pools
var (
	// We use a global pool for EventRecordHelper.
	helperPool    = sync.Pool{New: func() any { return &EventRecordHelper{} }}
	tdhBufferPool = sync.Pool{New: func() any { s := make([]uint16, 128); return &s }}

	// propertyNameCache stores slices of property names keyed by event schema.
	// This avoids repeatedly converting UTF-16 names to Go strings for common events.
	propertyNameCache sync.Map

	// traceEventInfoCache stores pre-parsed TRACE_EVENT_INFO structures.
	// It's a two-level map for performance:
	// Level 1: Provider GUID -> Level 2: *sync.Map
	// Level 2: Schema Key (ID/Opcode | Version) -> []byte
	traceEventInfoCache sync.Map

	// When true, the traceEventInfoCache is bypassed and TdhGetEventInformation
	// is called for every event. Useful for debugging.
	// Use `EnableTraceInfoCache(false)` to disable.
	traceEventInfoCacheEnabled = true

	// cache for metadata on fully parsed events
	hostname, _ = os.Hostname()
)

// EnableTraceInfoCache enables or disables the caching of TRACE_EVENT_INFO data.
// Disabling the cache forces a call to TdhGetEventInformation for every event,
// which can be useful for debugging but will impact performance.
// This function is not thread-safe and should be called before starting any trace sessions.
func EnableTraceInfoCache(enable bool) {
	traceEventInfoCacheEnabled = enable
}

// These EventRecord methods are defined here because they are only needed in etw_helpers.go

//lint:ignore U1000 option
type schemaKeyType32 uint32

//lint:ignore U1000 option
type schemaKeyType64 uint64

//lint:ignore U1000 option
type schemaKeyType struct {
	high uint64
	low  uint64
}

// schemaCacheKey generates a unique uint32 key for a given event schema within a provider.
// This key is used for the second level of the two-level cache.
// For manifest events, it packs ID and Version.
// For MOF events, it packs Opcode and Version.
// This requieres copying the cached schema for very event to patch the EventDescriptor.
func (er *EventRecord) schemaCacheKey32() schemaKeyType32 {
	desc := &er.EventHeader.EventDescriptor
	if er.IsMof() {
		// For MOF, Opcode (8 bits) + Version (8 bits) is the unique schema ID.
		return schemaKeyType32(uint32(desc.Opcode)<<8 | uint32(desc.Version))
	}
	// For Manifest, ID (16 bits) + Version (8 bits) is the unique schema ID.
	return schemaKeyType32(uint32(desc.Id)<<8 | uint32(desc.Version))
}

// schemaCacheKey packs the entire EventDescriptor into a schemaKeyType..
// it works for both Manifest and MOF events.
//
// It also has the benefit of making the entire TraceInfo static
// (so schema caching don't requiere patching EventDescriptor).
//
// It's 40ns for 128bit key vs 20ns for 64/32bit key but this saves copying the cached schema to patch the EventDescriptor.
func (er *EventRecord) schemaCacheKey() schemaKeyType {
	desc := &er.EventHeader.EventDescriptor
	// For Manifest and MOF, the entire descriptor defines the unique schema.
	// This single, robust key works for both types.
	// Pack fields into a uint64:
	// | 16 bits | 8 bits | 8 bits | 8 bits | 8 bits  | 16 bits |
	// | Task    | Opcode | Level  | Channel| Version | ID      |
	low := uint64(desc.Id)            // needed for manifest
	low |= uint64(desc.Version) << 16 // neded for manifest
	low |= uint64(desc.Channel) << 24
	low |= uint64(desc.Level) << 32  // needed for mof?
	low |= uint64(desc.Opcode) << 40 // needed for mof
	low |= uint64(desc.Task) << 48
	high := desc.Keyword // needed for mof

	return schemaKeyType{high: high, low: low}
}

// schemaCacheKey64 generates a unique uint64 key for a given event schema within a provider.
// This key is used for the second level of the two-level cache.
// It's as fast a the 32bit key and works for both Manifest and MOF events.
// This requieres copying the cached schema for very event to patch the EventDescriptor.
// because the keyword field is not used and it makes the key not unique for MOF events.
func (er *EventRecord) schemaCacheKey64() schemaKeyType64 {
	desc := &er.EventHeader.EventDescriptor
	// For Manifest and MOF, the entire descriptor defines the unique schema.
	// This single, robust key works for both types.
	// Pack fields into a uint64:
	// | 16 bits | 8 bits | 8 bits | 8 bits | 8 bits  | 16 bits |
	// | Task    | Opcode | Level  | Channel| Version | ID      |
	key := uint64(desc.Id)
	key |= uint64(desc.Version) << 16
	key |= uint64(desc.Channel) << 24
	key |= uint64(desc.Level) << 32
	key |= uint64(desc.Opcode) << 40
	key |= uint64(desc.Task) << 48
	return schemaKeyType64(key)
}

// schemaCacheHelper retrieves or creates the first-level cache (a *sync.Map) for a provider's events.
// Accepts a two-level cache map (like traceEventInfoCache or propertyNameCache)
func (er *EventRecord) schemaCacheHelper(baseMap *sync.Map) (shemaCache *sync.Map) {
	if val, ok := baseMap.Load(er.EventHeader.ProviderId); ok {
		shemaCache = val.(*sync.Map)
	} else {
		// This provider has not been seen before. Create its cache.
		// Use LoadOrStore to handle the race condition of two goroutines seeing it for the first time.
		newCache := &sync.Map{}
		actual, _ := baseMap.LoadOrStore(er.EventHeader.ProviderId, newCache)
		shemaCache = actual.(*sync.Map)
	}
	return
}

// traceStorage holds all the necessary reusable memory for a single trace (goroutine).
// This avoids using sync.Pool for thread-local data, reducing overhead.
type traceStorage struct {
	// Reusable buffers and slices. They are reset before processing each event.
	properties      map[string]*Property              // For single properties
	arrayProperties map[string]*[]*Property           // For arrays of properties
	structArrays    map[string][]map[string]*Property // For arrays of structs
	structSingle    []map[string]*Property            // For non-array structs
	selectedProps   map[string]bool                   // Properties selected for parsing
	integerValues   []uint16                          // For caching integer values used in property lengths/counts
	epiArray        []*EventPropertyInfo              // For caching EventPropertyInfo
	teiBuffer       []byte                            // For GetEventInformation()

	// Freelist cache for Property structs.
	propCache []Property
	propIdx   int

	// Pools for nested structures that can't be easily managed by a single slice.
	propertyMapPool sync.Pool // For nested structs in struct arrays.
	propSlicePool   sync.Pool // For simple arrays of properties.
}

// newTraceStorage creates a new storage area for a goroutine.
func newTraceStorage() *traceStorage {
	return &traceStorage{
		properties:      make(map[string]*Property, 64),
		arrayProperties: make(map[string]*[]*Property, 8),
		structArrays:    make(map[string][]map[string]*Property, 4),
		structSingle:    make([]map[string]*Property, 0, 4),
		selectedProps:   make(map[string]bool, 16),
		integerValues:   make([]uint16, 0, 64),
		epiArray:        make([]*EventPropertyInfo, 0, 64),
		teiBuffer:       make([]byte, 8192), // Initial size for GetEventInformation()

		// Initialize the property cache with a reasonable capacity to avoid frequent reallocations.
		propCache: make([]Property, 0, 256),
		propIdx:   0,

		propertyMapPool: sync.Pool{New: func() any { return make(map[string]*Property, 8) }},
		propSlicePool:   sync.Pool{New: func() any { s := make([]*Property, 0, 8); return &s }},
	}
}

// reset clears the storage so it can be reused for the next event.
// It resets slice lengths to 0 (preserving capacity) and clears maps.
func (ts *traceStorage) reset() {
	// 1. Reset property cache index. The underlying slice is reused.
	ts.propIdx = 0

	// 2. Clear properties map.
	clear(ts.properties)

	// 3. Clear array properties map, returning inner slices to the pool.
	for _, propSlicePtr := range ts.arrayProperties {
		clear(*propSlicePtr)
		*propSlicePtr = (*propSlicePtr)[:0]
		ts.propSlicePool.Put(propSlicePtr)
	}
	clear(ts.arrayProperties)

	// 4. Clear struct arrays map, returning inner maps to the pool.
	for _, structs := range ts.structArrays {
		for _, propStruct := range structs {
			clear(propStruct)
			ts.propertyMapPool.Put(propStruct)
		}
	}
	clear(ts.structArrays)

	// 5. Clear single struct slice, returning inner maps to the pool.
	for _, propStruct := range ts.structSingle {
		clear(propStruct)
		ts.propertyMapPool.Put(propStruct)
	}
	ts.structSingle = ts.structSingle[:0]

	// 6. Clear selected properties map.
	clear(ts.selectedProps)

	// 7. Reset integer values slice.
	ts.integerValues = ts.integerValues[:0]

	// 8. Reset epi array slice, clearing pointers to prevent stale data.
	clear(ts.epiArray)
	ts.epiArray = ts.epiArray[:0]

	// teiBuffer does not need to be reset, it gets overwritten.
}

type EventRecordHelper struct {
	EventRec *EventRecord
	// TraceInfo points to a TRACE_EVENT_INFO structure that describes the event's schema.
	//
	// IMPORTANT: This pointer often references a globally cached, shared, and immutable
	// memory buffer to maximize performance. DO NOT MODIFY the contents of the struct
	// pointed to by TraceInfo. Modifying it will corrupt the cache and lead to
	// unpredictable behavior and race conditions across different goroutines.
	// Treat it as strictly read-only.
	TraceInfo *TraceEventInfo

	// Important: use pointers to slices if using pools to avoid corruption
	// when storing EventRecordHelpers in a global pool.

	Properties      map[string]*Property
	ArrayProperties map[string]*[]*Property           // Changed to store pointers
	StructArrays    map[string][]map[string]*Property // For arrays of structs
	StructSingle    *[]map[string]*Property           // For non-array structs

	Flags struct {
		Skip      bool
		Skippable bool
	}

	// Stored property values for resolving array lengths
	// both are filled when an index is queried
	integerValues *[]uint16
	epiArray      *[]*EventPropertyInfo

	// Buffer that contains the memory for TraceEventInfo.
	// used internally to reuse the memory allocation.
	teiBuffer *[]byte

	// Position of the next byte of event data to be consumed.
	// increments after each call to prepareProperty
	userDataIt uintptr

	// Position of the end of the event data
	// For UserData length check [EventRec.UserDataLength]
	userDataEnd uintptr

	selectedProperties map[string]bool

	// A reference to the thread-local storage for this trace.
	storage *traceStorage

	// FILETIME format of this event timestamp (in case raw timestamp is used)
	timestamp int64
}

func (e *EventRecordHelper) remainingUserDataLength() uint16 {
	return uint16(e.userDataEnd - e.userDataIt)
}

func (e *EventRecordHelper) userContext() (c *traceContext) {
	return e.EventRec.userContext()
}

func (e *EventRecordHelper) addPropError() {
	c := e.userContext()
	if c != nil && c.trace != nil {
		c.trace.ErrorPropsParse.Add(1)
	}
}

// Timestamp returns the timestamp of the event as a time.Time from FILETIME.
//
// goetw converts the original timestamp clocktype to FILETIME if raw PROCESS_TRACE_MODE_RAW_TIMESTAMP is set.
//
// Session ClientContext: QPC, SystemTime and CPUClocks clocktypes are correctly converted to FILETIME.
// If the raw timestamp flag is not set, it just uses the FILETIME returned by etw in time.Time format.
func (e *EventRecordHelper) Timestamp() time.Time {
	return FromFiletime(e.timestamp) // use cached filetime timestamp
}

// TimestampFromProp converts a raw timestamp value from an event property (like WmiTime)
// into an absolute time.Time, using the session's clock type and conversion settings.
func (e *EventRecordHelper) TimestampFromProp(propTimestamp int64) time.Time {
	return e.EventRec.TimestampFromProp(propTimestamp)
}

// Release EventRecordHelper back to memory pool.
// Note: The reusable memory (maps, slices, etc.) referenced by EventRecordHelper
// is managed and reset by traceStorage.reset() before reuse. This method only
// zeroes out the struct fields themselves.
func (e *EventRecordHelper) release() {
	*e = EventRecordHelper{}
	helperPool.Put(e)
}

// newEventRecordHelper creates a new EventRecordHelper and retrieves the TRACE_EVENT_INFO
// for the given EventRecord. It implements a multi-level caching and fallback strategy:
// 1. Check a global two stage cache for a pre-parsed TRACE_EVENT_INFO.
// 2. If cache miss, call TdhGetEventInformation.
// 3. If the API call succeeds, store the result in the cache.
// 4. If the API fails for a classic MOF event, attempt to build the info from generated definitions.
// 5. If the MOF generation succeeds, store that result in the cache.
func newEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = helperPool.Get().(*EventRecordHelper)
	storage := er.userContext().storage
	teiBuffer := &storage.teiBuffer

	// Reset the thread-local storage before processing a new event.
	storage.reset()

	erh.storage = storage
	erh.EventRec = er
	var schemaKey schemaKeyType64 // Currently using the 64bit key (its safer to copy the cached schema)

	// --- Stage 1: Check Cache ---
	if traceEventInfoCacheEnabled {
		// 1. First-level lookup by Provider GUID.
		schemaCache := er.schemaCacheHelper(&traceEventInfoCache)

		// 2. Second-level lookup by schema key.
		schemaKey = er.schemaCacheKey64()
		if cachedTei, found := schemaCache.Load(schemaKey); found {
			// This commented block of code is if we need to copy the buffer to a local one. (2,1% performance hit)
			// NOTE: use er.schemaCacheKey32() or er.schemaCacheKey64() if using this block
			if true {
				// Cache hit: Use the cached TRACE_EVENT_INFO
				template := cachedTei.([]byte)
				// Ensure the thread-local buffer is large enough.
				if cap(storage.teiBuffer) < len(template) {
					storage.teiBuffer = make([]byte, len(template))
				}
				storage.teiBuffer = storage.teiBuffer[:len(template)]
				// Copy the cached template into the thread-local buffer.
				copy(storage.teiBuffer, template)
				erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&storage.teiBuffer[0]))
				erh.TraceInfo.EventDescriptor = er.EventHeader.EventDescriptor // important: patch EventDescriptor
				erh.teiBuffer = &storage.teiBuffer
			} else { // NOTE: use er.schemaCacheKey() if using this block

				// Cache hit: The template is immutable. Point directly to it. No copy needed.
				template := cachedTei.([]byte)
				erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&template[0]))

				// The buffer is the globally cached one, not the thread-local one.
				// Setting this to nil indicates it's not locally owned.
				erh.teiBuffer = nil
			}
			return erh, nil // Cache hit, we are done.
		}
	}

	// --- Stage 2: Call TdhGetEventInformation (Cache Miss) ---
	erh.TraceInfo, err = er.GetEventInformation(teiBuffer)
	if err != nil {
		apiErr := fmt.Errorf("%w: %v", ErrGetEventInformation, err)

		// --- Stage 3: Fallback to MOF Generator ---
		if er.IsMof() {
			if erh.TraceInfo, err = buildTraceInfoFromMof(er, teiBuffer); err == nil {
				// MOF generator succeeded. Cache the result.
				if traceEventInfoCacheEnabled {
					cloneAndCacheTraceInfo(er.EventHeader.ProviderId, schemaKey, *teiBuffer)
				}
				err = nil // Suppress the original API error.
			} else {
				err = apiErr // MOF generator also failed; return the original API error.
			}
		} else {
			err = apiErr // Not a MOF event, no fallback possible.
		}
	} else {
		// API call succeeded. Cache the result.
		if traceEventInfoCacheEnabled {
			cloneAndCacheTraceInfo(er.EventHeader.ProviderId, schemaKey, *teiBuffer)
		}
	}

	erh.teiBuffer = teiBuffer // Keep a reference
	return erh, err
}

// cloneAndCacheTraceInfo makes a copy of a TraceEventInfo buffer and stores it in the two-level cache.
func cloneAndCacheTraceInfo(providerGUID GUID, schemaKey schemaKeyType64, teiBuffer []byte) {
	// Get the second-level cache for this provider. It must exist at this point.
	val, _ := traceEventInfoCache.Load(providerGUID)
	schemaCache := val.(*sync.Map)

	// Create a copy of the buffer to store in the cache.
	// this done 1 time per shema so performance is not critical.
	cachedTei := make([]byte, len(teiBuffer))
	copy(cachedTei, teiBuffer)

	// Store the copied buffer in the second-level cache.
	schemaCache.Store(schemaKey, cachedTei)
}

// newEventRecordHelper_test is a performance testing variant of newEventRecordHelper.
// It prioritizes the custom buildTraceInfoFromMof function and falls back to the
// GetEventInformation API only if the custom builder fails. This is the reverse
// of the production logic and is used to measure the performance of the MOF fallback path.
func newEventRecordHelper_test(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = helperPool.Get().(*EventRecordHelper)
	storage := er.userContext().storage

	// Reset the thread-local storage before processing a new event.
	storage.reset()

	erh.storage = storage
	erh.EventRec = er

	// For testing, we prioritize our custom MOF builder.
	if er.IsMof() {
		erh.TraceInfo, err = buildTraceInfoFromMof(er, &storage.teiBuffer)
	} else {
		// If it's not a classic MOF event, we must use the API.
		// We set an error to force the fallback path.
		err = fmt.Errorf("not a MOF event, must use GetEventInformation")
	}

	// If our MOF builder failed (or it wasn't a MOF event), fall back to the API.
	if err != nil {
		mofBuilderErr := err // Preserve the builder error for context.
		if erh.TraceInfo, err = er.GetEventInformation(&storage.teiBuffer); err != nil {
			// Both the builder and the API failed. The API error is the one to report.
			err = fmt.Errorf("%w: %v: %v", ErrGetEventInformation, err, mofBuilderErr)
		} else {
			// API succeeded, so we can proceed. Clear the error.
			err = nil
		}
	} else {
		// // Our MOF builder succeeded.
		// // DEBUGGING: Compare our result with what the API would have returned.
		// if isDebug {
		//     var apiTeiBuffer []byte // Use a separate buffer for the API call to not corrupt our generated one.
		//     apiTei, apiErr := er.GetEventInformation(&apiTeiBuffer)
		//     if apiErr == nil && apiTei != nil {
		//         if compareTraceEventInfo(erh.TraceInfo, apiTei)&MismatchOther != 0 {
		//             fmt.Println("--- DEBUG: Comparing generated TraceEventInfo with original ---")
		//             log.Error().Interface("Original EventRecord", er).Msg("DEBUG EventRecord")
		//             log.Error().Interface("Original EventTraceInfo", apiTei).Msg("DEBUG EventRecord")
		//             fmt.Println("--- DEBUG: Comparison finished ---")
		//             fmt.Println()
		//             er.getUserContext().consumer.ctx.Done() // Stop processing events
		//             os.Exit(1)
		//         }
		//     }
		// }
	}

	erh.teiBuffer = &storage.teiBuffer // Keep a reference
	return
}

// This memory was already reseted when it was released.
func (e *EventRecordHelper) initialize() {
	storage := e.storage
	e.Properties = storage.properties
	e.ArrayProperties = storage.arrayProperties

	// Structure handling
	e.StructArrays = storage.structArrays
	e.StructSingle = &storage.structSingle

	e.selectedProperties = storage.selectedProps

	if e.TraceInfo == nil {
		// Nothing to initialize for properties if we have no schema.
		e.userDataIt = e.EventRec.UserData
		e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)
		return
	}

	maxPropCount := int(e.TraceInfo.PropertyCount)
	// Get and resize integer values
	if cap(storage.integerValues) < maxPropCount {
		storage.integerValues = make([]uint16, maxPropCount)
	}
	e.integerValues = &storage.integerValues
	*e.integerValues = (*e.integerValues)[:maxPropCount]

	// Get and resize epi array
	if cap(storage.epiArray) < maxPropCount {
		storage.epiArray = make([]*EventPropertyInfo, maxPropCount)
	}
	e.epiArray = &storage.epiArray
	*e.epiArray = (*e.epiArray)[:maxPropCount]

	// userDataIt iterator will be incremented for each queried property by prop size
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)
}

// newProperty retrieves a new property from the thread-local freelist.
func (e *EventRecordHelper) newProperty() *Property {
	storage := e.storage
	if storage.propIdx >= len(storage.propCache) {
		// Freelist is empty, grow the cache. Append will handle capacity increase.
		storage.propCache = append(storage.propCache, Property{})
	}

	// Get the next property from the cache.
	p := &storage.propCache[storage.propIdx]
	storage.propIdx++
	p.reset() // Ensure the property is clean before use.
	return p
}

func (e *EventRecordHelper) setEventMetadata(event *Event) {
	event.System.Computer = hostname

	// Some Providers don't have a ProcessID or ThreadID (there are set 0xFFFFFFFF)
	// because some events are logged by separate threads
	if e.EventRec.EventHeader.ProcessId == math.MaxUint32 {
		event.System.Execution.ProcessID = 0
	} else {
		event.System.Execution.ProcessID = e.EventRec.EventHeader.ProcessId
	}
	if e.EventRec.EventHeader.ThreadId == math.MaxUint32 {
		event.System.Execution.ThreadID = 0
	} else {
		event.System.Execution.ThreadID = e.EventRec.EventHeader.ThreadId
	}

	event.System.Execution.ProcessorID = e.EventRec.ProcessorNumber()

	// NOTE: for private session use e.EventRec.EventHeader.ProcessorTime
	if e.EventRec.EventHeader.Flags&
		(EVENT_HEADER_FLAG_PRIVATE_SESSION|EVENT_HEADER_FLAG_NO_CPUTIME) == 0 {
		event.System.Execution.KernelTime = e.EventRec.EventHeader.GetKernelTime()
		event.System.Execution.UserTime = e.EventRec.EventHeader.GetUserTime()
	} else {
		event.System.Execution.ProcessorTime = e.EventRec.EventHeader.ProcessorTime
	}

	// EVENT_RECORD.EVENT_HEADER.EventDescriptor == TRACE_EVENT_INFO.EventDescriptor for MOF events
	event.System.EventID = e.TraceInfo.EventID()
	event.System.Version = e.TraceInfo.EventDescriptor.Version
	event.System.Channel = e.TraceInfo.ChannelName()

	event.System.Provider.Guid = e.TraceInfo.ProviderGUID
	event.System.Provider.Name = e.TraceInfo.ProviderName()
	event.System.Level.Value = e.TraceInfo.EventDescriptor.Level
	event.System.Level.Name = e.TraceInfo.LevelName()
	event.System.Opcode.Value = e.TraceInfo.EventDescriptor.Opcode
	event.System.Opcode.Name = e.TraceInfo.OpcodeName()
	event.System.Keywords.Mask = e.TraceInfo.EventDescriptor.Keyword
	event.System.Keywords.Name = e.TraceInfo.KeywordsName()
	event.System.Task.Value = uint8(e.TraceInfo.EventDescriptor.Task)
	event.System.Task.Name = e.TraceInfo.TaskName()

	// Use the converted timestamp if available, otherwise fall back to raw timestamp
	event.System.TimeCreated.SystemTime = e.Timestamp()

	if e.TraceInfo.IsMof() {
		var eventType string
		// e.EventRec.EventHeader.ProviderId is the same as e.TraceInfo.EventGUID
		if c := MofErLookup(e.EventRec); c != nil {
			eventType = fmt.Sprintf("%s/%s", c.Name, e.TraceInfo.OpcodeName())
			// if t, ok := MofClassMapping[e.EventRec.EventHeader.ProviderId.Data1]; ok {
			// 	eventType = fmt.Sprintf("%s/%s", t.Name, e.TraceInfo.OpcodeName())
		} else {
			eventType = fmt.Sprintf("UnknownClass/%s", e.TraceInfo.OpcodeName())
		}

		event.System.EventType = eventType
		event.System.EventGuid = e.TraceInfo.EventGUID
		event.System.Correlation.ActivityID = e.TraceInfo.ActivityIDName()
		event.System.Correlation.RelatedActivityID = e.TraceInfo.RelatedActivityIDName()
	} else {
		event.System.Correlation.ActivityID = e.EventRec.EventHeader.ActivityId.StringU()
		if relatedActivityID := e.EventRec.ExtRelatedActivityID(); relatedActivityID.IsZero() {
			event.System.Correlation.RelatedActivityID = nullGUIDStr
		} else {
			event.System.Correlation.RelatedActivityID = relatedActivityID.StringU()
		}
	}
}

// Returns the size of the property at index i, using TdhGetPropertySize.
func (e *EventRecordHelper) getPropertySize(i uint32) (size uint32, err error) {
	dataDesc := PropertyDataDescriptor{}
	dataDesc.PropertyName = uint64(e.TraceInfo.PropertyNamePointer(i))
	dataDesc.ArrayIndex = math.MaxUint32
	err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDesc, &size)
	return
}

// cacheIntegerValues helps when a property length or array count needs to be
// calculated using a previous property's value. It is called for each property
// as its metadata is accessed, caching any scalar integer value. This ensures
// that when a subsequent property's length or count is calculated, the value
// it depends on is readily available.
func (e *EventRecordHelper) cacheIntegerValues(i uint32, epi *EventPropertyInfo) {
	// If this property is a scalar integer, remember the value in case it
	// is needed for a subsequent property's that has the PropertyParamLength flag set.
	// This is a Single Value property, not a struct and it doesn't have a param count
	// Basically: if !isStruct && !hasParamCount && isSingleValue
	if (epi.Flags&(PropertyStruct|PropertyParamCount)) == 0 &&
		epi.Count() == 1 {
		userdr := e.remainingUserDataLength()

		// integerValues is used sequentially, so we can reuse it without reseting
		switch inType := TdhInType(epi.InType()); inType {
		case TDH_INTYPE_INT8,
			TDH_INTYPE_UINT8:
			if (userdr) >= 1 {
				(*e.integerValues)[i] = uint16(*(*uint8)(unsafe.Pointer(e.userDataIt)))
			}
		case TDH_INTYPE_INT16,
			TDH_INTYPE_UINT16:
			if (userdr) >= 2 {
				(*e.integerValues)[i] = *(*uint16)(unsafe.Pointer(e.userDataIt))
			}
		case TDH_INTYPE_INT32,
			TDH_INTYPE_UINT32,
			TDH_INTYPE_HEXINT32:
			if (userdr) >= 4 {
				val := *(*uint32)(unsafe.Pointer(e.userDataIt))
				if val > 0xffff {
					(*e.integerValues)[i] = 0xffff
				} else {
					(*e.integerValues)[i] = uint16(val)
				}
			}
		}
	}
}

// Gets the EventPropertyInfo at index i, caching it for future use.
// also caches the data if it's an integer property if any other property needs it for length.
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	// (epiArray mem is reused, make sure the elements are set to nil before use)
	epi := (*e.epiArray)[i]
	if epi == nil {
		epi = e.TraceInfo.GetEventPropertyInfoAt(i)
		(*e.epiArray)[i] = epi
		e.cacheIntegerValues(i, epi)
	}
	return epi
}

// Returns the length of the property (can be 0) at index i and the actual size in bytes.
func (e *EventRecordHelper) getPropertyLength(i uint32) (propLength uint16, sizeBytes uint32, err error) {
	var epi = e.getEpiAt(i)

	// We recorded the values of all previous integer properties just
	// in case we need to determine the property length or count.
	// integerValues will have our length or count number.
	switch {
	case (epi.Flags & PropertyParamLength) != 0:
		// Length from another property
		propLength = (*e.integerValues)[epi.LengthPropertyIndex()]

	case (epi.Flags & PropertyParamFixedLength) != 0:
		// Fixed length specified in manifest
		propLength = epi.Length()
		if propLength == 0 {
			// Fixed zero length
			return 0, 0, nil
		}

	default:
		// Use length field
		propLength = epi.Length()
	}

	// Fix: Length will be in WCHAR count if TDH_INTYPE_UNICODESTRING
	if (propLength > 0) && (epi.InType() == TDH_INTYPE_UNICODESTRING) {
		sizeBytes = uint32(propLength) * 2
	} else {
		sizeBytes = uint32(propLength)
	}

	//* links:
	// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers#property-qualifiers

	// Improves performance (vs calling TdhGetPropertySize on every variable prop by ~6%)
	// We do this the long way to not abuse cgo calls on every prop.
	// (if go cgo improves in performance this will a 3 liner)
	//
	// Gets byte size for zero length cases (null-terminated or variable)
	if propLength == 0 {
		switch epi.InType() {

		case TDH_INTYPE_BINARY:
			if epi.OutType() == TDH_OUTTYPE_IPV6 &&
				epi.Length() == 0 &&
				(epi.Flags&(PropertyParamLength|PropertyParamFixedLength)) == 0 {
				return 16, 16, nil // special case for incorrectly-defined IPV6 addresses
			}
			if epi.OutType() == TDH_OUTTYPE_HEXBINARY {
				// TdhGetPropertySize returns 0 for these fields.
				// Microsoft-Windows-Kernel-Registry is an example to test.
				// The field is incorrectly encoded or the size is indeed 0.
				// NOTE(will be decoded in string form as "0x")
				return 0, 0, nil
			}
			// Try TdhGetPropertySize for other binary types

		case TDH_INTYPE_UNICODESTRING:
			// For non-null terminated strings, especially at end of event data,
			// use remaining data length as string length
			wchars := unsafe.Slice((*uint16)(unsafe.Pointer(e.userDataIt)),
				e.remainingUserDataLength()/2)
			sizeBytes = 0
			for _, w := range wchars {
				sizeBytes += 2 // include null terminator
				if w == 0 {
					break
				}
			}
			// size may be null included even if not null terminated, doesnt matter.
			// this is the last prop, the iterator will be at the end of the data.
			return 0, sizeBytes, nil

		case TDH_INTYPE_ANSISTRING:
			// Scan until null or end
			chars := unsafe.Slice((*byte)(unsafe.Pointer(e.userDataIt)),
				e.remainingUserDataLength())
			sizeBytes = 0
			for _, c := range chars {
				sizeBytes++ // include null terminator
				if c == 0 {
					break
				}
			}
			// size may be null included even if not null terminated, doesnt matter.
			// this is the last prop, the iterator will be at the end of the data.
			return 0, sizeBytes, nil

		// All counted string/binary types that have 2-byte length prefix
		case TDH_INTYPE_MANIFEST_COUNTEDBINARY,
			TDH_INTYPE_MANIFEST_COUNTEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_COUNTEDSTRING,
			TDH_INTYPE_COUNTEDANSISTRING:
			// Length is little-endian uint16 prefix
			if e.remainingUserDataLength() < 2 {
				break // try tdhGetPropertySize
			}
			sizeBytes = uint32(*(*uint16)(unsafe.Pointer(e.userDataIt))) + 2 // Include length prefix
			return 0, sizeBytes, nil

		case TDH_INTYPE_REVERSEDCOUNTEDSTRING,
			TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
			// Length is big-endian uint16 prefix
			if e.remainingUserDataLength() < 2 {
				break // try tdhGetPropertySize
			}
			byteLen := *(*uint16)(unsafe.Pointer(e.userDataIt))
			sizeBytes = uint32(Swap16(byteLen)) + 2 // Include length prefix
			return 0, sizeBytes, nil

		case TDH_INTYPE_SID,
			TDH_INTYPE_WBEMSID:
			// SID memory layout:
			// For TDH_INTYPE_SID:
			// +==============================================================+
			// | Offset | Size | Field                  | Description         |
			// |--------|------|------------------------|---------------------|
			// | 0      | 1    | Revision               | SID version (1)     |
			// | 1      | 1    | SubAuthorityCount      | Number of sub-auths |
			// | 2      | 6    | IdentifierAuthority    | Authority ID        |
			// | 8      | 4*N  | SubAuthority[N]        | N sub-authorities   |
			// +==============================================================+
			// Total size = 8 + (4 * SubAuthorityCount) bytes
			//
			// For TDH_INTYPE_WBEMSID:
			// +==============================================================+
			// | Offset | Size   | Field               | Description          |
			// |--------|--------|---------------------|----------------------|
			// | 0      | 4/8    | User ptr            | TOKEN_USER pointer   |
			// | 4/8    | 4/8    | Sid ptr             | SID pointer          |
			// | 8/16   | varies | SID structure       | Same as above        |
			// +==============================================================+
			// Note: First two fields are pointers - size depends on 32/64-bit

			// Minimum SID size is 8 bytes (header + identifier authority, no sub-authorities)
			if e.remainingUserDataLength() < 8 {
				break // try tdhGetPropertySize
			}
			var sidSize uint32
			if epi.InType() == TDH_INTYPE_WBEMSID {
				// For WBEMSID, skip TOKEN_USER structure
				// (contains 2 pointers - size depends on architecture)
				if e.EventRec.PointerSize() == 8 {
					sidSize += 16 // 64-bit: 2 * 8-byte pointers
				} else {
					sidSize += 8 // 32-bit: 2 * 4-byte pointers
				}
			}
			sidPtr := e.userDataIt + uintptr(sidSize) // Skip header
			// Read SubAuthorityCount from SID header
			subAuthCount := *(*uint8)(unsafe.Pointer(sidPtr + 1)) // offset 1 byte for Revision
			sidSize += 8 + (4 * uint32(subAuthCount))             // 8 byte header + 4 bytes per sub-authority
			// Verify we have enough data for the full SID
			if uint32(e.remainingUserDataLength()) <= sidSize {
				break // try tdhGetPropertySize
			}
			return 0, sidSize, nil

		case TDH_INTYPE_HEXDUMP:
			// First 4 bytes contain length
			if e.remainingUserDataLength() < 4 {
				break // try tdhGetPropertySize
			}
			sizeBytes = *(*uint32)(unsafe.Pointer(e.userDataIt))
			return 0, sizeBytes, nil

		default:
			if epi.Flags&PropertyStruct == PropertyStruct {
				// We don't support nested structs yet. ERROR
				break // Use TdhGetPropertySize
			}

			conlog.SampledWarn("proplength").
				Uint16("intype", epi.InType().V()).
				Str("outtype", epi.OutType().String()).
				Msg("unexpected length of 0")
		}

		// We already know how to get the size for each intype, but a single mistake could crash the event.
		// Use the tdh functions to advance the pointer when we are not sure of the size in bytes.
		// it shouldn't be called often anyway so it's a small performance loss
		sizeBytes, err = e.getPropertySize(i)
		if err != nil {
			return
		}
	}

	return
}

// Setups a property for parsing, will be parsed later (or not)
func (e *EventRecordHelper) prepareProperty(i uint32, name string) (p *Property, err error) {
	p = e.newProperty()

	p.evtPropInfo = e.getEpiAt(i)
	p.erh = e
	p.name = name
	p.pValue = e.userDataIt
	p.userDataRemaining = e.remainingUserDataLength()
	p.length, p.sizeBytes, err = e.getPropertyLength(i)
	if err != nil {
		return
	}

	// p.length has to be 0 on strings and structures for TdhFormatProperty to work.
	// We use size instead to advance when p.length is 0.
	e.userDataIt += uintptr(p.sizeBytes)

	return
}

// getArrayInfo determines if a property is an array and returns its count.
func (e *EventRecordHelper) getArrayInfo(epi *EventPropertyInfo) (count uint16, isArray bool) {
	if (epi.Flags & PropertyParamCount) != 0 {
		// Look up the value of a previous property
		count = (*e.integerValues)[epi.CountPropertyIndex()]
	} else {
		count = epi.Count()
	}

	// Note that PropertyParamFixedCount is a new flag and is ignored
	// by many decoders. Without the PropertyParamFixedCount flag,
	// decoders will assume that a property is an array if it has
	// either a count parameter or a fixed count other than 1. The
	// PropertyParamFixedCount flag allows for fixed-count arrays with
	// one element to be propertly decoded as arrays.
	isArray = count != 1 || (epi.Flags&(PropertyParamCount|PropertyParamFixedCount)) != 0
	return
}

// prepareStruct handles properties that are structs or arrays of structs.
func (e *EventRecordHelper) prepareStruct(i uint32, epi *EventPropertyInfo, arrayCount uint16, isArray bool, names []string) error {
	var p *Property
	var err error
	arrayName := names[i]

	// Treat non-array properties as arrays with one element.
	for range arrayCount {
		propStruct := e.storage.propertyMapPool.Get().(map[string]*Property)

		startIndex := epi.StructStartIndex()
		lastMember := startIndex + epi.NumOfStructMembers()

		for j := startIndex; j < lastMember; j++ {
			if p, err = e.prepareProperty(uint32(j), names[j]); err != nil {
				e.addPropError()
				// On error, return the map to the pool.
				// No need to release individual properties due to block pooling.
				clear(propStruct)
				e.storage.propertyMapPool.Put(propStruct)
				return err
			}
			propStruct[p.name] = p
		}

		// Add to appropriate collection
		if isArray {
			// Part of an array - add to StructArrays
			e.StructArrays[arrayName] = append(e.StructArrays[arrayName], propStruct)
		} else {
			// Single struct - add to SingleStructs
			*e.StructSingle = append(*e.StructSingle, propStruct)
		}
	}
	return nil
}

// prepareSimpleArray handles properties that are arrays of simple types (not structs).
func (e *EventRecordHelper) prepareSimpleArray(i uint32, epi *EventPropertyInfo,
	arrayCount uint16, names []string) error {

	arrayName := names[i]

	// Special case for MOF string arrays, which are common in classic kernel events.
	// if this is a MOF event, we don't need to parse the properties of the array
	// this will be a array of wchars, Kernel events EVENT_HEADER_FLAG_CLASSIC_HEADER (nt Kernel events)
	if e.TraceInfo.IsMof() &&
		e.EventRec.EventHeader.Flags&EVENT_HEADER_FLAG_CLASSIC_HEADER != 0 &&
		epi.InType() == TDH_INTYPE_UNICODECHAR {
		// C++ Definition example: wchar_t ThreadName[1]; (Variadic arrays)
		// arrayCount is usualy a cap in this case. Fixed 256 byte array usually.
		mofString := unsafe.Slice((*uint16)(unsafe.Pointer(e.userDataIt)), arrayCount)
		value := FromUTF16Slice(mofString)
		e.SetProperty(arrayName, value)
		e.userDataIt += (uintptr(arrayCount) * 2) // advance pointer
		return nil                                // Array parsed, we're done with this property.
	}

	// For regular simple arrays, get a slice from the pool.
	array := e.storage.propSlicePool.Get().(*[]*Property)
	if cap(*array) < int(arrayCount) {
		*array = make([]*Property, 0, arrayCount)
	}

	var p *Property
	var err error
	for range arrayCount {
		if p, err = e.prepareProperty(i, names[i]); err != nil {
			e.addPropError()
			// On error, return the slice to the pool.
			// No need to release individual properties due to block pooling.
			clear(*array)
			*array = (*array)[:0]
			e.storage.propSlicePool.Put(array)
			return err
		}
		*array = append(*array, p)
	}

	if len(*array) > 0 {
		e.ArrayProperties[arrayName] = array
	} else {
		// Return the unused slice to the pool if the array ended up empty.
		e.storage.propSlicePool.Put(array)
	}

	return nil
}

// getCachedPropNames retrieves the property names for the event schema.
// It uses a cache for each provider event type to avoid repeated UTF-16 to string conversions.
func (e *EventRecordHelper) getCachedPropNames() []string {
	// Use the same two-level cache keying strategy for property names.
	schemaKey := e.EventRec.schemaCacheKey()

	// 1. First-level lookup for the provider's property name cache.
	schemaNameCache := e.EventRec.schemaCacheHelper(&propertyNameCache)

	// 2. Second-level lookup for the specific schema's names.
	if cachedNames, ok := schemaNameCache.Load(schemaKey); ok {
		return cachedNames.([]string)
	}

	// Cache miss. Generate all property names for this schema once.
	names := make([]string, e.TraceInfo.PropertyCount)
	for i := range names {
		epi := e.TraceInfo.GetEventPropertyInfoAt(uint32(i))
		names[i] = FromUTF16AtOffset(e.TraceInfo.pointer(), uintptr(epi.NameOffset))
	}
	schemaNameCache.Store(schemaKey, names)
	return names
}

// Prepare will partially decode the event, extracting event info for later
//
// There is a lot of information available in the event even without decoding,
// including timestamp, PID, TID, provider ID, activity ID, and the raw data.
func (e *EventRecordHelper) prepareProperties() (err error) {

	// TODO: move this to a separate function before TraceInfo is used/created
	// Handle special case for MOF events that are just a single string.
	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
	if e.EventRec.IsMof() {
		// If there aren't any event property info structs, use the UserData directly.
		if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0 {
			str := (*uint16)(unsafe.Pointer(e.EventRec.UserData))
			value := FromUTF16Slice(
				unsafe.Slice(str, e.EventRec.UserDataLength/2))
			if e.EventRec.UserDataLength != 0 {
				e.SetProperty("String", value)
			}
			return
		}
	}

	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0 {
	// }
	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 {
	//	// Kernel events
	// }

	// Get or generate property names for this event schema.
	// This is a performance optimization to avoid repeated UTF-16 to string conversions.
	names := e.getCachedPropNames()

	// Process all top-level properties defined in the event schema.
	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		epi := e.getEpiAt(i)
		if epi == nil {
			e.addPropError()
			conlog.SampledError("epi-null").
				Uint32("index", i).
				Uint32("topLevelPropertyCount", e.TraceInfo.TopLevelPropertyCount).
				Msg("prepareProperties: getEpiAt returned nil, skipping property")

			continue // This is not a fatal error, we can continue processing.
		}

		arrayCount, isArray := e.getArrayInfo(epi)

		if (epi.Flags & PropertyStruct) != 0 {
			// Property is a struct or an array of structs.
			if err = e.prepareStruct(i, epi, arrayCount, isArray, names); err != nil {
				return err
			}
		} else if isArray {
			// Property is an array of simple types.
			if err = e.prepareSimpleArray(i, epi, arrayCount, names); err != nil {
				return err
			}
		} else {
			// Property is a single, non-array, non-struct value.
			var p *Property
			if p, err = e.prepareProperty(i, names[i]); err != nil {
				e.addPropError()
				return err
			}
			e.Properties[p.name] = p
		}
	}

	// After parsing all defined properties, check if there's any data left.
	// This can happen if the event schema is an older version.
	if e.userDataIt < e.userDataEnd {
		remainingBytes := uint32(e.userDataEnd - e.userDataIt)
		remainingData := unsafe.Slice((*byte)(unsafe.Pointer(e.userDataIt)), remainingBytes)

		// Probably this is because TraceEventInfo used an older Thread_V2_TypeGroup1
		// instead of a Thread_V3_TypeGroup1 MOF class to decode it.
		// Try to parse the remaining data as a MOF property.
		// TODO: remove this?
		if e.TraceInfo.IsMof() {
			if err2 := e.prepareMofPropertyFix(remainingData, remainingBytes); err2 == nil {
				return nil // Data was successfully parsed, return.
			}
		}

		e.addPropError()
		conlog.Warn().Interface("eventRecord", e.EventRec).
			Interface("traceInfo", e.TraceInfo).Uint32("remaining", remainingBytes).
			Int("total", int(e.EventRec.UserDataLength)).
			//Str("remainingHex", hex.EncodeToString(remainingData)). // Interface mashal already does this
			Msg("UserData not fully parsed")
	}

	return nil
}

// This is a common pattern with kernel ETW events where newer fields are added
// but backward compatibility needs to be maintained, so we must check if the
// data is a new field.
// TODO(tekert): use the new kernel mof generated classes to decode this.
// TODO: the problem is, for example FileIO V3 is not defined elsewere, and we get those events from ETW
func (e *EventRecordHelper) prepareMofPropertyFix(remainingData []byte, remaining uint32) (err error) {
	// Check if all bytes are padding (zeros)
	if bytes.IndexFunc(remainingData, func(r rune) bool {
		return r != 0
	}) == -1 {
		return nil
	}

	eventID := e.TraceInfo.EventID()
	//eventType := e.TraceInfo.EventDescriptor.Opcode

	// Thread_V3_TypeGroup1 new ThreadName not included in TraceEventInfo propierties on Windows 10.
	if (eventID == 5358 || // Thread/DCStart
		eventID == 5357 || // Thread/End
		eventID == 5359) && // Thread/DCEnd
		remaining > 2 {
		threadName := FromUTF16Bytes(remainingData)
		e.SetProperty("ThreadName", threadName)
		return nil
	}

	// Handle SystemConfig PnP events with device names
	if eventID == 1807 && // SystemConfig/PnP
		remaining > 2 {
		deviceName := FromUTF16Bytes(remainingData)
		e.SetProperty("DeviceName", deviceName)
		return nil
	}

	return fmt.Errorf("unhandled MOF event %d", eventID)
}

func (e *EventRecordHelper) buildEvent() (event *Event, err error) {
	event = NewEvent()
	event.Flags.Skippable = e.Flags.Skippable
	if err = e.parseAndSetAllProperties(event); err != nil {
		return
	}
	e.setEventMetadata(event)

	return
}

func (e *EventRecordHelper) parseAndSetProperty(name string, out *Event) (err error) {
	eventData := out.EventData

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = out.UserData
	}

	if p, ok := e.Properties[name]; ok {
		if eventData[p.name], err = p.FormatToString(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
		}
	}

	// parsing array
	if propSlicePtr, ok := e.ArrayProperties[name]; ok {
		values := make([]string, 0, len(*propSlicePtr))

		// iterate over the properties
		for _, p := range *propSlicePtr {
			var v string
			if v, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, name, err)
			}

			values = append(values, v)
		}

		eventData[name] = values
	}

	// Structure arrays
	if structs, ok := e.StructArrays[name]; ok {
		if structArray, err := e.formatStructs(structs, name); err != nil {
			return err
		} else {
			eventData[name] = structArray
		}
	}

	// Single structs - only check if requesting StructurePropertyName
	if name == StructurePropertyName && len(*e.StructSingle) > 0 {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			return err
		} else {
			eventData[StructurePropertyName] = structs
		}
	}

	return
}

func (e *EventRecordHelper) shouldParse(name string) bool {
	if len(e.selectedProperties) == 0 {
		return true
	}
	_, ok := e.selectedProperties[name]
	return ok
}

// this a bit inneficient, but it's not a big deal, we ussually want a few properties not all.
func (e *EventRecordHelper) parseAndSetAllProperties(out *Event) (last error) {
	var err error

	eventData := out.EventData

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = out.UserData
	}

	// Properties
	for _, p := range e.Properties {
		if !e.shouldParse(p.name) {
			continue
		}
		if _, err := p.FormatToString(); err != nil {
			last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, p.name, err)
		} else {
			eventData[p.name] = p.value
		}
	}

	// Arrays
	for pname, propsPtr := range e.ArrayProperties {
		if !e.shouldParse(pname) {
			continue
		}

		props := *propsPtr
		values := make([]string, 0, len(props))

		// iterate over the properties
		for _, p := range props {
			var v string
			if v, err = p.FormatToString(); err != nil {
				last = fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, pname, err)
			}

			values = append(values, v)
		}

		eventData[pname] = values
	}

	// Handle struct arrays
	for name, structs := range e.StructArrays {
		if !e.shouldParse(name) {
			continue
		}
		if structArray, err := e.formatStructs(structs, name); err != nil {
			last = err
		} else {
			eventData[name] = structArray
		}
	}

	// Handle single structs
	if len(*e.StructSingle) > 0 && e.shouldParse(StructurePropertyName) {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			last = err
		} else {
			eventData[StructurePropertyName] = structs
		}
	}

	return
}

func (e *EventRecordHelper) formatStructs(structs []map[string]*Property,
	name string) ([]map[string]string, error) {

	// NOTE: this is only used when parsing to json event, using reusable memory maybe it's not ideal.
	result := make([]map[string]string, 0, len(structs))
	var err error

	for _, propStruct := range structs {
		s := make(map[string]string)
		for field, prop := range propStruct {
			if s[field], err = prop.FormatToString(); err != nil {
				return nil, fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh, name, field, err)
			}
		}
		result = append(result, s)
	}
	return result, nil
}

/** Public methods **/

// SelectFields selects the properties that will be parsed and populated
// in the parsed ETW event. If this method is not called, all properties will
// be parsed and put in the event.
func (e *EventRecordHelper) SelectFields(names ...string) {
	for _, n := range names {
		e.selectedProperties[n] = true
	}
}

func (e *EventRecordHelper) ProviderGUID() GUID {
	return e.TraceInfo.ProviderGUID
}

func (e *EventRecordHelper) Provider() string {
	return e.TraceInfo.ProviderName()
}

func (e *EventRecordHelper) Channel() string {
	return e.TraceInfo.ChannelName()
}

// EventID returns the event ID of the event record.
// This is the same as TraceInfo.EventID().
// For MOF events, this ID is calculated from other data to be unique per event type.
// For non-MOF events, this is the same as EventRecord.EventDescriptor.Id.
func (e *EventRecordHelper) EventID() uint16 {
	// EventRec.EventID() Uses different fields but same result.
	return e.TraceInfo.EventID()
}

/*
ETW Property Access Methods

Provides typed access to event properties after preparation. Properties are parsed
on-demand using custom decoders (faster) with TDH fallback for complex types.
Values are cached after first access.
*/

// GetPropertyString returns the formatted string value of the named property.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyString(name string) (s string, err error) {
	if p, ok := e.Properties[name]; ok {
		return p.FormatToString()
	}

	return "", fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyInt returns the property value as int64.
// Returns overflow error for unsigned values exceeding math.MaxInt64.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetInt()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyUint returns the property value as uint64.
// Returns conversion error for negative signed values.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyUint(name string) (uint64, error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetUInt()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyFloat returns the property value as float64.
// Supports 32-bit and 64-bit IEEE 754 formats.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyFloat(name string) (float64, error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetFloat()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// SetProperty sets or updates a property value in the Properties map.
//
// This is used to set a property value manually. This is useful when
// you want to add a property that is not present in the event record.
func (e *EventRecordHelper) SetProperty(name, value string) *Property {
	if p, ok := e.Properties[name]; ok {
		p.value = value
		return p
	}

	p := e.newProperty()
	p.name = name
	p.value = value
	e.Properties[name] = p
	return p
}

/*
ETW Property Parsing Methods

Converts raw binary event data into formatted values on-demand. Uses custom
decoders for performance with TDH fallback for complex types. Results are cached.
*/

// ParseProperties parses multiple properties by name, returning the first error encountered.
func (e *EventRecordHelper) ParseProperties(names ...string) (err error) {
	for _, name := range names {
		if err = e.ParseProperty(name); err != nil {
			return
		}
	}

	return
}

// ParseProperty parses a single property by name, converting binary data to formatted string.
func (e *EventRecordHelper) ParseProperty(name string) (err error) {
	if p, ok := e.Properties[name]; ok {
		if _, err = p.FormatToString(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
		}
	}

	// parsing array
	if propSlicePtr, ok := e.ArrayProperties[name]; ok {
		// iterate over the properties
		for _, p := range *propSlicePtr {
			if _, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, name, err)
			}
		}
	}

	// Structure arrays
	if structs, ok := e.StructArrays[name]; ok {
		for _, propStruct := range structs {
			for field, prop := range propStruct {
				if _, err = prop.FormatToString(); err != nil {
					return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh, name, field, err)
				}
			}
		}
	}

	// Single structs - only check if requesting StructurePropertyName
	if name == StructurePropertyName && len(*e.StructSingle) > 0 {
		for _, propStruct := range *e.StructSingle {
			for field, prop := range propStruct {
				if _, err = prop.FormatToString(); err != nil {
					return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh,
						StructurePropertyName, field, err)
				}
			}
		}
	}

	return
}

// Skippable marks the event as "droppable" when the consumer channel is full.
// Events marked as skippable will not block the ETW callback when trying to send
// to a full Event channel. Instead, they will be counted in [Consumer.Skipped] and dropped.
// This is useful for high-volume, low-priority events where losing some events
// is preferable to blocking the ETW callback.
func (e *EventRecordHelper) Skippable() {
	e.Flags.Skippable = true
}

// Skip marks the event to be completely ignored during processing.
// When an event is marked with Skip, it will not be parsed or sent to
// the consumer channel at all. The event processing stops immediately
// after the current callback returns.
// This is useful when you want to filter out events early in the
// processing pipeline before any parsing overhead.
func (e *EventRecordHelper) Skip() {
	e.Flags.Skip = true
}

// ! TESTING, try todo these in another way.
/*
// GetPropertyUintAt finds and decodes a single property by its zero-based index,
// returning it as a uint64. This is a high-performance method for selectively
// reading data from high-frequency events without the overhead of preparing all properties.
//
// The function performs a lightweight scan from the beginning of the event data for each
// call and does not modify the state of the EventRecordHelper, making it safe to use
// in any callback.
func (e *EventRecordHelper) GetPropertyUintAt(index uint32) (uint64, error) {
	p, err := e.getPropertyAt(index)
	if err != nil {
		return 0, err
	}
	return p.GetUInt()
}

// GetPropertyStringAt finds and decodes a single property by its zero-based index,
// returning it as a string. This is a high-performance method for selectively
// reading data from high-frequency events without the overhead of preparing all properties.
//
// The function performs a lightweight scan from the beginning of the event data for each
// call and does not modify the state of the EventRecordHelper, making it safe to use
// in any callback.
func (e *EventRecordHelper) GetPropertyStringAt(index uint32) (string, error) {
	p, err := e.getPropertyAt(index)
	if err != nil {
		return "", err
	}
	return p.FormatToString()
}

// getPropertyAt is an internal helper that scans to the specified property index
// and prepares it for parsing. The function does not modify the state of the
// EventRecordHelper, making it safe to use in any callback.
func (e *EventRecordHelper) getPropertyAt(index uint32) (*Property, error) {
	if e.TraceInfo == nil {
		return nil, fmt.Errorf("no trace info available to get property at index %d", index)
	}
	if index >= e.TraceInfo.PropertyCount {
		return nil, fmt.Errorf("property index %d out of bounds (max %d)", index, e.TraceInfo.PropertyCount-1)
	}

	// Save original state that will be modified by the scan.
	originalUserDataIt := e.userDataIt
	originalPropIdx := e.storage.propIdx

	// The integerValues and epiArray caches are essential for the scan.
	// We must clear them to ensure a clean scan from the beginning,
	// as they might hold state from a previous partial parse.
	clear(*e.integerValues)
	clear(*e.epiArray)

	// Set iterator to the start for this local scan.
	e.userDataIt = e.EventRec.UserData
	defer func() {
		// Restore original state. This makes the function stateless to the caller.
		e.userDataIt = originalUserDataIt
		e.storage.propIdx = originalPropIdx
	}()

	// Scan up to the target property, advancing the iterator.
	for i := uint32(0); i < index; i++ {
		// getPropertyLength is the lightest way to calculate the size.
		// It correctly populates the epiArray and integerValues caches as it goes.
		_, sizeBytes, err := e.getPropertyLength(i)
		if err != nil {
			return nil, fmt.Errorf("error calculating size for preceding property %d: %w", i, err)
		}
		e.userDataIt += uintptr(sizeBytes)
		if e.userDataIt > e.userDataEnd {
			return nil, fmt.Errorf("event data overrun while scanning for property %d", index)
		}
	}

	// At the target index, create a temporary property and decode its value.
	// We pass a dummy name as it's not used for decoding the scalar value.
	return e.prepareProperty(index, "")
}
*/