//go:build windows

package etw

import (
	"bytes" // also slow but not used much here.
	"errors"
	"fmt"

	"math"
	"os"
	"sync"
	"time"
	"unsafe"
)

const (
	// StructurePropertyName is the key used in the parsed event's for TODO:
	StructurePropertyName = "Structures"
)

// Sentinel errors for property parsing.
var (
	// ErrInvalidPropertyIndex is returned when a property's length or count
	// refers to an invalid or future property index in the event data.
	ErrInvalidPropertyIndex = errors.New("invalid property index for length/count lookup")
	// ErrGetIntegerNoScalar is returned when a property that is not a scalar integer
	// is incorrectly used as a length or count for another property.
	ErrGetIntegerNoScalar = errors.New("property used for length/count is not a scalar integer")
	// ErrGetIntegerNoData is returned when there is not enough data in the event
	// to parse a value that is referenced by another property.
	ErrGetIntegerNoData = errors.New("insufficient data for on-demand integer parsing")
)

// Global Memory Pools and Caches
var (
	// // We use a global pool for EventRecordHelper to reduce allocations on the hot path.
	// helperPool = sync.Pool{New: func() any { return &EventRecordHelper{} }}

	// tdhBufferPool is used if using thd fallback for string conversion.
	tdhBufferPool = sync.Pool{New: func() any { s := make([]uint16, 128); return &s }}

	// globalSchemaCache stores all schema-related information for an event.
	// It's a two-level map for performance:
	// Level 1: Provider GUID -> Level 2: *sync.Map
	// Level 2: Schema Key (uint64) -> *schemaCacheEntry
	globalSchemaCache sync.Map

	// globalTraceEventInfoCacheEnabled controls whether the schema cache is used.
	// Disabling it forces a call to TdhGetEventInformation for every event, which is
	// useful for debugging but has a significant performance impact.
	globalTraceEventInfoCacheEnabled = true

	// cache for metadata on fully parsed events
	hostname, _ = os.Hostname()
)

// schemaCacheEntry holds all the cached information for a unique event schema.
type schemaCacheEntry struct {
	// The raw buffer for the TRACE_EVENT_INFO structure. This is a read-only template.
	teiBuffer []byte

	// Lazily populated slice of property names.
	propertyNames []string
	namesOnce     sync.Once

	// Lazily populated map of property names to their schema Wmi index.
	nameToIndex map[string]int
	indexOnce   sync.Once

	// Precomputed id for MOF and XML(manifest) events.
	eventID uint16 // Cached event ID. For MOF, this is the custom calculated ID.
	// Lazily populated cache for all metadata strings to avoid repeated conversions.
	providerName      string
	levelName         string // not hashes if using 64bit key
	channelName       string // not hashes if using 64bit key
	opcodeName        string
	taskName          string   // not hashes if using 64bit key
	keywordsNames     []string // not hashes if using 64bit key
	activityIDName    string
	relatedActivityID string
	mofEventTypeName  string
	metadataOnce      sync.Once
}

// GetPropertyNames parses and caches the property names from the TRACE_EVENT_INFO buffer.
// The parsing is performed only once per schema, on the first call, and is thread-safe.
func (sce *schemaCacheEntry) GetPropertyNames(traceInfo *TraceEventInfo) []string {
	sce.namesOnce.Do(func() {
		names := make([]string, traceInfo.PropertyCount)
		for i := range names {
			epi := traceInfo.GetEventPropertyInfoAt(uint32(i))
			names[i] = FromUTF16AtOffset(traceInfo.pointer(), uintptr(epi.NameOffset))
		}
		sce.propertyNames = names
	})
	return sce.propertyNames
}

// GetNameToIndexMap creates and caches a map of property names to their index.
// This is used for fast lookups when using the slice-based property storage.
func (sce *schemaCacheEntry) GetNameToIndexMap(traceInfo *TraceEventInfo) map[string]int {
	sce.indexOnce.Do(func() {
		names := sce.GetPropertyNames(traceInfo)
		sce.nameToIndex = make(map[string]int, len(names))
		for i, name := range names {
			sce.nameToIndex[name] = i
		}
	})
	return sce.nameToIndex
}

// cacheMetadata populates all string fields in the schemaCacheEntry from the TraceEventInfo.
// This is called once per schema and avoids repeated, expensive string conversions.
func (sce *schemaCacheEntry) cacheMetadata(er *EventRecord, traceInfo *TraceEventInfo) {
	sce.metadataOnce.Do(func() {
		sce.providerName = traceInfo.ProviderName()
		sce.levelName = traceInfo.LevelName()
		sce.channelName = traceInfo.ChannelName()
		sce.opcodeName = traceInfo.OpcodeName()
		sce.taskName = traceInfo.TaskName()
		sce.keywordsNames = traceInfo.KeywordsName()
		sce.eventID = traceInfo.EventID()
		sce.activityIDName = traceInfo.ActivityIDName()
		sce.relatedActivityID = traceInfo.RelatedActivityIDName()

		if traceInfo.IsMof() {
			// e.EventRec.EventHeader.ProviderId is the same as e.TraceInfo.EventGUID for MOF events
			if c := MofErLookup(er); c != nil {
				sce.mofEventTypeName = fmt.Sprintf("%s/%s", c.Name, sce.opcodeName)
			} else {
				sce.mofEventTypeName = fmt.Sprintf("UnknownClass/%s", sce.opcodeName)
			}
		}
	})
}

// These EventRecord methods are defined here because they are only needed in etw_helpers.go

//lint:ignore U1000 option for different keying strategies
type schemaKeyType32 uint32

//lint:ignore U1000 option for different keying strategies
type schemaKeyType64 uint64

//lint:ignore U1000 option for different keying strategies
type schemaKeyType128 struct {
	high uint64
	low  uint64
}

// schemaCacheKey32 generates a unique uint32 key for a given event schema within a provider.
// This has the same effect as the schemaCacheKey64 but same performance and doesn't requiere a isMof call.
func (er *EventRecord) schemaCacheKey32() schemaKeyType32 {
	desc := &er.EventHeader.EventDescriptor
	if er.IsMof() {
		// For MOF, Opcode (8 bits) + Version (8 bits) is the unique schema ID.
		return schemaKeyType32(uint32(desc.Opcode)<<8 | uint32(desc.Version))
	}
	// For Manifest, ID (16 bits) + Version (8 bits) is the unique schema ID.
	return schemaKeyType32(uint32(desc.Id)<<8 | uint32(desc.Version))
}

// schemaCacheKey128 packs the entire EventDescriptor into a 128-bit key.
// This is the most robust key, as it guarantees uniqueness across all event types
// by including the Keyword. Using this key allows for a performance optimization where
// the cached TRACE_EVENT_INFO buffer can be used directly without copying, as the
// EventDescriptor within it will be a perfect match.
// It's 40ns for 128bit key vs 20ns for 64/32bit key but this saves copying the cached schema to patch the EventDescriptor.
func (er *EventRecord) schemaCacheKey128() schemaKeyType128 {
	desc := &er.EventHeader.EventDescriptor
	// For Manifest and MOF, the entire descriptor defines the unique schema.
	// This single, robust key works for both types.
	// Pack fields into a uint64:
	// | 16 bits | 8 bits | 8 bits | 8 bits | 8 bits  | 16 bits |
	// | Task    | Opcode | Level  | Channel| Version | ID      |
	low := uint64(desc.Id)            // needed for manifest
	low |= uint64(desc.Version) << 16 // neded for manifest
	low |= uint64(desc.Channel) << 24
	low |= uint64(desc.Level) << 32
	low |= uint64(desc.Opcode) << 40 // needed for mof
	low |= uint64(desc.Task) << 48
	high := desc.Keyword

	return schemaKeyType128{high: high, low: low}
}

// schemaCacheKey64 generates a unique uint64 key for a given event schema.
// This key is sufficient to uniquely identify the *layout* of an event's properties
// for both manifest-based and classic MOF events. It excludes the Keyword field, which
// is used for event filtering rather than defining the schema structure.
// Because this key is not fully unique, the cached TRACE_EVENT_INFO is a template
// that must be copied to thread-local storage and have its EventDescriptor patched
// with the one from the live event.
// This is as fast as the 32-bit key that requires an if check.
func (er *EventRecord) schemaCacheKey64() schemaKeyType64 {
	desc := &er.EventHeader.EventDescriptor
	// Pack most descriptor fields into a single uint64.
	// This is enough to uniquely identify the schema for both Manifest and MOF events.
	// Pack fields into a uint64:
	// | 16 bits | 8 bits | 8 bits | 8 bits | 8 bits  | 16 bits |
	// | Task    | Opcode | Level  | Channel| Version | ID      |
	key := uint64(desc.Id)            // needed for manifest
	key |= uint64(desc.Version) << 16 // neded for manifest
	key |= uint64(desc.Channel) << 24
	key |= uint64(desc.Level) << 32
	key |= uint64(desc.Opcode) << 40 // needed for mof
	key |= uint64(desc.Task) << 48
	return schemaKeyType64(key)
}

// getOrSetProviderCache retrieves or creates the provider-specific cache (the second level of the two-level map).
// This is a thread-safe way to ensure the nested map is initialized only once per provider.
func (er *EventRecord) getOrSetProviderCache() (shemaCache *sync.Map) {
	if val, ok := globalSchemaCache.Load(er.EventHeader.ProviderId); ok {
		shemaCache = val.(*sync.Map)
	} else {
		// This provider has not been seen before. Create its cache.
		// Use LoadOrStore to handle the race condition of two goroutines seeing it for the first time.
		newCache := &sync.Map{}
		actual, _ := globalSchemaCache.LoadOrStore(er.EventHeader.ProviderId, newCache)
		shemaCache = actual.(*sync.Map)
	}
	return
}

// traceStorage holds all the necessary reusable memory for a single trace (goroutine).
// This avoids using sync.Pool for thread-local data, reducing overhead.
type traceStorage struct {
	helper EventRecordHelper // Was in pools before, but this increased performance by ~5%

	// Reusable buffers and slices. They are reset before processing each event.
	propertiesCustom  map[string]*Property              // For user-defined simple properties
	propertiesByIndex []*Property                       // For schema-defined simple properties
	arrayProperties   map[string]*[]*Property           // For arrays of properties
	structArrays      map[string][]map[string]*Property // For arrays of structs
	structSingle      []map[string]*Property            // For non-array structs
	selectedProps     map[string]bool                   // Properties selected by the user for parsing
	propertyOffsets   []uintptr                         // Caches property offsets for on-demand integer parsing.
	epiArray          []*EventPropertyInfo              // Caches pointers to EventPropertyInfo's.
	teiBuffer         []byte                            // Buffer for TdhGetEventInformation()

	// Freelist cache for Property structs.
	propCache []Property
	propIdx   int

	// Pools for nested structures that can't be easily managed by a single slice.
	propertyMapPool sync.Pool // For nested structs in struct arrays.
	propSlicePool   sync.Pool // For simple arrays of properties.
}

// newTraceStorage creates a new storage area for a goroutine in ProcessTrace.
func newTraceStorage() *traceStorage {
	ts := &traceStorage{
		propertiesCustom:  make(map[string]*Property, 8),
		propertiesByIndex: make([]*Property, 0, 64),
		arrayProperties:   make(map[string]*[]*Property, 8),
		structArrays:      make(map[string][]map[string]*Property, 4),
		structSingle:      make([]map[string]*Property, 0, 4),
		selectedProps:     make(map[string]bool, 16),
		propertyOffsets:   make([]uintptr, 0, 64),
		epiArray:          make([]*EventPropertyInfo, 0, 64),
		teiBuffer:         make([]byte, 8192), // Initial size for GetEventInformation()

		// Initialize the property cache with a reasonable capacity to avoid frequent reallocations.
		propCache: make([]Property, 0, 256),
		propIdx:   0,

		propertyMapPool: sync.Pool{New: func() any { return make(map[string]*Property, 8) }},
		propSlicePool:   sync.Pool{New: func() any { s := make([]*Property, 0, 8); return &s }},
	}
	ts.helper.storage = ts
	return ts
}

// reset clears the storage so it can be reused for the next event.
// It resets slice lengths to 0 (preserving capacity) and clears maps.
func (ts *traceStorage) reset() {
	// 1. Reset property freelist index. The underlying slice memory is reused.
	ts.propIdx = 0

	// 2. Clear properties slice and map.
	clear(ts.propertiesCustom)
	clear(ts.propertiesByIndex)
	ts.propertiesByIndex = ts.propertiesByIndex[:0]

	// 3. Clear array properties map, returning inner slices to their pool.
	for _, propSlicePtr := range ts.arrayProperties {
		clear(*propSlicePtr)
		*propSlicePtr = (*propSlicePtr)[:0]
		ts.propSlicePool.Put(propSlicePtr)
	}
	clear(ts.arrayProperties)

	// 4. Clear struct arrays map, returning inner maps to their pool.
	for _, structs := range ts.structArrays {
		for _, propStruct := range structs {
			clear(propStruct)
			ts.propertyMapPool.Put(propStruct)
		}
	}
	clear(ts.structArrays)

	// 5. Clear single struct slice, returning inner maps to their pool.
	for _, propStruct := range ts.structSingle {
		clear(propStruct)
		ts.propertyMapPool.Put(propStruct)
	}
	ts.structSingle = ts.structSingle[:0]

	// 6. Clear selected properties map.
	clear(ts.selectedProps)

	// 7. The propertyOffsets slice does not need to be reset. It is re-sliced to the
	// correct size in initialize() and its contents are overwritten for each event,
	// making a reset here redundant.
	//ts.propertyOffsets = ts.propertyOffsets[:0]

	// 8. Reset epi array slice, clearing pointers to prevent stale data.
	clear(ts.epiArray)
	ts.epiArray = ts.epiArray[:0]

	// teiBuffer does not need to be reset, it gets overwritten.
}

/*
	PERFORMANCE NOTE: Pointer vs. Direct Slice Access in `EventRecordHelper`

	A key performance optimization in this package involves how slices from the thread-local
	`traceStorage` (like `epiArray` and `propertyOffsets`) are accessed by the temporary
	`EventRecordHelper`.

	It may seem simpler to access these slices directly, e.g., `e.storage.epiArray[i]`.
	However, benchmarks and assembly analysis have shown that this is consistently ~3% slower
	than the current implementation, which uses pointers on the helper struct:
	e.g., `e.epiArray *[]*EventPropertyInfo` and `(*e.epiArray)[i]`.

	The reason for this performance difference lies in the Go compiler's ability to perform
	**Bounds Check Elimination (BCE)**.

	---

	### The Fast Version (Current Implementation with Pointers)

	1.  **How it works:** In `initialize()`, we assign a pointer to the storage slice to the
		helper: `e.epiArray = &storage.epiArray`. We then re-slice it to a fixed, known
		length: `*e.epiArray = (*e.epiArray)[:maxPropCount]`. Accesses in hot loops
		are then done via `(*e.epiArray)[i]`.

	2.  **Why it's fast:** The compiler has a direct, local pointer (`e.epiArray`) to the
		slice header. It can more easily prove that the slice's length (`maxPropCount`)
		is constant throughout the helper's lifecycle. This proof allows the optimizer to
		**eliminate the bounds check** (the implicit `if i >= len(...)`) on every single
		access within the hot loops of `prepareProperties`. Removing this repeated check
		in code that runs millions of times per second results in a measurable performance gain.

	---

	### The Slower Version (Direct Access, Avoided)

	1.  **How it would work:** The helper would access the slice directly through its storage
		field: `e.storage.epiArray[i]`.

	2.  **Why it's slow:** The access path involves multiple pointer dereferences (`e -> storage -> epiArray`).
		Due to **pointer aliasing**, the compiler becomes more conservative. It cannot easily
		prove that some other part of the code with access to `e.storage` has not modified
		the `epiArray` slice header (e.g., by re-slicing it) between the `initialize()` call
		and the access in the hot loop. This uncertainty forces the compiler to keep the
		safety bounds check on every access. The cumulative cost of these millions of extra
		checks results in the ~3% performance degradation.

	---

	**Conclusion:** The use of pointers to slices on `EventRecordHelper` is a deliberate and
	critical micro-optimization. It provides the compiler with the necessary information to
	generate more efficient machine code by eliminating redundant safety checks on the hot path
	of event processing. It also prevents race conditions when using pools (explained below).
*/

// EventRecordHelper provides methods to parse and access properties of an ETW event.
// It is a temporary object, retrieved from a pool for each event and released afterward.
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

	// IMPORTANT: use pointers to slices if using pools to avoid corruption
	//  Because the `EventRecordHelper` is pooled, multiple goroutines could get the same
	//  helper instance and modify the same underlying slice array, causing corruption.
	// The core issue arises because sync.Pool can give the exact same EventRecordHelper
	//  instance (at the same memory address) to different goroutines (in order). If a field on this
	//  helper is a slice value (e.g., `PropertiesByIndex []*Property`), its slice header
	//  (pointer to backing array, len, cap) is part of the helper's struct. When the
	//  helper is returned to the pool, this slice header remains unchanged, still pointing
	//  to the backing array of the last goroutine that used it.

	// PropertiesCustom stores simple, scalar properties of the event.
	// - Structure: A map where the key is the property name (e.g., "ProcessId")
	//   and the value is a `*Property` object holding its raw data.
	// - Final JSON Example: "ProcessId": "1234"
	PropertiesCustom map[string]*Property
	// PropertiesByIndex stores simple, scalar properties of the event, indexed by property order.
	// This is used for fast population during the prepare phase.
	PropertiesByIndex *[]*Property
	// ArrayProperties stores arrays of simple, scalar types.
	// - Structure: A map where the key is the array's name (e.g., "SIDs") and
	//   the value is a pointer to a slice of `*Property` objects, each
	//   representing an element in the array.
	// - Final JSON Example: "SIDs": ["S-1-5-18", "S-1-5-19"]
	ArrayProperties map[string]*[]*Property
	// StructArrays stores arrays of complex structures.
	// - Structure: A map where the key is the array's name (e.g., "Adapters").
	//   The value is a slice of maps. Each map in the slice represents one
	//   struct instance, with its keys being the struct's field names
	//   (e.g., "IPAddress") and values being the corresponding `*Property` objects.
	// - Final JSON Example: "Adapters": [{"IPAddress": "1.2.3.4"}, {"IPAddress": "5.6.7.8"}]
	StructArrays map[string][]map[string]*Property
	// StructSingle stores top-level properties that are structs but are NOT arrays.
	// Since these structs don't have a single collective name, they are grouped
	// into a slice(array) and published under a special key in the final event.
	// - Structure: A slice of maps, where each map represents a single struct
	//   instance, similar to an element in `StructArrays`.
	// - Final JSON Example: "Structures": [{"FieldA": "Val1"}, {"FieldB": "Val2"}]
	//   (Note: These are published under the special "Structures" key).
	StructSingle *[]map[string]*Property

	// Flags control event processing behavior, e.g., skipping or dropping events.
	Flags struct {
		Skip      bool
		Skippable bool // TODO: does this work?
	}

	// Cached provider schema information to avoid repeated lookups.
	schemaCache *schemaCacheEntry // This will be lazily populated.

	// Stored property values for resolving array lengths
	// both are filled when a prop is about to be prepared.
	propertyOffsets *[]uintptr
	epiArray        *[]*EventPropertyInfo

	// Buffer that contains the memory for TraceEventInfo.
	// used internally to reuse the memory allocation.
	teiBuffer *[]byte

	// userDataIt is the current position (iterator) in the event's user data buffer.
	// increments after each call to prepareProperty
	userDataIt uintptr
	// userDataEnd is the end position of the event's user data buffer.
	// For UserData length use [EventRec.UserDataLength]
	userDataEnd uintptr

	selectedProperties map[string]bool

	// A reference to the thread-local storage for this trace.
	storage *traceStorage

	// FILETIME format of this event timestamp. (In case raw timestamp is used)
	// If raw is not set then it's just the same as EventRec.EventHeader.TimeStamp
	timestamp int64
}

// remainingUserDataLength returns the number of bytes remaining in the event's user data
func (e *EventRecordHelper) remainingUserDataLength() uint16 {
	return uint16(e.userDataEnd - e.userDataIt)
}

// userContext retrieves the thread local traceContext associated with the EventRecord.
func (e *EventRecordHelper) userContext() (c *traceContext) {
	return e.EventRec.userContext()
}

// addPropError increments the error counter for property parsing errors in the traceContext.
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
//
// To get the raw timestamp of the event use EventRecordHelper.EventRec.EventHeader.TimeStamp directly.
func (e *EventRecordHelper) Timestamp() time.Time {
	return FromFiletime(e.timestamp) // use previously converted and cached filetime timestamp
}

// TimestampFromProp converts a raw timestamp value from an event property (like WmiTime)
// into an absolute time.Time, using the session's clock type and conversion settings.
func (e *EventRecordHelper) TimestampFromProp(propTimestamp int64) time.Time {
	return e.EventRec.TimestampFromProp(propTimestamp)
}

// release returns the EventRecordHelper to the global pool.
// The associated traceStorage is NOT reset here; it's reset at the beginning
// of the next event's processing.
func (e *EventRecordHelper) release() {
	*e = EventRecordHelper{}
	//helperPool.Put(e) // no using pools for now
}

// newEventRecordHelper creates a new EventRecordHelper and retrieves the TRACE_EVENT_INFO
// for the given EventRecord. It implements a multi-level caching and fallback strategy.
// +120% performance gain by using caching vs no caching of the TraceInfo (while caching names etc)
func newEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) { // mi version
	//erh = helperPool.Get().(*EventRecordHelper)  // no using pools for now
	storage := er.userContext().storage
	erh = &storage.helper

	// Reset the thread-local storage before processing a new event.
	storage.reset()

	erh.storage = storage
	erh.EventRec = er
	erh.teiBuffer = &storage.teiBuffer // Keep a reference before calling internal funcs

	providerCache := er.getOrSetProviderCache()
	schemaKey := er.schemaCacheKey64()

	// TODO: erase the  globalTraceEventInfoCacheEnabled when tested enough

	// --- Stage 1: Check Cache ---
	if globalTraceEventInfoCacheEnabled {
		if cachedEntry, found := providerCache.Load(schemaKey); found {
			entry := cachedEntry.(*schemaCacheEntry)
			// A valid cache hit requires a non-nil buffer. A nil buffer means it's a
			// "shell" entry created when caching was previously disabled.
			if entry.teiBuffer != nil {
				// --- Cache Hit: Populate helper from cache ---
				template := entry.teiBuffer
				// This commented block of code is if we need to copy the buffer to a local one. (2,1% performance hit)
				// NOTE: use er.schemaCacheKey32() or er.schemaCacheKey64() if using this block
				if true {
					// Ensure the thread-local buffer is large enough.
					if cap(storage.teiBuffer) < len(template) {
						storage.teiBuffer = make([]byte, len(template))
					}
					storage.teiBuffer = storage.teiBuffer[:len(template)]
					// Copy the cached template into the thread-local buffer.
					copy(storage.teiBuffer, template)
					erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&storage.teiBuffer[0]))
					erh.TraceInfo.EventDescriptor = er.EventHeader.EventDescriptor // Important: patch EventDescriptor
				} else {
					// NOTE: use er.schemaCacheKey128() if using this block
					// The template is immutable. Point directly to it. No copy needed.
					erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&template[0]))
					// The buffer is the globally cached one, not the thread-local one.
					// Setting this to nil indicates it's not locally owned.
					erh.teiBuffer = nil
				}

				return erh, nil // Cache hit, we are done.
			}
		}
	}

	// --- Stage 2: Call TdhGetEventInformation (Cache Miss or Cache Disabled) ---
	erh.TraceInfo, err = er.GetEventInformation(erh.teiBuffer)
	if err != nil {
		apiErr := fmt.Errorf("%w: %v", ErrGetEventInformation, err)
		// Fallback to MOF Generator
		if er.IsMof() {
			if erh.TraceInfo, err = buildTraceInfoFromMof(er, erh.teiBuffer); err == nil {
				err = nil //  MOF generator succeeded. Suppress the original API error.
			} else {
				err = apiErr // MOF generator also failed; return the original API error.
			}
		} else {
			err = apiErr // Not a MOF event, no fallback possible.
		}
	}

	// If we failed to get TraceInfo, we can't proceed to caching.
	if err != nil {
		return erh, err
	}

	// --- Stage 3: Update Cache ---
	//  We always create an entry to support property name caching.
	// It will be a "shell" (with a nil teiBuffer) if TEI caching is disabled.
	newEntry := &schemaCacheEntry{}
	if globalTraceEventInfoCacheEnabled {
		// If caching is enabled, make a copy of the buffer to store.
		newEntry.teiBuffer = make([]byte, len(*erh.teiBuffer))
		copy(newEntry.teiBuffer, *erh.teiBuffer)
	}
	// Store the new entry, overwriting any previous (e.g., shell) entry.
	// The small race of overwriting is acceptable for the performance gain.
	providerCache.Store(schemaKey, newEntry)

	return erh, err
}

// getCachedSchemaEntry is a helper that retrieves the cached schema information for the current event.
func (e *EventRecordHelper) getCachedSchemaEntry() *schemaCacheEntry {
	// Lazy-load optimization: If we've already looked this up for this event,
	// return the cached pointer from the helper itself.
	if e.schemaCache != nil {
		return e.schemaCache
	}

	// The schema MUST be in the cache at this point.
	// newEventRecordHelper ensures it's populated on both cache hits and misses.

	// 1. First-level lookup. Already exists.
	providerCache, _ := globalSchemaCache.Load(e.EventRec.EventHeader.ProviderId)

	// 2. Second-level lookup. Already exists.
	// We use the same 64-bit key that was used to cache the TRACE_EVENT_INFO.
	schemaKey := e.EventRec.schemaCacheKey64()
	cachedEntry, _ := providerCache.(*sync.Map).Load(schemaKey)

	// Cache the result on the helper for subsequent calls within the same event's lifecycle.
	e.schemaCache = cachedEntry.(*schemaCacheEntry)
	return e.schemaCache
}

// getCachedPropNames retrieves the property names for the event schema.
// It uses a cache for each provider event type to avoid repeated UTF-16 to string conversions.
func (e *EventRecordHelper) getCachedPropNames() []string {
	entry := e.getCachedSchemaEntry()
	return entry.GetPropertyNames(e.TraceInfo) // will lazily parse the names on first call
}

// getCachedNameToIndexMap retrieves the name-to-index map for the event schema.
// It uses the same caching mechanism as getCachedPropNames.
func (e *EventRecordHelper) getCachedNameToIndexMap() map[string]int {
	entry := e.getCachedSchemaEntry()
	return entry.GetNameToIndexMap(e.TraceInfo) // will lazily parse the map on first call
}

// This memory was already reseted when it was released.
func (e *EventRecordHelper) initialize() {
	storage := e.storage
	e.PropertiesCustom = storage.propertiesCustom // custom properties.
	e.ArrayProperties = storage.arrayProperties

	// Structure handling
	e.StructArrays = storage.structArrays
	e.StructSingle = &storage.structSingle

	e.selectedProperties = storage.selectedProps

	// userDataIt iterator will be incremented for each queried property by prop size
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)

	if e.TraceInfo == nil {
		// Nothing more to initialize if we have no schema.
		return
	}

	maxPropCount := int(e.TraceInfo.PropertyCount)
	// Get and resize properties slice for fast indexed access.
	if cap(storage.propertiesByIndex) < maxPropCount {
		storage.propertiesByIndex = make([]*Property, maxPropCount)
	} else {
		storage.propertiesByIndex = storage.propertiesByIndex[:maxPropCount]
	}
	e.PropertiesByIndex = &storage.propertiesByIndex

	// Get and resize property offsets
	if cap(storage.propertyOffsets) < maxPropCount {
		storage.propertyOffsets = make([]uintptr, maxPropCount)
	}
	e.propertyOffsets = &storage.propertyOffsets
	*e.propertyOffsets = (*e.propertyOffsets)[:maxPropCount]

	// Get and resize epi array
	if cap(storage.epiArray) < maxPropCount {
		storage.epiArray = make([]*EventPropertyInfo, maxPropCount)
	}
	e.epiArray = &storage.epiArray
	*e.epiArray = (*e.epiArray)[:maxPropCount]
	// Pre-populate the entire epiArray to make getEpiAt branchless (faster).
	for i := range maxPropCount {
		(*e.epiArray)[i] = e.TraceInfo.GetEventPropertyInfoAt(uint32(i))
	}
}

// newProperty retrieves a new Property struct from the thread-local freelist (propCache).
// This block-pooling strategy avoids individual allocations for each property.
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

	p.erh = e
	p.traceInfo = e.TraceInfo
	p.pointerSize = e.EventRec.PointerSize()

	return p
}

// setEventMetadata populates the System and metadata fields of the final Event object.
func (e *EventRecordHelper) setEventMetadata(event *Event) {
	sce := e.getCachedSchemaEntry()
	sce.cacheMetadata(e.EventRec, e.TraceInfo)

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
	event.System.EventID = sce.eventID // Use the cached ID.
	event.System.Version = e.TraceInfo.EventDescriptor.Version

	event.System.Provider.Guid = e.TraceInfo.ProviderGUID
	event.System.Provider.Name = sce.providerName

	event.System.Opcode.Value = e.TraceInfo.EventDescriptor.Opcode
	event.System.Opcode.Name = sce.opcodeName

	// These are not hashed when using 64bit key, so we must get the current values.
	// TODO: cache these using a 128bit key exept channelName
	event.System.Channel = e.TraceInfo.ChannelName() // sce.channelName
	event.System.Level.Value = e.TraceInfo.EventDescriptor.Level
	event.System.Level.Name = e.TraceInfo.LevelName() //sce.levelName
	event.System.Keywords.Mask = e.TraceInfo.EventDescriptor.Keyword
	event.System.Keywords.Name = e.TraceInfo.KeywordsName() //sce.traceInfo.keywordsName
	event.System.Task.Value = uint8(e.TraceInfo.EventDescriptor.Task)
	event.System.Task.Name = e.TraceInfo.TaskName() //sce.taskName

	// Use the converted timestamp if available, otherwise fall back to raw timestamp
	event.System.TimeCreated.SystemTime = e.Timestamp()

	if e.TraceInfo.IsMof() {
		event.System.EventType = sce.mofEventTypeName
		event.System.EventGuid = e.TraceInfo.EventGUID
		event.System.Correlation.ActivityID = sce.activityIDName
		event.System.Correlation.RelatedActivityID = sce.relatedActivityID
	} else {
		event.System.Correlation.ActivityID = e.EventRec.EventHeader.ActivityId.StringU()
		if relatedActivityID := e.EventRec.ExtRelatedActivityID(); relatedActivityID.IsZero() {
			event.System.Correlation.RelatedActivityID = nullGUIDStr
		} else {
			event.System.Correlation.RelatedActivityID = relatedActivityID.StringU()
		}
	}
}

// Returns the size of the property at index i at index i, using TdhGetPropertySize.
func (e *EventRecordHelper) getPropertySize(i uint32) (size uint32, err error) {
	dataDesc := PropertyDataDescriptor{}
	dataDesc.PropertyName = uint64(e.TraceInfo.PropertyNamePointer(i))
	dataDesc.ArrayIndex = math.MaxUint32
	err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDesc, &size)
	return
}

// getIntegerValueAt helps when a property length or array count needs to be
// calculated using a previous property's value. It parses the value on-demand
// using the pre-cached property offset.
func (e *EventRecordHelper) getIntegerValueAt(i uint32) (uint16, error) {
	// Get the data pointer from our offset cache. This is an absolute pointer.
	dataPtr := (*e.propertyOffsets)[i]
	// Fetch the schema for the property at the target index 'i'.
	epi := e.getEpiAt(i)

	// The property must be a scalar integer to be used for length/count.
	if (epi.Flags&(PropertyStruct|PropertyParamCount)) != 0 || epi.Count() != 1 {
		return 0, ErrGetIntegerNoScalar
	}

	// Check remaining data from the property's own start point for safety.
	remaining := e.userDataEnd - dataPtr

	switch inType := TdhInType(epi.InType()); inType {
	case TDH_INTYPE_INT8,
		TDH_INTYPE_UINT8:
		if remaining >= 1 {
			return uint16(*(*uint8)(unsafe.Pointer(dataPtr))), nil
		}
	case TDH_INTYPE_INT16,
		TDH_INTYPE_UINT16:
		if remaining >= 2 {
			return *(*uint16)(unsafe.Pointer(dataPtr)), nil
		}
	case TDH_INTYPE_INT32,
		TDH_INTYPE_UINT32,
		TDH_INTYPE_HEXINT32:
		if remaining >= 4 {
			val := *(*uint32)(unsafe.Pointer(dataPtr))
			if val > 0xffff { // Lengths are uint16, so cap at max.
				return 0xffff, nil
			}
			return uint16(val), nil
		}
	}
	return 0, ErrGetIntegerNoData
}

// Gets the EventPropertyInfo at index i, (already cached in initialize()).
// big performance vs caching on the fly.
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	// (epiArray mem is reused, make sure the elements are set to nil before use)
	return (*e.epiArray)[i]
}

// Returns the length of the property (can be 0) at index i and the actual size in bytes.
func (e *EventRecordHelper) getPropertyLength(i uint32, epi *EventPropertyInfo) (propLength uint16, sizeBytes uint32, err error) {
	// We keep track of the property offset for on-demand parsing of integer values.
	switch {
	case (epi.Flags & PropertyParamLength) != 0:
		// Length from another property.
		index := uint32(epi.LengthPropertyIndex())
		// For safety, ensure the index points to a property we've already processed.
		if index >= i {
			return 0, 0, ErrInvalidPropertyIndex
		}
		propLength, err = e.getIntegerValueAt(index)
		if err != nil {
			return 0, 0, err
		}

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

	// Store the offset of this property so we can parse it later if needed.
	// We store the absolute pointer, which is safe within the callback context.
	(*e.propertyOffsets)[i] = e.userDataIt

	epi := e.getEpiAt(i)
	p.evtPropInfo = epi
	p.name = name
	p.pValue = e.userDataIt
	p.userDataRemaining = e.remainingUserDataLength()
	p.length, p.sizeBytes, err = e.getPropertyLength(i, epi)
	if err != nil {
		e.addPropError()
		return
	}

	// p.length has to be 0 on strings and structures for TdhFormatProperty to work.
	// We use size instead to advance when p.length is 0.
	e.userDataIt += uintptr(p.sizeBytes)

	return
}

// getArrayInfo determines if a property is an array and returns its count.
func (e *EventRecordHelper) getArrayInfo(i uint32, epi *EventPropertyInfo) (count uint16, isArray bool, err error) {
	if (epi.Flags & PropertyParamCount) != 0 {
		// Look up the value of a previous property.
		index := uint32(epi.CountPropertyIndex())
		// For safety, ensure the index points to a property we've already processed.
		if index >= i {
			return 0, false, ErrInvalidPropertyIndex
		}

		count, err = e.getIntegerValueAt(index)
		if err != nil {
			return 0, false, err
		}
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
func (e *EventRecordHelper) prepareStruct(i uint32, epi *EventPropertyInfo, arrayCount uint16, isArray bool) error {
	var p *Property
	var err error
	names := e.getCachedPropNames()
	arrayName := names[i]

	// Treat non-array properties as arrays with one element.
	for range arrayCount {
		propStruct := e.storage.propertyMapPool.Get().(map[string]*Property)

		startIndex := epi.StructStartIndex()
		lastMember := startIndex + epi.NumOfStructMembers()

		for j := startIndex; j < lastMember; j++ {
			if p, err = e.prepareProperty(uint32(j), names[j]); err != nil {
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
func (e *EventRecordHelper) prepareSimpleArray(i uint32, epi *EventPropertyInfo, arrayCount uint16) error {
	names := e.getCachedPropNames()
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
		e.SetCustomProperty(arrayName, value)
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

// Prepare will partially decode the event, extracting event info for later
//
// There is a lot of information available in the event even without decoding,
// including timestamp, PID, TID, provider ID, activity ID, and the raw data.
func (e *EventRecordHelper) prepareProperties() (err error) {

	// TODO: move this to a separate function before TraceInfo is used/created or not
	// Handle special case for MOF events that are just a single string.
	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
	if e.EventRec.IsMof() {
		// If there aren't any event property info structs, use the UserData directly.
		if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0 {
			str := (*uint16)(unsafe.Pointer(e.EventRec.UserData))
			value := FromUTF16Slice(
				unsafe.Slice(str, e.EventRec.UserDataLength/2))
			if e.EventRec.UserDataLength != 0 {
				e.SetCustomProperty("String", value)
			}
			return
		}
	}

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

		arrayCount, isArray, err := e.getArrayInfo(i, epi)
		if err != nil {
			e.addPropError()
			return err
		}

		if (epi.Flags & PropertyStruct) != 0 {
			// Property is a struct or an array of structs.
			if err = e.prepareStruct(i, epi, arrayCount, isArray); err != nil {
				return err
			}
		} else if isArray {
			// Property is an array of simple types.
			if err = e.prepareSimpleArray(i, epi, arrayCount); err != nil {
				return err
			}
		} else {
			// Property is a single, non-array, non-struct value.
			var p *Property
			if p, err = e.prepareProperty(i, names[i]); err != nil {
				return err
			}
			(*e.PropertiesByIndex)[i] = p
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

	mofID := e.TraceInfo.EventMofID()
	//eventType := e.TraceInfo.EventDescriptor.Opcode

	// Thread_V3_TypeGroup1 new ThreadName not included in TraceEventInfo propierties on Windows 10.
	if (mofID == 5358 || // Thread/DCStart
		mofID == 5357 || // Thread/End
		mofID == 5359) && // Thread/DCEnd
		remaining > 2 {
		threadName := FromUTF16Bytes(remainingData)
		e.SetCustomProperty("ThreadName", threadName)
		return nil
	}

	// Handle SystemConfig PnP events with device names
	if mofID == 1807 && // SystemConfig/PnP
		remaining > 2 {
		deviceName := FromUTF16Bytes(remainingData)
		e.SetCustomProperty("DeviceName", deviceName)
		return nil
	}

	return fmt.Errorf("unhandled MOF event %d", mofID)
}

// buildEvent creates the final Event object, populates its properties and metadata.
func (e *EventRecordHelper) buildEvent() (event *Event, err error) {
	event = NewEvent()
	event.Flags.Skippable = e.Flags.Skippable
	if err = e.parseAndSetAllProperties(event); err != nil {
		return
	}
	e.setEventMetadata(event)

	return event, err
}

// parseAndSetProperty parses a single named property and sets its value in the output Event.
func (e *EventRecordHelper) parseAndSetProperty(name string, out *Event) (err error) {
	var eventData *Properties
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = &out.UserData
	} else {
		eventData = &out.EventData
	}

	// Check simple properties from schema first using the index map for a fast lookup.
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				var val string
				if val, err = p.FormatToString(); err != nil {
					return fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, p.name, err)
				}
				*eventData = append(*eventData, EventProperty{Name: p.name, Value: val})
				return nil // Property found and parsed.
			}
		}
	}

	// Check for custom properties in the map.
	if p, ok := e.PropertiesCustom[name]; ok {
		// Custom properties have their value pre-formatted as a string.
		*eventData = append(*eventData, EventProperty{Name: p.name, Value: p.value})
		return nil
	}

	// simple arrays.
	if propsSlicePtr, ok := e.ArrayProperties[name]; ok {
		values := make([]string, len(*propsSlicePtr))

		// iterate over the properties
		for i, p := range *propsSlicePtr {
			if values[i], err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s[%d]: %s", ErrPropertyParsingTdh, name, i, err)
			}
		}
		*eventData = append(*eventData, EventProperty{Name: name, Value: values})
		return nil
	}

	// Structure arrays
	if structs, ok := e.StructArrays[name]; ok {
		if structArray, err := e.formatStructs(structs, name); err != nil {
			return err
		} else {
			*eventData = append(*eventData, EventProperty{Name: name, Value: structArray})
		}
		return nil
	}

	// Single structs - only check if requesting StructurePropertyName
	if name == StructurePropertyName && len(*e.StructSingle) > 0 {
		if singleStructs, err := e.formatStructs(*e.StructSingle, name); err != nil {
			return err
		} else {
			*eventData = append(*eventData, EventProperty{Name: name, Value: singleStructs})
		}
		return nil
	}

	return fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// shouldParse determines if a property should be parsed based on user selection.
// If no properties were selected, all properties are parsed.
func (e *EventRecordHelper) shouldParse(name string) bool {
	if len(e.selectedProperties) == 0 {
		return true
	}
	_, ok := e.selectedProperties[name]
	return ok
}

// Improved performance by just saving scalars as scalars and not strings.
func (e *EventRecordHelper) parseAndSetAllProperties(out *Event) (last error) {
	var err error
	var eventData *Properties

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = &out.UserData
	} else {
		eventData = &out.EventData
	}

	// Get or generate property names for this event schema.
	// This is a performance optimization to avoid repeated UTF-16 to string conversions.
	names := e.getCachedPropNames()

	// Properties
	for i, p := range *e.PropertiesByIndex {
		if p == nil {
			continue
		}
		name := names[i]
		if !e.shouldParse(name) {
			continue
		}

		// If it's a simple scalar with no value map, parse it to its native Go type.
		// Otherwise, format it to a string.
		if p.isScalarInType() && p.evtPropInfo.MapNameOffset() == 0 {
			var val any
			inType := p.evtPropInfo.InType()

			// Use the existing decoders to get native types.
			if inType == TDH_INTYPE_FLOAT || inType == TDH_INTYPE_DOUBLE {
				val, err = p.decodeFloatIntype()
			} else {
				uval, signed, err_ := p.decodeScalarIntype()
				err = err_
				if err == nil {
					if signed {
						val = int64(uval)
					} else {
						val = uval
					}
				}
			}

			if err != nil {
				last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
			} else {
				*eventData = append(*eventData, EventProperty{Name: name, Value: val})
			}

		} else {
			// (COMPLEX TYPES): Format to a string immediately.
			var val string
			if val, err = p.FormatToString(); err != nil {
				last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
			} else {
				*eventData = append(*eventData, EventProperty{Name: name, Value: val})
			}
		}
	}

	// Custom properties from map
	for name, p := range e.PropertiesCustom {
		if !e.shouldParse(name) {
			continue
		}
		// This property was added by manually, value is already a string.
		*eventData = append(*eventData, EventProperty{Name: name, Value: p.value})
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
		*eventData = append(*eventData, EventProperty{Name: pname, Value: values})
	}

	// Handle struct arrays
	for name, structs := range e.StructArrays {
		if !e.shouldParse(name) {
			continue
		}
		if structArray, err := e.formatStructs(structs, name); err != nil {
			last = err
		} else {
			*eventData = append(*eventData, EventProperty{Name: name, Value: structArray})
		}
	}

	// Handle single structs
	if len(*e.StructSingle) > 0 && e.shouldParse(StructurePropertyName) {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			last = err
		} else {
			*eventData = append(*eventData, EventProperty{Name: StructurePropertyName, Value: structs})
		}
	}

	return
}

// formatStructs parses a array of name:props into an array of name:value
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

// ProviderGUID returns the GUID of the event provider.
func (e *EventRecordHelper) ProviderGUID() GUID {
	return e.TraceInfo.ProviderGUID
}

// Provider returns the name of the event provider.
func (e *EventRecordHelper) Provider() string {
	return e.TraceInfo.ProviderName()
}

// Channel returns the name of the channel the event was logged to.
// A channel belongs to one of the four types: admin, operational, analytic, and debug.
//
// https://learn.microsoft.com/en-us/archive/msdn-magazine/2007/april/event-tracing-improve-debugging-and-performance-tuning-with-etw
func (e *EventRecordHelper) Channel() string {
	return e.TraceInfo.ChannelName()
}

// EventID returns the event ID of the event record.
// This returns the same as the call to TraceInfo.EventID().
// For MOF events, this ID is unique derived from provider id and opcode.
// For non-MOF events, this is the EventRecord.EventDescriptor.Id.
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

// TODO: make the names of this functions match the common types of etw properties to go, GetPropertyAsGoType

// GetPropertyString returns the formatted string value of the named property.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyString(name string) (s string, err error) {
	nameToIndex := e.getCachedNameToIndexMap() // <- this was cached before we got here, so it's fast
	if index, ok := nameToIndex[name]; ok {    // <- this is the same as p := Properties[name] would have done it.
		if index < len(*e.PropertiesByIndex) { // <- this is fast
			if p := (*e.PropertiesByIndex)[index]; p != nil { // <- this is fast, no bound check.
				return p.FormatToString()
				// So, the cost of a p := Properties[name] vs this is negligible
				// but we gain +100% (yes, double) speed on the preparing part.
			}
		}
	}
	if p, ok := e.PropertiesCustom[name]; ok { // Check for custom properties last. (rare)
		return p.FormatToString()
	}
	return "", fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyInt returns the property value as int64.
//
// Filetime intypes are returned as int64 nanoseconds.
//
// Returns overflow error for unsigned values exceeding math.MaxInt64.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				return p.GetInt()
			}
		}
	}
	if _, ok := e.PropertiesCustom[name]; ok { // Check for custom properties last. (rare)
		return 0, fmt.Errorf("custom property %s cannot be read as integer", name)
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyWmiTime retrieves a timestamp property from the event record
// specified by the given property name. The property is expected to be in
// WMI time format, which is an integer value representing the time based
// on the trace ClockType.
//
// The ClockType determines the format of the timestamp:
// if session Wnode.ClientContext is set to PROCESS_TRACE_MODE_RAW_TIMESTAMP
// the wmitime property is in raw format, else filetime.
//   - If CLockType is 1, the property will be in QPC (Query Performance Counter) format.
//   - If CLockType is 2, the property will be in SystemTime format.
//   - If CLockType is 3, the property will be in CPUTick format.
//
// The method uses the dedicated TimestampFromProp function to calculate the
// absolute time based on the trace ClockType.
//
// Returns the timestamp as a time.Time (usually but not always in UTC).
func (e *EventRecordHelper) GetPropertyWmiTime(name string) (time time.Time, err error) {
	wmiTime, err := e.GetPropertyInt(name)
	if err != nil {
		return time, err
	}
	return e.EventRec.TimestampFromProp(int64(wmiTime)), nil
}

// GetPropertyFileTime returns the Filetime property value as time.Time.
//
// Filetime intypes are returned as time.Time (usually but not always UTC).
//
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyFileTime(name string) (time.Time, error) {
	nanoseconds, err := e.GetPropertyInt(name)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, nanoseconds), nil
}

// GetPropertyUint returns the property value as uint64.
//
// Filetime intypes are returned as uint64 nanoseconds.
//
// Returns conversion error for negative signed values.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyUint(name string) (uint64, error) {
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				return p.GetUInt()
			}
		}
	}
	if _, ok := e.PropertiesCustom[name]; ok { // Check for custom properties last. (rare)
		return 0, fmt.Errorf("custom property %s cannot be read as integer", name)
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyFloat returns the property value as float64.
// Supports 32-bit and 64-bit IEEE 754 formats.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyFloat(name string) (float64, error) {
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				return p.GetFloat()
			}
		}
	}
	if _, ok := e.PropertiesCustom[name]; ok { // Check for custom properties last. (rare)
		return 0, fmt.Errorf("custom property %s cannot be read as float", name)
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyPGUID returns the property value as a pointer to a GUID struct.
// Returns a pointer to a GUID struct, which should not be modified, copy it if needed.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyPGUID(name string) (g *GUID, err error) {
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				return p.GetGUID()
			}
		}
	}
	if _, ok := e.PropertiesCustom[name]; ok { // Check for custom properties last. (rare)
		return nil, fmt.Errorf("custom property %s cannot be read as GUID", name)
	}
	return nil, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// SetCustomProperty sets or updates a property value in the CustomProperties map.
// This is useful for adding a property that is not present in the provider event shema,
// NOTE: This now only works for adding *new* synthetic properties. It cannot
// override a property from the event schema.
func (e *EventRecordHelper) SetCustomProperty(name, value string) *Property {
	if p, ok := e.PropertiesCustom[name]; ok {
		p.value = value
		// Make it unparseable so this user defined value is always used,
		// even if the new value is an empty string. This prevents `FormatToString`
		// from re-parsing the original data. By setting pValue to 0, the
		// Parseable() method will return false.
		p.pValue = 0
		return p
	}

	p := e.newProperty()
	p.name = name
	p.value = value
	e.PropertiesCustom[name] = p
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

// ParseProperty parses a single property by name, converting its binary data to a formatted value.
func (e *EventRecordHelper) ParseProperty(name string) (err error) {
	// Parse custom simple property.
	if p, ok := e.PropertiesCustom[name]; ok {
		if _, err = p.FormatToString(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
		}
	}

	// Parse simple property from schema using the index map for a fast lookup.
	nameToIndex := e.getCachedNameToIndexMap()
	if index, ok := nameToIndex[name]; ok {
		if index < len(*e.PropertiesByIndex) {
			if p := (*e.PropertiesByIndex)[index]; p != nil {
				if _, err = p.FormatToString(); err != nil {
					return fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
				}
			}
		}
	}

	// Parse array of properties.
	if propSlicePtr, ok := e.ArrayProperties[name]; ok {
		// iterate over the properties
		for _, p := range *propSlicePtr {
			if _, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, name, err)
			}
		}
	}

	// Parse struct array property.
	if structs, ok := e.StructArrays[name]; ok {
		for _, propStruct := range structs {
			for field, prop := range propStruct {
				if _, err = prop.FormatToString(); err != nil {
					return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh, name, field, err)
				}
			}
		}
	}

	// Parse single struct property. - only check if requesting StructurePropertyName
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
