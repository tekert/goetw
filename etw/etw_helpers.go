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
	// Level 1: Provider GUID -> *providerCache
	// Level 2: Schema Key (uint64) -> *schemaCacheEntry
	globalSchemaCache sync.Map

	// cache for metadata on fully parsed events
	hostname, _ = os.Hostname()
)

// --- Schema Key Configuration ---
// preferredSchemaKey controls the keying method used for the global schema cache.
// Change this value to switch between strategies.
// 64: Uses a 64-bit key. Faster, but requires copying the schema buffer on a cache hit.
// 128: Uses a 128-bit key. Slower key generation, but allows for zero-copy cache hits.
type preferredSchemaKey = schemaKeyType128

const (
	// The following boolean constant is derived from preferredSchemaKey at compile time
	// by comparing the size of the aliased type. This allows the compiler to perform
	// dead code elimination, providing conditional compilation from a single type alias change.
	//
	// The nil pointer dereference is never executed; it only provides a typed
	// expression for the compiler to evaluate the size of.
	use64bitKey = unsafe.Sizeof(*(*preferredSchemaKey)(nil)) == unsafe.Sizeof(schemaKeyType64(0))
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

// globalSchemaCacheKey combines the Provider GUID and the event-specific schema key
// to create a single, globally unique key for an event schema. This allows for
// a flattened, single-level global cache.
type globalSchemaCacheKey struct {
	providerGUIDHigh uint64
	providerGUIDLow  uint64
	schemaKey        preferredSchemaKey
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

// SchemaKey is a constraint that permits any of our defined schema key types.
// This is used by the generic getSchemaKey function.
type SchemaKey interface {
	schemaKeyType64 | schemaKeyType128
}

//lint:ignore U1000 option for different keying strategies
type schemaKeyType64 uint64

//lint:ignore U1000 option for different keying strategies
type schemaKeyType128 struct {
	high uint64
	low  uint64
}

// getSchemaKey is a generic function that generates a unique key for an event's schema.
// The keying strategy is controlled at compile-time via the `preferredSchemaKey` type alias,
// which determines the specific key type (`schemaKeyType64` or `schemaKeyType128`) to generate.
//
//   - `schemaKeyType64`: A fast 64-bit key identifying the event's property layout.
//     Because it excludes the `Keyword`, it is not fully unique. This requires the cached
//     schema EventDescriptor to be copied and patched on a cache hit, trading zero-copy for faster key generation.
//
//   - `schemaKeyType128`: A robust 128-bit key that includes the `Keyword`, guaranteeing
//     uniqueness. This enables a zero-copy optimization on cache hits, as the program can
//     point directly to the immutable cached schema buffer, but uses more memory.
//
// It's 40ns for 128bit key vs 20ns for 64/32bit key but 128bit saves copying the cached schema
// to patch the EventDescriptor on cache hits. The copy is about 60-70ns.
// 128bit key is overall 10% faster in practice because it avoids the copy on cache hits,
// but uses more memory. The choice depends on the expected memory and performance needs.
func getSchemaKey[K SchemaKey](er *EventRecord) K {
	var key K
	desc := &er.EventHeader.EventDescriptor

	switch any(key).(type) {
	case schemaKeyType64:
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
		val := schemaKeyType64(key)
		return any(val).(K)

	case schemaKeyType128:
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
		val := schemaKeyType128{high: high, low: low}
		return any(val).(K)
	}

	// This part of the code is unreachable because the type K is constrained
	// by the SchemaKey interface, but the compiler requires a return statement.
	panic("unsupported key type")
}

// schemaCacheKey generates a memory friedly composite key for the global schema cache.
// It combines the provider GUID and the schema key into a struct of scalar types,
// which helps prevent stack memory writes during map lookups and instead use registers.
func (er *EventRecord) schemaCacheKey() globalSchemaCacheKey {
	// Directly access the GUID bytes and interpret them as two uint64s.
	// This is much faster using GUID struct directly.
	guidPtr := (*[2]uint64)(unsafe.Pointer(&er.EventHeader.ProviderId))
	return globalSchemaCacheKey{
		providerGUIDHigh: guidPtr[0],
		providerGUIDLow:  guidPtr[1],
		schemaKey:        getSchemaKey[preferredSchemaKey](er),
	}
}

// traceStorage holds all the necessary reusable memory for a single trace (goroutine).
// This avoids using sync.Pool for thread-local data, reducing overhead.
type traceStorage struct {
	helper      EventRecordHelper // Was in pools before, but this increased performance by ~5%
	parsedEvent *Event            // Caches the fully parsed event.

	// Reusable buffers and slices. They are reset before processing each event.
	propertiesCustom     map[string]*Property     // For user-defined simple properties
	propertiesByIndex    []*Property              // For schema-defined simple properties
	arrayProperties      []*[]*Property           // For arrays of properties, indexed by property schema index
	usedArrayIndices     []int                    // Tracks populated indices in arrayProperties for fast reset.
	structArrays         [][]map[string]*Property // For arrays of structs, indexed by property schema index
	usedStructArrIndices []int                    // Tracks populated indices in structArrays for fast reset.
	structSingle         []map[string]*Property   // For non-array structs
	selectedProps        map[string]bool          // Properties selected by the user for parsing
	propertyOffsets      []uintptr                // Caches property offsets for on-demand integer parsing.
	//epiArray          []*EventPropertyInfo              // Caches pointers to EventPropertyInfo's.
	teiBuffer []byte // Buffer for TdhGetEventInformation()

	// Freelist cache for Property structs.
	propCache []Property
	propIdx   int

	// Pools for nested structures that can't be easily managed by a single slice.
	propertyMapPool sync.Pool // For nested structs in struct arrays.
	propSlicePool   sync.Pool // For simple arrays of properties.
}

// newTraceStorage creates a new storage area for a goroutine in ProcessTrace.
// TODO: Explore a mechanism to periodically shrink the capacity of slices in traceStorage
// (e.g., propCache, propertiesByIndex) if they grow excessively due to a single large event.
// This would manage the "high-water mark" memory issue, trading a small performance cost
// for better long-term memory usage in scenarios with highly variable event sizes.
func newTraceStorage() *traceStorage {
	ts := &traceStorage{
		propertiesCustom:     make(map[string]*Property, 8),
		propertiesByIndex:    make([]*Property, 0, 64),
		arrayProperties:      make([]*[]*Property, 0, 16),
		usedArrayIndices:     make([]int, 0, 16),
		structArrays:         make([][]map[string]*Property, 0, 8),
		usedStructArrIndices: make([]int, 0, 8),
		structSingle:         make([]map[string]*Property, 0, 4),
		selectedProps:        make(map[string]bool, 16),
		propertyOffsets:      make([]uintptr, 0, 64),
		teiBuffer:            make([]byte, 8192), // Initial size for GetEventInformation()

		// Initialize the property cache with a reasonable capacity to avoid frequent reallocations.
		propCache: make([]Property, 0, 256),
		propIdx:   0,

		propertyMapPool: sync.Pool{New: func() any { return make(map[string]*Property, 8) }},
		propSlicePool:   sync.Pool{New: func() any { s := make([]*Property, 0, 8); return &s }},
	}
	ts.helper.storage = ts
	return ts
}

/*
   PERFORMANCE NOTE: Pointer vs. Direct Slice Access in `EventRecordHelper`

   A key performance optimization in this package involves how slices from the thread-local
   `traceStorage` are accessed by the temporary `EventRecordHelper`. Benchmarks and assembly
   analysis have shown that using pointers to slices on the helper struct (the current
   implementation) is consistently **~5% faster** than using direct slice values, even when
   compiling with bounds checks disabled.

   This performance difference is due to two main factors: **Function Call Overhead (Stack Spilling)**
   and **Bounds Check Elimination (BCE)**.

   ---

   ### 1. Function Call Overhead (The Primary Reason)

   The `EventRecordHelper` struct is a method receiver on the hottest paths of event
   processing (e.g., `prepareProperty`). The Go compiler tries to pass method receivers
   and arguments in fast CPU registers. However, there is a limited budget for this.

   -   **Pointer Version (Fast):** The helper struct contains only pointers (8 bytes each).
       This keeps the total size of the struct small and "lightweight." The compiler can
       easily pass the entire helper in registers when calling its methods.

   -   **Slice Version (Slow):** A slice header is 24 bytes (pointer, len, cap). Using
       direct slice fields makes the `EventRecordHelper` struct much larger ("fatter").
       It exceeds the register budget, forcing the compiler to perform **stack spilling**—
       writing the struct's contents to main memory (the stack) for every method call.

   Profiling confirms this: the cumulative time of the `CALL e.prepareProperty` instruction
   is significantly higher in the slice version due to the overhead of these memory
   operations on every single call. This is the dominant reason for the performance gap.

   ---

   ### 2. Bounds Check Elimination (BCE)

   When compiling with default settings, the pointer-based approach also helps the Go
   optimizer eliminate bounds checks (`if i >= len(...)`) in hot loops.

   By assigning a pointer and re-slicing it to a known length in `initialize()`, the
   compiler can more easily prove that the slice's length is constant throughout the
   helper's lifecycle. This certainty allows it to remove the redundant safety checks
   inside loops, further improving performance.

   ---

   **Conclusion:** The use of pointers to slices on `EventRecordHelper` is a deliberate and
   critical optimization. It ensures the helper struct remains lightweight, avoiding expensive
   stack spills during function calls, while also providing the compiler with the necessary
   information to perform bounds check elimination.
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
	ArrayProperties *[]*[]*Property
	// StructArrays stores arrays of complex structures.
	// - Structure: A map where the key is the array's name (e.g., "Adapters").
	//   The value is a slice of maps. Each map in the slice represents one
	//   struct instance, with its keys being the struct's field names
	//   (e.g., "IPAddress") and values being the corresponding `*Property` objects.
	// - Final JSON Example: "Adapters": [{"IPAddress": "1.2.3.4"}, {"IPAddress": "5.6.7.8"}]
	StructArrays *[][]map[string]*Property
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
		Skip bool
	}

	// Cached provider schema information to avoid repeated lookups.
	schemaCache *schemaCacheEntry // This will be lazily populated.

	// Stored property values for resolving array lengths
	// both are filled when a prop is about to be prepared.
	propertyOffsets *[]uintptr
	//epiArray        *[]*EventPropertyInfo

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

	// currentPrepCount tracks the number of (sequantial) properties that have been prepared so far.
	// This enables lazy, on-demand property preparation.
	currentPrepCount uint32

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

// reset returns the EventRecordHelper to the global pool.
// The associated traceStorage is NOT reset here; it's reset at the beginning
// of the next event's processing.
func (e *EventRecordHelper) reset() {
	//*e = EventRecordHelper{} // 2% performance drop
	e.TraceInfo = nil
	//helperPool.Put(e) // no using pools for now
}

// newEventRecordHelper creates a new EventRecordHelper and retrieves the TRACE_EVENT_INFO
// for the given EventRecord. It implements a multi-level caching and fallback strategy.
// +120% performance gain by using caching vs no caching of the TraceInfo (also caching names etc)
func newEventRecordHelper(er *EventRecord, storage *traceStorage) (erh *EventRecordHelper, err error) {
	//erh = helperPool.Get().(*EventRecordHelper)  // no using pools for now
	erh = &storage.helper

	// Reset the thread-local storage before processing a new event.
	//storage.reset()

	erh.storage = storage
	erh.EventRec = er
	erh.teiBuffer = &storage.teiBuffer // Keep a reference before calling internal funcs

	key := er.schemaCacheKey()

	// --- Stage 1: Check Global Cache (Single, direct lookup) ---
	if val, found := globalSchemaCache.Load(key); found {
		cachedEntry := val.(*schemaCacheEntry)
		// Since caching is always enabled, a found entry is guaranteed to be valid and have a non-nil teiBuffer
		erh.schemaCache = cachedEntry // Cache the entry on the helper for later use.
		// --- Cache Hit: Populate helper from cache ---
		schema := cachedEntry.teiBuffer
		// This commented block of code is if we need to copy the buffer to a local one. (2,1% performance hit)
		// NOTE: use er.schemaCacheKey32() or er.schemaCacheKey64() if using this block
		if use64bitKey {
			// Ensure the thread-local buffer is large enough.
			if cap(storage.teiBuffer) < len(schema) {
				storage.teiBuffer = make([]byte, len(schema))
			}
			storage.teiBuffer = storage.teiBuffer[:len(schema)]
			// Copy the cached template into the thread-local buffer.
			copy(storage.teiBuffer, schema) // 2.1% performance hit
			erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&storage.teiBuffer[0]))
			erh.TraceInfo.EventDescriptor = er.EventHeader.EventDescriptor // Important: patch EventDescriptor
		} else {
			// NOTE: use er.schemaCacheKey128() if using this block
			// The template is immutable. Point directly to it. No copy needed.
			erh.TraceInfo = (*TraceEventInfo)(unsafe.Pointer(&schema[0]))
			// The buffer is the globally cached one, not the thread-local one.
			// Setting this to nil indicates it's not locally owned.
			erh.teiBuffer = nil
		}

		// Perform smart cleanup now that we know the schema
		erh.resetStorageFor(erh.TraceInfo)
		return erh, nil // Cache hit, we are done.
	}

	// --- Stage 2: Call TdhGetEventInformation (Cache Miss) ---
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

	// --- Stage 3: Update Cache (Single, direct store) ---
	// Create a new cache entry with a copy of the TEI buffer.
	newEntry := &schemaCacheEntry{}
	newEntry.teiBuffer = make([]byte, len(*erh.teiBuffer))
	copy(newEntry.teiBuffer, *erh.teiBuffer)

	// Use LoadOrStore to handle the race where two threads miss the cache for the same schema simultaneously.
	// The first one to call Store wins, and the second one will get the already-stored value, preventing duplicates.
	actual, _ := globalSchemaCache.LoadOrStore(key, newEntry)
	erh.schemaCache = actual.(*schemaCacheEntry) // Always use the value that's in the map.

	// Perform smart cleanup now that we know the schema
	erh.resetStorageFor(erh.TraceInfo)
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
	key := e.EventRec.schemaCacheKey()
	val, _ := globalSchemaCache.Load(key)
	cachedEntry := val.(*schemaCacheEntry)

	// Cache the result on the helper for subsequent calls within the same event's lifecycle.
	e.schemaCache = cachedEntry
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

// initialize sets up the helper pointers and state for the current event.
// This is called after resetForEvent and assumes the storage has been properly cleaned.
// This function does NOT perform any cleanup; it only assigns values.
func (e *EventRecordHelper) initialize() {
	storage := e.storage

	// Assign map pointers
	e.PropertiesCustom = storage.propertiesCustom
	e.selectedProperties = storage.selectedProps

	// Assign struct pointer
	e.StructSingle = &storage.structSingle

	// Set up user data iteration pointers
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)

	// Reset preparation counter for the new event
	e.currentPrepCount = 0

	if e.TraceInfo == nil {
		// No schema available, nothing more to set up
		return
	}

	// Assign slice pointers (slices were already sized in resetForEvent)
	e.PropertiesByIndex = &storage.propertiesByIndex
	e.ArrayProperties = &storage.arrayProperties
	e.StructArrays = &storage.structArrays
	e.propertyOffsets = &storage.propertyOffsets
}

// TODO: clear some mem allocated is some event caused peak alloc?
// resetStorageFor performs selective cleanup of the previous event's state based on
// what the current event will actually use. This is called after the schema is known
// but before property preparation begins.
//
// It only clears what will be overwritten or reused, avoiding unnecessary work.
func (e *EventRecordHelper) resetStorageFor(traceInfo *TraceEventInfo) {
	storage := e.storage
	//traceInfo := e.TraceInfo

	// --- Part 1: Clean up complex pooled structures from PREVIOUS event ---
	// These MUST be cleaned because they hold pooled resources that need to be returned.

	// Return array property slices to pool
	for _, i := range storage.usedArrayIndices {
		propSlicePtr := storage.arrayProperties[i]
		clear(*propSlicePtr)
		*propSlicePtr = (*propSlicePtr)[:0]
		storage.propSlicePool.Put(propSlicePtr)
		storage.arrayProperties[i] = nil
	}
	storage.usedArrayIndices = storage.usedArrayIndices[:0]

	// Return struct array maps to pool
	for _, i := range storage.usedStructArrIndices {
		structs := storage.structArrays[i]
		for _, propStruct := range structs {
			clear(propStruct)
			storage.propertyMapPool.Put(propStruct)
		}
		storage.structArrays[i] = nil
	}
	storage.usedStructArrIndices = storage.usedStructArrIndices[:0]

	// Return single struct maps to pool
	for _, propStruct := range storage.structSingle {
		clear(propStruct)
		storage.propertyMapPool.Put(propStruct)
	}
	storage.structSingle = storage.structSingle[:0]

	// --- Part 2: Reset simple state for CURRENT event ---
	// Reset the property freelist index. The underlying slice memory is reused.
	storage.propIdx = 0

	// Clear the cached optional parsed event.
	storage.parsedEvent = nil

	// Clear maps that will be repopulated
	clear(storage.propertiesCustom)
	clear(storage.selectedProps)

	// --- Part 3: Selective slice cleanup based on current event's schema ---
	if traceInfo != nil {
		maxPropCount := int(traceInfo.PropertyCount)

		// propertiesByIndex: will be fully repopulated, so clear only what we'll use
		if cap(storage.propertiesByIndex) >= maxPropCount {
			// We have enough capacity. Clear only the range we'll use.
			storage.propertiesByIndex = storage.propertiesByIndex[:maxPropCount]
			clear(storage.propertiesByIndex)
		} else {
			storage.propertiesByIndex = make([]*Property, maxPropCount)
		}

		// arrayProperties: entries are nil by default and set on-demand, so just resize
		if cap(storage.arrayProperties) >= maxPropCount {
			storage.arrayProperties = storage.arrayProperties[:maxPropCount]
			// NO CLEAR - entries are nil and will be checked before use
		} else {
			storage.arrayProperties = make([]*[]*Property, maxPropCount)
		}

		// structArrays: entries are nil by default and set on-demand, so just resize
		if cap(storage.structArrays) >= maxPropCount {
			storage.structArrays = storage.structArrays[:maxPropCount]
			// NO CLEAR - entries are nil and will be checked before use
		} else {
			storage.structArrays = make([][]map[string]*Property, maxPropCount)
		}

		// propertyOffsets: will be overwritten during prepareProperty, so just resize
		if cap(storage.propertyOffsets) < maxPropCount {
			storage.propertyOffsets = make([]uintptr, maxPropCount)
		}
		storage.propertyOffsets = storage.propertyOffsets[:maxPropCount]
		// NO CLEAR - values are overwritten during prepareProperty
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

	// When using the 128-bit key, the cached schema is a perfect match, and we can
	// use the pre-cached metadata strings for better performance. With the 64-bit key,
	// we must retrieve the live metadata from the current event's TraceInfo.
	// This 'if' is resolved at compile time.
	if use64bitKey {
		event.System.Channel = e.TraceInfo.ChannelName()
		event.System.Level.Name = e.TraceInfo.LevelName()
		event.System.Keywords.Name = e.TraceInfo.KeywordsName()
		event.System.Task.Name = e.TraceInfo.TaskName()
	} else {
		event.System.Channel = sce.channelName
		event.System.Level.Name = sce.levelName
		event.System.Keywords.Name = sce.keywordsNames
		event.System.Task.Name = sce.taskName
	}

	event.System.Level.Value = e.TraceInfo.EventDescriptor.Level
	event.System.Keywords.Mask = e.TraceInfo.EventDescriptor.Keyword
	event.System.Task.Value = uint8(e.TraceInfo.EventDescriptor.Task)

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
//
// NOTE: This is very slow, so only use it when absolutely necessary (e.g. for very complex types).
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
	// // Fetch the schema for the property at the target index 'i'.
	//epi2 := e.getEpiAt(i) // <- equivalent but ~0.5% slower
	// The property at `i` has already been prepared, so its info is cached.
	propAtIndex := (*e.PropertiesByIndex)[i]
	assert(propAtIndex != nil, "property at index %d not yet prepared", i)
	epi := propAtIndex.evtPropInfo

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

// Gets the EventPropertyInfo at index i.
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	return e.TraceInfo.GetEventPropertyInfoAt(i) // it's cached by the cpu most of the time.
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
			if nullPos := bytes.IndexByte(chars, 0); nullPos != -1 {
				sizeBytes = uint32(nullPos + 1) // Found null, size includes terminator.
			} else {
				sizeBytes = uint32(len(chars)) // No null, consume all remaining data.
			}
			// size may be null included even if not null terminated, doesn't matter.
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
func (e *EventRecordHelper) prepareProperty(i uint32, name string, epi *EventPropertyInfo) (p *Property, err error) {
	p = e.newProperty()

	// Store the offset of this property so we can parse it later if needed.
	// We store the absolute pointer, which is safe within the callback context.
	(*e.propertyOffsets)[i] = e.userDataIt

	//epi := e.getEpiAt(i) // slow.
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

	// Treat non-array properties as arrays with one element.
	for range arrayCount {
		propStruct := e.storage.propertyMapPool.Get().(map[string]*Property)

		startIndex := epi.StructStartIndex()
		lastMember := startIndex + epi.NumOfStructMembers()

		for j := startIndex; j < lastMember; j++ {
			epiprop := e.getEpiAt(uint32(j))
			if p, err = e.prepareProperty(uint32(j), names[j], epiprop); err != nil {
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
			// Track the index if this is the first struct for this property.
			if (*e.StructArrays)[i] == nil {
				e.storage.usedStructArrIndices = append(e.storage.usedStructArrIndices, int(i))
			}
			(*e.StructArrays)[i] = append((*e.StructArrays)[i], propStruct)
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
		if p, err = e.prepareProperty(i, names[i], epi); err != nil {
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
		(*e.ArrayProperties)[i] = array
		// Track that this index is now populated.
		e.storage.usedArrayIndices = append(e.storage.usedArrayIndices, int(i))
	} else {
		// Return the unused slice to the pool if the array ended up empty.
		e.storage.propSlicePool.Put(array)
	}

	return nil
}

// preparePropertiesUpTo will partially decode the event, property offsets, sizes, indexes, etc.
// Prepares up to target ID inclusive, these are the properties IDx in the event schema
// and they start from 1.
func (e *EventRecordHelper) preparePropertiesUpTo(targetID uint32) (err error) {
	// Clamp the targetIndex to a valid maximum to prevent out-of-bounds access.
	if targetID > e.TraceInfo.TopLevelPropertyCount {
		targetID = e.TraceInfo.TopLevelPropertyCount
	}
	if e.currentPrepCount >= targetID {
		return nil // Already prepared all properties.
	}

	// TODO: move this to a separate function before TraceInfo(schema) is used/created or not
	// Handle special case for MOF events that are just a single string.
	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
	if e.EventRec.IsMof() && (e.EventRec.EventHeader.Flags&EVENT_HEADER_FLAG_STRING_ONLY) != 0 {
		if e.currentPrepCount == 0 {
			// If there aren't any event property info structs, use the UserData directly.
			str := (*uint16)(unsafe.Pointer(e.EventRec.UserData))
			value := FromUTF16Slice(unsafe.Slice(str, e.EventRec.UserDataLength/2))
			if e.EventRec.UserDataLength != 0 {
				e.SetCustomProperty("String", value)
			}
			e.currentPrepCount = e.TraceInfo.TopLevelPropertyCount // Mark all as "done".
		}
		return nil
	}

	// Get or generate property names for this event schema.
	// This is a performance optimization to avoid repeated UTF-16 to string conversions.
	names := e.getCachedPropNames()

	// Get the pointer to the first EventPropertyInfo struct once before the loop.
	epiPtr := uintptr(unsafe.Pointer(&e.TraceInfo.EventPropertyInfoArray[0]))

	//propsByIndexSlice := *e.PropertiesByIndex

	// Process all top-level properties defined in the event schema up to targetIndex.
	for i := e.currentPrepCount; i < targetID; i++ {
		epi := (*EventPropertyInfo)(unsafe.Pointer(epiPtr))
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
			if p, err = e.prepareProperty(i, names[i], epi); err != nil {
				return err
			}
			(*e.PropertiesByIndex)[i] = p // PERF-NOTE: Heavy write barrier here, go sheningans, but unavoidable.
		}

		epiPtr += gEpiSize // Move to the next EventPropertyInfo struct.
	}
	e.currentPrepCount = max(targetID, e.currentPrepCount)

	// After parsing all defined properties, check if there's any data left.
	if e.currentPrepCount == (e.TraceInfo.TopLevelPropertyCount) {
		// This can happen if the event schema is an older version.
		if e.userDataIt < e.userDataEnd {
			remainingBytes := uint32(e.userDataEnd - e.userDataIt)
			remainingData := unsafe.Slice((*byte)(unsafe.Pointer(e.userDataIt)), remainingBytes)

			// Probably this is because TraceEventInfo used an older Thread_V2_TypeGroup1
			// instead of a Thread_V3_TypeGroup1 MOF class to decode it.
			// Try to parse the remaining data as a MOF property.
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
	if err = e.parseAndSetAllProperties(event); err != nil {
		return
	}
	e.setEventMetadata(event)

	return event, err
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
			inType := p.evtPropInfo.InType()

			switch inType {
			// Use the existing decoders to get native types.
			case TDH_INTYPE_FLOAT, TDH_INTYPE_DOUBLE:
				fval, err := p.decodeFloatIntype()
				if err != nil {
					last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
				} else {
					*eventData = append(*eventData,
						EventProperty{Name: name, Type: TypeFloat64, FloatValue: fval})
				}

			case TDH_INTYPE_BOOLEAN:
				// Boolean is 4 bytes in ETW. True if non-zero.
				uval, _, err := p.decodeScalarIntype()
				if err != nil {
					last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
				} else {
					*eventData = append(*eventData,
						EventProperty{Name: name, Type: TypeBool, BoolValue: uval != 0})
				}

			case TDH_INTYPE_POINTER:
				// Handle pointers specially: parse as uint64 but tag for hex formatting.
				uval, _, err := p.decodeScalarIntype()
				if err != nil {
					last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
				} else {
					*eventData = append(*eventData,
						EventProperty{Name: name, Type: TypeHexUint64, UintValue: uval})
				}

			default: // All other integer types
				uval, signed, err := p.decodeScalarIntype()
				if err != nil {
					last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
				} else {
					if signed {
						*eventData = append(*eventData,
							EventProperty{Name: name, Type: TypeInt64, IntValue: int64(uval)})
					} else {
						*eventData = append(*eventData,
							EventProperty{Name: name, Type: TypeUint64, UintValue: uval})
					}
				}
			}
		} else {
			// (COMPLEX TYPES or MAPPED SCALARS): Format to a string using the arena.
			startOffset := len(out.dataBuffer)
			var err error
			out.dataBuffer, err = p.decodeToString(p.evtPropInfo.OutType(), out.dataBuffer)
			if err != nil {
				out.dataBuffer = out.dataBuffer[:startOffset] // Rewind on error
				last = fmt.Errorf("%w %s: %s", ErrPropertyParsingTdh, name, err)
			} else {
				// Create a string header pointing to the new data in our buffer.
				stringPtr := unsafe.SliceData(out.dataBuffer[startOffset:])
				val := unsafe.String(stringPtr, len(out.dataBuffer)-startOffset)
				*eventData = append(*eventData,
					EventProperty{Name: name, Type: TypeString, StringValue: val})
			}
		}
	}

	// Custom properties from map are always strings.
	if len(e.PropertiesCustom) > 0 {
		for name, p := range e.PropertiesCustom {
			if !e.shouldParse(name) {
				continue
			}
			*eventData = append(*eventData,
				EventProperty{Name: name, Type: TypeString, StringValue: p.value})
		}
	}

	// Arrays are complex types, store them in OtherValue.
	if len(e.storage.usedArrayIndices) > 0 {
		for _, i := range e.storage.usedArrayIndices {
			pname := names[i]
			if !e.shouldParse(pname) {
				continue
			}
			props := *(*e.ArrayProperties)[i]
			values := make([]string, 0, len(props))

			for _, p := range props {
				var v string
				if v, err = p.FormatToString(); err != nil {
					last = fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, pname, err)
				}
				values = append(values, v)
			}
			*eventData = append(*eventData,
				EventProperty{Name: pname, Type: TypeOther, OtherValue: values})
		}
	}

	// Structs are complex types, store them in OtherValue.
	if len(e.storage.usedStructArrIndices) > 0 {
		for _, i := range e.storage.usedStructArrIndices {
			name := names[i]
			if !e.shouldParse(name) {
				continue
			}
			structs := (*e.StructArrays)[i]
			if structArray, err := e.formatStructs(structs, name); err != nil {
				last = err
			} else {
				*eventData = append(*eventData,
					EventProperty{Name: name, Type: TypeOther, OtherValue: structArray})
			}
		}
	}

	// Handle single structs
	if len(*e.StructSingle) > 0 && e.shouldParse(StructurePropertyName) {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			last = err
		} else {
			*eventData = append(*eventData,
				EventProperty{Name: StructurePropertyName, Type: TypeOther, OtherValue: structs})
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

// getPrepProperty is a private helper that centralizes the logic for finding a
// property by name.
func (e *EventRecordHelper) getPrepProperty(name string) (p *Property, isCustom bool, err error) {
	// Check schema-defined properties first (the common case).
	nameToIndex := e.getCachedNameToIndexMap() // <- this was cached before we got here, so it's fast
	if index, ok := nameToIndex[name]; ok {    // <- this is the same as p := Properties[name] would have done it.
		// Lazily prepare properties up to the requested target ID (index+1)
		if err = e.preparePropertiesUpTo(uint32(index) + 1); err != nil {
			return nil, false, err
		}
		// The bounds check is a safety measure. It should not happen.
		if index < len(*e.PropertiesByIndex) {
			if p = (*e.PropertiesByIndex)[index]; p != nil {
				return p, false, nil // Found in schema properties.
			}
		}
	}

	if p, ok := e.PropertiesCustom[name]; ok {
		return p, true, nil // Found in custom properties.
	}

	return nil, false, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// GetPropertyString returns the formatted string value of the named property.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyString(name string) (s string, err error) {
	p, _, err := e.getPrepProperty(name)
	if err != nil {
		return "", err
	}
	return p.FormatToString()
}

// GetPropertyInt returns the property value as int64.
//
// Filetime intypes are returned as int64 nanoseconds.
//
// Returns overflow error for unsigned values exceeding math.MaxInt64.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	p, isCustom, err := e.getPrepProperty(name)
	if err != nil {
		return 0, err
	}
	if isCustom {
		return 0, fmt.Errorf("custom property %s cannot be read as integer", name)
	}
	return p.GetInt()
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
	p, isCustom, err := e.getPrepProperty(name)
	if err != nil {
		return 0, err
	}
	if isCustom {
		return 0, fmt.Errorf("custom property %s cannot be read as integer", name)
	}
	return p.GetUInt()
}

// GetPropertyFloat returns the property value as float64.
// Supports 32-bit and 64-bit IEEE 754 formats.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyFloat(name string) (float64, error) {
	p, isCustom, err := e.getPrepProperty(name)
	if err != nil {
		return 0, err
	}
	if isCustom {
		return 0, fmt.Errorf("custom property %s cannot be read as float", name)
	}
	return p.GetFloat()
}

// GetPropertyPGUID returns the property value as a pointer to a GUID struct.
// Returns a pointer to a GUID struct, which should not be modified, copy it if needed.
// Returns ErrUnknownProperty if the property doesn't exist.
func (e *EventRecordHelper) GetPropertyPGUID(name string) (g *GUID, err error) {
	p, isCustom, err := e.getPrepProperty(name)
	if err != nil {
		return nil, err
	}
	if isCustom {
		return nil, fmt.Errorf("custom property %s cannot be read as GUID", name)
	}
	return p.GetGUID()
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

// GetHelper is the entry point for on-demand event parsing. It retrieves a
// temporary helper object that provides access to the event's schema and
// parsing methods.
//
// On its first call for an event, it performs the necessary schema cache lookup
// Subsequent calls for the same event return the already prepared helper instantly.
//
// The returned helper is only valid within the scope of the EventRecordCallback
// from which it was called.
func (er *EventRecord) GetHelper() (*EventRecordHelper, error) {
	usrCtx := er.userContext()
	storage := usrCtx.storage
	if storage.helper.TraceInfo != nil {
		// already initialized, return it
		return &storage.helper, nil
	}

	// we get the TraceContext from EventRecord.UserContext
	// Parse TRACE_EVENT_INFO from the event record
	if h, err := newEventRecordHelper(er, storage); err == nil {

		// Convert EventRecord timestamp to FILETIME based on Session
		// ClientContext settings (Controller side where the trace is).
		// Does nothing if PROCESS_TRACE_MODE_RAW_TIMESTAMP (Consumer side) is not set.
		// If that flag is not set, ETW already converts it to FILETIME format.
		if usrCtx.trace.processTraceMode&PROCESS_TRACE_MODE_RAW_TIMESTAMP != 0 {
			h.timestamp = usrCtx.trace.fromRawTimestamp(er.EventHeader.TimeStamp)
		} else {
			h.timestamp = er.EventHeader.TimeStamp
		}

		// initialize before preparing properties
		h.initialize()

		return h, nil
	} else {
		// On failure, we must still reset the helper so the next event can try again.
		storage.helper.reset()
		return nil, err
	}
}

// PrepareAll ensures all properties for the event are prepared.
// This is optional. If not called, properties will be prepared on-demand
// when a GetProperty* method is called. Use this if you intend to iterate
// over all properties and want to pay the preparation cost up-front.
func (e *EventRecordHelper) PrepareAll() error {
	// Call the engine with the highest possible index to ensure everything is prepared.
	return e.preparePropertiesUpTo(e.TraceInfo.TopLevelPropertyCount)
}

/*
	ETW Property Parsing Methods

	Converts raw binary event data into formatted values on-demand. Uses custom
	decoders for performance with TDH fallback for complex types. Results are cached.
*/

// GetParsedEvent performs a full parse of the event, creating the final *Event object
// with all its metadata and properties formatted.
//
// The returned *Event object is retrieved from a pool and should
// be released via `event.Release()` when you are done with it, especially if
// you are not using the default `Consumer.EventCallback`.
func (h *EventRecordHelper) GetParsedEvent() (*Event, error) {
	if h.storage.parsedEvent != nil {
		return h.storage.parsedEvent, nil
	}
	// Ensure properties are prepared before building the final event.
	if err := h.PrepareAll(); err != nil {
		return nil, err
	}

	// buildEvent creates the final object and populates all fields.
	event, err := h.buildEvent()
	if err != nil {
		if event != nil {
			event.Release()
		}
		return nil, err
	}

	// Cache the result before returning.
	h.storage.parsedEvent = event
	return event, nil
}

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

		// Parse array of properties.
		if index < len(*e.ArrayProperties) {
			if propSlicePtr := (*e.ArrayProperties)[index]; propSlicePtr != nil {
				// iterate over the properties
				for _, p := range *propSlicePtr {
					if _, err = p.FormatToString(); err != nil {
						return fmt.Errorf("%w array %s: %s", ErrPropertyParsingTdh, name, err)
					}
				}
			}
		}

		// Parse struct array property.
		if index < len(*e.StructArrays) {
			if structs := (*e.StructArrays)[index]; structs != nil {
				for _, propStruct := range structs {
					for field, prop := range propStruct {
						if _, err = prop.FormatToString(); err != nil {
							return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh, name, field, err)
						}
					}
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

// TODO: delete this when done with the new callback system
// Skip marks the event to be completely ignored during processing.
// When an event is marked with Skip, it will not be parsed or sent to
// the consumer channel at all. The event processing stops immediately
// after the current callback returns.
// This is useful when you want to filter out events early in the
// processing pipeline before any parsing overhead.
func (e *EventRecordHelper) Skip() {
	e.Flags.Skip = true
}
