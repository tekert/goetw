//go:build windows

package etw

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

var (
	providers       ProviderMap
	providersOnce   sync.Once
	defaultProvider = Provider{
		EnableLevel:      0xff,
		MatchAnyKeyword:  0xffffffffffffffff,
		MatchAllKeyword:  0,
		EnableProperties: EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
	}

	// Error returned when a provider is not found on the system
	ErrUnkownProvider = fmt.Errorf("unknown provider")
)

// ProviderMap is a map that indexes ETW providers by both their name and GUID string representation.
type ProviderMap map[string]*Provider

// Provider represents an ETW event provider, identified by its name and GUID,
// and includes the necessary options for enabling it in a trace session.
type Provider struct {

	// The provider's unique identifier (GUID). Must be specified.
	GUID GUID

	// Friendly name of the provider. (not used for enabling, just informational)
	Name string

	// The logging level specified. The provider typically writes an event if the
	// event's level is less than or equal to this value, in addition to meeting
	// the keyword criteria.
	//
	// Each value of Level enables the specified level and all more-severe levels.
	// For example, if you specify TRACE_LEVEL_WARNING (3), your consumer will
	// receive warning, error, and critical events.
	//
	// Standard logging levels are:
	//   - 1 (TRACE_LEVEL_CRITICAL): Abnormal exit or termination events.
	//   - 2 (TRACE_LEVEL_ERROR): Severe error events.
	//   - 3 (TRACE_LEVEL_WARNING): Warning events such as allocation failures.
	//   - 4 (TRACE_LEVEL_INFORMATION): Non-error informational events.
	//   - 5 (TRACE_LEVEL_VERBOSE): Detailed diagnostic events.
	//
	// Supplying 255 (0xFF) is the standard method for capturing all supported levels.
	EnableLevel uint8

	// 64-bit bitmask of keywords that determine the categories of events that you want the provider to write.
	// The provider typically writes an event if the event's keyword bits match any of the bits set in this
	// value or if the event has no keyword bits set, in addition to meeting the Level and MatchAllKeyword criteria.
	//
	// When used with modern (manifest-based or TraceLogging) providers, a MatchAnyKeyword value of 0 is treated
	// the same as a MatchAnyKeyword value of 0xFFFFFFFFFFFFFFFF, i.e. it enables all event keywords.
	// However, this behavior does not apply to legacy (MOF or TMF-based WPP) providers.
	// To enable all event keywords from a legacy provider, set MatchAnyKeyword to 0xFFFFFFFF.
	// To enable all event keywords from both legacy and modern providers, set MatchAnyKeyword to 0xFFFFFFFFFFFFFFFF.
	//
	// Filtering at kernel level is inherently faster than user mode filtering (following the parsing process).
	MatchAnyKeyword uint64

	// 64-bit bitmask of keywords that restricts the events that you want the provider to write.
	// The provider typically writes an event if the event's keyword bits match 'all' of the bits
	// set in this value or if the event has no keyword bits set, in addition to meeting the Level
	// and MatchAllKeyword criteria.
	//
	// This value is frequently set to 0.
	//
	// Note that this mask is not used if Keywords(Any) is set to zero.
	MatchAllKeyword uint64

	// Filters provides a mechanism for more granular, kernel-level filtering.
	// This maps to the `EnableParameters` argument of the `EnableTraceEx2` API.
	//
	// # Filter Types and Performance
	//
	// ETW supports several types of filtering with different performance characteristics.
	// It is crucial to understand the distinction to build efficient tracers.
	//
	//   - **Provider-Side Filtering (Level & Keywords):** This is the most efficient
	//     method. The provider's own code checks the enabled Level and Keywords
	//     *before* generating an event. If an event is filtered out, the call to
	//     `EventWrite` is skipped entirely, resulting in near-zero overhead.
	//
	//   - **Scope Filtering (`PIDFilter`, `ExecutableNameFilter`):** This is highly
	//     efficient. The ETW runtime can prevent a provider from being enabled
	//     within a process altogether, eliminating all event generation overhead
	//     from that process.
	//
	//   - **Attribute & Payload Filtering (`EventIDFilter`, etc.):** This filtering is
	//     performed by the ETW runtime *after* the provider has generated the event
	//     and sent it to ETW. This means the CPU cost of creating the event has
	//     already been paid. This type of filtering is effective for reducing trace
	//     data volume but is not as effective for reducing trace CPU overhead.
	//
	// For more info read:
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters EnableFilterDesc
	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor EVENT_FILTER_TYPE_EVENT_ID

	Filters []ProviderFilter

	// EnableProperties specifies flags from the EVENT_ENABLE_PROPERTY_* constants.
	// These flags control special ETW features for the provider when enabling it in a trace session.
	//
	// Enabled by default: (EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
	//
	// Supported flags (combine using bitwise OR):
	//
	//   EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0
	//     - Filters out events where the event's keyword is 0.
	//
	//   EVENT_ENABLE_PROPERTY_PROVIDER_GROUP
	//     - Enables a provider group rather than an individual event provider.
	//
	//   EVENT_ENABLE_PROPERTY_PROCESS_START_KEY
	//     - Includes the Process Start Key in the event's extended data.
	//       Retrieve with: EventRecord.ExtProcessStartKey()
	//
	//   EVENT_ENABLE_PROPERTY_EVENT_KEY
	//     - Includes a unique Event Key in the event's extended data.
	//       Retrieve with: EventRecord.ExtEventKey()
	//
	//   EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE
	//     - Filters out events marked as InPrivate or from InPrivate processes.
	//
	//   EVENT_ENABLE_PROPERTY_SID
	//     - Includes the security identifier (SID) of the user in the event's extended data.
	//       Retrieve with: EventRecord.ExtSid()
	//
	//   EVENT_ENABLE_PROPERTY_TS_ID
	//     - Includes the terminal session identifier in the event's extended data.
	//       Retrieve with: EventRecord.ExtTerminalSessionID()
	//
	//   EVENT_ENABLE_PROPERTY_STACK_TRACE
	//     - Adds a call stack trace to the extended data of events written using EventWrite.
	//       Retrieve with: EventRecord.ExtStackTrace()
	//
	//   EVENT_ENABLE_PROPERTY_CONTAINER_ID
	//     - Includes the container ID (GUID) in the event's extended data.
	//       Retrieve with: EventRecord.ExtContainerID()
	//
	// Example usage:
	//   prov.EnableProperties = EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_SID
	//
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
	EnableProperties uint32
}

// IsZero returns true if the provider is empty
func (p *Provider) IsZero() bool {
	return p.GUID.IsZero()
}

// MustParseProvider is a helper that wraps ParseProvider and panics on error.
func MustParseProvider(s string) Provider {
	p, err := ParseProvider(s)
	if err != nil {
		panic(err)
	}
	return p
}

// IsKnownProvider returns true if the provider is known
func IsKnownProvider(p string) bool {
	prov := ResolveProvider(p)
	return !prov.IsZero()
}

// ParseProvider parses a configuration string and returns a Provider with its
// configuration options.
//
// The format is strictly positional:
// (Name|GUID)[:Level[:EventIDs[:MatchAnyKeyword[:MatchAllKeyword]]]]
//
// To skip a parameter, an empty value must be provided. For example, to specify
// only a keyword, the format would be "ProviderName:::0x10".
//
// Example: "Microsoft-Windows-Kernel-File:0xff:12,13,14"
//
// NOTE: For finding events ID check the manifest in your system.
//
//	> logman query providers "provider-name"
//	> wevtutil gp "provider-name"
//
// Or Use https://github.com/zodiacon/EtwExplorer
//
// More info at:
// https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events
func ParseProvider(s string) (p Provider, err error) {
	var u uint64

	// Use default provider configuration
	p = defaultProvider

	parts := strings.Split(s, ":")

	for i, chunk := range parts {
		// An empty chunk means the user wants to use the default for this position.
		if chunk == "" && i > 0 { // i > 0 to not skip the provider name
			continue
		}

		switch i {
		case 0: // Part 0: Name/GUID (required)
			resolvedProvider := ResolveProvider(chunk)
			if resolvedProvider.IsZero() {
				err = fmt.Errorf("%w %s", ErrUnkownProvider, chunk)
				return
			}
			// Only copy the identifying information, preserving the defaults set above.
			p.GUID = resolvedProvider.GUID
			p.Name = resolvedProvider.Name
		case 1: // Part 1: Level
			if u, err = strconv.ParseUint(chunk, 0, 8); err != nil {
				err = fmt.Errorf("failed to parse EnableLevel '%s': %w", chunk, err)
				return
			}
			p.EnableLevel = uint8(u)
		case 2: // Part 2: EventIDs
			idStrings := strings.Split(chunk, ",")
			ids := make([]uint16, 0, len(idStrings))
			for _, idStr := range idStrings {
				if u, err = strconv.ParseUint(idStr, 0, 16); err != nil {
					err = fmt.Errorf("failed to parse EventID '%s': %w", idStr, err)
					return
				}
				ids = append(ids, uint16(u))
			}
			if len(ids) > 0 {
				p.Filters = append(p.Filters, NewEventIDFilter(true, ids...))
			}
		case 3: // Part 3: MatchAnyKeyword
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				err = fmt.Errorf("failed to parse MatchAnyKeyword '%s': %w", chunk, err)
				return
			}
			p.MatchAnyKeyword = u
		case 4: // Part 4: MatchAllKeyword
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				err = fmt.Errorf("failed to parse MatchAllKeyword '%s': %w", chunk, err)
				return
			}
			p.MatchAllKeyword = u
		}
	}
	return
}

// EnumerateProviders returns a ProviderMap containing available providers,
// keys are both provider's GUIDs and provider's names
func EnumerateProviders() (m ProviderMap) {
	var buf *ProviderEnumerationInfo
	size := uint32(1)
	for {
		tmp := make([]byte, size)
		buf = (*ProviderEnumerationInfo)(unsafe.Pointer(&tmp[0]))
		if err := TdhEnumerateProviders(buf, &size); err != ERROR_INSUFFICIENT_BUFFER {
			break
		}
	}
	m = make(ProviderMap)
	startProvEnumInfo := uintptr(unsafe.Pointer(buf))
	it := uintptr(unsafe.Pointer(&buf.TraceProviderInfoArray[0]))
	for i := uintptr(0); i < uintptr(buf.NumberOfProviders); i++ {
		ptpi := (*TraceProviderInfo)(unsafe.Pointer(it + i*unsafe.Sizeof(buf.TraceProviderInfoArray[0])))
		guidString := ptpi.ProviderGuid.StringU()
		name := FromUTF16AtOffset(startProvEnumInfo, uintptr(ptpi.ProviderNameOffset))
		p := Provider{}
		p.GUID = ptpi.ProviderGuid
		p.Name = name
		m[name] = &p
		m[guidString] = &p
	}
	return
}

func initProviders() {
	providers = EnumerateProviders()
}

// ResolveProvider return a Provider structure given a GUID or
// a provider name as input
func ResolveProvider(s string) (p Provider) {
	providersOnce.Do(initProviders)

	if g, err := ParseGUID(s); err == nil {
		s = g.StringU()
	}

	if prov, ok := providers[s]; ok {
		// search provider by name
		return *prov
	}

	return
}
