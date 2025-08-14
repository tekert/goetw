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
	defaultProvider = Provider{EnableLevel: 0xff, MatchAnyKeyword: 0xffffffffffffffff, MatchAllKeyword: 0}

	// Error returned when a provider is not found on the system
	ErrUnkownProvider = fmt.Errorf("unknown provider")
)

// ProviderMap is a map that indexes ETW providers by both their name and GUID string representation.
type ProviderMap map[string]*Provider

// Provider represents an ETW event provider, identified by its name and GUID,
// and includes the necessary options for enabling it in a trace session.
type Provider struct {
	GUID GUID
	Name string

	// The logging level specified. Standard logging levels are:
	// 0 — Log Always; 1 — Critical; 2 — Error; 3 — Warning; 4 — Informational; 5 — Verbose.
	// Custom logging levels can also be defined, but levels 6–15 are reserved.
	// More than one logging level can be captured by ORing respective levels;
	// supplying 255 (0xFF) is the standard method of capturing all supported logging levels.
	// Note that if you set the EnableLevel to LogAlways, it ensures that all error events will always be written.
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
	// The provider typically writes an event if the event's keyword bits match all of the bits
	// set in this value or if the event has no keyword bits set, in addition to meeting the Level
	// and MatchAllKeyword criteria.
	//
	// This value is frequently set to 0.
	//
	// Note that this mask is not used if Keywords(Any) is set to zero.
	MatchAllKeyword uint64

	// Filters provides a mechanism for more granular, kernel-level filtering,
	// supporting types like EventIDFilter, PIDFilter, etc.
	//
	// Performance Note: There is a significant performance difference between filtering
	// via Level/Keywords and filtering via this `Filters` slice.
	//
	// - Level/Keyword Filtering (Highest Performance): This is "provider-side" filtering.
	//   The provider code itself checks if a specific level or keyword is enabled *before*
	//   it generates an event. If the event is disabled, the `EventWrite` call is skipped
	//   entirely, resulting in near-zero CPU and memory overhead for filtered-out events.
	//
	// - `Filters` Slice (Medium Performance): This is "runtime-side" filtering. The provider
	//   generates the event and sends it to the ETW runtime. The runtime then checks these
	//   filters (e.g., EventID, PID) before forwarding the event to the session buffer.
	//   This means the overhead of creating and serializing the event has already been
	//   incurred. This method is effective for reducing trace data volume but does not
	//   reduce the initial CPU overhead of event generation.
	//
	// For more info read:
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters EnableFilterDesc
	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor EVENT_FILTER_TYPE_EVENT_ID
	Filters []ProviderFilter
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
//  > logman query providers "provider-name"
//  > wevtutil gp "provider-name"
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
		name := UTF16AtOffsetToString(startProvEnumInfo, uintptr(ptpi.ProviderNameOffset))
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
