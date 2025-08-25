//go:build windows

package etw

// Important documentation "hidden" in the Remarks section:
// It's about almost everything session and provider related.
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Trace Session interface
type Session interface {
	TraceName() string
	Providers() []Provider
	IsKernelSession() bool
}

// Real time Trace Session
type RealTimeSession struct {
	traceProps    *EventTraceProperties2Wrapper
	sessionHandle syscall.Handle
	traceName     string

	enabledProviders []Provider
}

func (p *RealTimeSession) IsKernelSession() bool {
	return p.traceName == NtKernelLogger ||
		(p.traceProps.LogFileMode&EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0
}

// NewRealTimeSession creates a new ETW trace session to receive events in real time.
//
// This is the standard session type for providers in both user-mode applications
// and kernel-mode drivers. By default, it uses non-paged memory for its buffers,
// which offers high performance but consumes a more limited system resource.
// For tracing user-mode providers where the absolute lowest latency is not
// critical, or to conserve non-paged memory, consider using [NewPagedRealTimeSession].
// You can check current created sessions with
//
//	> logman query -ets
func NewRealTimeSession(name string) (s *RealTimeSession) {
	s = &RealTimeSession{}
	s.traceProps = NewRealTimeEventTraceProperties()
	s.traceName = name
	s.enabledProviders = make([]Provider, 0)
	return
}

// NewPagedRealTimeSession creates a new ETW trace session that receives events in
// real time and uses paged memory for its buffers.
//
// This session type is configured with the EVENT_TRACE_USE_PAGED_MEMORY flag in the
// LogFileMode field of the session properties. Using paged memory is less
// resource-intensive than the default non-paged memory and is recommended for
// tracing user-mode providers that do not generate an extremely high volume of events.
//
// IMPORTANT: Kernel-mode providers and system loggers cannot log events to sessions
// that use paged memory. Attempting to enable a kernel provider on such a session
// will fail. This session type is strictly for user-mode providers.
func NewPagedRealTimeSession(name string) (s *RealTimeSession) {
	s = NewRealTimeSession(name)
	s.traceProps.LogFileMode |= EVENT_TRACE_USE_PAGED_MEMORY
	return
}

// TODO: remove "Using the library" and use the new interface in v0.8
// NewKernelRealTimeSession creates a special ETW session for the "NT Kernel Logger".
// This is a unique, system-wide session that is the only way to capture events
// directly from the Windows kernel (use this if below win 11).
//
// Only one NT Kernel Logger session can be active at a time. If another process
// is already running a kernel session, starting a new one with this library will
// stop the existing one first when calling Start().
//
// # Enabling Kernel Events
//
// Unlike regular ETW sessions, nt kernel event groups are enabled at session creation
// by passing EnableFlags to this function. Each flag corresponds to a category of
// kernel events, such as process creations, disk I/O, or network activity.
//
// # Discovering Kernel Event Groups
//
// The available kernel event groups and their corresponding flags can be discovered
// in several ways:
//
//   - Using the library: The [etw.KernelProviders] slice contains a list of known kernel event groups.
//     Use [GetKernelProviderFlags] to convert provider names into flags.
//
//     Example (capture File I/O and Disk I/O events):
//
//     flags := etw.GetKernelProviderFlags("FileIo", "DiskIo")
//     kernelSession, err := etw.NewKernelRealTimeSession(flags)
//
//     To list all available kernel provider names:
//
//     for _, p := range etw.KernelProviders {
//     fmt.Println(p.Name)
//     }
//
//   - Using logman: The `logman` command-line tool can query the "Windows Kernel Trace"
//     provider to show available keywords (flags):
//
//     logman query providers "Windows Kernel Trace"
//
//   - Using wevtutil: The `wevtutil` tool can also list providers, though it is less
//     commonly used for kernel event groups:
//
//     wevtutil gp "Windows Kernel Trace"
//
// # Event Format
//
// NOTE: The events from the NT Kernel Logger are legacy MOF-based events. They do not
// have a modern XML manifest.
//
// For more details on the EnableFlags, see the #microsoft-docs:
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
//
// Some MOF are not documented on the microsoft site, for example: Process_V4_TypeGroup1 etc..
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx
// TODO: use KernelFlag as type for flags in v0.8
func NewKernelRealTimeSession(flags ...uint32) (p *RealTimeSession) {
	p = NewRealTimeSession(NtKernelLogger)
	// guid must be set for Kernel Session
	p.traceProps.Wnode.Guid = *systemTraceControlGuid
	for _, flag := range flags {
		p.traceProps.EnableFlags |= flag
	}
	return
}

// NewSystemTraceProviderSession creates a session for the modern SystemTraceProvider.
// This the modern way to capture kernel events, offer more flexibility.
//
// IMPORTANT: This feature is only available on Windows 11 and later.
//
// This function creates a session that can consume events from the new "System
// Providers" model. This model replaces the monolithic "NT Kernel Logger" with
// individual providers for different kernel components (e.g., processes, memory, I/O).
//
// Unlike the legacy kernel session, which is configured with bitmask flags at creation,
// this session is started first and then individual system providers are enabled
// using `EnableProvider`, just like any other manifest-based provider. This allows
// for more granular and flexible kernel tracing.
//
// For a full list of system providers and their keywords, see:
// https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
//
// For more background information, see:
// https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
//
// Example - Capturing process and thread start/stop events:
//
//	s, err := etw.NewSystemTraceProviderSession("MySystemSession")
//	if err != nil {
//		// handle error
//	}
//	defer s.Stop()
//
//	processProvider := etw.Provider{
//		GUID:            etw.SystemProcessProviderGuid,
//		MatchAnyKeyword: etw.SYSTEM_PROCESS_KW_GENERAL | etw.SYSTEM_PROCESS_KW_THREAD,
//	}
//
//	if err := s.EnableProvider(processProvider); err != nil {
//		// handle error
//	}
//
// You can discover the names of the available system providers using 'logman':
//
//	logman query providers | findstr -i system
func NewSystemTraceProviderSession(name string) (s *RealTimeSession) {
	s = NewRealTimeSession(name)
	s.traceProps.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE
	return
}

// NewRealTimeEventTraceProperties creates and initializes an EventTraceProperties2Wrapper
// for a real-time ETW session.
//
// This function sets up the necessary fields in the underlying EVENT_TRACE_PROPERTIES_V2
// structure required by the Windows API for [StartTrace] a session. It configures the
// session for real-time event consumption without logging to a file.
//
// As per the Windows API documentation for StartTrace, the session name is passed as a
// separate parameter to the API call. StartTrace then copies that name into the properties
// structure using the provided LoggerNameOffset. Therefore, this function only needs to
// calculate and set the offset, not write the name string itself.
func NewRealTimeEventTraceProperties() *EventTraceProperties2Wrapper {
	traceProps, size := NewEventTracePropertiesV2()

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2
	// https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
	// Necessary fields for SessionProperties struct
	traceProps.Wnode.BufferSize = size // this is optimized by ETWframework
	traceProps.Wnode.Guid = GUID{}     // Will be set by etw
	// Only used if PROCESS_TRACE_MODE_RAW_TIMESTAMP is set in the Consumer side
	traceProps.Wnode.ClientContext = 1 // QPC
	seslog.Debug().Uint32("ClientContext", traceProps.Wnode.ClientContext).
		Str("ClockType", ClockType(traceProps.Wnode.ClientContext).String()).
		Msg("Session configured with clock type")
	// WNODE_FLAG_ALL_DATA Flag is part of the legacy WMI query interface,
	// its is for querying data not for starting a trace session.
	// WNODE_FLAG_VERSIONED_PROPERTIES means use EventTraceProperties2
	// These are used so that StartTrace know what to start.
	traceProps.Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES
	traceProps.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
	traceProps.LogFileNameOffset = 0
	//* ETW event can be up to 64KB size so if the buffer size is not at least
	// big enough to contain such an event, the event will be lost
	// source: https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
	traceProps.BufferSize = 64

	// StartTrace will copy the string for us.
	traceProps.LoggerNameOffset = traceProps.GetTraceNameOffset()

	return traceProps
}

// SetClockResolution sets the clock resolution for the session.
// Set this before calling Start() to ensure the session uses the desired clock type.
// returns true if the clock resolution was set successfully.
func (s *RealTimeSession) SetClockResolution(c ClockType) bool {
	// If the session is already started, we cannot change the clock resolution.
	if s.IsStarted() {
		return false
	}
	if c < 1 || c > 2 {
		seslog.Error().Uint32("ClockType", uint32(c)).
			Msg("Invalid clock type, must be between QPC, SystemTime and CpuCycle")
		return false
	}
	s.traceProps.Wnode.ClientContext = uint32(c)

	seslog.Debug().Uint32("ClientContext", s.traceProps.Wnode.ClientContext).
		Str("ClockType", ClockType(s.traceProps.Wnode.ClientContext).String()).
		Msg("Session configured with clock type")

	return true
}

// IsStarted returns true if the session is already started
func (s *RealTimeSession) IsStarted() bool {
	return s != nil && s.sessionHandle != 0
}

// Start setups our session buffers so that providers can write to it
func (s *RealTimeSession) Start() (err error) {
	if s.IsStarted() {
		return
	}

	var u16TraceName *uint16
	if u16TraceName, err = syscall.UTF16PtrFromString(s.traceName); err != nil {
		return err
	}

	if s.IsKernelSession() {
		// Remove EVENT_TRACE_USE_PAGED_MEMORY flag from session properties
		s.traceProps.LogFileMode &= ^uint32(EVENT_TRACE_USE_PAGED_MEMORY)
	}

	traceProps := &s.traceProps.EventTraceProperties2
	if err = StartTrace(&s.sessionHandle, u16TraceName, traceProps); err != nil {
		// we handle the case where the trace already exists
		if err == ERROR_ALREADY_EXISTS {
			// we have to use a copy of properties as ControlTrace modifies
			// the structure and if we don't do that we cannot StartTrace later
			// the contigous memory space is not needed for this operation
			propCopy := *traceProps
			// we close the trace first
			ControlTrace(0, u16TraceName, &propCopy, EVENT_TRACE_CONTROL_STOP)
			return StartTrace(&s.sessionHandle, u16TraceName, traceProps)
		}
		return
	}

	return
}

// EnableProvider enables the trace session to receive events from a given provider
// using the configuration options specified within the Provider struct.
//
// Performance Note: Filtering events via the provider's Level and Keywords is the
// most efficient method, as it prevents the provider from generating disabled events
// in the first place. Other filter types (e.g., EventIDFilter) are applied by the
// ETW runtime after the event has been generated (depends on provider), which reduces
// trace volume but not the initial CPU overhead of generation.
func (s *RealTimeSession) EnableProvider(prov Provider) (err error) {
	// If the trace is not started yet we have to start it
	// otherwise we cannot enable provider
	if !s.IsStarted() {
		if err = s.Start(); err != nil {
			return
		}
	}

	var descriptors []EventFilterDescriptor
	// The data backing the pointers in the descriptors is managed by Go's GC.
	// It will be kept alive on the stack/heap during the synchronous EnableTraceEx2 call.
	for _, f := range prov.Filters {
		desc, _ := f.build() // cleanup is not needed for these simple filter types
		if desc.Type != EVENT_FILTER_TYPE_NONE {
			descriptors = append(descriptors, desc)
		}
	}

	params := EnableTraceParameters{}

	params.Version = 2
	params.EnableProperty = prov.EnableProperties

	if len(descriptors) > 0 {
		params.EnableFilterDesc = (*EventFilterDescriptor)(unsafe.Pointer(&descriptors[0]))
		params.FilterDescCount = uint32(len(descriptors))
	}

	if err = EnableTraceEx2(
		s.sessionHandle,
		&prov.GUID,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		prov.EnableLevel,
		prov.MatchAnyKeyword,
		prov.MatchAllKeyword,
		0,
		&params,
	); err != nil {
		return fmt.Errorf("EnableTraceEx2 failed for provider %s (%s): %w", prov.Name, prov.GUID.String(), err)
	}

	s.enabledProviders = append(s.enabledProviders, prov)

	return
}

// DisableProvider removes a provider from the session.
// Returns nil if session is not started (no-op).
func (s *RealTimeSession) DisableProvider(prov Provider) (err error) {
	if !s.IsStarted() {
		// Can't disable a provider on a session that isn't running.
		return nil
	}

	if err = EnableTraceEx2(
		s.sessionHandle,
		&prov.GUID,
		EVENT_CONTROL_CODE_DISABLE_PROVIDER,
		0, // Level, Keywords, etc. are ignored for disable.
		0,
		0,
		0,
		nil,
	); err != nil {
		return
	}

	// Remove from the active provider list.
	newEnabled := s.enabledProviders[:0]
	for _, p := range s.enabledProviders {
		if !p.GUID.Equals(&prov.GUID) {
			newEnabled = append(newEnabled, p)
		}
	}
	s.enabledProviders = newEnabled

	return
}

// GetRundownEvents forces rundown events now on this session.
// a null provider will force rundown for all manifest providers in the session
//
// NOTE: nt kernel sessions do not support SystemConfig rundown events. Access Denied.
// Just start a nt kernel session and stop it to get SystemConfig rundown events.
func (s *RealTimeSession) GetRundownEvents(guid *GUID) (err error) {
	if !s.IsStarted() {
		return fmt.Errorf("session not started")
	}
	if guid != nil {
		return EnableTraceEx2(
			s.sessionHandle,
			guid,
			EVENT_CONTROL_CODE_CAPTURE_STATE,
			0, 0, 0, 0, nil)
	} else {
		if len(s.enabledProviders) == 0 {
			return fmt.Errorf("no providers enabled in session %s", s.traceName)
		}
		for _, p := range s.enabledProviders {
			if err = EnableTraceEx2(
				s.sessionHandle,
				&p.GUID,
				EVENT_CONTROL_CODE_CAPTURE_STATE,
				0, 0, 0, 0, nil); err != nil {
				return
			}
		}
	}

	return nil
}

// TraceName returns the name of the trace that was used to create the session
func (s *RealTimeSession) TraceName() string {
	return s.traceName
}

// Providers returns a slice of all currently enabled providers for this session.
func (s *RealTimeSession) Providers() []Provider {
	// Return a copy to prevent modification of the internal slice.
	providers := make([]Provider, len(s.enabledProviders))
	copy(providers, s.enabledProviders)
	return providers
}

// Stop stops the session. It first attempts to disable all enabled providers
// and then blocks until all buffers are flushed and the session is fully stopped.
func (s *RealTimeSession) Stop() error {
	// It's best practice to disable providers before stopping the session.
	for _, p := range s.enabledProviders {
		// We can ignore errors here, as we're stopping the session anyway.
		_ = s.DisableProvider(p)
	}

	s.enabledProviders = nil // Clear the slice

	return ControlTrace(s.sessionHandle, nil, &s.traceProps.EventTraceProperties2,
		EVENT_TRACE_CONTROL_STOP)
}

// Gets a copy of the current EventTraceProperties file used for this session
func (s *RealTimeSession) GetTracePropertyCopy() *EventTraceProperties2Wrapper {
	return s.traceProps.Clone()
}

// Queries the current trace session to get updated trace properties and stats.
// This is the "controller's view" of the session, using the session handle
// obtained when Start() was called. It is the most direct way to query a session
// that this process has created and is actively managing.
//
// The returned pointer refers to the session's internal properties struct and should
// not be modified.
func (s *RealTimeSession) QueryTrace() (prop *EventTraceProperties2Wrapper, err error) {
	// If you are reusing a EVENT_TRACE_PROPERTIES structure
	// (i.e. using a structure that you previously passed to StartTrace or ControlTrace),
	// be sure to set the LogFileNameOffset member to 0 unless you are changing the log file name.
	s.traceProps.LogFileNameOffset = 0
	if err := ControlTrace(s.sessionHandle, nil, &s.traceProps.EventTraceProperties2,
		EVENT_TRACE_CONTROL_QUERY); err != nil {
		return nil, err
	}
	return s.traceProps, nil
}

// Flushes the session's active buffers.
// This will block until all buffers are flushed and the session is fully stopped
// If the session is not started, it returns an error.
func (s *RealTimeSession) Flush() error {
	if s.sessionHandle == 0 {
		return fmt.Errorf("session not started")
	}

	return ControlTrace(s.sessionHandle, nil, &s.traceProps.EventTraceProperties2,
		EVENT_TRACE_CONTROL_FLUSH)
}

// NewQueryTraceProperties creates a properties structure used to query an existing
// ETW session by its name. The `traceName` parameter specifies the name of the
// running session to query, which can belong to any session on the system.
//
// This function initializes an [EventTraceProperties2Wrapper] with the minimum
// fields required by the ControlTrace API for an EVENT_TRACE_CONTROL_QUERY
// operation. The wrapper handles the memory layout of the underlying
// Windows struct, which requires a single contiguous buffer for both the
// properties and the session name string, avoiding manual pointer arithmetic.
func NewQueryTraceProperties(traceName string) *EventTraceProperties2Wrapper {
	traceProps, size := NewEventTracePropertiesV2()
	// Set only required fields for QUERY
	traceProps.Wnode.BufferSize = size
	traceProps.Wnode.Guid = GUID{}
	traceProps.SetTraceName(traceName)
	traceProps.LoggerNameOffset = traceProps.GetTraceNameOffset()
	traceProps.LogFileNameOffset = 0

	if traceProps.Wnode.BufferSize < traceProps.LoggerNameOffset+uint32(len(traceProps.LoggerName)*2) {
		panic("Not enough buffer space for LoggerName")
	}
	if traceProps.Wnode.BufferSize < traceProps.LogFileNameOffset+uint32(len(traceProps.LogFileName)*2) {
		panic("Not enough buffer space for LogFileName")
	}

	return traceProps
}

// QueryTrace queries the properties and status of a running trace session by name.
//
// This is a low-level function that wraps the [ControlTrace] API with the
// `EVENT_TRACE_CONTROL_QUERY` command. This allows querying any running session,
// even those started by other processes, using its instance name (loggerName or traceName).
// This implementation does not support querying sessions via a log file name (logFileName).
//
// The queryProp parameter serves as both input and output. It must be a
// non-nil pointer to an EventTraceProperties2Wrapper struct, typically created
// with [NewQueryTraceProperties]. On input, the ControlTrace API uses the
// session name within this struct to identify the session to query. On success,
// the API populates the same struct with the current properties and statistics
// of the session.
//
// This function is used internally by [ConsumerTrace.QueryTrace()].
func QueryTrace(queryProp *EventTraceProperties2Wrapper) (err error) {
	if queryProp == nil {
		return fmt.Errorf("data must be non nil")
	}
	instanceName := queryProp.GetTraceName()

	// If you are reusing a EVENT_TRACE_PROPERTIES structure
	// (i.e. using a structure that you previously passed to StartTrace or ControlTrace),
	// be sure to set the LogFileNameOffset member to 0 unless you are changing the log file name.
	queryProp.LogFileNameOffset = 0

	// There is no need to have the loggerName in queryProp.LoggerName
	// ControlTrace will set it for us on return. (instaceName -> quertProp.LoggerNameOffset)
	if err := ControlTrace(
		syscall.Handle(0),
		instanceName,
		&queryProp.EventTraceProperties2,
		EVENT_TRACE_CONTROL_QUERY); err != nil {
		return fmt.Errorf("ControlTrace query failed: %w", err)
	}
	return nil
}

// StopSession stops a trace session by its name. This is useful for cleaning up
// sessions that might have been left running from previous processes.
func StopSession(name string) error {
	prop := NewQueryTraceProperties(name)
	// The session handle is not used when stopping a trace by name.
	const nullTraceHandle = 0
	u16Name, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	return ControlTrace(nullTraceHandle, u16Name, &prop.EventTraceProperties2, EVENT_TRACE_CONTROL_STOP)
}

// (used for internal debuggging)
func newQueryProperties2(tname string) *EventTraceProperties2Wrapper {
	traceProps, size := NewEventTracePropertiesV2()
	// Set only required fields for QUERY
	traceProps.Wnode.BufferSize = size
	traceProps.Wnode.Guid = GUID{}

	traceProps.SetTraceName(tname)
	traceProps.LoggerNameOffset = traceProps.GetTraceNameOffset()
	traceProps.LogFileNameOffset = 0

	return traceProps
}

// Gets the properties of a trace session pointed by props
// Use a valid properties struct created with [NewQueryTraceProperties]
// The trace name is taken from props.LoggerNameOffset.
// (used for internal debuggging)
func queryTrace2(traceProps *EventTraceProperties2Wrapper) (err error) {
	// get loggerName from the props.LoggerNameOffset
	loggerName := traceProps.GetTraceName()

	// There is no need to have the loggerName in the properties
	// but we use for save us another parameter
	if err := ControlTrace(
		syscall.Handle(0),
		loggerName,
		&traceProps.EventTraceProperties2,
		EVENT_TRACE_CONTROL_QUERY); err != nil {
		return fmt.Errorf("ControlTrace query failed: %w", err)
	}
	return nil
}
