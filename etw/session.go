//go:build windows

package etw

// Important documentation "hidden" in the Remarks section:
// It's about almost everything session and provider related.
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2

import (
	"fmt"
	"maps"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Trace Session interface
type Session interface {
	TraceName() string
	Providers() []Provider
	Restart() error
}

// Real time Trace Session
type RealTimeSession struct {
	traceProps    *EventTraceProperties2Wrapper
	configProps   *EventTraceProperties2Wrapper // used only for config that survives Stop/Start
	sessionHandle syscall.Handle
	traceName     string

	mu               sync.Mutex        // Protects session state during Start/Stop/Enable/Disable
	addedProviders   map[GUID]Provider // Providers configured before Start()
	enabledProviders map[GUID]Provider // Providers active on a running session
}

func (p *RealTimeSession) IsNtKernelSession() bool {
	return p.traceName == NtKernelLogger || (p.configProps.Wnode.Guid == *SystemTraceControlGuid)
}

func (p *RealTimeSession) IsSystemSession() bool {
	return (p.configProps.LogFileMode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0
}

// NewRealTimeSession creates a new ETW trace session to receive events in real time.
//
// This is the standard session type for providers in both user-mode applications
// and kernel-mode drivers. By default, it uses non-paged memory for its buffers,
// which offers high performance but consumes a more limited system resource.
// For tracing user-mode providers where the absolute lowest latency is not
// critical, or to conserve non-paged memory, consider using [NewPagedRealTimeSession].
//
// # Best Practices for Session Naming and Lifecycle
//
// As per Microsoft's documentation for the `StartTrace` API, ETW sessions are a
// limited system resource (typically 64 sessions per system). It is crucial to:
//   - Use a descriptive and unique name for your session so its ownership and
//     purpose can be easily identified.
//   - Ensure your application calls `Stop()` to clean up the session when it is
//     no longer needed. If an application terminates unexpectedly, the session
//     may be left running.
//
// You can check currently active sessions with the command: `logman query -ets`
func NewRealTimeSession(name string) (s *RealTimeSession) {
	s = &RealTimeSession{}
	s.configProps = NewRealTimeEventTraceProperties()
	s.traceName = name
	s.addedProviders = make(map[GUID]Provider)
	s.enabledProviders = make(map[GUID]Provider)
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
	s.configProps.LogFileMode |= EVENT_TRACE_USE_PAGED_MEMORY
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
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2
//
// Some MOF are not documented on the microsoft site, for example: Process_V4_TypeGroup1 etc..
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364083(v=vs.85).aspx
func NewKernelRealTimeSession(flags ...KernelNtFlag) (p *RealTimeSession) {
	p = NewRealTimeSession(NtKernelLogger)
	// guid must be set for Kernel Session
	p.configProps.Wnode.Guid = *SystemTraceControlGuid
	for _, flag := range flags {
		p.configProps.EnableFlags |= uint32(flag)
	}
	return
}

// NewSystemTraceSession creates a session for the modern SystemTraceProvider.
// This the modern way to capture kernel events, offer more flexibility.
//
// IMPORTANT: This feature is only available on Windows 11 and later.
//
// This function creates a session that can consume events from the new "System
// Providers" in conjuction with the normal providers.
// This model replaces the monolithic "NT Kernel Logger" with
// individual providers for different kernel components (e.g., processes, memory, I/O).
//
// # System Logger Restrictions
//
// Because system loggers receive special kernel events, they are subject to
// additional restrictions:
//   - There can be no more than 8 system loggers active on the same system.
//   - System loggers cannot be created within a Windows Server container.
//   - System loggers cannot use paged memory (the EVENT_TRACE_USE_PAGED_MEMORY flag).
//
// For a full list of system providers and their keywords, see:
// https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
//
// For more background information, see:
// https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
//
// Example - Capturing process and thread start/stop events:
//
//	s, err := etw.NewSystemTraceSession("MySystemSession")
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
func NewSystemTraceSession(name string) (s *RealTimeSession) {
	s = NewRealTimeSession(name)
	s.configProps.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE
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
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2
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
	s.configProps.Wnode.ClientContext = uint32(c)

	seslog.Debug().Uint32("ClientContext", s.configProps.Wnode.ClientContext).
		Str("ClockType", ClockType(s.configProps.Wnode.ClientContext).String()).
		Msg("Session configured with clock type")

	return true
}

// SetGuid sets the session's GUID. This is an advanced option with specific use cases.
// The following is from the official Microsoft documentation for the Wnode.Guid field:
//
// For an NT Kernel Logger session, set this member to SystemTraceControlGuid.
//
// If this member is set to SystemTraceControlGuid or GlobalLoggerGuid, the logger will be a system logger.
//
// For a private logger session, set this member to the provider's GUID that you are going to enable for the session.
//
// If you start a session that is not a kernel logger or private logger session, you do not have to specify a session GUID. If you do not specify a GUID, ETW creates one for you. You need to specify a session GUID only if you want to change the default permissions associated with a specific session. For details, see the EventAccessControl function.
//
// You cannot start more than one session with the same session GUID.
//
// Library-specific notes:
//   - For the "NT Kernel Logger" session, this GUID is fixed and automatically set to `etw.SystemTraceControlGuid` when you call `NewKernelRealTimeSession`.
//   - For standard real-time sessions (created with `NewRealTimeSession`), if you do not provide a GUID, ETW will assign one when `Start()` is called. You can retrieve this assigned GUID by calling the `GetGuid()` method after the session starts.
//
// This must be called before `Start()`. Returns false if the session is already started.
//
// Wnode.Guid: https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
func (s *RealTimeSession) SetGuid(guid GUID) bool {
	// If the session is already started, we cannot change the GUID.
	if s.IsStarted() {
		seslog.Error().Str("guid", guid.String()).Msg("Cannot set session GUID after the session has started")
		return false
	}
	s.configProps.Wnode.Guid = guid
	seslog.Debug().Str("guid", guid.String()).Msg("Session GUID configured")
	return true
}

// GetGuid returns the GUID of the session.
//
// For sessions where the GUID is auto-assigned by ETW (the default for non-kernel
// sessions), this method is most useful after `Start()` has been called to retrieve
// the assigned GUID of the session.
//
// Wnode.Guid: https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
func (s *RealTimeSession) GetGuid() GUID {
	return s.configProps.Wnode.Guid
}

// TraceProperties returns a pointer to the underlying properties structure for the session.
// This allows advanced users to fine-tune session parameters like buffer sizes,
// flush timers, and other options before the session is started.
//
// WARNING: This provides direct access to the session's configuration.
// Modifications should be made with care and only before calling Start().
// Changing fundamental properties like LogFileMode or the LoggerNameOffset after
// the session has been initialized may lead to unexpected behavior or errors.
//
// Example of customizing buffer settings:
//
//	s := etw.NewRealTimeSession("MyCustomSession")
//	props := s.TraceProperties()
//	props.BufferSize = 128 // 128 KB
//	props.MinimumBuffers = 16
//	props.MaximumBuffers = 64
//	s.Start()
func (s *RealTimeSession) TraceProperties() *EventTraceProperties2Wrapper {
	return s.configProps
}

// IsStarted returns true if the session is already started
func (s *RealTimeSession) IsStarted() bool {
	return s != nil && s.sessionHandle != 0
}

// Restart stops and then starts the ETW session, re-enabling all previously
// enabled providers. This is useful for recovering a session that was stopped
// externally. It ensures the session is running with the same configuration
// and all providers are active.
func (s *RealTimeSession) Restart() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop the session first. This is idempotent and will clean up any existing state,
	// moving the list of enabled providers into the "added" list for restart.
	// We ignore the error because the session might already be stopped, which is fine.
	_ = s.stop()

	// Start the session again. This will re-enable all the providers that were
	// moved into the "added" list by the stop() call.
	if err := s.start(); err != nil {
		return fmt.Errorf("failed to restart session %q: %w", s.traceName, err)
	}

	seslog.Info().Str("session", s.traceName).Msg("Session restarted successfully")
	return nil
}

// Start setups our session buffers so that providers can write to it
func (s *RealTimeSession) Start() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.start()
}

// start is the internal, non-locking version of Start.
func (s *RealTimeSession) start() (err error) {
	if s.IsStarted() {
		return nil
	}

	var u16TraceName *uint16
	if u16TraceName, err = syscall.UTF16PtrFromString(s.traceName); err != nil {
		return err
	}

	if s.IsNtKernelSession() {
		// Remove EVENT_TRACE_USE_PAGED_MEMORY flag from session properties
		s.configProps.LogFileMode &= ^uint32(EVENT_TRACE_USE_PAGED_MEMORY)
	}

	if s.IsNtKernelSession() && s.configProps.EnableFlags == 0 {
		return fmt.Errorf("cannot start kernel session without any kernel flags enabled")
	}

	// StartTrace
	propsForAPI := s.configProps.Clone()
	traceProps := &propsForAPI.EventTraceProperties2
	if err = StartTrace(&s.sessionHandle, u16TraceName, traceProps); err != nil {
		// we handle the case where the trace already exists
		if err == ERROR_ALREADY_EXISTS {
			// we have to use a copy of properties as ControlTrace modifies
			// the structure and if we don't do that we cannot StartTrace later
			// the contigous memory space is not needed for this operation
			propCopy := *traceProps
			// we close the trace first
			ControlTrace(0, u16TraceName, &propCopy, EVENT_TRACE_CONTROL_STOP)
			err = StartTrace(&s.sessionHandle, u16TraceName, traceProps)
		}
	}

	// On success, store the live properties returned by the API.
	s.traceProps = propsForAPI

	// Now, enable all pre-configured providers.
	// Iterate over a copy of the providers since enableProvider modifies the map.
	providersToEnable := make([]Provider, 0, len(s.addedProviders))
	for _, p := range s.addedProviders {
		providersToEnable = append(providersToEnable, p)
	}

	for _, p := range providersToEnable {
		if err := s.enableProvider(p); err != nil {
			// If enabling a provider fails, stop the session to leave it in a clean state.
			_ = s.stop()
			return fmt.Errorf("failed to enable provider %q during session start: %w", p.Name, err)
		}
	}

	seslog.Info().Str("session", s.traceName).
		Uint64("Handle", uint64(s.sessionHandle)).
		Uint32("BufferSizeKB", s.traceProps.BufferSize).
		Uint32("MinBuffers", s.traceProps.MinimumBuffers).
		Uint32("MaxBuffers", s.traceProps.MaximumBuffers).
		Msg("Session started")

	return err
}

// AddProvider configures a provider to be enabled when the session starts.
// This method allows you to define all required providers before activating the
// session, minimizing the time between session start and event consumption.
//
// This is a configuration step and does not interact with the ETW subsystem.
// The providers are activated only when Start() is called. If a provider with
// the same GUID is added multiple times, the last one overwrites the previous ones.
func (s *RealTimeSession) AddProvider(prov Provider) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.IsStarted() {
		return fmt.Errorf("cannot add provider %q to a running session; use EnableProvider() instead", prov.Name)
	}
	s.addedProviders[prov.GUID] = prov
	return nil
}

// EnableProvider enables the trace session to receive events from a given provider
// using the configuration options specified within the Provider struct.
//
// If the session is not yet running, this method will add the provider and then
// start the session, which enables all other providers that have been added.
// If the session is already running, the provider is enabled immediately.
//
// # Updating Provider Settings
//
// If a provider is already enabled for this session, calling `EnableProvider` again
// with the same provider GUID will update the session's configuration for that
// provider. This is the correct way to change the `Level`, `Keywords`, or `Filters`
// for a provider on a live session.
//
// As per the `EnableTraceEx2` documentation: "Every time EnableTraceEx2 is called,
// the filters for the provider in that session are replaced by the new parameters."
//
// # Performance Note
//
// Filtering events via the provider's Level and Keywords is the most efficient
// method, as it prevents the provider from generating disabled events in the first
// place. Scope filters (e.g., PIDFilter) are also highly efficient.
// Other filter types (e.g., EventIDFilter) are applied by the ETW runtime after
// the event has been generated, which reduces trace volume but not the initial
// CPU overhead of generation.
func (s *RealTimeSession) EnableProvider(prov Provider) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.IsStarted() {
		// Add the provider to the configured list. The map handles duplicates.
		s.addedProviders[prov.GUID] = prov
		// Start the session, which will enable this provider and any others.
		return s.start()
	}

	// If session is already running, enable the provider directly.
	return s.enableProvider(prov)
}

// enableProvider is the internal, non-locking version of EnableProvider.
// It is the single point of truth for enabling a provider via the API
// and updating the session's internal state maps.
func (s *RealTimeSession) enableProvider(prov Provider) (err error) {
	var descriptors []EventFilterDescriptor
	// The data backing the pointers in the descriptors is managed by Go's GC.
	// It will be kept alive on the stack/heap during the synchronous EnableTraceEx2 call.
	var keepAlives []any
	for _, f := range prov.Filters {
		desc, buf := f.build() // cleanup is not needed for these simple filter types
		if desc.Type != EVENT_FILTER_TYPE_NONE {
			descriptors = append(descriptors, desc)
			if buf != nil {
				keepAlives = append(keepAlives, buf)
			}
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

	// On success, update state: add/update the provider in the "enabled" map
	// and ensure it's removed from the "added" map.
	s.enabledProviders[prov.GUID] = prov
	delete(s.addedProviders, prov.GUID)

	// By reaching this point, the C call is done. The `cleanups` slice
	// can now go out of scope, and the GC is free to collect the buffers.
	runtime.KeepAlive(keepAlives)

	return nil
}

// DisableProvider removes a provider from a running session.
// Returns nil if session is not started (no-op).
func (s *RealTimeSession) DisableProvider(prov Provider) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disableProvider(prov)
}

// disableProvider is the internal, non-locking version of DisableProvider.
func (s *RealTimeSession) disableProvider(prov Provider) (err error) {
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
	delete(s.enabledProviders, prov.GUID)

	return
}

// GetRundownEvents forces rundown events now on this session.
// a null provider will force rundown for all manifest providers in the session
//
// NOTE: nt kernel sessions do not support SystemConfig rundown events. Access Denied.
// Just start a nt kernel session and stop it to get SystemConfig rundown events.
func (s *RealTimeSession) GetRundownEvents(guid *GUID) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	s.mu.Lock()
	defer s.mu.Unlock()
	// Return a copy to prevent modification of the internal map.
	providers := make([]Provider, 0, len(s.enabledProviders))
	for _, p := range s.enabledProviders {
		providers = append(providers, p)
	}
	return providers
}

// Stop stops the session. It first attempts to disable all enabled providers
// and then blocks until all buffers are flushed and the session is fully stopped.
func (s *RealTimeSession) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stop()
}

// stop is the internal, non-locking version of Stop.
func (s *RealTimeSession) stop() error {
	if !s.IsStarted() {
		return nil
	}
	seslog.Debug().Msg("Session stopping...")

	// It's best practice to disable providers before stopping the session.
	for _, p := range s.enabledProviders {
		// We can ignore errors here, as we're stopping the session anyway.
		_ = s.disableProvider(p)
	}
	//seslog.Debug().Str("trace", s.traceName).Interface("Props", *s.traceProps).Msg("Properties BEFORE closing")

	// we have to use a copy of properties as ControlTrace modifies
	// the structure and if we don't do that we cannot StartTrace later
	propClone := *s.traceProps.Clone()
	// - The contigous memory space is not needed for this operation (LoggerName in the Props)
	// - For some reason after this call, if this prop is reused in StartTrace, doesn't fail but the handle is invalid.
	// - After this call the props become unusable.
	err := ControlTrace(s.sessionHandle, nil, &propClone.EventTraceProperties2,
		EVENT_TRACE_CONTROL_STOP)

	//seslog.Debug().Str("trace", s.traceName).Interface("closedProps", propClone).Msg("Properties AFTER trace closed")
	// s.traceProps = &propClone          // ! TESTING
	// s.traceProps.LogFileNameOffset = 0 // ! TESTING

	// Always reset the handle after a stop attempt to ensure IsStarted() is accurate.
	s.sessionHandle = 0

	// For potential Restart(), move the list of what was enabled into the "added" list.
	maps.Copy(s.addedProviders, s.enabledProviders)
	clear(s.enabledProviders)

	seslog.Info().Str("session", s.traceName).Msg("Session stopped")
	return err
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
