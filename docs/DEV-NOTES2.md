# Event Tracing for Windows (ETW) - Comprehensive Guide

NOTE, this is the only doc where i asked IA for help, i was tired of formatting text from my raw notes.  
I also asked it to use my internal test examples and expose them.   
Reviewed it and it's faily good written, it's based on my notes so no random ia crap.  

## Table of Contents
- Overview
- ETW Architecture
- Sessions
- Providers
- Trace Controllers
- Consumers
- AutoLogger Sessions
- Filtering and Performance
- Code Examples
- Best Practices
- Troubleshooting

## Overview

Event Tracing for Windows (ETW) is a high-performance, kernel-level tracing facility built into Windows that provides an infrastructure for events raised by both user-mode applications and kernel-mode components. ETW offers a unified API that combines the processes of logging and writing trace events to consumers in a single, convenient mechanism.

### Historical Context

Before Windows 2000, only basic text-based tracing mechanisms were available (DbgPrint() and DebugPrint() APIs). The Windows tracing mechanism evolved over time, and today four different tracing mechanisms are available. ETW and Event Log API sets were merged into the Unified Event Logging API set in Windows Vista, providing users and developers with a unified mechanism for raising events.

## ETW Architecture

ETW consists of four main components that work together to provide comprehensive event tracing capabilities:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐     ┌─────────────┐
│   Provider  │───▶│   Session  │───▶│ Controller  │───▶│  Consumer   │
│             │    │             │    │             │     │             │
│ Generates   │    │ Buffers &   │    │ Manages     │     │ Processes   │
│ Events      │    │ Collects    │    │ Sessions    │     │ Events      │
└─────────────┘    └─────────────┘    └─────────────┘     └─────────────┘
```

### Component Roles

- **Provider**: The logical entity that raises events and writes them to a session
- **Session**: Provides an environment that accepts and buffers events from providers
- **Controller**: Manages the lifecycle of sessions and enables/disables providers
- **Consumer**: Receives and processes events from sessions in real-time or from log files

## Sessions

A **Session** is a buffer allocated by you using ETW syscalls that can be configured as paged memory, non-paged memory, real-time, circular buffer, or written to a file. There are many session properties you can configure, allocated using `StartTrace`. You provide a name or use another existing trace to form a **Trace Session**.

### Session Types

#### Real-time Sessions
Real-time sessions process events as they arrive in the session buffer:

```go
// Create a real-time session
s := etw.NewRealTimeSession("TestingGoEtw")
defer s.Stop()

// For non-kernel providers, you can use paged memory for better resource utilization
s := etw.NewPagedRealTimeSession("TestingGoEtw") 
defer s.Stop()
```

#### Kernel Sessions
Special system sessions for kernel/system providers. Only one kernel session can run at a time:

```go
// Traditional kernel session using legacy flags
kernelSession := etw.NewKernelRealTimeSession(
    etw.GetKernelProviderFlags("FileIo", "FileIoInit"))
defer kernelSession.Stop()

// Windows 11+ System Trace Provider sessions (recommended)
systemSession := etw.NewSystemTraceProviderSession("MySystemTrace")
defer systemSession.Stop()
```

#### AutoLogger Sessions
AutoLogger sessions start automatically when the system boots, before user logon:

```go
// Create an AutoLogger configuration
autoLogger := &etw.AutoLogger{
    Name:        "MyAutoLogger",
    GuidS:       "{12345678-1234-1234-1234-123456789012}",
    LogFileMode: etw.EVENT_TRACE_FILE_MODE_CIRCULAR,
    BufferSize:  64,  // KB
    ClockType:   etw.EVENT_TRACE_CLOCK_SYSTEMTIME,
    MaxFileSize: 100, // MB
}

// Create the AutoLogger registry entries
if err := autoLogger.Create(); err != nil {
    panic(err)
}

// Enable a provider for the AutoLogger
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File")
if err := autoLogger.EnableProvider(provider); err != nil {
    panic(err)
}
```

### Session Properties

Key session properties include:

- **BufferSize**: Size of each buffer in KB (minimum 64KB for ETW events up to 64KB)
- **LogFileMode**: Determines session behavior (real-time, file, circular, etc.)
- **ClockType**: Timestamp format (QPC, SystemTime, etc.)
- **MaxFileSize**: Maximum log file size in MB
- **EnableFlags**: For kernel sessions, specifies which kernel providers to enable

## Providers

A **Provider** is the logical entity that raises events and writes them to a Session. Providers must register with ETW before they can send events.

### Provider Configuration

Providers are configured using a structured format that specifies filtering options:

```
(Name|GUID)[:Level[:EventIDs[:MatchAnyKeyword[:MatchAllKeyword]]]]
```

#### Configuration Parameters

1. **Level** (Default: 0xFF - All levels)
   - Standard levels: 0 (Always), 1 (Critical), 2 (Error), 3 (Warning), 4 (Informational), 5 (Verbose)
   - Custom levels 6-15 are reserved
   - 0xFF captures all supported logging levels

2. **EventIDs** (Default: All events)
   - Comma-separated list of specific event IDs to include
   - Provides fast kernel-level filtering before event generation

3. **MatchAnyKeyword** (Default: 0xFFFFFFFFFFFFFFFF - All keywords)
   - 64-bit bitmask for keyword-based filtering
   - Event is written if any of its keyword bits match any bits in this mask

4. **MatchAllKeyword** (Default: 0 - No restriction)
   - 64-bit bitmask for additional keyword filtering
   - Event is written only if all bits in this mask exist in the event's keywords

### Provider Examples

```go
// Basic provider (all events, all levels)
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File")

// Provider with specific level (Informational and above)
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File:4")

// Provider with specific event IDs
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File:0xff:12,13,14")

// Provider with keywords (KERNEL_FILE_KEYWORD_CREATE = 0x80)
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File:0xff::0x80")

// Complete configuration
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File:0xff:12,13,14:0x80:0x00")
```

### Provider Types

#### User-mode Providers
Standard application providers that can be enabled in multiple sessions:

```go
// Enable a user-mode provider
provider := etw.MustParseProvider("Microsoft-Windows-WinINet")
if err := session.EnableProvider(provider); err != nil {
    panic(err)
}
```

#### Kernel Providers (Legacy)
Traditional MOF-based kernel providers using enable flags:

```go
// Enable kernel providers using flags
kernelSession := etw.NewKernelRealTimeSession(
    etw.EVENT_TRACE_FLAG_PROCESS | etw.EVENT_TRACE_FLAG_THREAD,
    etw.EVENT_TRACE_FLAG_DISK_IO | etw.EVENT_TRACE_FLAG_DISK_FILE_IO,
    etw.EVENT_TRACE_FLAG_NETWORK_TCPIP,
)
```

#### System Providers (Windows 11+)
Modern manifest-based system providers:

```go
// New system trace provider approach
systemSession := etw.NewSystemTraceProviderSession("MySystemTrace")
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-Process:0xff::0x10")
if err := systemSession.EnableProvider(provider); err != nil {
    panic(err)
}
```

### Finding Providers and Keywords

Use these commands to discover available providers and their configurations:

```cmd
:: List all providers
logman query providers

:: Get provider details
logman query providers "Microsoft-Windows-Kernel-File"
wevtutil gp "Microsoft-Windows-Kernel-File"

:: Query running sessions
logman query -ets
```

## Trace Controllers

The **Trace Controller** is the component responsible for managing trace sessions. It performs these key tasks:

- Defines the size and location of ETW log files
- Starts and stops ETW sessions
- Enables providers so they can log events to sessions
- Manages buffer pool sizes
- Obtains execution statistics for sessions

### Controller Operations

```go
// Start a session with providers
session := etw.NewRealTimeSession("MyTrace")
defer session.Stop()

// Enable multiple providers
providers := []etw.Provider{
    etw.MustParseProvider("Microsoft-Windows-Kernel-File:0xff:12,13"),
    etw.MustParseProvider("Microsoft-Windows-Kernel-Process:4"),
}

for _, provider := range providers {
    if err := session.EnableProvider(provider); err != nil {
        log.Printf("Failed to enable provider %s: %v", provider.Name, err)
    }
}

// Query session statistics
if props, err := session.QueryTrace(); err == nil {
    fmt.Printf("Buffers used: %d\n", props.NumberOfBuffers)
    fmt.Printf("Events lost: %d\n", props.EventsLost)
    fmt.Printf("Buffers lost: %d\n", props.LogBuffersLost)
}
```

## Consumers

A **Consumer** is an application that reads events from active trace sessions in real-time or from ETL log files. Consumers can select multiple sessions as event sources and receive events in chronological order.

### Consumer Architecture

The `Consumer` in this library provides a sophisticated event processing pipeline:

```
EventRecord → EventRecordCallback → EventRecordHelperCallback → 
EventPreparedCallback → EventCallback → Events Channel
```

### Consumer Setup

```go
// Create a consumer with context for graceful shutdown
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

consumer := etw.NewConsumer(ctx)
defer consumer.Stop()

// Configure session sources
consumer.FromSessions(session) // From active sessions
// or
consumer.FromTraceNames("MyTrace") // From session names

// Set up event processing
go func() {
    consumer.ProcessEvents(func(e *etw.Event) {
        fmt.Printf("Event: %s from %s\n", e.EventHeader.EventDescriptor.ID, e.Provider.Name)
        // Process event...
    })
}()

// Start consuming events
if err := consumer.Start(); err != nil {
    panic(err)
}
```

### Custom Event Callbacks

You can customize event processing at different stages:

```go
// Filter at the raw EventRecord level (highest performance)
consumer.EventRecordCallback = func(er *etw.EventRecord) bool {
    // Return false to skip further processing
    return er.EventHeader.EventDescriptor.ID == 12
}

// Process events after parsing but before property extraction
consumer.EventRecordHelperCallback = func(erh *etw.EventRecordHelper) error {
    if erh.GetEventID() == 13 {
        erh.Flags.Skip = true // Skip this event
    }
    return nil
}

// Custom event processing
consumer.EventCallback = func(event *etw.Event) error {
    defer event.Release() // Important: release event memory
    
    // Process event properties
    for _, prop := range event.Properties {
        fmt.Printf("%s: %v\n", prop.Name, prop.Value)
    }
    return nil
}
```

### Consumer Statistics

Track consumer performance and event loss:

```go
// Get consumer statistics
fmt.Printf("Lost events: %d\n", consumer.LostEvents.Load())
fmt.Printf("Skipped events: %d\n", consumer.Skipped.Load())

// Get per-trace statistics
if trace, ok := consumer.GetTrace("MyTrace"); ok {
    fmt.Printf("Trace events processed: %d\n", trace.EventsProcessed.Load())
    fmt.Printf("Trace lost events: %d\n", trace.RTLostEvents.Load())
}
```

## AutoLogger Sessions

AutoLogger sessions enable ETW tracing to start automatically during system boot, before user logon. This is crucial for capturing early boot events and system startup issues.

### AutoLogger Configuration

AutoLogger sessions are configured through registry entries that the system reads during boot:

```go
// Define AutoLogger configuration
autoLogger := &etw.AutoLogger{
    Name:        "MyBootTrace",
    GuidS:       "{12345678-1234-1234-1234-123456789012}",
    LogFileMode: etw.EVENT_TRACE_FILE_MODE_CIRCULAR | etw.EVENT_TRACE_REAL_TIME_MODE,
    BufferSize:  128, // KB
    ClockType:   etw.EVENT_TRACE_CLOCK_SYSTEMTIME,
    MaxFileSize: 500, // MB - 0 means no limit
}

// Create the AutoLogger (writes to registry)
if err := autoLogger.Create(); err != nil {
    panic(err)
}

// Enable providers for the AutoLogger
providers := []etw.Provider{
    etw.MustParseProvider("Microsoft-Windows-Kernel-Boot"),
    etw.MustParseProvider("Microsoft-Windows-Kernel-Process:0xff:1,3,5"),
}

for _, provider := range providers {
    if err := autoLogger.EnableProvider(provider); err != nil {
        log.Printf("Failed to enable provider: %v", err)
    }
}
```

### AutoLogger Management

```go
// Check if AutoLogger exists
if autoLogger.Exists() {
    fmt.Println("AutoLogger already configured")
}

// Remove AutoLogger configuration
if err := autoLogger.Delete(); err != nil {
    log.Printf("Failed to delete AutoLogger: %v", err)
}
```

### AutoLogger Provider Filters

AutoLogger sessions support advanced filtering through the registry:

```go
// Provider with multiple filter types
provider := etw.Provider{
    GUID:            etw.MustParseGUID("{provider-guid}"),
    EnableLevel:     etw.TRACE_LEVEL_INFORMATION,
    MatchAnyKeyword: 0x8000000000000000,
    Filters: []etw.ProviderFilter{
        etw.NewEventIDFilter(true, 1, 3, 5, 7),           // Include specific event IDs
        etw.NewPIDFilter(1234, 5678),                      // Include specific PIDs
        etw.NewExecutableNameFilter("notepad.exe", "calc.exe"), // Include specific executables
    },
}

if err := autoLogger.EnableProvider(provider); err != nil {
    panic(err)
}
```

## Filtering and Performance

ETW provides multiple levels of filtering, each with different performance characteristics. Understanding these differences is crucial for optimal trace performance.

### Filtering Hierarchy (Performance Order)

1. **Provider-side Filtering (Highest Performance)**
   - Level and Keyword filtering
   - Provider checks if events are enabled *before* generating them
   - Near-zero overhead for disabled events

2. **Runtime-side Filtering (Medium Performance)**
   - Event ID, PID, Executable Name filters
   - Events are generated but filtered by ETW runtime before reaching consumers
   - Reduces trace volume but not generation overhead

3. **Consumer-side Filtering (Lowest Performance)**
   - Filtering in EventCallback or ProcessEvents functions
   - Full event generation and delivery cost has been paid
   - Use only for complex post-processing logic

### Performance Optimization Examples

```go
// BEST: Provider-side filtering
provider := etw.MustParseProvider("Microsoft-Windows-Kernel-File:4::0x80") // Only Error+ level, CREATE keyword

// GOOD: Runtime-side filtering
provider := etw.Provider{
    GUID:            etw.MustParseGUID("{provider-guid}"),
    EnableLevel:     etw.TRACE_LEVEL_ERROR,
    MatchAnyKeyword: 0x80,
    Filters: []etw.ProviderFilter{
        etw.NewEventIDFilter(true, 12, 13, 14), // Runtime filtering
        etw.NewPIDFilter(os.Getpid()),          // Only current process
    },
}

// AVOID FOR HIGH-VOLUME: Consumer-side filtering
consumer.EventCallback = func(event *etw.Event) error {
    // This filtering happens after full event processing cost
    if event.EventHeader.EventDescriptor.ID != 12 {
        return nil // Skip event
    }
    // Process event...
    return nil
}
```

### Filter Types and Limitations

#### Event ID Filter
```go
// Include specific event IDs (efficient runtime filtering)
filter := etw.NewEventIDFilter(true, 12, 13, 14, 15)

// Exclude specific event IDs
filter := etw.NewEventIDFilter(false, 99, 100, 101)
```

#### PID Filter
```go
// Scope filter - highly efficient for user-mode providers
// WARNING: Generally ignored by kernel providers (they run in kernel context)
filter := etw.NewPIDFilter(1234, 5678, 9012) // Max 8 PIDs
```

#### Executable Name Filter
```go
// Scope filter - efficient for user-mode providers
// WARNING: Generally ignored by kernel providers
filter := etw.NewExecutableNameFilter("notepad.exe", "calc.exe", "chrome.exe")
```

### Kernel Provider Filtering Limitations

**Important**: PID and Executable Name filters have critical limitations with kernel providers:

- **Kernel providers** (e.g., "Microsoft-Windows-Kernel-Process") run in kernel context (PID 4 or 0)
- When PID filters for user-mode processes are applied to kernel providers, ETW **ignores the filter**
- Events will still be received as if no PID filter was applied
- This is because the provider itself is the kernel, not the user-mode processes being monitored

```go
// This PID filter will be IGNORED for kernel providers
kernelProvider := etw.Provider{
    GUID: etw.SystemProcessProviderGuid,
    EnableLevel: 0xff,
    MatchAnyKeyword: etw.SYSTEM_PROCESS_KW_GENERAL,
    Filters: []etw.ProviderFilter{
        etw.NewPIDFilter(1234), // IGNORED - kernel provider events will still arrive
    },
}
```

## Code Examples

### Complete Session Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "time"

    "github.com/tekert/goetw/etw"
)

func main() {
    // Create context for graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle Ctrl+C
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt)
    go func() {
        <-sigChan
        cancel()
    }()

    // Create real-time session
    session := etw.NewRealTimeSession("ExampleTrace")
    defer session.Stop()

    // Configure providers with different filtering strategies
    providers := []etw.Provider{
        // High-level filtering (most efficient)
        etw.MustParseProvider("Microsoft-Windows-Kernel-File:4::0x80"), // Error+ level, CREATE operations
        
        // Runtime filtering
        {
            GUID:            etw.MustParseGUID("{guid}"),
            EnableLevel:     etw.TRACE_LEVEL_INFORMATION,
            MatchAnyKeyword: 0xFFFFFFFFFFFFFFFF,
            Filters: []etw.ProviderFilter{
                etw.NewEventIDFilter(true, 1, 3, 5),
                etw.NewPIDFilter(uint32(os.Getpid())),
            },
        },
    }

    // Enable providers
    for _, provider := range providers {
        if err := session.EnableProvider(provider); err != nil {
            log.Printf("Failed to enable provider %s: %v", provider.Name, err)
        }
    }

    // Create consumer
    consumer := etw.NewConsumer(ctx)
    defer consumer.Stop()

    // Configure consumer callbacks
    consumer.EventRecordCallback = func(er *etw.EventRecord) bool {
        // Fast filtering at raw EventRecord level
        return er.EventHeader.ProviderId.Data1 != 0x12345678 // Skip specific provider
    }

    consumer.EventCallback = func(event *etw.Event) error {
        defer event.Release() // Important: release memory
        
        fmt.Printf("[%s] %s: Event ID %d\n",
            event.Header.TimeStamp.Format(time.RFC3339Nano),
            event.Provider.Name,
            event.EventHeader.EventDescriptor.ID,
        )
        
        // Print event properties
        for _, prop := range event.Properties {
            fmt.Printf("  %s: %v\n", prop.Name, prop.Value)
        }
        return nil
    }

    // Start consuming from session
    consumer.FromSessions(session)

    // Process events in background
    go func() {
        if err := consumer.Start(); err != nil {
            log.Printf("Consumer error: %v", err)
        }
    }()

    // Wait for shutdown signal
    <-ctx.Done()
    fmt.Println("Shutting down...")
}
```

### AutoLogger Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/tekert/goe/etw"
)

func main() {
    // Create AutoLogger configuration
    autoLogger := &etw.AutoLogger{
        Name:        "BootTrace",
        GuidS:       "{12345678-1234-1234-1234-123456789012}",
        LogFileMode: etw.EVENT_TRACE_FILE_MODE_CIRCULAR,
        BufferSize:  64,
        ClockType:   etw.EVENT_TRACE_CLOCK_SYSTEMTIME,
        MaxFileSize: 100,
    }

    // Check if already exists
    if autoLogger.Exists() {
        fmt.Println("AutoLogger already exists, deleting...")
        if err := autoLogger.Delete(); err != nil {
            log.Fatal(err)
        }
    }

    // Create AutoLogger
    if err := autoLogger.Create(); err != nil {
        log.Fatal(err)
    }

    // Enable providers
    providers := []etw.Provider{
        etw.MustParseProvider("Microsoft-Windows-Kernel-Boot"),
        {
            GUID:            etw.SystemProcessProviderGuid,
            EnableLevel:     etw.TRACE_LEVEL_INFORMATION,
            MatchAnyKeyword: etw.SYSTEM_PROCESS_KW_GENERAL,
            Filters: []etw.ProviderFilter{
                etw.NewEventIDFilter(true, 1, 3, 5), // Process start, end, exit
            },
        },
    }

    for _, provider := range providers {
        if err := autoLogger.EnableProvider(provider); err != nil {
            log.Printf("Failed to enable provider: %v", err)
        }
    }

    fmt.Println("AutoLogger configured successfully")
    fmt.Println("Reboot to activate, then consume with:")
    fmt.Println(`  consumer.FromTraceNames("BootTrace")`)
}
```


## Best Practices

### Session Management

1. **Always use defer to stop sessions**:
   ```go
   session := etw.NewRealTimeSession("MyTrace")
   defer session.Stop() // Ensures cleanup even if program crashes
   ```

2. **Check for existing sessions**:
   ```go
   // Stop any existing session before starting
   if err := etw.StopSession("MyTrace"); err != nil {
       // Session might not exist, which is fine
   }
   ```

3. **Use appropriate buffer sizes**:
   ```go
   // ETW events can be up to 64KB, so buffer size should be at least 64KB
   session.BufferSize = 64 // Minimum recommended
   session.BufferSize = 128 // Better for high-volume scenarios
   ```

### Provider Configuration

1. **Prefer Level/Keyword filtering**:
   ```go
   // GOOD: Provider-side filtering
   provider := etw.MustParseProvider("Provider:4::0x80")
   
   // AVOID: Consumer-side filtering for high-volume events
   ```

2. **Use specific event IDs when possible**:
   ```go
   // Filter specific events at runtime level
   provider := etw.MustParseProvider("Provider:0xff:1,3,5,7")
   ```

3. **Be aware of kernel provider limitations**:
   ```go
   // PID filters don't work with kernel providers
   kernelProvider := etw.MustParseProvider("Microsoft-Windows-Kernel-Process")
   // Don't add PID filters to kernel providers
   ```

### Consumer Optimization

1. **Always release events**:
   ```go
   consumer.EventCallback = func(event *etw.Event) error {
       defer event.Release() // Critical for memory management
       // Process event...
       return nil
   }
   ```

2. **Use appropriate callback levels**:
   ```go
   // Filter early for best performance
   consumer.EventRecordCallback = func(er *etw.EventRecord) bool {
       return er.EventHeader.EventDescriptor.ID == targetID
   }
   
   // Avoid heavy processing in callbacks
   consumer.EventCallback = func(event *etw.Event) error {
       // Quick processing or queue for background processing
       return nil
   }
   ```

3. **Monitor consumer health**:
   ```go
   // Check for event loss
   go func() {
       ticker := time.NewTicker(30 * time.Second)
       defer ticker.Stop()
       for range ticker.C {
           lost := consumer.LostEvents.Load()
           if lost > 0 {
               log.Printf("WARNING: %d events lost", lost)
           }
       }
   }()
   ```

### Error Handling

1. **Handle provider enable failures gracefully**:
   ```go
   for _, provider := range providers {
       if err := session.EnableProvider(provider); err != nil {
           log.Printf("Failed to enable %s: %v", provider.Name, err)
           // Continue with other providers
       }
   }
   ```

2. **Implement timeout for consumer shutdown**:
   ```go
   // Use StopWithTimeout for non-responsive sessions
   if err := consumer.StopWithTimeout(10 * time.Second); err != nil {
       log.Printf("Consumer stop timeout: %v", err)
   }
   ```

### Performance Monitoring

1. **Track session statistics**:
   ```go
   if props, err := session.QueryTrace(); err == nil {
       fmt.Printf("Events lost: %d\n", props.EventsLost)
       fmt.Printf("Buffers lost: %d\n", props.LogBuffersLost)
       fmt.Printf("Real-time buffers lost: %d\n", props.RealTimeBuffersLost)
   }
   ```

2. **Monitor consumer backlog**:
   ```go
   // Check events channel backlog
   backlog := len(consumer.Events.Channel)
   if backlog > 1000 {
       log.Printf("WARNING: High event backlog: %d", backlog)
   }
   ```

## Troubleshooting

### Common Issues

#### 1. Events Lost / Missing Events

**Symptoms**: Event count lower than expected, `EventsLost` > 0 in session statistics

**Causes**:
- Event size > 64KB (unfixable - application issue)
- Buffer size smaller than event size
- Consumer not processing events fast enough
- Disk too slow for file logging

**Solutions**:
```go
// Increase buffer size
session.BufferSize = 128 // or higher

// Increase buffer count
session.NumberOfBuffers = 64

// Use paged memory for better performance (non-kernel providers only)
session := etw.NewPagedRealTimeSession("MyTrace")

// Optimize consumer processing
consumer.EventCallback = func(event *etw.Event) error {
    defer event.Release()
    
    // Queue for background processing instead of processing inline
    select {
    case eventQueue <- event:
    default:
        // Drop event if queue full rather than blocking
    }
    return nil
}
```

#### 2. High CPU Usage

**Symptoms**: High CPU usage during tracing

**Causes**:
- Too many events being generated
- Inefficient event processing
- Consumer callbacks taking too long

**Solutions**:
```go
// Use more restrictive provider filtering
provider := etw.MustParseProvider("Provider:3::0x10") // Warning level only, specific keyword

// Process events in batches
go func() {
    consumer.ProcessEvents(func(e *etw.Event) {
        // Events are processed in batches automatically
        processEventQuickly(e)
    })
}()

// Filter early in the pipeline
consumer.EventRecordCallback = func(er *etw.EventRecord) bool {
    // Fast filtering before full event parsing
    return er.EventHeader.EventDescriptor.ID < 10
}
```

#### 3. Provider Not Found

**Symptoms**: `ErrUnknownProvider` when parsing provider strings

**Causes**:
- Provider not installed on system
- Typo in provider name
- Provider GUID incorrect

**Solutions**:
```go
// Check if provider exists
if !etw.IsKnownProvider("Microsoft-Windows-Kernel-File") {
    fmt.Println("Provider not found")
}

// List available providers
providers := etw.EnumerateProviders()
for name := range providers {
    fmt.Println(name)
}

// Use GUID directly if name resolution fails
provider := etw.Provider{
    GUID: etw.MustParseGUID("{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"),
    EnableLevel: 0xff,
    MatchAnyKeyword: 0xFFFFFFFFFFFFFFFF,
}
```

#### 4. Session Already Exists

**Symptoms**: `ERROR_ALREADY_EXISTS` when starting sessions

**Solutions**:
```go
// Stop existing session first
etw.StopSession("MyTrace")

// Or handle in session start
session := etw.NewRealTimeSession("MyTrace")
if err := session.Start(); err != nil {
    if err == etw.ERROR_ALREADY_EXISTS {
        etw.StopSession("MyTrace")
        err = session.Start() // Retry
    }
    if err != nil {
        panic(err)
    }
}
```

#### 5. Access Denied

**Symptoms**: Access denied errors when starting sessions or enabling providers

**Causes**:
- Insufficient privileges
- Not running as administrator

**Solutions**:
- Run program as administrator
- Use elevated command prompt
- Check user account permissions
- Use etw.EnableProfilingPrivileges or etw.EnablePrivileges if profiling is disabled.

#### 6. Consumer Hangs on Stop

**Symptoms**: `consumer.Stop()` blocks indefinitely

**Causes**:
- ProcessTrace waiting for buffers to empty
- Consumer callback blocking

**Solutions**:
```go
// Use timeout for consumer stop
if err := consumer.StopWithTimeout(10 * time.Second); err != nil {
    // Force stop if timeout
    consumer.Abort()
}

// Ensure callbacks don't block
consumer.EventCallback = func(event *etw.Event) error {
    defer event.Release()
    
    // Don't block in callback
    select {
    case eventQueue <- event:
    case <-ctx.Done():
        return nil
    default:
        // Drop event rather than block
    }
    return nil
}
```

### Debugging Commands

```cmd
:: List running sessions
logman query -ets

:: Stop specific session
logman stop "MyTrace" -ets

:: List available providers
logman query providers

:: Get provider details
logman query providers "Microsoft-Windows-Kernel-File"

:: Start test session
logman start "TestTrace" -p "Microsoft-Windows-Kernel-Process" -o test.etl -ets

:: Stop test session  
logman stop "TestTrace" -ets

:: Convert ETL to readable format
tracerpt test.etl
```

### Performance Analysis

Use these techniques to analyze ETW performance:

// TODO: use my benchmarks code.

```

This comprehensive guide should help you effectively use the goetw library for Event Tracing for Windows. Remember that ETW is a powerful but complex system, and optimal configuration depends on your specific use case, system resources, and performance requirements.
