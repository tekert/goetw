[![GoDoc](https://pkg.go.dev/badge/github.com/tekert/goetw)](https://pkg.go.dev/github.com/tekert/goetw/etw?GOOS=windows)
![Version](https://img.shields.io/github/v/tag/tekert/goetw?label=version)
<!-- Coverage badge hidden but still accessible
 [![Coverage](https://raw.githubusercontent.com/tekert/goetw/master/.github/coverage/badge.svg)](https://raw.githubusercontent.com/tekert/goetw/refs/heads/fork/.github/coverage/coverage.txt)
-->

`goetw` is a high-performance, pure Go library for consuming Event Tracing for Windows (ETW) events. It's designed for efficiency, providing direct access to ETW data without requiring CGO.

## Examples

The basic workflow involves creating a `Session` to start a trace, enabling one or more `Provider`s, and using a `Consumer` to process the events.

### 1. Basic Real-Time Consumption

This example shows the simplest way to start a session, enable a provider by name, and process its events in real-time.

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/tekert/goetw/etw"
)

func main() {
    // A session is required to start a trace.
    s, err := etw.NewRealTimeSession("MyRealtimeSession")
    if err != nil {
        panic(err)
    }
    defer s.Stop()

    // Enable a provider by its name. The string format allows for quick configuration.
    // Format: "ProviderName[:Level[:EventIDs[:MatchAnyKeyword[:MatchAllKeyword]]]]"
    provider, err := etw.ParseProvider("Microsoft-Windows-Kernel-Process")
    if err != nil {
        panic(err)
    }
    if err := s.EnableProvider(provider); err != nil {
        panic(err)
    }

    // A consumer attaches to the session to process events.
    c := etw.NewConsumer(context.Background())
    defer c.Stop()

    // Tell the consumer which session to process events from.
    c.FromSessions(s)

    // ProcessEvents blocks until the context is canceled or an error occurs.
    // It's common to run this in a separate goroutine.
    go func() {
        c.ProcessEvents(func(e *etw.Event) {
            // For simplicity, we marshal to JSON. For high performance,
            // access event fields directly.
            j, _ := json.Marshal(e)
            fmt.Println(string(j))
        })
    }()

    if err := c.Start(); err != nil {
        panic(err)
    }

    time.Sleep(5 * time.Second)
}
```
**Note:** A `Session` creates the trace, and a `Consumer` attaches to it to receive events. You must `Stop()` both when you are done to release system resources.

### 2. Advanced Provider Configuration

This example demonstrates how to configure a provider with specific levels, keywords, and filters for more granular control.

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/tekert/goetw/etw"
)

func main() {
    s, _ := etw.NewRealTimeSession("MyAdvancedSession")
    defer s.Stop()

    // Configure the provider programmatically for fine-grained control.
    provider := etw.Provider{
        GUID:            etw.MustParseGUID("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"), // Microsoft-Windows-Kernel-File
        Name:            "Microsoft-Windows-Kernel-File",
        EnableLevel:     etw.LevelInformational,
        MatchAnyKeyword: 0x10, // FileIoCreate
        Filters: []etw.ProviderFilter{
            // Only include events with ID 12 (File Create).
            etw.NewEventIDFilter(true, 12),
            // Only include events from processes named "explorer.exe".
            etw.NewExecutableNameFilter("explorer.exe"),
        },
    }

    if err := s.EnableProvider(provider); err != nil {
        panic(err)
    }

    c := etw.NewConsumer(context.Background())
    defer c.Stop()
    c.FromSessions(s)

    go c.ProcessEvents(func(e *etw.Event) {
        fmt.Printf("Received File Create event from PID %d\n", e.System.Execution.ProcessID)
    })

    c.Start()
    time.Sleep(5 * time.Second)
}
```
**Note:** Using `Level`, `MatchAnyKeyword`, and `Filters` allows ETW to filter events at the kernel level, which is highly efficient and reduces the volume of data sent to your application.

### 3. Consuming from the NT Kernel Logger

This example shows how to consume events from the special "NT Kernel Logger" session, which provides deep insights into the OS.

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/tekert/goetw/etw"
)

func main() {
    // The NT Kernel Logger is a special session with a fixed name.
    s, err := etw.NewRealTimeSession(etw.NtKernelLogger)
    if err != nil {
        // Fails if another kernel session is already running.
        panic(err)
    }
    defer s.Stop()

    // Enable kernel providers by name. The library resolves the required flags.
    // Here, we ask for Process and Thread start/stop events.
    flags := etw.GetKernelProviderFlags("Process", "Thread")
    if err := s.EnableKernelProvider(flags, 0); err != nil {
        panic(err)
    }

    c := etw.NewConsumer(context.Background())
    defer c.Stop()
    c.FromSessions(s)

    go c.ProcessEvents(func(e *etw.Event) {
        // Kernel events have well-known structures.
        if e.System.EventID == 1 { // Process Start
            if name, ok := e.GetPropertyString("ImageFileName"); ok {
                fmt.Printf("Process Started: %s (PID: %d)\n", name, e.System.Execution.ProcessID)
            }
        }
    })

    c.Start()
    time.Sleep(5 * time.Second)
}
```
**Note:** Only one NT Kernel Logger session can be active on a system at a time. You must have administrator privileges to start it.

### 4. Reading from an ETL File

This example demonstrates how to process events from a pre-recorded `.etl` log file instead of a real-time session.

```go
package main

import (
    "context"
    "fmt"

    "github.com/tekert/goetw/etw"
)

func main() {
    // Path to your ETL file.
    etlFile := `C:\path\to\your\logfile.etl`

    c := etw.NewConsumer(context.Background())
    defer c.Stop()

    // Instead of FromSessions, use FromTraceNames with the file path.
    c.FromTraceNames(etlFile)

    // When processing a file, Start() blocks until all events are read,
    // so we don't need to run it in a goroutine or sleep.
    err := c.Start()
    if err != nil {
        panic(err)
    }

    // Process the events that were buffered during the file read.
    c.ProcessEvents(func(e *etw.Event) {
        fmt.Printf("Event from file: ID %d, Provider %s\n", e.System.EventID, e.System.Provider.Name)
    })
}
```
**Note:** The workflow for file-based consumption is nearly identical to real-time. The `Consumer` handles the differences internally.

## How ETW works

- [docs/NOTES.md](docs/NOTES.md)

## Related Documentation

- (Best) [ETW Framework Conceptual Tutorial][ETW Framework Conceptual Tutorial-WMM]
(Actually deleted by microsoft... using wayback machine)
- [Instrumenting Your Code with ETW](https://learn.microsoft.com/en-us/windows-hardware/test/weg/instrumenting-your-code-with-etw)

- [Core OS Events in Windows, Part 1](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/september/core-os-events-in-windows-7-part-1)
- [Core OS Events in Windows, Part 2](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/october/core-instrumentation-events-in-windows-7-part-2)
- [About Event Tracing, Provider Types](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [How are Events Created](https://learn.microsoft.com/en-us/windows/win32/etw/event-metadata-overview)


- [ETW API](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/)

- [Advanced ETWSession Configuration][ETW Buffer Configuration-WWM] (Actually deleted by microsoft... using wayback machine)

## Related Work

- [ETW Explorer][etw-explorer]
(use this to browse manifest providers in your system)
- [ETWProviders](https://github.com/repnz/etw-providers-docs)

[etw-explorer]: https://github.com/zodiacon/EtwExplorer

[ETW Framework Conceptual Tutorial]: https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial
[ETW Framework Conceptual Tutorial-WMM]: http://web.archive.org/web/20240331153956/https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial

[ETW Buffer Configuration]: https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
[ETW Buffer Configuration-WWM]: http://web.archive.org/web/20220120013651/https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings