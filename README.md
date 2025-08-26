[![GoDoc](https://pkg.go.dev/badge/github.com/tekert/goetw)](https://pkg.go.dev/github.com/tekert/goetw/etw?GOOS=windows)
![Version](https://img.shields.io/github/v/tag/tekert/goetw?label=version)
<!-- Coverage badge hidden but still accessible
 [![Coverage](https://raw.githubusercontent.com/tekert/goetw/master/.github/coverage/badge.svg)](https://raw.githubusercontent.com/tekert/goetw/refs/heads/fork/.github/coverage/coverage.txt)
-->

`goetw` is a high-performance, pure Go library for consuming Event Tracing for Windows (ETW) events. It's designed for efficiency.

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
    // A session is required to start a trace. The name is like and ID in etw.
    s := etw.NewRealTimeSession("MyRealtimeSession")
    defer s.Stop()

    // Enable a provider by its name. The string format allows for quick configuration.
    // Format: "ProviderName[:Level[:EventIDs[:MatchAnyKeyword[:MatchAllKeyword]]]]"
    provider, err := etw.ParseProvider("Microsoft-Windows-Kernel-Process")
    if err != nil {
        panic(err)
    }
    // This just adds the provider to the session. (It starts the session if not started)
    if err := s.EnableProvider(provider); err != nil {
        panic(err)
    }

    // A consumer attaches to the session to process events.
    c := etw.NewConsumer(context.Background())
    defer c.Stop()

    // Tell the consumer which session to process events from.
    c.FromSessions(s) // this just extracts the session names

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
    s := etw.NewRealTimeSession("MyAdvancedSession")
    defer s.Stop()

    // Configure the provider programmatically for fine-grained control.
    provider := etw.Provider{
        // Or use etw.IsKnownProvider etw.ResolveProvider 
        GUID:            etw.MustParseGUID("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"),
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
    // The NT Kernel Logger is a special session. Kernel event groups are enabled
    // at session creation by passing flags.
    // TODO: this changed in v0.8, reflect that.
    s := etw.NewKernelRealTimeSession(etw.Process | etw.Thead)
    defer s.Stop()

    // For kernel sessions, we must explicitly start the session.
    // This can fail if another kernel session is already running (though this
    // library attempts to stop it first and restart it for our use).
    if err := s.Start(); err != nil {
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

    if err := c.Start(); err != nil {
        panic(err)
    }
    time.Sleep(5 * time.Second)
}
```
**Note:** Only one NT Kernel Logger session can be active on a system at a time. You must have administrator privileges to start it. (Windows 11 can use manifest kernel providers and don't have this limitation)

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

## Overview

Basically there are two main elements in ETW, the session(called controller) and the consumer.  
In go terms, session is a command line app that just setups some buffers and signals some etw providers to write to it. 

Consumer would be another app that just (by name only) hooks into the session created by the controller and starts receiving the events from the providers, this connection is usually called a trace for real time traces.

There are also etl files, the one created with logman or any other tool, where the session is not needed, you just consumer from the file, so you only need a filename instead of session name.

Lastly, for the consumer, there are 4 mainly consuming "levels", each for how fast they are. 

- EventRecordCallback -> [1] this can process like 4 000 000 events/s on modern hardware, here you get the raw EventRecord structure that the etw provider "provided".

- EventRecordHelperCallback -> [2] this one process 2 000 000 events/s, half of the other, here you receive a wrapper with trace info data for that event, that is used to decode the data in the event, it's the TraceEventInfo.
This lib uses a bunch of code to make it easy to consume events from this data, so this callback alone is not very useful, you only have the Trace Info. 
This handles cases where the schema for the nt kernel events may be corrupted on systems, and uses pre generated mof classes to decode those events if the microsoft parser fails to find the schema on your system.

- EventPreparedCallback -> [3] Here we are down to 1 000 000 events/s, This is where Trace Info was used by goetw to "prepare" meaning, decoding all the positions in the event binary blob where a prop may be, wich name it has, size, etc etc. This where the most code was written and debugged, profiled, a bunch of nasty work so you don't have to. Here the wrapper called `EventRecordHelper` will have 3 maps, each one for the types of properties that where prepared, simple props (map of props), array of props, array of strucs of structs,
Example: 

`ArrayPropeties`: If an event has a property ThreadIDs defined as ThreadIDs[4], it will be stored in ArrayProperties["ThreadIDs"] as a slice of Property pointers. 

`StructArrays`: If an event has a property IORequests defined as IORequests[3] where each IORequest is a struct with fields like Size, Type, etc., it will be stored in StructArrays["IORequests"] as a slice of maps (each map is a struct instance). 

`StructSingle`: If an event has a property ProcessInfo which is a struct (not an array), it will be stored in StructSingle as a single map of field names to Property pointers. 

The properties are not parsed here, but you can parse them using the Get* methods.

- EventCallback -> [4] This is where the events/s depends on the json parser but on my benchmarks here we just fall to the 300 000 events/s range, this just outputs `Event` structs will all the parsed data plus metadata, This us usually used to do light work, maybe file tracking or analizing strings from events, metadata etc, just like other microsoft tools outputs the decoded events but in go.

`ProcessEvents()` is just a wrapper for the Default EventCallback [4] that automatically handles events in a queue using batched channels and releases memory allocated for each event on return, you can do that using the EventCallback. This was made just to make it really easy to consume events without worring about releasing.


## Why made this

This all started with the desire to track wich files where written by wich process (and some other data for later aggregation by a time series database or some other).  
While searching for libs to quicky do that in go (I'm mostly a c++ programmer but wanted some easier and really quick to use to get some prometheus metrics out of it).  
Realized quicky that this would be another "let's add more functionality", where you start discovering some bugs, features, quirks of etw, bugs even on the tools microsoft provides (perfviev and logman don't track kernel times and user times in the event correctly), etc.  

All of sudden you want to track everything correctly, some high frequancy kernel events, blah blah, everyone knows the drill, all of sudden this becomes a standalone library and has all the things I would want to track ETW events at high speed for almost anything kernel related, should work for some other etw providers too, but as the time of writting this was mostly thoughly tested for kernel providers.  

I know there a some exelent c++ libs for this, in another realite that's what i would use, but thats how this project started like a quick side project, finished as "almost" full library, that's the story.  

In the end, it's very fast, highly optimized (i like optimizing) for being a go library, cgo calls are reducen to just 1, `GetEventPropertyInfo` that is just called 1 time per event and go syscalls do a petty good job of keeping latency down, i've tried to use my custom parser to replace that call (for kernel events) and the aditional code just barely surpassed the latency from go cgo and the fast parsin from the microsoft dlls libs, so i'm farly calm that at least this project is useful to decode high event rate.  

## Internal notes

- [docs/DEV-NOTES.md](docs/DEV-NOTES.md)
But they are old, I know more now.

- [docs/DEV-NOTES2.md](docs/DEV-NOTES2.md)
New notes for myself2

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

## Related Work by others

- [ETW Explorer][etw-explorer]
(use this to browse manifest providers in your system)
- [ETWProviders](https://github.com/repnz/etw-providers-docs)

[etw-explorer]: https://github.com/zodiacon/EtwExplorer

[ETW Framework Conceptual Tutorial]: https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial
[ETW Framework Conceptual Tutorial-WMM]: http://web.archive.org/web/20240331153956/https://learn.microsoft.com/en-us/message-analyzer/etw-framework-conceptual-tutorial

[ETW Buffer Configuration]: https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
[ETW Buffer Configuration-WWM]: http://web.archive.org/web/20220120013651/https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
