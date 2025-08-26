## Overview of how ETW works:
This is my best attempt to explain the worst-designed API created by Microsoft as simply as I can. It may contain some personal reminders.

There are a few of general terms used in ETW:
- "Trace"
- "Trace Session"/"Session"
- "Trace controller"
- "Consumer"
- "Provider"

Here we go:  

#### Sessions
A Session is a buffer you allocate using ETW syscalls (it can be paged, non-paged, real-time, a circular buffer, written to a file, etc.). There are many forms of session properties you can select. It's allocated using `StartTrace`, where you provide a name or use another existing trace for this new Session to form a Trace Session.
Trace is the flow of events, so this is normally called a Trace Session when it's receiving events from providers.

For example in code, for a real-time session (meaning we want to process events as soon as they arrive in our buffer), this is done by calling:  
```
s := etw.NewRealTimeSession("TestingGoEtw")
defer s.Stop()
```

#### Providers

A Provider is the logical entity that raises events and writes them to a Session.
For example, to assign providers to the real-time session we created earlier:  
``` s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-Disk") ```  

We can attach another provider to the trace with keywords:
```s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-File:0xff:13,14:0x80:0x00")```

`":0xff:13,14:0x80:0x00"` after the provider name means:  

`LogLevel as hex`:`<EventIDs as ints separated by comma>`:`MatchAnyKeyword in HEX`:`MatchAllKeyword in HEX`

Everything is optional.

You can see the accepted levels and keywords for this example by using:
> `logman query providers Microsoft-Windows-Kernel-File`  
or  
> `Wevtutil gp "Microsoft-Windows-Kernel-File"`

Definitions:  

- `LogLevel as hex`  (Default is All levels = 0xFF)  
The event level defines the event's severity or importance and is a
primary means for filtering events. Microsoft-defined levels (in
evntrace.h and  winmeta.h) are 1 (critical/fatal), 2 (error),
3 (warning), 4 (information), and 5 (verbose). Levels 6-9 are reserved.
Level 0 means the event is always-on (will not be filtered by level).
For a provider, a lower level means the event is more important. An
event with level 0 will always pass any level-based filtering.
For a consumer, a lower level means the session's filter is more
restrictive. However, setting a session's level to 0 disables level
filtering (i.e. session level 0 is the same as session level 255).  
Custom logging levels can also be defined, but levels 6–15 are reserved.  
More than one logging level can be captured by ORing respective levels;  
supplying 255 (0xFF) is the standard method of capturing all supported logging levels.  
More info [here](https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-leveltype-complextype#remarks)  

- `<EventIDs as ints separed by comma>`  (Default is to include ALL events IDs)   
 You can check the event IDs a provider supports by looking at its manifest with [ETW Explorer][etw-explorer] or with the `Wevtutil gp` command previously executed. These IDs are used as a fast filter in `EnableTraceEx2`.
 This is used in this library as follows:  
From Doc at: [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters) -> FilterDescCount  
FilterDescCount -> [EVENT_FILTER_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor) -> EVENT_FILTER_TYPE_EVENT_ID  
 This feature allows enabling or disabling filtering for a list of events. The provided filter includes an EVENT_FILTER_EVENT_ID structure that contains an array of event IDs and a Boolean value that indicates whether to filter for the specified events. Each event write call (from a provider) will go through this array quickly to determine whether to enable or disable logging the event.
 This is faster than filtering at the Consumer.

- `MatchAnyKeyword in HEX` (Default is to include ALL events = 0x00)  
The event is written by the provider if any of the event's keyword bits match any of the bits set in this mask or if the event has no keyword bits set.
The keywords can be inspected by using the `logman` or `Wevtutil gp` command mentioned previously (look for the mask/hex form).
0x80 for this provider means: KERNEL_FILE_KEYWORD_CREATE  
An event can have many keywords. If an event contains the KERNEL_FILE_KEYWORD_CREATE flag, then it's sent by the provider.
Filtering at the kernel level is inherently faster than user-mode filtering (following the parsing process).

- `MatchAllKeyword in HEX` (Default is to include ALL events = 0x00)  
Bitmask where for those events that matched the "MatchAnyKeyword" case, the event is written by the provider only if all of the bits in the "MatchAllKeyword" mask exist in the event's keyword bitmask or if the event has no keyword bits set.  
This value is frequently set to 0.  
Note that this mask is not used if Keywords(Any) is set to zero.  

The evntprov.h source header has the best documentation on this:  
```cpp
// An event will pass the session's keyword filtering  
// if the following expression is true:  
event.Keyword == 0 || (  
(event.Keyword & session.KeywordAny) != 0 &&  
(event.Keyword & session.KeywordAll) ==  session.KeywordAll).  
// In other words, uncategorized events (events with no keywords set) always pass keyword filtering, and categorized events pass if they match any keywords in KeywordAny and match all keywords in KeywordAll.  
```

More info in  
[evntprov.h](https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/evntprov.h#L284)  
[Keywords](https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events)  
An also at [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)  

#### Writing events to a .etl file
Usually, when using a provider to output events to a file, you create an .etl trace file using Windows tools, like the `logman` command.
For example, let's start with the special Kernel Trace:
> logman query providers "Windows Kernel Trace"  

You can see the keywords used for filtering events.
To log events you can use the keywords in `logman` like this:
>logman start "NT Kernel Logger" –p "Windows Kernel Trace" (process,thread,img,disk,net,registry) –o systemevents.etl –ets

And when you want to stop use:
> logman stop "NT Kernel Logger"

NOTE: Use filtering; some events can write a gigabyte of data in a few seconds.

You can also create kernel .etl traces using Performance Monitor -> System Performance, but it selects only a few keywords by default.
NOTE: events like context switches can only be read from the NT Kernel Logger trace (with its "Windows Kernel Trace" only provider). The manifest-based "Kernel" providers don't have it.

You can use [PerfView](https://github.com/microsoft/perfview) to open that .etl file and see the events from a GUI for easy debugging.

You assign providers to write to your trace (buffer or file). You can filter events using keywords (which are implemented on the provider side before an event is formed, thus being the fastest way to filter events) or filter events once the event is formed. This library currently only supports filtering by event ID.
A manifest provider is just a provider that defines what events it can output and what the properties in those events mean. You can browse the manifest providers installed on your system using [ETW Explorer][etw-explorer].


#### Trace Controller
The Trace Controller is the software doing the trace control between providers and the Session. The output of events for this session is the Trace. The Session is the broader concept of forming the connection, also known as a Trace Session.

#### Trace Session
Finally, once the providers you have selected are enabled and writing events to your Session, it means you have formed a Trace Session. Many providers can write to your session.
The other case is to use an existing Trace Session from other trace controllers. You can consult them with:
> logman query -ets

These are Trace Sessions that are already started. If you wanted to consume from it to process its events directly in user code, there is no need to create a new session (buffer).
Reading the events the Trace session is collecting means to Consume from it.
Most of the time it is called a Trace; the terms change based on perspective (Producing vs. Consuming).
Provider -> Session (producing)
Session -> Consumer (consuming)
The Trace would be the "->" connecting them.

#### Consumer
Consumption is the act of opening an active Trace with `OpenTrace` and then processing it (from the consumer side, we have to open it first) with a blocking call to `ProcessTrace` in a new thread/goroutine. This involves setting callbacks to read stats from the buffer you allocated and another callback to finally receive the actual events. Parsing the events efficiently is another story, but this library already handles it for easy consumption.  
``` 
c := etw.NewConsumer(context.Background()) 
defer c.Stop()
c.FromSessions(s)
// ...
// Create goroutine to recive events
// ...
// Start processing events from traces, any non opened trace is opened.
if err := c.Start(); err != nil {
    panic(err)
}

```  
`c.FromSessions` registers the real-time trace names that we created with `NewRealTimeSession`, in this case, "TestingGoEtw".

`c.Start` opens the trace sessions that were registered (in this case, only "TestingGoEtw") and starts processing them in a new goroutine.

NOTE: If, for example, "TestingGoEtw" already existed and was not closed, it means you only need to consume from it; no need to create another Session.
`c.FromTraceNames` can do that.


The context here is just a means to sync the goroutines on exit.  
Each will contain traces with a blocking `ProcessTrace` func that will call the previously defined callbacks on the same thread/goroutine from which `ProcessTrace` is blocking. This means only one event can be processed at a time. If an event is not processed fast enough, the Trace Session buffer can fill up, and events could be lost.
More info on buffer sizes when creating the `Session` at [EVENT_TRACE_PROPERTIES_V2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2]) and [here][ETW Buffer Configuration-WWM]

There are 3 non-deprecated ways to check for lost events in modern ETW.  

- One is to catch an event that comes from a special Provider ID (the process that generated the event) GUID that tracks events lost in a real-time session.  
 
- Another is to read the [EVENT_TRACE_LOGFILE](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea) header when it arrives at the [BufferCallback](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbacka) (ETW calls the callback after delivering all events in the buffer to the consumer). The [TRACE_LOGFILE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header) will have our EventsLost field.
Do not use the EventsLost field from the `EVENT_TRACE_LOGFILE`.

- Manually by using `ControlTrace` with the ControlCode parameter set to `EVENT_TRACE_CONTROL_QUERY`, which will return an [`EVENT_TRACE_PROPERTIES_V2`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2).

EventsLost from the Consumer are events lost on your side; this can be equal to the one from ControlTrace if this is your session.

#### Stopping ETW Traces
To stop this, you have to stop two things:
`The Provider -> Trace` connection (aka `Session`)  
and the  
`Trace -> Consumer` connection (aka `Consumer`)  

- `The Provider -> Trace Session` is usually a real-time `Trace Session`, meaning you want to receive events in real time as the provider outputs them. It can also be a memory circular buffer. There are special Kernel/System trace sessions that only admit one consumer (`ProcessTrace`) at a time. For example, the "NT Kernel Logger" `Trace` already exists and can't be connected to any providers except the "Windows Kernel Trace" provider, which is already connected by default.
To stop the connection, you use the `ControlTrace` syscall.  
In this library, it is simply deferring a call to `Stop()` for a `Session`.  

It is **important** to close this, as it can persist even if the program crashes or exits abnormally.
From the command line, you can close a trace session with: (replace `<TRACE_NAME>` with your trace name)
>  logman stop <TRACE_NAME> -ets  

You can also inspect the current opened traces with:
> logman -ets

- `The Trace -> Consumer` is stopped when the `ProcessTrace` blocking call ends. This can be done by returning 0 from the buffer callback, using the `CloseTrace` syscall, or terminating the `Trace Controller` (this library's process).
In this library, it is the simple act of deferring a call to `Stop()` for a `Consumer`.

- The `Log File -> Consumer` connection is a Trace (an .etl trace file to consume from) -> Consumer. To close them, you use the same `CloseTrace`.
In this library, it is the simple act of deferring a call to `Stop()` for a `Consumer` or waiting for the file read to end.

--------------

Some sanitized AI definitions: (because not even Microsoft's docs and blogs define this so clearly), except for the deleted conceptual tutorial from Microsoft. You can read it below at [ETW Framework Conceptual Tutorial].

### Session
- In ETW, "Session" often refers to a Trace Session, but it is a broader term that could include the conceptual idea of managing providers, consumers, and log files.
- Usage Context:
Sometimes used interchangeably with "Trace Session."
May refer to the overall lifecycle of event tracing, including starting, stopping, and managing the session.

### Trace Session
- A Trace Session is the active logging mechanism that collects events from one or more providers and writes them to a log file or delivers them in real-time to a consumer.
- Key Features:
It's a container for ETW events.
Can collect events from multiple providers.
Configured using EventTraceProperties and started with StartTrace.

### Trace
- A Trace typically refers to the actual process of recording events during a Trace Session.
- Key Points:
It’s the action of capturing data.
The term is more abstract and refers to the output of the session (e.g., a log file or real-time events).
Examples:
"Capturing a trace" means enabling a session and collecting events.

### Trace Controller
- A Trace Controller is the component or entity responsible for managing trace sessions. It issues commands to start, stop, or configure trace sessions.
- Key Responsibilities:
Configures trace sessions using APIs like StartTrace, ControlTrace, and StopTrace.
Enables or disables providers using APIs like EnableTraceEx2.
Ensures proper setup of log files, real-time delivery, and session settings.