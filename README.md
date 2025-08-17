[![GoDoc](https://pkg.go.dev/badge/github.com/tekert/goetw)](https://pkg.go.dev/github.com/tekert/goetw/etw?GOOS=windows)
![Version](https://img.shields.io/github/v/tag/tekert/goetw?label=version)
<!-- Coverage badge hidden but still accessible
 [![Coverage](https://raw.githubusercontent.com/tekert/goetw/master/.github/coverage/badge.svg)](https://raw.githubusercontent.com/tekert/goetw/refs/heads/fork/.github/coverage/coverage.txt)
-->
High performant etw library to consume ETW logs.

Pure Golang (no need to enable CGO) library to consume ETW logs.

## Examples

See [./examples](./examples)

```go
package main

import (
	"context"
	"encoding/json" // recommend a faster library for json meshing.
	"fmt"
	"time"

	"github.com/tekert/goetw/etw"
)

func main() {
	// ETW needs a trace to be created before being able to consume from
	// it. Traces can be created using goetw or they might be already
	// existing (created from an autologgers for instance) like Eventlog-Security.

	// Creating the trace (producer part)
	s := etw.NewRealTimeSession("TestingGoEtw")

	// We have to stop the session or it will be kept alive and session name
	// will not be available anymore for next calls
	defer s.Stop()

	// we need to enable the trace to collect logs from given providers
	// several providers can be enabled per trace, in this example we
	// enable only one provider
	if err := s.EnableProvider(etw.MustParseProvider("Microsoft-Windows-Kernel-File")); err != nil {
		panic(err)
	}

	// Consuming from the trace
	c := etw.NewConsumer(context.Background())

	defer c.Stop()

	c.FromSessions(s)

	// When events are parsed they get sent to Consumer's
	// Events channel by the default EventCallback method
	// EventCallback can be modified to do otherwise
	go func() {
		var b []byte
		var err error
		c.ProcessEvents(func(e *etw.Event) {
			if b, err = json.Marshal(e); err != nil {
				panic(err)
			}
			fmt.Println(string(b))
		})
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)

	if c.Err() != nil {
		panic(c.Err())
	}

}
```

## How ETW works

- [doc/NOTES](docs/NOTES.md)

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
