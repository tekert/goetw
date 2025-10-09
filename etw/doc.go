// Package etw provides high-performance access to Windows Event Tracing (ETW).
//
// It allows creating ETW sessions, enabling providers, and consuming ETW events
// in real-time or from .etl files without requiring CGO. The package handles the
// full ETW pipeline including session management, provider control, and event
// parsing.
//
// Basic usage:
//
//	c := etw.NewConsumer(context.Background())
//	defer c.Stop()
//
//	c.FromTraces("MyTrace")
//	c.ProcessEvents(func(e *Event) {
//	    // Process event
//	})
//
//	if err := c.Start(); err != nil {
//	    log.Fatal(err)
//	}
package etw

// To modernize:
// go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...