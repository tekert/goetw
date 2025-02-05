//go:build windows
// +build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tekert/golang-etw/etw"
)

func main2() {
	// ETW needs a trace to be created before being able to consume from
	// it. Traces can be created using golang-etw or they might be already
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
		for batch := range c.Events.Channel {
			for _, e := range batch {
				if b, err = json.Marshal(e); err != nil {
					panic(err)
				}
				fmt.Println(string(b))
			}
		}
	}()

	if err := c.Start(); err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)

	if c.LastError() != nil {
		panic(c.LastError())
	}

}
