//go:build windows

package etw

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tekert/goetw/internal/test"
)

const (
	// providers
	SysmonProviderGuid       = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	KernelMemoryProviderGuid = "{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}"
	KernelFileProviderName   = "Microsoft-Windows-Kernel-File"
	// sessions
	EventlogSecuritySession = "Eventlog-Security" // Need special permissions
)

const (
	// finite resource
	testSessioName = "TestingGoEtw"
)

func init() {
	//rand.Seed(time.Now().UnixNano())
	// As of Go 1.20, the global random number generator is automatically seeded
}

func randBetween(min, max int) (i int) {
	for ; i < min; i = rand.Int() % max {
	}
	return
}

func TestIsKnownProvider(t *testing.T) {
	t.Parallel()

	tt := test.FromT(t)

	tt.Assert(IsKnownProvider("Microsoft-Windows-Kernel-File"))
	tt.Assert(!IsKnownProvider("Microsoft-Windows-Unknown-Provider"))
}

func TestProducerConsumer(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := test.FromT(t)

	// Producer part
	ses := NewRealTimeSession(testSessioName)
	defer ses.Stop()

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	// starting producer
	tt.CheckErr(ses.Start())
	// checking producer is running
	tt.Assert(ses.IsStarted())

	// Consumer part
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewConsumer(ctx).FromSessions(ses) //.FromTraces(EventlogSecurity)

	c.EventCallback = func(e *Event) (err error) {
		defer e.Release()
		eventCount++

		if e.System.Provider.Name == KernelFileProviderName {
			tt.Assert(e.System.EventID == 12 ||
				e.System.EventID == 13 ||
				e.System.EventID == 14 ||
				e.System.EventID == 15 ||
				e.System.EventID == 16)
		}

		_, err = json.Marshal(&e)
		tt.CheckErr(err)
		//t.Log(string(b))

		// Stop after receiving one event.
		if eventCount > 0 {
			cancel()
		}
		return err
	}

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()
	// starting consumer
	tt.CheckErr(c.Start())
	start := time.Now()

	// Wait for the consumer to be canceled.
	<-ctx.Done()

	// stopping consumer
	tt.CheckErr(c.Stop())
	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.LastError())
}

func TestKernelSession(t *testing.T) {
	tt := test.FromT(t)
	eventCount := 0

	traceFlags := []KernelNtFlag{
		// Trace process creation / termination
		//EVENT_TRACE_FLAG_PROCESS,
		// Trace image loading
		EVENT_TRACE_FLAG_IMAGE_LOAD,
		// Trace file operations
		//EVENT_TRACE_FLAG_FILE_IO_INIT,
		//EVENT_TRACE_FLAG_ALPC,
		EVENT_TRACE_FLAG_REGISTRY,
	}

	// producer part
	kp := NewKernelRealTimeSession(traceFlags...)

	// starting kernel producer
	tt.CheckErr(kp.Start())
	// checking producer is started
	tt.Assert(kp.IsStarted())

	// consumer part
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewConsumer(ctx).FromSessions(kp)

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	c.EventCallback = func(e *Event) error {
		defer e.Release()
		eventCount++

		_, err := json.Marshal(&e)
		tt.CheckErr(err)
		//t.Log(string(b))

		// Stop after receiving one event.
		if eventCount > 0 {
			cancel()
		}
		return nil
	}

	tt.CheckErr(c.Start())
	start := time.Now()

	// Wait for the context to be canceled or a timeout.
	select {
	case <-ctx.Done():
		// Canceled as expected.
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for an event")
	}

	tt.CheckErr(c.Stop())
	tt.CheckErr(kp.Stop())

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))
}

func TestEventMapInfo(t *testing.T) {
	tt := test.FromT(t)
	eventCount := 0

	prod := NewRealTimeSession(testSessioName)

	mapInfoChannels := []string{
		"Microsoft-Windows-ProcessStateManager",
		"Microsoft-Windows-DNS-Client",
		"Microsoft-Windows-Win32k",
		"Microsoft-Windows-RPC",
		"Microsoft-Windows-Kernel-IoTrace"}

	for _, c := range mapInfoChannels {
		t.Log(c)
		prov, err := ParseProvider(c)
		tt.CheckErr(err)
		tt.CheckErr(prod.EnableProvider(prov))
	}

	// starting producer
	tt.CheckErr(prod.Start())
	// checking producer is running
	tt.Assert(prod.IsStarted())

	defer prod.Stop()

	// consumer part
	fakeError := fmt.Errorf("fake")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewConsumer(ctx).FromSessions(prod)
	// TODO: remove commented code.
	// // reducing size of channel so that we are obliged to skip events
	// c.Events.Channel = make(chan []*Event)
	// c.Events.BatchSize = 1
	c.EventPreparedCallback = func(erh *EventRecordHelper) error {

		erh.TraceInfo.EventMessage()
		erh.TraceInfo.ActivityIDName()
		erh.TraceInfo.RelatedActivityIDName()

		erh.Skip()

		for _, p := range erh.PropertiesCustom {
			// calling those two method just to test they don't cause memory corruption
			p.evtPropInfo.Count()
			p.evtPropInfo.CountPropertyIndex()
			if p.evtPropInfo.MapNameOffset() > 0 {
				erh.Flags.Skip = false
			}
		}

		// don't skip events with related activity ID
		erh.Flags.Skip = erh.EventRec.ExtRelatedActivityID() == nullGUID

		return fakeError
	}

	// we have to declare a func otherwise c.Stop seems to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	c.EventCallback = func(e *Event) error {
		defer e.Release()
		eventCount++

		_, err := json.Marshal(&e)
		tt.CheckErr(err)
		if e.System.Correlation.ActivityID != nullGUIDStr && e.System.Correlation.RelatedActivityID != nullGUIDStr {
			t.Logf("Provider=%s ActivityID=%s RelatedActivityID=%s", e.System.Provider.Name, e.System.Correlation.ActivityID, e.System.Correlation.RelatedActivityID)
		}
		// Stop after receiving one event.
		if eventCount > 0 {
			cancel()
		}
		return nil
	}

	tt.CheckErr(c.Start())
	start := time.Now()

	// Wait for the context to be canceled or a timeout.
	select {
	case <-ctx.Done():
		// Canceled as expected.
	case <-time.After(10 * time.Second):
		t.Log("Test timed out waiting for an event")
		cancel() // ensure context is canceled on timeout
	}

	tt.CheckErr(c.Stop())

	// // we got many events so some must have been skipped
	// t.Logf("skipped %d events", c.Skipped.Load())
	// tt.Assert(c.Skipped.Load() == 0)

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	tt.ExpectErr(c.LastError(), fakeError)
}

func TestLostEvents(t *testing.T) {
	tt := test.FromT(t)

	// Producer part
	ses := NewRealTimeSession(testSessioName)
	// small buffer size on purpose to trigger event loss
	ses.traceProps.BufferSize = 1

	//prov, err := ParseProvider("Microsoft-Windows-Kernel-Memory" + ":0xff")
	prov, err := ParseProvider("Microsoft-Windows-Kernel-Memory" + ":0xff")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	defer ses.Stop()
	tt.CheckErr(ses.Start())

	// ! TESTING
	// // Set acces for the Eventlog-Security trace (admin is not enough)
	// const SecurityLogReadFlags2 = TRACELOG_ACCESS_REALTIME |
	// 	TRACELOG_REGISTER_GUIDS |
	// 	WMIGUID_QUERY |
	// 	WMIGUID_NOTIFICATION
	// securityLogGuid := MustParseGUID("54849625-5478-4994-a5ba-3e3b0328c30d")
	// tt.CheckErr(AddProviderAccess(securityLogGuid, "", SecurityLogReadFlags2))
	// EventAccessControl(
	// 	securityLogGuid,
	// 	uint32(EventSecuritySetSACL), // Use SET instead of ADD
	// 	nil,                             // Use current process token
	// 	SecurityLogReadFlags,
	// 	true,
	// )

	// Consumer part
	ctx := t.Context()
	c := NewConsumer(ctx).FromSessions(ses) //.FromTraces(EventlogSecurity)
	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()

	cnt := uint64(0)
	c.EventRecordCallback = func(e *EventRecord) bool {
		//for range c.Events {
		//c.ProcessEvents(func(e *Event) {
		atomic.AddUint64(&cnt, 1)
		return false
	}

	// starting consumer
	tt.CheckErr(c.Start())

	// Periodically check for lost events until they are detected or timeout.
	checkForLostEvents := func() bool {
		traceInfo, ok := c.GetTrace(testSessioName)
		if !ok {
			return false
		}
		if traceInfo.RTLostEvents.Load() > 1 {
			return true
		}
		// sessionProps, err := ses.QueryTrace()
		// if err != nil {
		// 	return false
		// }
		//return sessionProps.EventsLost > 0
		return false
	}

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			if checkForLostEvents() {
				t.Log("Lost events detected, stopping consumer.")
				break loop
			}
		case <-timeout:
			t.Log("Timed out waiting for lost events.")
			break loop
		}
	}

	// Get traceInfo reference before closing consumer
	traceInfo, ok := c.GetTrace(testSessioName)
	tt.Assert(ok, "TraceInfo not found")

	tt.CheckErr(c.Stop())
	t.Logf("Events received: %d", cnt)
	t.Logf("Events lost: %d", c.LostEvents.Load())

	// 1. Check stats from the consumer's perspective (counting RTLostEvent events).
	// This is the most direct way to see lost events as they are reported to the consumer.
	consumerLostEvents := traceInfo.RTLostEvents.Load()
	t.Logf("[Consumer] RTLostEvents count: %d", consumerLostEvents)
	t.Logf("[Consumer] RTLostBuffer: %d", traceInfo.RTLostBuffer.Load())
	t.Logf("[Consumer] RTLostFile: %d", traceInfo.RTLostFile.Load())
	tt.Assert(consumerLostEvents > 0, "Expected to lose events due to small buffer (checked via RTLostEvent)")
	tt.Assert(c.LostEvents.Load() == consumerLostEvents, "Consumer total lost events should match trace-specific lost events")

	// 2. Check stats from the session controller's perspective (querying the session).
	// This gives the total number of events lost by the session buffers.
	sessionProps, err := ses.QueryTrace()
	tt.CheckErr(err)
	sessionLostEvents := sessionProps.EventsLost
	t.Logf("[Session] Properties.EventsLost: %d", sessionLostEvents)
	tt.Assert(sessionLostEvents > 0, "Expected to lose events due to small buffer (checked via session query)")

	// 3. Check the (unreliable for real-time) stats from the buffer callback.
	// As documented, these fields are often not populated in newer versions.
	logFile := traceInfo.GetLogFileCopy()
	if logFile != nil {
		t.Logf(`[BufferCallback] EventTraceLogfile.LogfileHeader.EventsLost: %d
		 (Note: often 0 for real-time)`, logFile.LogfileHeader.GetEventsLost())
		t.Logf(`[BufferCallback] EventTraceLogfile.EventsLost: %d
		 (Note: documented as 'Not used')`, logFile.EventsLost)
	}
}

func TestConsumerCallbacks(t *testing.T) {
	var prov Provider
	var err error

	eventCount := 0
	tt := test.FromT(t)

	// Producer part
	ses := NewRealTimeSession(testSessioName)

	prov, err = ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	// enabling provider
	tt.CheckErr(ses.EnableProvider(prov))
	// starting session
	tt.CheckErr(ses.Start())
	// checking session is running (routing events to our session)
	tt.Assert(ses.IsStarted())
	kernelFileProviderChannel := prov.Name + "/Analytic"
	kernelProviderGUID := prov.GUID

	defer ses.Stop()

	// Consumer part
	ctx := t.Context()
	c := NewConsumer(ctx).FromSessions(ses) //.FromTraces(EventlogSecurity)

	c.EventRecordHelperCallback = func(erh *EventRecordHelper) (err error) {

		switch erh.EventID() {
		case 12, 14, 15, 16:
			break
		default:
			erh.Skip()
		}

		return
	}

	type file struct {
		name  string
		flags struct {
			read  bool
			write bool
		}
	}

	fileObjectMapping := make(map[string]*file)
	c.EventPreparedCallback = func(h *EventRecordHelper) error {
		tt.Assert(h.ProviderName() == prov.Name)
		tt.Assert(h.ProviderGUID() == prov.GUID)
		tt.Assert(h.EventRec.EventHeader.ProviderId.Equals(&kernelProviderGUID))
		tt.Assert(h.TraceInfo.ProviderGUID.Equals(&kernelProviderGUID))
		tt.Assert(h.ChannelName() == kernelFileProviderChannel)

		switch h.EventID() {
		case 12:
			tt.CheckErr(h.ParseProperties("FileName", "FileObject", "CreateOptions"))

			if fo, err := h.GetPropertyString("FileObject"); err == nil {
				if fn, err := h.GetPropertyString("FileName"); err == nil {
					fileObjectMapping[fo] = &file{name: fn}
				}
			}

			coUint, err := h.GetPropertyUint("CreateOptions")
			tt.CheckErr(err)
			coInt, err := h.GetPropertyInt("CreateOptions")
			tt.CheckErr(err)
			tt.Assert(coUint != 0 && coUint == uint64(coInt))

			unk, err := h.GetPropertyString("UnknownProperty")
			tt.Assert(unk == "")
			tt.ExpectErr(err, ErrUnknownProperty)

			// we skip file create events
			h.Skip()

		case 14:
			tt.CheckErr(h.ParseProperties("FileObject"))

			if object, err := h.GetPropertyString("FileObject"); err == nil {
				delete(fileObjectMapping, object)
			}

			// skip file close events
			h.Skip()

		case 15, 16:
			var f *file
			var object string
			var ok bool

			tt.CheckErr(h.ParseProperty("FileObject"))

			if object, err = h.GetPropertyString("FileObject"); err != nil {
				h.Skip()
				break
			}

			foUint, _ := h.GetPropertyUint("FileObject")
			tt.Assert(fmt.Sprintf("0x%X", foUint) == object)

			if f, ok = fileObjectMapping[object]; !ok {
				// we skip events we cannot enrich
				h.Skip()
				break
			}

			if (h.EventID() == 15 && f.flags.read) ||
				(h.EventID() == 16 && f.flags.write) {
				h.Skip()
				break
			}

			h.SetCustomProperty("FileName", f.name)
			f.flags.read = (h.EventID() == 15)
			f.flags.write = (h.EventID() == 16)

		default:
			h.Skip()
		}

		return nil
	}

	//testfile := `\Windows\Temp\test.txt`
	testfile := filepath.Join(t.TempDir()[2:], "test.txt")
	// Strip drive letter from testfile (e.g. "E:" -> "")
	t.Logf("testfile: %s", testfile)

	var etwread int32
	var etwwrite int32

	pid := os.Getpid()
	c.EventCallback = func(e *Event) error {
		defer e.Release()
		eventCount++

		_, err := json.Marshal(&e)
		tt.CheckErr(err)
		switch e.System.EventID {
		case 15, 16:
			var fn string
			var ok bool

			if fn, ok = e.GetPropertyString("FileName"); !ok {
				break
			}

			if !strings.Contains(fn, testfile) {
				break
			}

			if e.System.Execution.ProcessID != uint32(pid) {
				break
			}

			if e.System.EventID == 15 {
				atomic.AddInt32(&etwread, 1)
			} else {
				atomic.AddInt32(&etwwrite, 1)
			}
		}
		return nil
	}

	// we have to declare a func otherwise c.Stop does not seem to be called
	defer func() { tt.CheckErr(c.Stop()) }()
	// starting consumer
	tt.CheckErr(c.Start())
	start := time.Now()

	// creating test files
	nReadWrite := 0
	//tf := fmt.Sprintf("C:%s", testfile) // error
	tf := testfile
	for ; nReadWrite < randBetween(800, 1000); nReadWrite++ {
		tmp := fmt.Sprintf("%s.%d", tf, nReadWrite)
		tt.CheckErr(os.WriteFile(tmp, []byte("testdata"), 0644))
		_, err = os.ReadFile(tmp)
		tt.CheckErr(err)
		time.Sleep(time.Millisecond)
	}

	// Wait until all generated file events are received or timeout.
	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&etwread) >= int32(nReadWrite) && atomic.LoadInt32(&etwwrite) >= int32(nReadWrite) {
				t.Log("All file IO events received.")
				// Wait a bit longer to catch any potential extra events.
				time.Sleep(2 * time.Second)
				break loop
			}
		case <-timeout:
			t.Log("Timed out waiting for all file IO events.")
			break loop
		}
	}

	// stopping consumer
	tt.CheckErr(c.Stop())

	tt.Assert(eventCount != 0, "did not receive any event")
	// tt.Assert(c.Skipped.Load() == 0)
	// verifying that we caught all events
	t.Logf("read=%d etwread=%d", nReadWrite, atomic.LoadInt32(&etwread))
	tt.Assert(nReadWrite == int(atomic.LoadInt32(&etwread)))
	t.Logf("write=%d etwwrite=%d", nReadWrite, atomic.LoadInt32(&etwwrite))
	tt.Assert(nReadWrite == int(atomic.LoadInt32(&etwwrite)))

	delta := time.Since(start)
	eps := float64(eventCount) / delta.Seconds()
	t.Logf("Received: %d events in %s (%d EPS)", eventCount, delta, int(eps))

	// checking any consumer error
	tt.CheckErr(c.LastError())
}

func TestParseProvider(t *testing.T) {
	t.Parallel()

	tt := test.FromT(t)

	// Test case 1: Just name
	p, err := ParseProvider(KernelFileProviderName)
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 0xff, "Default level should be 0xff")
	tt.Assert(p.MatchAnyKeyword == 0xffffffffffffffff, "Default MatchAnyKeyword should be all 1s")
	tt.Assert(p.MatchAllKeyword == 0, "Default MatchAllKeyword should be 0")
	tt.Assert(len(p.Filters) == 0, "Default should have no filters")

	// Test case 2: Name and Level
	p, err = ParseProvider(KernelFileProviderName + ":10")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 10, "Level should be parsed")

	// Test case 3: Name, Level, and EventIDs
	p, err = ParseProvider(KernelFileProviderName + ":10:1,2,3")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 10, "Level should be parsed")
	tt.Assert(p.MatchAnyKeyword == 0xffffffffffffffff, "Keyword should be default when only IDs are provided")
	tt.Assert(len(p.Filters) == 1, "Should have one filter")
	if idFilter, ok := p.Filters[0].(*EventIDFilter); ok {
		tt.Assert(len(idFilter.IDs) == 3, "Should have 3 event IDs")
		tt.Assert(idFilter.IDs[0] == 1 && idFilter.IDs[1] == 2 && idFilter.IDs[2] == 3, "Event IDs mismatch")
	} else {
		t.Fatal("Expected EventIDFilter")
	}

	// Test case 4: Name, Level, MatchAnyKeyword, and EventIDs
	p, err = ParseProvider(KernelFileProviderName + ":10:1,2,3:0x42")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 10)
	tt.Assert(p.MatchAnyKeyword == 0x42)
	tt.Assert(p.MatchAllKeyword == 0)
	tt.Assert(len(p.Filters) == 1)

	// Test case 5: Name, Level, MatchAnyKeyword, MatchAllKeyword, and EventIDs
	p, err = ParseProvider(KernelFileProviderName + ":10:1,2,3:0x42:0x1337")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 10)
	tt.Assert(p.MatchAnyKeyword == 0x42)
	tt.Assert(p.MatchAllKeyword == 0x1337)
	tt.Assert(len(p.Filters) == 1)

	// Test case 6: Skipping MatchAnyKeyword but providing MatchAllKeyword
	p, err = ParseProvider(KernelFileProviderName + ":10:1,2,3::0x1337")
	tt.CheckErr(err)
	tt.Assert(p.EnableLevel == 10)
	tt.Assert(p.MatchAnyKeyword == 0xffffffffffffffff, "MatchAnyKeyword should be default when skipped")
	tt.Assert(p.MatchAllKeyword == 0x1337)
	tt.Assert(len(p.Filters) == 1)

	// this calls must panic on error
	MustParseProvider(KernelFileProviderName)
	tt.ShouldPanic(func() { MustParseProvider("Microsoft-Unknown-Provider") })
}

func TestConvertSid(t *testing.T) {
	t.Parallel()

	var sid *SID
	var err error

	tt := test.FromT(t)
	systemSID := "S-1-5-18"

	sid, err = ConvertStringSidToSidW(systemSID)
	tt.CheckErr(err)
	tt.Log(sid)
}

func TestSessionSlice(t *testing.T) {
	t.Parallel()

	tt := test.FromT(t)

	intSlice := make([]int, 0)
	sessions := make([]Session, 0)
	for i := range 10 {
		sessions = append(sessions, NewRealTimeSession(fmt.Sprintf("test-%d", i)))
		intSlice = append(intSlice, i)
	}

	tt.Assert(len(SessionSlice(sessions)) == len(sessions))
	// should panic because parameter is not a slice
	tt.ShouldPanic(func() { SessionSlice(sessions[0]) })
	// should panic because items do not implement Session
	tt.ShouldPanic(func() { SessionSlice(intSlice) })
}

// When TestingGoEtw session buffer fills up due to high event rate from providers
// CloseTrace will not terminate ProcessTrace, the docs don't mention this in detail
// but ProcessTrace will exit only when all remaining events are processed
// (means, that callback has been called an returned from each remaining event)
// bufferCallback returning 0 will NOT cause ProcessTrace to exit inmediately.
// it still has to wait as if CloseTrace was called. (you can debug this to see it)
//
// Since we are using a sleep inside the callback on purpose, ProcessTrace will
// not end, thus the goroutine will not trigger Done() signaling that it ended.
// This will cause c.Wait() to wait for too long, an hour with this test.
// The test will use StopWithTimeout to limit the consumer if after a certain
// amount of time ProcessTrace does not exit after timeout it will terminate
// the goroutine.
// Abort is the same but with no timeout.
func TestCallbackConcurrency(t *testing.T) {
	tt := test.FromT(t)
	SetLogDebugLevel()

	ctx := tt.Context()
	c := NewConsumer(ctx)

	c.EventRecordHelperCallback = nil
	c.EventPreparedCallback = nil
	c.EventCallback = nil

	var callCount atomic.Int32
	var concurrent atomic.Bool
	var currentlyExecuting atomic.Int32

	// Replace default callback with test version
	c.EventRecordCallback = func(er *EventRecord) bool {
		callCount.Add(1)

		// If another callback is already executing, we have concurrent execution
		if currentlyExecuting.Add(1) > 1 {
			concurrent.Store(true)
		}
		time.Sleep(100 * time.Millisecond) // Force overlap if concurrent
		currentlyExecuting.Add(-1)
		return true
	}

	s := NewRealTimeSession("TestingGoEtw")
	defer s.Stop()

	// add some potential high volume providers
	providers := []string{
		"Microsoft-Windows-Kernel-Process",
		"Microsoft-Windows-Kernel-File:0xff:12,13,14,15,16",
	}
	for _, pstr := range providers {
		prov, err := ParseProvider(pstr)
		if err != nil {
			t.Fatalf("Parse provider error: %v", err)
		}
		if err := s.EnableProvider(prov); err != nil {
			t.Fatalf("Enable provider error: %v", err)
		}
	}

	// Open multiple traces to force potential concurrent execution
	c.FromSessions(s).
		FromTraces("EventLog-System").
		FromTraces("EventLog-Application").
		FromTraces("Steam Event Tracing")

	tt.CheckErr(c.Start())

	// Wait until we've seen a few callbacks or a timeout occurs.
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
waitLoop:
	for {
		select {
		case <-timeout:
			t.Log("Test duration finished.")
			break waitLoop
		case <-ticker.C:
			if callCount.Load() > 5 {
				t.Log("Sufficient callbacks executed.")
				break waitLoop
			}
		}
	}

	t.Logf("Waiting for consumer to stop")
	// Stop consumer before checking results
	done := make(chan struct{})
	go func() {
		tt.CheckErr(c.StopWithTimeout(5 * time.Second))
		//tt.CheckErr(c.Abort())
		//tt.CheckErr(c.Stop())
		c.Wait() // make sure the goroutines are actually ended.
		close(done)
	}()

	//time.Sleep(5 * time.Hour)

	select {
	case <-done:
		// Test passed
	case <-time.After(15 * time.Second):
		t.Fatal("c.Wait() did not return within 15 seconds")
		os.Exit(1)
	}

	// This is useful for debugging etw
	t.Logf("Total callbacks executed: %d", callCount.Load())
	if concurrent.Load() {
		t.Logf("Callbacks executed concurrently")
	}
}

type FilterBehavior int

const (
	BehaviorUnknown FilterBehavior = iota
	BehaviorUnsupported
	BehaviorIgnored
	BehaviorApplied
)

func (b FilterBehavior) String() string {
	switch b {
	case BehaviorUnsupported:
		return "Unsupported"
	case BehaviorIgnored:
		return "Ignored"
	case BehaviorApplied:
		return "Applied"
	default:
		return "Unknown"
	}
}

// Helper to compare static properties between two trace properties
func assertStaticPropsEqual(t *test.T, expected, actual *EventTraceProperties2Wrapper, contextMsg string) {
	t.Assertf(actual.BufferSize == expected.BufferSize,
		"%s: BufferSize mismatch: expected=%d, got=%d",
		contextMsg, expected.BufferSize, actual.BufferSize)
	t.Assertf(actual.MinimumBuffers == expected.MinimumBuffers,
		"%s: MinimumBuffers mismatch: expected=%d, got=%d",
		contextMsg, expected.MinimumBuffers, actual.MinimumBuffers)
	t.Assertf(actual.MaximumBuffers == expected.MaximumBuffers,
		"%s: MaximumBuffers mismatch: expected=%d, got=%d",
		contextMsg, expected.MaximumBuffers, actual.MaximumBuffers)
	t.Assertf(actual.LogFileMode == expected.LogFileMode,
		"%s: LogFileMode mismatch: expected=%d, got=%d",
		contextMsg, expected.LogFileMode, actual.LogFileMode)
}

// Helper to validate trace name
func assertTraceName(t *test.T, prop *EventTraceProperties2Wrapper, expectedName string, contextMsg string) {
	name := FromUTF16Pointer(prop.GetTraceName())
	t.Assertf(name == expectedName,
		"%s: Name mismatch: expected=%s, got=%s",
		contextMsg, expectedName, name)
}

// Helper to validate runtime stats
func assertRuntimeStats(t *test.T, prop *EventTraceProperties2Wrapper, contextMsg string) {
	t.Assertf(prop.NumberOfBuffers > 0,
		"%s: Expected NumberOfBuffers > 0, got %d",
		contextMsg, prop.NumberOfBuffers)
	t.Assertf(prop.BuffersWritten > 0,
		"%s: Expected BuffersWritten > 0, got %d",
		contextMsg, prop.BuffersWritten)
}

// Helper to compare runtime stats between properties
func assertRuntimeStatsEqual(t *test.T, expected, actual *EventTraceProperties2Wrapper, contextMsg string) {
	t.Assertf(actual.NumberOfBuffers == expected.NumberOfBuffers,
		"%s: NumberOfBuffers mismatch: expected=%d, got=%d",
		contextMsg, expected.NumberOfBuffers, actual.NumberOfBuffers)
	t.Assertf(actual.BuffersWritten == expected.BuffersWritten,
		"%s: BuffersWritten mismatch: expected=%d, got=%d",
		contextMsg, expected.BuffersWritten, actual.BuffersWritten)
	t.Assertf(actual.EventsLost == expected.EventsLost,
		"%s: EventsLost mismatch: expected=%d, got=%d",
		contextMsg, expected.EventsLost, actual.EventsLost)
}

// TestQueryTraceMethods comprehensively tests the different ways to query trace session properties:
// 1. As a session controller (`Session.QueryTrace`).
// 2. As a consumer attached to a session (`ConsumerTrace.QueryTrace`).
// 3. As an independent process using the global `QueryTrace` function.
// It verifies that static properties are consistent across all methods and that runtime
// statistics are updated correctly.
func TestQueryTraceMethods(t *testing.T) {
	tt := test.FromT(t)
	loggerName := testSessioName
	//loggerNameW, err := syscall.UTF16PtrFromString(loggerName)
	//tt.CheckErr(err)

	t.Log("Phase 1: Session Setup & Initial Controller Query")
	ses := NewRealTimeSession(loggerName)
	prov, err := ParseProvider(KernelFileProviderName + ":0xff:12,13,14,15,16")
	tt.CheckErr(err)
	tt.CheckErr(ses.EnableProvider(prov))
	tt.CheckErr(ses.Start())
	defer ses.Stop()

	// Query via Session (Controller's view)
	sesData, err := ses.QueryTrace()
	tt.CheckErr(err)
	assertTraceName(tt, sesData, loggerName, "1. Session.QueryTrace (Controller)")

	t.Log("Phase 2: Global and Consumer Queries")
	// Query using global function (Independent process view)
	gloData := NewQueryTraceProperties(loggerName)
	tt.CheckErr(QueryTrace(gloData))
	assertTraceName(tt, gloData, loggerName, "2. Global QueryTrace (Independent)")
	assertStaticPropsEqual(tt, sesData, gloData, "Controller vs. Independent (Static)")

	// Compare initial properties
	assertStaticPropsEqual(tt, sesData, gloData, "Initial Session vs Global")

	// Setup consumer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewConsumer(ctx).FromSessions(ses)

	eventsReceived := uint32(0)
	c.EventCallback = func(e *Event) error {
		defer e.Release()
		if atomic.AddUint32(&eventsReceived, 1) > 10 {
			cancel()
		}
		return nil
	}

	defer c.Stop()
	tt.CheckErr(c.Start())

	// Query via Consumer (Consumer's view)
	conTrace, ok := c.GetTrace(loggerName)
	tt.Assert(ok, "Failed to get ConsumerTrace object")
	conProp, err := conTrace.QueryTrace()
	tt.CheckErr(err)
	tt.Assert(conProp != nil, "Expected conProp to be non-nil")
	assertTraceName(tt, conProp, loggerName, "3. ConsumerTrace.QueryTrace (Consumer)")
	assertStaticPropsEqual(tt, sesData, conProp, "Controller vs. Consumer (Static)")

	t.Log("Phase 3: Runtime Stats Validation")

	// Wait for context to be canceled or timeout
	select {
	case <-ctx.Done():
		// Canceled as expected
	case <-time.After(10 * time.Second):
		t.Log("Timed out waiting for events")
	}

	tt.CheckErr(c.Stop())

	// Query final properties from all three perspectives
	sesData2, err := ses.QueryTrace()
	tt.CheckErr(err)
	tt.CheckErr(QueryTrace(gloData)) // reusing prop struct.
	conProp2, err := conTrace.QueryTrace()
	tt.CheckErr(err)

	// Validate runtime stats are updated and consistent
	t.Logf("Final stats: BuffersWritten=%d, EventsLost=%d", sesData2.BuffersWritten, sesData2.EventsLost)
	assertRuntimeStats(tt, sesData2, "Final Session Stats")
	assertRuntimeStatsEqual(tt, sesData2, gloData, "Final Session vs Global")
	assertRuntimeStatsEqual(tt, sesData2, conProp2, "Final Session vs Consumer")

	t.Log("Phase 4: Error Cases")
	badData := NewQueryTraceProperties("NonExistentTrace_XYZ")
	err = QueryTrace(badData)
	tt.Assert(err != nil, "Expected error for non-existent trace")

	// Log final events count
	t.Logf("Total events received: %d", atomic.LoadUint32(&eventsReceived))
	tt.Assert(atomic.LoadUint32(&eventsReceived) > 0, "Expected events > 0")
}

// TestConsumerTrace_QueryTraceFail validates that calling QueryTrace on a standalone
// ConsumerTrace object that is not associated with a running session correctly fails.
func TestConsumerQueryTraceFail(t *testing.T) {
	tt := test.FromT(t)
	_ = tt

	// This test validates that calling QueryTrace on a standalone ConsumerTrace
	// object that is not associated with a running session correctly fails.
	trace := newConsumerTrace("non-existent-trace")
	trace.realtime = true

	prop, err := trace.QueryTrace()
	tt.Assert(err != nil, "Expected an error when querying a non-existent trace")
	tt.Assert(prop == nil, "Expected properties to be nil on failure")
}

// TestEnableProperties validates that setting EnableProperties on a provider
// correctly includes the requested extended data in the event record.
func TestEnableProperties(t *testing.T) {
	tt := test.FromT(t)
	sessionName := testSessioName

	_ = StopSession(sessionName)
	time.Sleep(250 * time.Millisecond)

	providersToTest := []string{
		"Microsoft-Windows-RPC",
		"Microsoft-Windows-Kernel-Process",
		"Microsoft-Windows-Kernel-File",
	}

	// Just test these is enough
	enableProperties := EVENT_ENABLE_PROPERTY_PROCESS_START_KEY |
		EVENT_ENABLE_PROPERTY_SID |
		EVENT_ENABLE_PROPERTY_EVENT_KEY |
		EVENT_ENABLE_PROPERTY_STACK_TRACE

	// Track which properties we've seen in any event
	var seenStartKey, seenSID, seenEventKey, seenStackTrace atomic.Bool

	_ = StopSession(sessionName)
	time.Sleep(100 * time.Millisecond)

	ses := NewRealTimeSession(sessionName)
	defer ses.Stop()

	for _, providerName := range providersToTest {
		prov, err := ParseProvider(providerName)
		if err != nil {
			tt.Fatalf("ParseProvider(%s): %v", providerName, err)
		}
		prov.EnableProperties = uint32(enableProperties)
		if err := ses.EnableProvider(prov); err != nil {
			tt.Fatalf("EnableProvider(%s): %v", providerName, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewConsumer(ctx).FromSessions(ses)

	c.EventPreparedCallback = func(erh *EventRecordHelper) error {
		if !seenStartKey.Load() {
			_, has := erh.EventRec.ExtProcessStartKey()
			if has {
				seenStartKey.Store(true)
				tt.Log("Found ProcessStartKey")
			}
		}
		if !seenSID.Load() {
			sid := erh.EventRec.ExtSid()
			if sid != nil {
				seenSID.Store(true)
				tt.Log("Found SID")
			}
		}
		if !seenEventKey.Load() {
			_, has := erh.EventRec.ExtEventKey()
			if has {
				seenEventKey.Store(true)
				tt.Log("Found EventKey")
			}
		}
		if !seenStackTrace.Load() {
			stack, has := erh.EventRec.ExtStackTrace()
			if has && len(stack.Addresses) > 0 {
				seenStackTrace.Store(true)
				tt.Log("Found StackTrace")
			}
		}
		// If all properties have been seen, stop the test early
		if seenStartKey.Load() && seenSID.Load() && seenEventKey.Load() && seenStackTrace.Load() {
			cancel()
		}
		return nil
	}

	if err := c.Start(); err != nil {
		tt.Fatalf("Consumer.Start: %v", err)
	}

	// Wait for events or timeout
	timeout := time.After(10 * time.Second)
	select {
	case <-ctx.Done():
		// All properties found
	case <-timeout:
		tt.Log("Timeout reached before all properties were found")
	}

	_ = c.Stop()
	_ = ses.Stop()

	tt.Assert(seenStartKey.Load(), "Did not see ProcessStartKey in any event")
	tt.Assert(seenSID.Load(), "Did not see SID in any event")
	tt.Assert(seenEventKey.Load(), "Did not see EventKey in any event")
	tt.Assert(seenStackTrace.Load(), "Did not see StackTrace in any event")
}

// TestManifestCache validates the library's TraceEventInfo caching, specifically checking
// that the cache correctly handles multiple sessions enabling the same provider with
// different keywords.
func TestManifestCache(t *testing.T) {
	// NOTE: Dont test MOF providers, they can be cached from generated mof shecmas wich have more lax enforcement

	// --- Setup: Two sessions, multiple providers, with mirrored but different keyword sets ---
	providersToTest := map[string][2]uint64{
		"Microsoft-Windows-Kernel-Process": {0x10, 0x20},   // Process vs Thread
		"Microsoft-Windows-Kernel-File":    {0x100, 0x200}, // Read vs Write
		"Microsoft-Windows-Kernel-Memory":  {0x100, 0x200}, // Page Fault vs Hard Fault
	}

	session1 := NewRealTimeSession(testSessioName)
	defer session1.Stop()
	session2 := NewRealTimeSession("GolangTest2")
	defer session2.Stop()

	for name, keywords := range providersToTest {
		provider, err := ParseProvider(name)
		if err != nil {
			t.Fatalf("Failed to parse provider %s: %v", name, err)
		}

		// Enable provider on session 1 with the first keyword.
		provider1 := provider
		provider1.MatchAnyKeyword = keywords[0]
		if err := session1.EnableProvider(provider1); err != nil {
			t.Logf("Failed to enable %s on session 1: %v", name, err)
		}

		// Enable provider on session 2 with the second keyword.
		provider2 := provider
		provider2.MatchAnyKeyword = keywords[1]
		if err := session2.EnableProvider(provider2); err != nil {
			t.Logf("Failed to enable %s on session 2: %v", name, err)
		}
	}

	if err := session1.Start(); err != nil {
		t.Fatalf("Failed to start session 1: %v", err)
	}
	if err := session2.Start(); err != nil {
		t.Fatalf("Failed to start session 2: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	// Consume from both sessions simultaneously.
	consumer := NewConsumer(ctx).FromSessions(session1, session2)

	var eventsCompared, compareMismatches atomic.Uint64

	consumer.EventRecordHelperCallback = func(erh *EventRecordHelper) error {
		erh.Skip()
		if erh.TraceInfo == nil || erh.EventRec.IsMof() {
			return nil
		}
		eventsCompared.Add(1)

		var originalTeiBuffer []byte
		originalTei, err := erh.EventRec.GetEventInformation(&originalTeiBuffer)
		if err != nil {
			return nil
		}

		// We perform a deep comparison of the cached TraceInfo struct
		// against a freshly retrieved one from the API.
		mismatchMask := compareTraceInfo(erh.TraceInfo, originalTei, t, false)
		if mismatchMask != MismatchNone {
			compareMismatches.Add(1)
			t.Errorf("CRITICAL: Manifest event cache mismatch for event (Provider: %s, ID: %d). This indicates a flaw in the caching logic.",
				originalTei.ProviderName(), originalTei.EventID())
			// The compareTraceInfo function already logs detailed mismatch info.
			cancel()
		}
		return nil
	}
	consumer.EventPreparedCallback = nil
	consumer.EventCallback = nil

	if err := consumer.Start(); err != nil {
		t.Fatalf("Failed to start consumer: %v", err)
	}
	defer consumer.Stop()

	t.Log("Starting manifest cache validation for 10 seconds...")
	<-ctx.Done()

	t.Log("Finished event collection.")
	t.Logf("--- Manifest Cache Validation Report ---")
	t.Logf("  Manifest Events Compared: %d", eventsCompared.Load())
	t.Logf("  Blob Mismatches (Cache):  %d", compareMismatches.Load())
	t.Logf("-------------------------------------------")

	if compareMismatches.Load() > 0 {
		t.Fatal("Test failed due to critical mismatches in manifest cache.")
	}
}

// Mismatch constants for compareTraceEventInfo bitmask.
const (
	MismatchNone      = 0
	MismatchClassName = 1 << 0 // TaskName or OpcodeName
	MismatchOutType   = 1 << 1 // Specific OutType differences allowed for MOF
	MismatchLength    = 1 << 2 // Specific Length differences allowed for MOF
	MismatchFlags     = 1 << 3 // Specific Flags differences allowed for MOF
	MismatchOther     = 1 << 4 // Any other (critical) difference
)

// compareTraceInfo is a shared helper to compare a generated TEI with an original from the API.
// It returns a bitmask of mismatch types and logs detailed debug info if corresponding flags are set.
func compareTraceInfo(generated, original *TraceEventInfo, t *testing.T, isMof bool) int {
	t.Helper()
	mismatchMask := MismatchNone
	eventName := fmt.Sprintf("Event '%s' (Provider: %s, Opcode: %d)", original.TaskName(), original.ProviderName(), original.EventDescriptor.Opcode)

	// Helper for logging mismatches.
	logMismatch := func(field string, gen, org any) {
		mismatchMask |= MismatchOther
		t.Logf("CRITICAL MISMATCH: %s for %s\n  - Have: %v\n  - Want: %v", field, eventName, gen, org)
	}

	// --- Header Comparison ---
	if generated.ProviderGUID != original.ProviderGUID {
		logMismatch("ProviderGUID", generated.ProviderGUID, original.ProviderGUID)
	}
	if generated.EventGUID != original.EventGUID {
		logMismatch("EventGUID", generated.EventGUID, original.EventGUID)
	}
	if generated.EventDescriptor != original.EventDescriptor {
		logMismatch("EventDescriptor", fmt.Sprintf("%+v", generated.EventDescriptor), fmt.Sprintf("%+v", original.EventDescriptor))
	}
	if generated.DecodingSource != original.DecodingSource {
		logMismatch("DecodingSource", generated.DecodingSource, original.DecodingSource)
	}
	if generated.PropertyCount != original.PropertyCount {
		logMismatch("PropertyCount", generated.PropertyCount, original.PropertyCount)
		return mismatchMask // Stop property comparison if counts differ.
	}
	if generated.TopLevelPropertyCount != original.TopLevelPropertyCount {
		logMismatch("TopLevelPropertyCount", generated.TopLevelPropertyCount, original.TopLevelPropertyCount)
	}
	if generated.Flags != original.Flags {
		if isMof {
			mismatchMask |= MismatchFlags
			if *mofDebugFlags {
				t.Logf("DEBUG: Flags mismatch for MOF %s\n  - Have: %d\n  - Want: %d", eventName, generated.Flags, original.Flags)
			}
		} else {
			logMismatch("Flags", generated.Flags, original.Flags)
		}
	}

	// --- String & Union Comparison ---
	if generated.ProviderName() != original.ProviderName() {
		logMismatch("ProviderName", generated.ProviderName(), original.ProviderName())
	}
	if generated.LevelName() != original.LevelName() {
		logMismatch("LevelName", generated.LevelName(), original.LevelName())
	}
	if generated.ChannelName() != original.ChannelName() {
		logMismatch("ChannelName", generated.ChannelName(), original.ChannelName())
	}
	if generated.EventMessage() != original.EventMessage() {
		logMismatch("EventMessage", generated.EventMessage(), original.EventMessage())
	}
	if generated.ProviderMessage() != original.ProviderMessage() {
		logMismatch("ProviderMessage", generated.ProviderMessage(), original.ProviderMessage())
	}
	if generated.TaskName() != original.TaskName() || generated.OpcodeName() != original.OpcodeName() {
		if isMof {
			mismatchMask |= MismatchClassName
			if *mofDebugClassName {
				t.Logf("DEBUG: ClassName mismatch for MOF %s\n  - TaskName: Have: '%s', Want: '%s'\n  - OpcodeName: Have: '%s', Want: '%s'",
					eventName, generated.TaskName(), original.TaskName(), generated.OpcodeName(), original.OpcodeName())
			}
		} else {
			logMismatch("Task/OpcodeName", generated.TaskName()+"/"+generated.OpcodeName(), original.TaskName()+"/"+original.OpcodeName())
		}
	}
	if generated.EventName() != original.EventName() {
		logMismatch("EventName", generated.EventName(), original.EventName())
	}
	if generated.ActivityIDName() != original.ActivityIDName() {
		logMismatch("ActivityIDName", generated.ActivityIDName(), original.ActivityIDName())
	}
	if generated.EventAttributes() != original.EventAttributes() {
		logMismatch("EventAttributes", generated.EventAttributes(), original.EventAttributes())
	}
	if generated.RelatedActivityIDName() != original.RelatedActivityIDName() {
		logMismatch("RelatedActivityIDName", generated.RelatedActivityIDName(), original.RelatedActivityIDName())
	}

	// --- Property Array Comparison ---
	for i := uint32(0); i < original.PropertyCount; i++ {
		genEpi := generated.GetEventPropertyInfoAt(i)
		orgEpi := original.GetEventPropertyInfoAt(i)
		propName := original.stringAt(uintptr(orgEpi.NameOffset))
		propContext := fmt.Sprintf("Prop[%d:%s] in %s", i, propName, eventName)

		logPropMismatch := func(field string, gen, org any) {
			mismatchMask |= MismatchOther
			t.Logf("CRITICAL MISMATCH: %s for %s\n  - Have: %v\n  - Want: %v", field, propContext, gen, org)
		}

		if generated.stringAt(uintptr(genEpi.NameOffset)) != propName {
			logPropMismatch("Name", generated.stringAt(uintptr(genEpi.NameOffset)), propName)
		}
		if genEpi.Flags != orgEpi.Flags {
			if isMof {
				mismatchMask |= MismatchFlags
				if *mofDebugFlags {
					t.Logf("DEBUG: Prop Flags mismatch for %s\n  - Have: %#x\n  - Want: %#x", propContext, genEpi.Flags, orgEpi.Flags)
				}
			} else {
				logPropMismatch("Flags", fmt.Sprintf("%#x", genEpi.Flags), fmt.Sprintf("%#x", orgEpi.Flags))
			}
		}

		// Compare unions based on flags
		if (orgEpi.Flags & PropertyStruct) != 0 {
			if genEpi.StructStartIndex() != orgEpi.StructStartIndex() || genEpi.NumOfStructMembers() != orgEpi.NumOfStructMembers() {
				logPropMismatch("StructInfo",
					fmt.Sprintf("{Start: %d, Members: %d}", genEpi.StructStartIndex(), genEpi.NumOfStructMembers()),
					fmt.Sprintf("{Start: %d, Members: %d}", orgEpi.StructStartIndex(), orgEpi.NumOfStructMembers()))
			}
		} else {
			if genEpi.InType() != orgEpi.InType() {
				isPointerSizeMismatch := isMof &&
					((genEpi.InType() == TDH_INTYPE_POINTER && orgEpi.InType() == TDH_INTYPE_SIZET) ||
						(genEpi.InType() == TDH_INTYPE_SIZET && orgEpi.InType() == TDH_INTYPE_POINTER))
				if !isPointerSizeMismatch {
					logPropMismatch("InType", genEpi.InType(), orgEpi.InType())
				}
			}
			if genEpi.OutType() != orgEpi.OutType() {
				isStringNullMismatch := isMof &&
					((genEpi.OutType() == TDH_OUTTYPE_STRING && orgEpi.OutType() == TDH_OUTTYPE_NULL) ||
						(genEpi.OutType() == TDH_OUTTYPE_NULL && orgEpi.OutType() == TDH_OUTTYPE_STRING))
				if !isStringNullMismatch {
					if isMof {
						mismatchMask |= MismatchOutType
						if *mofDebugOutType {
							t.Logf("DEBUG: OutType mismatch for %s\n  - Have: %s\n  - Want: %s", propContext, genEpi.OutType(), orgEpi.OutType())
						}
					} else {
						logPropMismatch("OutType", genEpi.OutType(), orgEpi.OutType())
					}
				}
			}
			if generated.stringAt(uintptr(genEpi.MapNameOffset())) != original.stringAt(uintptr(orgEpi.MapNameOffset())) {
				logPropMismatch("MapName", generated.stringAt(uintptr(genEpi.MapNameOffset())), original.stringAt(uintptr(orgEpi.MapNameOffset())))
			}
		}

		if genEpi.CountUnion != orgEpi.CountUnion {
			logPropMismatch("CountUnion", genEpi.CountUnion, orgEpi.CountUnion)
		}
		if genEpi.LengthUnion != orgEpi.LengthUnion {
			if isMof && (orgEpi.Flags&PropertyParamLength) == 0 {
				mismatchMask |= MismatchLength
				if *mofDebugLength {
					t.Logf("DEBUG: Length mismatch for %s\n  - Have: %d\n  - Want: %d", propContext, genEpi.Length(), orgEpi.Length())
				}
			} else if !isMof {
				logPropMismatch("LengthUnion", genEpi.LengthUnion, orgEpi.LengthUnion)
			}
		}
		if genEpi.ResTagUnion != orgEpi.ResTagUnion {
			logPropMismatch("ResTagUnion", genEpi.ResTagUnion, orgEpi.ResTagUnion)
		}
	}
	return mismatchMask
}
