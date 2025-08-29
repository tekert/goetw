//go:build windows

package etw

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync/atomic"
	"testing"
	"time"
)

// Command-line flags to enable verbose logging for specific mismatch types.
var (
	mofDebugClassName = flag.Bool("mof.debug.classname", false, "Print details for MOF TaskName/OpcodeName mismatches")
	mofDebugOutType   = flag.Bool("mof.debug.outtype", false, "Print details for MOF OutType mismatches")
	mofDebugLength    = flag.Bool("mof.debug.length", false, "Print details for MOF Length mismatches")
	mofDebugFlags     = flag.Bool("mof.debug.flags", false, "Print details for MOF property Flags mismatches")
)

// TestMofGenerator validates the buildTraceInfoFromMof function against the live TDH API.
// It runs a kernel session, and for each classic MOF event, it generates a TraceEventInfo
// and compares it field-by-field against the one returned by the API.
func TestMofGenerator(t *testing.T) {

	// 	// Enable all kernel providers for a comprehensive test.
	// var allKernelFlags uint32
	// for _, kp := range KernelProviders {
	// 	allKernelFlags |= kp.Flags
	// }
	// // Disable PROFILE flag as it can be very noisy and is not a MOF provider.
	// allKernelFlags ^= EVENT_TRACE_FLAG_PROFILE

	kernelFlags := KernelNtFlag(
		EVENT_TRACE_FLAG_DISK_FILE_IO |
			EVENT_TRACE_FLAG_FILE_IO |
			EVENT_TRACE_FLAG_CSWITCH |
			EVENT_TRACE_FLAG_DPC)

	session := NewKernelRealTimeSession(kernelFlags)
	if err := session.Start(); err != nil {
		t.Fatalf("Failed to start kernel session: %v", err)
	}
	defer session.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	consumer := NewConsumer(ctx).FromSessions(session)

	var (
		mofEventsCompared  atomic.Uint64
		criticalMismatches atomic.Uint64
		mismatchCounts     = make(map[string]*atomic.Uint64)
	)
	mismatchTypes := []string{"ClassName", "OutType", "Length", "Flags"}
	for _, mt := range mismatchTypes {
		mismatchCounts[mt] = &atomic.Uint64{}
	}

	// We use EventRecordCallback for efficiency, as we don't need the full helper.
	consumer.EventRecordCallback = func(er *EventRecord) bool {
		if !er.IsMof() {
			return true // Continue processing.
		}
		mofEventsCompared.Add(1)

		// Get the "ground truth" from the API.
		var originalTeiBuffer []byte
		originalTei, err := er.GetEventInformation(&originalTeiBuffer)
		if err != nil {
			return true // Can't compare if API fails.
		}

		// Generate our version to be tested.
		var generatedTeiBuffer []byte
		generatedTei, err := buildTraceInfoFromMof(er, &generatedTeiBuffer)
		if err != nil {
			return true // Our generator doesn't have a definition for this event.
		}

		// Perform the comparison.
		mismatchMask := compareTraceInfo(generatedTei, originalTei, t, true)
		if mismatchMask == MismatchNone {
			return true
		}

		// Process the results.
		if (mismatchMask & MismatchOther) != 0 {
			criticalMismatches.Add(1)
			t.Errorf("CRITICAL mismatch for MOF event (Provider: %s, Opcode: %d)",
				originalTei.ProviderName(), originalTei.EventDescriptor.Opcode)
			cancel()
		}
		if (mismatchMask & MismatchClassName) != 0 {
			mismatchCounts["ClassName"].Add(1)
		}
		if (mismatchMask & MismatchOutType) != 0 {
			mismatchCounts["OutType"].Add(1)
		}
		if (mismatchMask & MismatchLength) != 0 {
			mismatchCounts["Length"].Add(1)
		}
		if (mismatchMask & MismatchFlags) != 0 {
			mismatchCounts["Flags"].Add(1)
		}

		return true // Continue processing.
	}
	consumer.EventPreparedCallback = nil
	consumer.EventCallback = nil

	if err := consumer.Start(); err != nil {
		t.Fatalf("Failed to start consumer: %v", err)
	}
	defer consumer.Stop()

	t.Log("Starting MOF generator validation for 15 seconds...")
	<-ctx.Done()

	t.Log("Finished event collection.")
	t.Logf("--- MOF Generator Validation Report ---")
	t.Logf("  MOF Events Compared:      %d", mofEventsCompared.Load())
	t.Logf("  Critical Mismatches:      %d", criticalMismatches.Load())
	t.Logf("  Non-Critical Mismatches:")
	t.Logf("    ClassName:   %d (use -mof.debug.classname for details)", mismatchCounts["ClassName"].Load())
	t.Logf("    OutType:     %d (use -mof.debug.outtype for details)", mismatchCounts["OutType"].Load())
	t.Logf("    Length:      %d (use -mof.debug.length for details)", mismatchCounts["Length"].Load())
	t.Logf("    Prop. Flags: %d (use -mof.debug.flags for details)", mismatchCounts["Flags"].Load())
	t.Logf("-------------------------------------------")

	if criticalMismatches.Load() > 0 {
		t.Fatal("Test failed due to critical mismatches in MOF generator.")
	}
}
