//go:build windows

package etw

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"sync/atomic"
	"testing"
	"time"
)

// Command-line flags to enable verbose logging for specific mismatch types.
// Example usage: go test -v -run TestKernelMofAgainstApi -debug.outtype
var (
	debugOutType   = flag.Bool("debug.outtype", false, "Print details for OutType mismatches")
	debugLength    = flag.Bool("debug.length", false, "Print details for Length mismatches")
	debugClassName = flag.Bool("debug.classname", false, "Print details for TaskName/OpcodeName mismatches")
)

// TestKernelMofAgainstApi runs a live kernel session and compares the output of
// our buildTraceInfoFromMof function against the live TdhGetEventInformation API.
//
// It fails on critical mismatches (e.g., PropertyCount) but only counts and reports
// non-critical ones (e.g., OutType, Length) to gauge accuracy without failing CI builds.
// Use the -debug.* flags to get detailed logs for specific mismatch types.
func TestKernelMofAgainstApi(t *testing.T) {
	// Enable all kernel providers for a comprehensive test.
	var allKernelFlags uint32
	for _, kp := range KernelProviders {
		allKernelFlags |= kp.Flags
	}
	// Disable PROFILE flag as it can be very noisy and is not a MOF provider.
	allKernelFlags ^= EVENT_TRACE_FLAG_PROFILE

	session := NewKernelRealTimeSession(allKernelFlags)
	if err := session.Start(); err != nil {
		t.Fatalf("Failed to start kernel session: %v", err)
	}
	defer session.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Handle Control-C (SIGINT) to stop the session gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		t.Log("Received Control-C (SIGINT), stopping test and session...")
		cancel()
	}()

	consumer := NewConsumer(ctx).FromSessions(session)

	// Define counters for non-critical mismatches.
	var (
		eventsProcessed     uint64
		mofEventsCompared   uint64
		outTypeMismatches   uint64
		lengthMismatches    uint64
		classNameMismatches uint64
	)

	// Hook into the first callback to get the raw EventRecord. This is the most
	// efficient way to test, as it avoids creating the EventRecordHelper.
	consumer.EventRecordCallback = func(er *EventRecord) bool {
		atomic.AddUint64(&eventsProcessed, 1)

		// We only test classic MOF events.
		if !er.IsMof() {
			return false // Stop processing non-MOF events.
		}

		// Get the official API version for comparison. This is our "ground truth".
		var originalTeiBuffer []byte
		originalTei, err := er.GetEventInformation(&originalTeiBuffer)
		if err != nil {
			// If the API fails, we can't compare. This is not a test failure.
			return false // Stop processing.
		}

		// Now, generate our version of the TraceEventInfo using the builder.
		var generatedTeiBuffer []byte
		generatedTei, err := buildTraceInfoFromMof(er, &generatedTeiBuffer)
		if err != nil {
			// Our builder doesn't have a definition for this event, so we can't compare.
			return false // Stop processing.
		}

		atomic.AddUint64(&mofEventsCompared, 1)

		// --- Start Comparison ---
		// Critical Header Mismatches -> Fail Test
		if generatedTei.PropertyCount != originalTei.PropertyCount {
			t.Errorf("CRITICAL: PropertyCount mismatch for event (%s, Opcode %d, Version %d)\nGen: %d, Org: %d",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version, generatedTei.PropertyCount, originalTei.PropertyCount)
			cancel() // Stop test on critical failure
			return false
		}
		if generatedTei.EventGUID != originalTei.EventGUID {
			t.Errorf("CRITICAL: EventGUID mismatch for event (%s, Opcode %d, Version %d)\nGen: %s, Org: %s",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version, generatedTei.EventGUID.StringU(), originalTei.EventGUID.StringU())
			cancel()
			return false
		}

		// Non-Critical Header Mismatches -> Count and optionally log
		if generatedTei.TaskName() != originalTei.TaskName() || generatedTei.OpcodeName() != originalTei.OpcodeName() {
			atomic.AddUint64(&classNameMismatches, 1)
			if *debugClassName {
				t.Logf("DEBUG: ClassName mismatch for event (Opcode %d, Version %d)\nTaskName: Gen: '%s', Org: '%s'\nOpcodeName: Gen: '%s', Org: '%s'",
					originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
					generatedTei.TaskName(), originalTei.TaskName(),
					generatedTei.OpcodeName(), originalTei.OpcodeName())

				if eventJson, err := json.Marshal(er); err == nil {
					t.Logf("EventRecord JSON: %s", string(eventJson))
				}
			}
		}

		// Property-level comparison
		for i := uint32(0); i < originalTei.PropertyCount; i++ {
			genEpi := generatedTei.GetEventPropertyInfoAt(i)
			orgEpi := originalTei.GetEventPropertyInfoAt(i)
			orgName := originalTei.stringAt(uintptr(orgEpi.NameOffset))

			// Critical Property Mismatches -> Fail Test
			if generatedTei.stringAt(uintptr(genEpi.NameOffset)) != orgName {
				t.Errorf("CRITICAL: Property Name mismatch at index %d for event (%s, Opcode %d)\nGen: '%s', Org: '%s'",
					i, originalTei.TaskName(), originalTei.EventDescriptor.Opcode, generatedTei.stringAt(uintptr(genEpi.NameOffset)), orgName)
				cancel()
				return false
			}
			if genEpi.InType() != orgEpi.InType() {
				isPointerSizeMismatch := (genEpi.InType() == TDH_INTYPE_POINTER && orgEpi.InType() == TDH_INTYPE_SIZET) ||
					(genEpi.InType() == TDH_INTYPE_SIZET && orgEpi.InType() == TDH_INTYPE_POINTER)
				if !isPointerSizeMismatch {
					t.Errorf("CRITICAL: InType mismatch for property '%s' in event (%s, Opcode %d)\nGen: %s (%d), Org: %s (%d)",
						orgName, originalTei.TaskName(),
						originalTei.EventDescriptor.Opcode,
						genEpi.InType().String(), genEpi.InType(),
						orgEpi.InType().String(), orgEpi.InType())
					cancel()
					return false
				}
			}

			// Non-Critical Property Mismatches -> Count and optionally log
			if genEpi.OutType() != orgEpi.OutType() {
				isStringNullMismatch := (genEpi.OutType() == TDH_OUTTYPE_STRING && orgEpi.OutType() == TDH_OUTTYPE_NULL) ||
					(genEpi.OutType() == TDH_OUTTYPE_NULL && orgEpi.OutType() == TDH_OUTTYPE_STRING)
				if !isStringNullMismatch {
					atomic.AddUint64(&outTypeMismatches, 1)
					if *debugOutType {
						t.Logf("DEBUG: OutType mismatch for property '%s' in event (%s, Opcode %d)\nGen: %s (%d), Org: %s (%d)",
							orgName, originalTei.TaskName(), originalTei.EventDescriptor.Opcode,
							genEpi.OutType().String(), genEpi.OutType(),
							orgEpi.OutType().String(), orgEpi.OutType())

						if eventJson, err := json.Marshal(er); err == nil {
							t.Logf("EventRecord JSON: %s", string(eventJson))
						}
					}
				}
			}
			if (orgEpi.Flags&PropertyParamLength) == 0 && genEpi.Length() != orgEpi.Length() {
				atomic.AddUint64(&lengthMismatches, 1)
				if *debugLength {
					t.Logf("DEBUG: Length mismatch for property '%s' in event (%s, Opcode %d)\nGen: %d, Org: %d",
						orgName, originalTei.TaskName(), originalTei.EventDescriptor.Opcode, genEpi.Length(), orgEpi.Length())

					if eventJson, err := json.Marshal(er); err == nil {
						t.Logf("EventRecord JSON: %s", string(eventJson))
					}
				}
			}
		}

		// We've done our comparison, so return false to stop further processing for this event.
		return false
	}

	// We are not using the final event channel or other callbacks.
	consumer.EventPreparedCallback = nil
	consumer.EventCallback = nil

	if err := consumer.Start(); err != nil {
		t.Fatalf("Failed to start consumer: %v", err)
	}
	defer consumer.Stop()

	t.Log("Starting kernel event collection for 15 seconds...")

	// Wait for the test to finish (or be canceled by a critical error).
	<-ctx.Done()

	t.Log("Finished event collection.")
	t.Logf("--- MOF Comparison Report ---")
	t.Logf("Total Events Processed: %d", eventsProcessed)
	t.Logf("MOF Events Compared:    %d", mofEventsCompared)
	t.Logf("---------------------------")
	t.Logf("ClassName Mismatches:   %d (Benign, use -debug.classname for details)", classNameMismatches)
	t.Logf("OutType Mismatches:     %d (Benign, use -debug.outtype for details)", outTypeMismatches)
	t.Logf("Length Mismatches:      %d (Benign, use -debug.length for details)", lengthMismatches)
	t.Logf("---------------------------")
}
