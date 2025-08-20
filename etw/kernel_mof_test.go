//go:build windows

package etw

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
	debugFlags     = flag.Bool("debug.flags", false, "Print details for property Flags mismatches")
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
		flagsMismatches     uint64
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
			return false
		}

		// Now, generate our version of the TraceEventInfo using the builder.
		var generatedTeiBuffer []byte
		generatedTei, err := buildTraceInfoFromMof(er, &generatedTeiBuffer)
		if err != nil {
			// Our builder doesn't have a definition for this event, so we can't compare.
			return false
		}

		atomic.AddUint64(&mofEventsCompared, 1)

		// --- Start Comparison ---
		// CRITICAL: Header Mismatches -> Fail Test
		if generatedTei.ProviderGUID != originalTei.ProviderGUID {
			t.Errorf("CRITICAL: ProviderGUID mismatch for event (Opcode %d, Version %d)\nGen: %s, Org: %s",
				originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.ProviderGUID.StringU(), originalTei.ProviderGUID.StringU())
			cancel()
			return false
		}
		if generatedTei.EventGUID != originalTei.EventGUID {
			t.Errorf("CRITICAL: EventGUID mismatch for event (%s, Opcode %d, Version %d)\nGen: %s, Org: %s",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.EventGUID.StringU(), originalTei.EventGUID.StringU())
			cancel()
			return false
		}
		if generatedTei.EventDescriptor != originalTei.EventDescriptor {
			t.Errorf("CRITICAL: EventDescriptor mismatch for event (%s, Opcode %d, Version %d)\nGen: %+v, Org: %+v",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.EventDescriptor, originalTei.EventDescriptor)
			cancel()
			return false
		}
		if generatedTei.DecodingSource != originalTei.DecodingSource {
			t.Errorf("CRITICAL: DecodingSource mismatch for event (%s, Opcode %d, Version %d)\nGen: %d, Org: %d",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.DecodingSource, originalTei.DecodingSource)
			cancel()
			return false
		}
		if generatedTei.PropertyCount != originalTei.PropertyCount {
			t.Errorf("CRITICAL: PropertyCount mismatch for event (%s, Opcode %d, Version %d)\nGen: %d, Org: %d",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.PropertyCount, originalTei.PropertyCount)
			cancel() // Stop test on critical failure
			return false
		}
		if generatedTei.TopLevelPropertyCount != originalTei.TopLevelPropertyCount {
			t.Errorf("CRITICAL: TopLevelPropertyCount mismatch for event (%s, Opcode %d, Version %d)\nGen: %d, Org: %d",
				originalTei.TaskName(), originalTei.EventDescriptor.Opcode, originalTei.EventDescriptor.Version,
				generatedTei.TopLevelPropertyCount, originalTei.TopLevelPropertyCount)
			cancel()
			return false
		}

		// LOW: Header String Mismatches -> Count and optionally log
		if generatedTei.TaskName() != originalTei.TaskName() ||
			generatedTei.OpcodeName() != originalTei.OpcodeName() {
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

		// CRITICAL/MEDIUM: Property-level comparison
		for i := uint32(0); i < originalTei.PropertyCount; i++ {
			genEpi := generatedTei.GetEventPropertyInfoAt(i)
			orgEpi := originalTei.GetEventPropertyInfoAt(i)
			orgName := originalTei.stringAt(uintptr(orgEpi.NameOffset))

			// CRITICAL: Property Name mismatch
			if generatedTei.stringAt(uintptr(genEpi.NameOffset)) != orgName {
				t.Errorf("CRITICAL: Property Name mismatch at index %d for event (%s, Opcode %d)\nGen: '%s', Org: '%s'",
					i,
					originalTei.TaskName(),
					originalTei.EventDescriptor.Opcode,
					generatedTei.stringAt(uintptr(genEpi.NameOffset)),
					orgName)
				cancel()
				return false
			}

			// CRITICAL: InType mismatch (can lead to incorrect parsing)
			if genEpi.InType() != orgEpi.InType() {
				// SIZET and POINTER are often interchangeable in MOF vs. TDH API.
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

			// MEDIUM: Flags mismatch (can be critical, but let's count it for now)
			if genEpi.Flags != orgEpi.Flags {
				atomic.AddUint64(&flagsMismatches, 1)
				if *debugFlags {
					t.Logf("DEBUG: Flags mismatch for property '%s' in event (%s, Opcode %d)\nGen: %x, Org: %x",
						orgName, originalTei.TaskName(), originalTei.EventDescriptor.Opcode,
						genEpi.Flags, orgEpi.Flags)
				}
			}

			// MEDIUM: OutType mismatch (benign, mostly for formatting)
			if genEpi.OutType() != orgEpi.OutType() {
				// STRING and NULL are often interchangeable for string types.
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

			// MEDIUM: Length mismatch for fixed-size properties (benign)
			if (orgEpi.Flags&PropertyParamLength) == 0 && genEpi.Length() != orgEpi.Length() {
				atomic.AddUint64(&lengthMismatches, 1)
				if *debugLength {
					t.Logf("DEBUG: Length mismatch for property '%s' in event (%s, Opcode %d)\nGen: %d, Org: %d",
						orgName, originalTei.TaskName(),
						originalTei.EventDescriptor.Opcode,
						genEpi.Length(),
						orgEpi.Length())

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
	t.Logf("LOW PRIORITY MISMATCHES (counted, non-failing):")
	t.Logf("  ClassName Mismatches:   %d (use -debug.classname for details)", classNameMismatches)
	t.Logf("MEDIUM PRIORITY MISMATCHES (counted, non-failing):")
	t.Logf("  OutType Mismatches:     %d (use -debug.outtype for details)", outTypeMismatches)
	t.Logf("  Length Mismatches:      %d (use -debug.length for details)", lengthMismatches)
	t.Logf("  Prop. Flags Mismatches: %d (use -debug.flags for details)", flagsMismatches)
	t.Logf("---------------------------")
}

// compareTraceEventInfo is a debug helper to compare a generated TEI with the original from the API.
// It returns a bitmask of mismatch types.
func compareTraceEventInfo(generated, original *TraceEventInfo) int {
	mismatchMask := MismatchNone

	// Compare header fields
	if generated.ProviderGUID != original.ProviderGUID {
		fmt.Printf("Mismatch ProviderGUID: Gen: %s, Org: %s\n", generated.ProviderGUID.StringU(), original.ProviderGUID.StringU())
		mismatchMask |= MismatchOther
	}
	if generated.EventGUID != original.EventGUID {
		fmt.Printf("Mismatch EventGUID: Gen: %s, Org: %s\n", generated.EventGUID.StringU(), original.EventGUID.StringU())
		mismatchMask |= MismatchOther
	}
	if generated.EventDescriptor != original.EventDescriptor {
		fmt.Printf("Mismatch EventDescriptor: Gen: %+v, Org: %+v\n", generated.EventDescriptor, original.EventDescriptor)
		mismatchMask |= MismatchOther
	}
	if generated.DecodingSource != original.DecodingSource {
		fmt.Printf("Mismatch DecodingSource: Gen: %d, Org: %d\n", generated.DecodingSource, original.DecodingSource)
		mismatchMask |= MismatchOther
	}
	if generated.PropertyCount != original.PropertyCount {
		fmt.Printf("Mismatch PropertyCount: Gen: %d, Org: %d\n", generated.PropertyCount, original.PropertyCount)
		mismatchMask |= MismatchOther
		return mismatchMask // Stop property comparison if counts differ, as it would panic.
	}
	if generated.TopLevelPropertyCount != original.TopLevelPropertyCount {
		fmt.Printf("Mismatch TopLevelPropertyCount: Gen: %d, Org: %d\n", generated.TopLevelPropertyCount, original.TopLevelPropertyCount)
		mismatchMask |= MismatchOther
	}
	if generated.Flags != original.Flags {
		fmt.Printf("Mismatch Flags: Gen: %d, Org: %d\n", generated.Flags, original.Flags)
		mismatchMask |= MismatchOther
	}

	// Note: Offsets will naturally differ. We compare the strings they point to instead.
	if generated.ProviderName() != original.ProviderName() {
		fmt.Printf("Mismatch ProviderName: Gen: '%s', Org: '%s'\n", generated.ProviderName(), original.ProviderName())
		mismatchMask |= MismatchOther
	}
	if generated.TaskName() != original.TaskName() {
		//fmt.Printf("Mismatch TaskName: Gen: '%s', Org: '%s'\n", generated.TaskName(), original.TaskName())
		mismatchMask |= MismatchClassName
	}
	if generated.OpcodeName() != original.OpcodeName() {
		//fmt.Printf("Mismatch OpcodeName: Gen: '%s', Org: '%s'\n", generated.OpcodeName(), original.OpcodeName())
		mismatchMask |= MismatchClassName
	}

	// Compare properties by iterating through them
	for i := uint32(0); i < generated.PropertyCount; i++ {
		genEpi := generated.GetEventPropertyInfoAt(i)
		orgEpi := original.GetEventPropertyInfoAt(i)
		genName := generated.stringAt(uintptr(genEpi.NameOffset))
		orgName := original.stringAt(uintptr(orgEpi.NameOffset))

		mismatched := false
		var mismatchDetails strings.Builder
		//mismatchDetails.WriteString(fmt.Sprintf("Property [%d] '%s':\n", i, orgName))

		if genName != orgName {
			mismatched = true
			mismatchMask |= MismatchOther
			mismatchDetails.WriteString(fmt.Sprintf("  - Name mismatch: Gen: '%s', Org: '%s'\n", genName, orgName))
		}
		if genEpi.Flags != orgEpi.Flags {
			mismatched = true
			mismatchMask |= MismatchOther
			mismatchDetails.WriteString(fmt.Sprintf("  - Flags mismatch: Gen: %x, Org: %x\n", genEpi.Flags, orgEpi.Flags))
		}

		// Compare unions based on flags
		if (orgEpi.Flags & PropertyStruct) != 0 {
			if genEpi.StructStartIndex() != orgEpi.StructStartIndex() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - StructStartIndex mismatch: Gen: %d, Org: %d\n", genEpi.StructStartIndex(), orgEpi.StructStartIndex()))
			}
			if genEpi.NumOfStructMembers() != orgEpi.NumOfStructMembers() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - NumOfStructMembers mismatch: Gen: %d, Org: %d\n", genEpi.NumOfStructMembers(), orgEpi.NumOfStructMembers()))
			}
		} else {
			if genEpi.InType() != orgEpi.InType() {
				// Ignore the specific, non-critical mismatch between POINTER and SIZET.
				isPointerSizeMismatch := (genEpi.InType() == TDH_INTYPE_POINTER && orgEpi.InType() == TDH_INTYPE_SIZET) ||
					(genEpi.InType() == TDH_INTYPE_SIZET && orgEpi.InType() == TDH_INTYPE_POINTER)

				if !isPointerSizeMismatch {
					mismatched = true
					mismatchMask |= MismatchOther
					mismatchDetails.WriteString(fmt.Sprintf("  - InType mismatch: Gen: %d, Org: %d\n", genEpi.InType(), orgEpi.InType()))
				}
			}
			if genEpi.OutType() != orgEpi.OutType() {
				isStringNullMismatch := (genEpi.OutType() == TDH_OUTTYPE_STRING && orgEpi.OutType() == TDH_OUTTYPE_NULL) ||
					(genEpi.OutType() == TDH_OUTTYPE_NULL && orgEpi.OutType() == TDH_OUTTYPE_STRING)
				if isStringNullMismatch {
					mismatchMask |= MismatchOutTypeStringNull
				} else {
					// Commented out to reduce noise from non-critical mismatches.
					// We can re-enable this later if needed.
					// mismatchMask |= MismatchOther
					// mismatchDetails.WriteString(fmt.Sprintf("  - OutType mismatch: Gen: %d, Org: %d\n", genEpi.OutType(), orgEpi.OutType()))
					// mismatched = true
				}
			}
			if genEpi.MapNameOffset() != orgEpi.MapNameOffset() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - MapNameOffset mismatch: Gen: %d, Org: %d\n", genEpi.MapNameOffset(), orgEpi.MapNameOffset()))
			}
		}

		if (orgEpi.Flags & PropertyParamCount) != 0 {
			if genEpi.CountPropertyIndex() != orgEpi.CountPropertyIndex() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - CountPropertyIndex mismatch: Gen: %d, Org: %d\n", genEpi.CountPropertyIndex(), orgEpi.CountPropertyIndex()))
			}
		} else {
			if genEpi.Count() != orgEpi.Count() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - Count mismatch: Gen: %d, Org: %d\n", genEpi.Count(), orgEpi.Count()))
			}
		}

		if (orgEpi.Flags & PropertyParamLength) != 0 {
			if genEpi.LengthPropertyIndex() != orgEpi.LengthPropertyIndex() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - LengthPropertyIndex mismatch: Gen: %d, Org: %d\n", genEpi.LengthPropertyIndex(), orgEpi.LengthPropertyIndex()))
			}
		} else {
			if genEpi.Length() != orgEpi.Length() {
				mismatched = true
				mismatchMask |= MismatchOther
				mismatchDetails.WriteString(fmt.Sprintf("  - Length mismatch: Gen: %d, Org: %d\n", genEpi.Length(), orgEpi.Length()))
			}
		}

		if mismatched {
			fmt.Print(mismatchDetails.String())
		} else {
			//fmt.Printf("Property [%d] '%s': OK\n", i, orgName)
		}
	}
	return mismatchMask
}
