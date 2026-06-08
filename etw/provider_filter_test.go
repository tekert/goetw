package etw

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tekert/goetw/internal/test"
)

// TestProviderFiltering systematically tests filter support across different providers.
// It discovers which filters are supported, ignored, or cause errors for each provider type.
func TestProviderFiltering(t *testing.T) {
	tt := test.FromT(t)

	sessionName := testSessioName

	currentPID := uint32(os.Getpid())
	exePath, err := os.Executable()
	tt.CheckErr(err)
	exeName := filepath.Base(exePath)

	const testDuration = 3 * time.Second

	type TestCase struct {
		Provider    string
		FilterType  string
		Filter      ProviderFilter
		TestEventID uint16         // Expected common event ID for validation
		Result      FilterBehavior // Expected behavior
		Message     string         // Will be set during test
	}

	testCases := []TestCase{
		// Kernel Memory Provider Tests
		{"Microsoft-Windows-Kernel-Memory", "EventID-Include", NewEventIDFilter(true, 1), 1, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-Memory", "EventID-Exclude", NewEventIDFilter(false, 10), 10, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-Memory", "PID", NewPIDFilter(currentPID), 0, BehaviorIgnored, ""},
		{"Microsoft-Windows-Kernel-Memory", "ExeName", NewExecutableNameFilter(exeName), 0, BehaviorIgnored, ""},

		// Kernel File Provider Tests
		{"Microsoft-Windows-Kernel-File", "EventID-Include", NewEventIDFilter(true, 12), 12, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-File", "EventID-Exclude", NewEventIDFilter(false, 14), 14, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-File", "PID", NewPIDFilter(currentPID), 0, BehaviorIgnored, ""},
		{"Microsoft-Windows-Kernel-File", "ExeName", NewExecutableNameFilter(exeName), 0, BehaviorIgnored, ""},

		// Kernel Process Provider Tests
		{"Microsoft-Windows-Kernel-Process", "EventID-Include", NewEventIDFilter(true, 1), 1, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-Process", "EventID-Exclude", NewEventIDFilter(false, 2), 2, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-Process", "PID", NewPIDFilter(currentPID), 0, BehaviorIgnored, ""},
		{"Microsoft-Windows-Kernel-Process", "ExeName", NewExecutableNameFilter(exeName), 0, BehaviorIgnored, ""},

		// User-mode RPC Provider Tests
		{"Microsoft-Windows-RPC", "EventID-Include", NewEventIDFilter(true, 5), 5, BehaviorApplied, ""},
		{"Microsoft-Windows-RPC", "EventID-Exclude", NewEventIDFilter(false, 6), 6, BehaviorApplied, ""},
		{"Microsoft-Windows-RPC", "PID", NewPIDFilter(currentPID), 0, BehaviorApplied, ""},
		{"Microsoft-Windows-RPC", "ExeName", NewExecutableNameFilter(exeName), 0, BehaviorApplied, ""},

		// Scope Filters: Package ID / App ID
		// Ignored on Kernel providers
		{"Microsoft-Windows-Kernel-Process", "PackageID", NewPackageIDFilter("DummyPackage"), 0, BehaviorIgnored, ""},
		{"Microsoft-Windows-Kernel-Process", "PackageAppID", NewPackageAppIDFilter("DummyAppID"), 0, BehaviorIgnored, ""},
		// Applied successfully on User-Mode providers
		{"Microsoft-Windows-RPC", "PackageID", NewPackageIDFilter("DummyPackage"), 0, BehaviorApplied, ""},
		{"Microsoft-Windows-RPC", "PackageAppID", NewPackageAppIDFilter("DummyAppID"), 0, BehaviorApplied, ""},

		// TraceLogging Provider Tests
		// Test 1: A Manifest-based provider ignores the EventName filter -> BehaviorIgnored
		{"Microsoft-Windows-Kernel-Process", "EventName-Include", NewEventNameFilter(true, "DummyEventName"), 0, BehaviorIgnored, ""},
		// Test 2: We use a dummy GUID for a TraceLogging provider. Windows accepts the filter, generates 0 events -> BehaviorApplied
		{"{11111111-2222-3333-4444-555555555555}", "EventName-Include", NewEventNameFilter(true, "DummyEventName"), 0, BehaviorApplied, ""},

		// StackWalk Provider Tests
		{"Microsoft-Windows-Kernel-Process", "StackWalk-LevelKW", NewEventLevelKWFilter(true, 5, 0, 0), 0, BehaviorApplied, ""},
		{"Microsoft-Windows-Kernel-Process", "StackWalk-EventID", NewStackWalkFilter(true, 1, 2), 0, BehaviorApplied, ""},
		{"{11111111-2222-3333-4444-555555555555}", "StackWalk-Name", NewStackWalkNameFilter(true, "DummyEventName"), 0, BehaviorApplied, ""},

		// Advanced Filters (Payload & Schematized)
		// Note: We pass invalid dummy binary data. The ETW runtime (kernel) actively validates Payload/Schematized filters.
		// EnableProvider will fail (ERROR_INVALID_PARAMETER), which proves our memory descriptors are correctly reaching the kernel.
		{"Microsoft-Windows-Kernel-Process", "Payload", NewPayloadFilter([]byte{0x01, 0x02, 0x03}), 0, BehaviorUnsupported, ""},
		// The API doesn't validate Schematized payloads; it just forwards them to the provider, which ignores the garbage and emits events.
		{"Microsoft-Windows-Kernel-Process", "Schematized", NewSchematizedFilter(1, 0, []byte{0x01, 0x02, 0x03}), 0, BehaviorApplied, ""},
	}

	for i := range testCases {
		tc := &testCases[i] // Get pointer to modify in place

		t.Run(fmt.Sprintf("%s/%s", tc.Provider, tc.FilterType), func(t *testing.T) {
			_ = StopSession(sessionName)

			ses := NewRealTimeSession(sessionName)
			defer ses.Stop()

			// Parse and configure provider
			prov, err := ParseProvider(tc.Provider)
			if err != nil {
				tc.Message = fmt.Sprintf("Failed to parse provider: %v", err)
				tt.Assert(tc.Result == BehaviorUnsupported, tc.Message)
				return
			}
			prov.Filters = []ProviderFilter{tc.Filter}

			// IMPORTANT: Enable the stack trace property if we are testing a StackWalk filter.
			// The Windows API requires this flag to be set for the LevelKW filter to take effect.
			if strings.HasPrefix(tc.FilterType, "StackWalk") {
				prov.EnableProperties |= EVENT_ENABLE_PROPERTY_STACK_TRACE
			}

			// Try to enable provider - this is where unsupported filters fail
			err = ses.EnableProvider(prov)
			if err != nil {
				tc.Message = fmt.Sprintf("EnableProvider failed: %v", err)
				tt.Assert(tc.Result == BehaviorUnsupported, tc.Message)
				return
			}

			// If we get here, the filter was accepted
			ctx, cancel := context.WithTimeout(context.Background(), testDuration)
			defer cancel()

			c := NewConsumer(ctx).FromSessions(ses)

			var eventCount int
			var violationFound bool
			var violationMsg string
			c.EventCallback = func(h *EventRecordHelper) error {
				eventCount++

				systemMetadata := h.System()

				// Check if filter is being ignored by the ETW runtime
				switch tc.FilterType {
				case "EventID-Include":
					if systemMetadata.EventID != tc.TestEventID {
						violationFound = true
						violationMsg = fmt.Sprintf("Got EventID %d, expected only %d", systemMetadata.EventID, tc.TestEventID)
						cancel()
					}
				case "EventID-Exclude":
					if systemMetadata.EventID == tc.TestEventID {
						violationFound = true
						violationMsg = fmt.Sprintf("Got excluded EventID %d", systemMetadata.EventID)
						cancel()
					}
				case "PID":
					if systemMetadata.Execution.ProcessID != currentPID {
						violationFound = true
						violationMsg = fmt.Sprintf("Got PID %d, expected %d", systemMetadata.Execution.ProcessID, currentPID)
						cancel()
					}
				case "ExeName":
					// For exe name, we just check if we get events from other PIDs
					if systemMetadata.Execution.ProcessID != currentPID {
						violationFound = true
						violationMsg = fmt.Sprintf("Got PID %d, expected current process %d", systemMetadata.Execution.ProcessID, currentPID)
						cancel()
					}
				case "PackageID", "PackageAppID":
					// We filter by a "Dummy" package. If we receive any events,
					// it means the ETW runtime ignored our filter.
					violationFound = true
					violationMsg = fmt.Sprintf("Received event despite filtering for dummy %s", tc.FilterType)
					cancel()
				case "EventName-Include":
					// If we receive AT LEAST ONE event when searching for "DummyEventName",
					// it means the ETW runtime ignored our filter (which is typical for Manifest providers).
					violationFound = true
					violationMsg = "Received event despite EventName filter (filter ignored by ETW runtime)"
					cancel()
				case "StackWalk-LevelKW":
					// StackWalk filters do not drop events, they simply attach (or omit) the StackTrace property.
					// Since EnableProvider succeeded and events flow, the API accepted the filter.
					// We consider this successfully applied.
				}

				// Stop after first few events if no violation
				if eventCount >= 30 {
					cancel()
				}
				return nil
			}

			err = c.Start()
			if err != nil {
				tc.Message = fmt.Sprintf("Consumer start failed: %v", err)
				tt.Assert(tc.Result == BehaviorUnsupported, tc.Message)
				return
			}
			defer c.Stop()

			<-ctx.Done()

			// Determine actual behavior and compare with expected
			var actualBehavior FilterBehavior
			var message string

			if violationFound {
				actualBehavior = BehaviorIgnored
				message = fmt.Sprintf("Filter ignored: %s (%d events)", violationMsg, eventCount)
			} else if eventCount > 0 {
				actualBehavior = BehaviorApplied
				message = fmt.Sprintf("Filter applied correctly (%d events)", eventCount)
			} else {
				actualBehavior = BehaviorApplied
				message = "No events received (filter may be working or provider inactive)"
			}

			// Update test case with results
			tc.Message = message

			// ENFORCE EXPECTED BEHAVIOR - This will make the test fail if behavior doesn't match
			tt.Assert(actualBehavior == tc.Result,
				fmt.Sprintf("Expected %s but got %s. %s", tc.Result.String(), actualBehavior.String(), message))
		})
	}

	// Print results table
	t.Log("\n--- ETW Provider Filter Support Matrix ---")
	t.Logf("%-35s %-15s %-12s %s", "Provider", "Filter", "Behavior", "Details")
	t.Log(strings.Repeat("-", 100))

	for _, tc := range testCases {
		t.Logf("%-35s %-15s %-12s %s", tc.Provider, tc.FilterType, tc.Result.String(), tc.Message)
	}
	t.Log(strings.Repeat("-", 100))
}
