//go:build windows

package etw

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/tekert/goetw/internal/test"
)

const (
	testKernelFileProvider = "Microsoft-Windows-Kernel-File:0xff"
)

// regQueryValue is a helper to read a specific registry value for tests.
func regQueryValue(path, valueName string) (string, error) {
	out, err := exec.Command("reg", "QUERY", path, "/v", valueName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to query reg value %s\\%s: %w, output: %s", path, valueName, err, string(out))
	}
	// Output is in the format: `\n<Path>\n    <ValueName>    <Type>    <Data>\n`
	fields := strings.Fields(string(out))
	if len(fields) < 4 {
		return "", fmt.Errorf("unexpected output from reg query: %s", string(out))
	}
	// The last field is the data.
	return fields[len(fields)-1], nil
}

func TestAutologger(t *testing.T) {
	// DO NOT run in parallel. These tests modify a global system resource (registry).
	tt := test.FromT(t)

	guid, err := UUID()
	tt.CheckErr(err)

	a := AutoLogger{
		Name:        "GoETWAutologgerTest", // Use a fixed, unique name for the test session.
		GuidS:       guid,
		LogFileMode: EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_FILE_MODE_SEQUENTIAL,
		BufferSize:  64,
		ClockType:   1, // QPC
	}

	// Ensure cleanup happens even if the test fails.
	defer a.Delete()
	// Clean up any leftover from a previous failed run before we start.
	_ = a.Delete()

	t.Run("CreateAndVerify", func(t *testing.T) {
		tt := test.FromT(t)
		tt.CheckErr(a.Create())
		tt.Assert(a.Exists(), "Autologger key should exist after creation")

		// Verify a few key values were written correctly.
		val, err := regQueryValue(a.Path(), "Start")
		tt.CheckErr(err)
		tt.Assertf(val == "0x1", "Expected Start to be 1, got %s", val)

		val, err = regQueryValue(a.Path(), "GUID")
		tt.CheckErr(err)
		tt.Assert(strings.EqualFold(val, a.GuidS), "GUID mismatch in registry")
	})

	t.Run("EnableProviderWithFilter", func(t *testing.T) {
		tt := test.FromT(t)
		provider, err := ParseProvider(testKernelFileProvider)
		tt.CheckErr(err)

		// Add a filter to the provider to test the serialization logic.
		provider.Filters = []ProviderFilter{NewEventIDFilter(true, 10, 12)}

		tt.CheckErr(a.EnableProvider(provider))

		// Verify that the FilterData value was created correctly.
		providerPath := fmt.Sprintf(`%s\%s`, a.Path(), provider.GUID.StringU())
		val, err := regQueryValue(providerPath, "FilterData")
		if err != nil {
			t.Log("FilterData value should exist")
		}
		tt.CheckErr(err)

		// Corrected: Expected binary format for an EventIDFilter with 2 IDs (10, 12):
		// EVENT_FILTER_DESCRIPTOR (16 bytes) + EVENT_FILTER_EVENT_ID data (8 bytes) = 24 bytes total.
		// The hex string will be twice that length (48 characters).
		tt.Assertf(len(val) == 48, "Expected FilterData to be 48 hex chars long, got %d", len(val))
	})

	t.Run("Delete", func(t *testing.T) {
		tt := test.FromT(t)
		tt.CheckErr(a.Delete())
		tt.Assertf(!a.Exists(), "Autologger key should not exist after deletion")
	})
}
