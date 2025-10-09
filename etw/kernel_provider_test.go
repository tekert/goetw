//go:build windows

package etw

import "testing"

func hasFlag(flags, flag KernelNtFlag) bool {
	return flags&flag == flag
}

func TestKernelProviders(t *testing.T) {
	t.Run("IndividualProviders", func(t *testing.T) {
		for _, p := range KernelProviders {
			t.Run(p.Name, func(t *testing.T) {
				// Test IsKernelProvider with name
				if !IsKernelProvider(p.Name) {
					t.Errorf("IsKernelProvider(%q) = false, want true", p.Name)
				}

				// Test IsKernelProvider with GUID
				guidStr := p.GUID.String()
				if !IsKernelProvider(guidStr) {
					t.Errorf("IsKernelProvider(%q) = false, want true for provider %s", guidStr, p.Name)
				}

				// Test GetKernelProviderFlags with name
				flagsByName := GetKernelProviderFlags(p.Name)
				if !hasFlag(flagsByName, p.Flags) {
					t.Errorf("GetKernelProviderFlags(%q) returned %d, which does not contain flag %d", p.Name, flagsByName, p.Flags)
				}

				// Test GetKernelProviderFlags with GUID
				// Multiple providers can share a GUID, so the map will hold the OR'd flags.
				// We must check that the specific flag for this provider is present.
				flagsByGUID := GetKernelProviderFlags(guidStr)
				if !hasFlag(flagsByGUID, p.Flags) {
					t.Errorf("GetKernelProviderFlags(%q) returned %d, which does not contain flag %d for provider %s", guidStr, flagsByGUID, p.Flags, p.Name)
				}
			})
		}
	})

	t.Run("CombinedFlags", func(t *testing.T) {
		combinedFlags := GetKernelProviderFlags("ALPC", "ImageLoad")

		if !hasFlag(combinedFlags, ALPC) {
			t.Errorf("combined flags should have ALPC flag, but does not")
		}
		if !hasFlag(combinedFlags, ImageLoad) {
			t.Errorf("combined flags should have ImageLoad flag, but does not")
		}
		if hasFlag(combinedFlags, Process) {
			t.Errorf("combined flags should not have Process flag, but does")
		}
	})

	t.Run("InvalidProvider", func(t *testing.T) {
		if IsKernelProvider("ThisIsDefinitelyNotARealProvider") {
			t.Error("IsKernelProvider returned true for an invalid provider name")
		}
		if GetKernelProviderFlags("ThisIsAlsoNotARealProvider") != 0 {
			t.Error("GetKernelProviderFlags returned non-zero flags for an invalid provider name")
		}
	})
}
