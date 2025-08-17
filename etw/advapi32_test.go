//go:build windows

package etw

import (
	"testing"

	"github.com/tekert/goetw/internal/test"
)

func TestAccessString(t *testing.T) {

	tt := test.FromT(t)

	//systemSID := "S-1-5-18"

	for _, p := range EnumerateProviders() {

		_, err := GetAccessString(&p.GUID)

		tt.CheckErr(err)

		/*err = AddProviderAccess(p.GUID, systemSID, 0x120fff)
		// we might have some access denied sometimes
		if err == ERROR_ACCESS_DENIED {
			continue
		}

		tt.CheckErr(err)*/

	}
}
