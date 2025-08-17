//go:build windows

package etw

import (
	"fmt"
	"os/user"
	"unsafe"
)

// TODO(tekert): test or delete.
var (
	// Need access before use (admin is not enough) call SetAccess with this GUID
	// and flags:
	SecurityLogReadFlags uint32 = TRACELOG_ACCESS_REALTIME | WMIGUID_QUERY
	// EventLog-Security GUID {54849625-5478-4994-a5ba-3e3b0328c30d}
	SecurityLogGuid = &GUID{
		Data1: 0x54849625,
		Data2: 0x5478,
		Data3: 0x4994,
		Data4: [8]byte{0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d},
	}
)

func GetAccessString(guid *GUID) (s string, err error) {

	g := guid
	bSize := uint32(0)
	// retrieves size
	EventAccessQuery(g, nil, &bSize)
	buffer := make([]byte, bSize)
	sd := (*SecurityDescriptor)(unsafe.Pointer(&buffer[0]))
	// we get the security descriptor
	EventAccessQuery(g, sd, &bSize)

	if s, err = ConvertSecurityDescriptorToStringSecurityDescriptorW(
		sd,
		SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION); err != nil {
		return
	}

	return
}

// Adds an ACE to the current DACL.
// if sid is empty: current user is used.
func AddProviderAccess(guid *GUID, sidString string, rights uint32) (err error) {
	var sid *SID

	if sidString != "" {
		if sid, err = ConvertStringSidToSidW(sidString); err != nil {
			err = fmt.Errorf("failed to convert string to sid: %w", err)
			return
		}
	} else {
		sid, err = currentUserSid()
		if err != nil {
			return fmt.Errorf("failed to get current user sid %s", err)
		}
	}

	return EventAccessControl(
		guid,
		uint32(EventSecurityAddDACL),
		sid,
		rights,
		true,
	)
}

// Clears the current system access control list (SACL) and adds an audit ACE to the SACL.
// rights if set to 0: TRACELOG_ALL will be used instead.
// if sid is empty: current user is used.
//
// Access last only for the duration of the process that called EventAccessControl
// When the process terminates, the permissions are automatically revoked
//
// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol
func SetProviderAccess(guid GUID, sidString string, rights uint32) (err error) {
	var sid *SID

	if sidString != "" {
		// Convert system SID string to SID object
		if sid, err = ConvertStringSidToSidW(sidString); err != nil {
			return fmt.Errorf("failed to convert string %s to sid %s", sidString, err)
		}
	} else {
		sid, err = currentUserSid()
		if err != nil {
			return fmt.Errorf("failed to get current user sid %s", err)
		}
	}

	g := &guid

	if rights == 0 {
		rights = TRACELOG_ALL
	}

	if err = EventAccessControl(
		g,
		uint32(EventSecuritySetDACL),
		sid, // nil uses current user
		rights,
		true,
	); err != nil {
		return fmt.Errorf("failed to set access %s", err)
	}

	return nil
}

func currentUserSid() (sid *SID, err error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	return ConvertStringSidToSidW(currentUser.Uid)
}

func currentUserSID_Is(sidString string) (r bool, err error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}
	// ensure this is a valid sid
	_, err = ConvertStringSidToSidW(sidString)
	if err != nil {
		return false, fmt.Errorf("invalid sid: %w", err)
	}
	return (currentUser.Uid == sidString), nil
}
