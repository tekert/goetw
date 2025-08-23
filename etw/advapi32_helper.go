//go:build windows

package etw

import (
	"fmt"
	"os/user"
	"syscall"
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
		sid, err = GetCurrentSID()
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
		sid, err = GetCurrentSID()
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

// GetCurrentSID retrieves the SID of the current user as a *SID structure.
func GetCurrentSID() (sid *SID, err error) {
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	return ConvertStringSidToSidW(currentUser.Uid)
}

// IsCurrentSid checks if the provided SID string matches the current user's SID.
func IsCurrentSid(sidString string) (r bool, err error) {
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

// enablePrivilege enables a specific Windows privilege for the current process
func enablePrivilege(privilegeName string) error {
	var tokenHandle syscall.Token

	// Get current process handle
	processHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess failed: %v", err)
	}

	// Use the process handle to open the process token
	err = syscall.OpenProcessToken(processHandle,
		TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tokenHandle)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	// Lookup privilege LUID
	var luid LUID
	privName, err := syscall.UTF16PtrFromString(privilegeName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %v", err)
	}

	err = LookupPrivilegeValue(nil, privName, &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup privilege %s: %v", privilegeName, err)
	}

	// Set up TOKEN_PRIVILEGES structure
	var tp TOKEN_PRIVILEGES
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	// Enable the privilege
	err = AdjustTokenPrivileges(tokenHandle, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", err)
	}

	return nil
}

// EnableProfilingPrivileges enables the SeSystemProfilePrivilege required for EVENT_TRACE_FLAG_PROFILE
// This must be called before starting an ETW session with profiling enabled.
// Returns an error if the privilege cannot be enabled (usually means not running as administrator).
func EnableProfilingPrivileges() error {
	return enablePrivilege(SE_SYSTEM_PROFILE_NAME)
}

//	The name of the privilege,
//	as defined in the Winnt.h header file. For example, this parameter could specify the constant,
//	SE_SECURITY_NAME, or its corresponding string, "SeSecurityPrivilege".
//
// Look in https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
func EnablePrivileges(privName string) error {
	if err := enablePrivilege(privName); err != nil {
		fmt.Printf("Warning: Could not enable privilege %s: %v\n", privName, err)
	}

	return nil
}
