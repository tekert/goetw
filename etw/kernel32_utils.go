//go:build windows

//lint:file-ignore U1000 exports

package etw

import (
	"syscall"
)

// Exports from kernel32.dll
var (
	kernel32Dll       = syscall.MustLoadDLL("kernel32.dll")
	setThreadPriority = kernel32Dll.MustFindProc("SetThreadPriority")
	getThreadPriority = kernel32Dll.MustFindProc("GetThreadPriority")
)

// Thread priority constants used with SetThreadPriority.
const (
	// THREAD_MODE_BACKGROUND_BEGIN begins background processing mode. The system
	// lowers the resource scheduling priorities of the thread so that it can
	// perform background work without significantly affecting activity in the
	// foreground.
	THREAD_MODE_BACKGROUND_BEGIN = 0x00010000

	// THREAD_MODE_BACKGROUND_END ends background processing mode. The system
	// restores the resource scheduling priorities of the thread as they were
	// before the thread entered background processing mode.
	THREAD_MODE_BACKGROUND_END = 0x00020000

	// THREAD_PRIORITY_ABOVE_NORMAL indicates a priority 1 point above the priority class.
	THREAD_PRIORITY_ABOVE_NORMAL = 1

	// THREAD_PRIORITY_BELOW_NORMAL indicates a priority 1 point below the priority class.
	THREAD_PRIORITY_BELOW_NORMAL = -1

	// THREAD_PRIORITY_HIGHEST indicates a priority 2 points above the priority class.
	THREAD_PRIORITY_HIGHEST = 2

	// THREAD_PRIORITY_IDLE indicates a base priority of 1 for IDLE_PRIORITY_CLASS,
	// BELOW_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
	// ABOVE_NORMAL_PRIORITY_CLASS, or HIGH_PRIORITY_CLASS processes, and a base
	// priority of 16 for REALTIME_PRIORITY_CLASS processes.
	THREAD_PRIORITY_IDLE = -15

	// THREAD_PRIORITY_LOWEST indicates a priority 2 points below the priority class.
	THREAD_PRIORITY_LOWEST = -2

	// THREAD_PRIORITY_NORMAL indicates the normal priority for the priority class.
	THREAD_PRIORITY_NORMAL = 0

	// THREAD_PRIORITY_TIME_CRITICAL indicates a base priority of 15 for
	// IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
	// ABOVE_NORMAL_PRIORITY_CLASS, or HIGH_PRIORITY_CLASS processes, and a base
	// priority of 31 for REALTIME_PRIORITY_CLASS processes.
	THREAD_PRIORITY_TIME_CRITICAL = 15

	// THREAD_PRIORITY_ERROR_RETURN is the value returned by GetThreadPriority on failure.
	THREAD_PRIORITY_ERROR_RETURN = 0x7fffffff
)

// Functions

// Helper call it as:
//
//	syscall.Handle(CurrentThread())
func CurrentThread() uintptr { return ^uintptr(2 - 1) }

// SetThreadPriority sets the priority value for the specified thread. This value,
// together with the priority class of the thread's process, determines the
// thread's base priority level.
//
// For more information, see https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority
func SetThreadPriority(hThread syscall.Handle, nPriority int) error {
	r1, _, err := syscall.SyscallN(setThreadPriority.Addr(),
		uintptr(hThread),
		uintptr(nPriority))
	if r1 == 0 {
		return err // Use the error returned by SyscallN
	}
	return nil
}

// GetThreadPriority retrieves the priority value for the specified thread. This
// value, together with the priority class of the thread's process, determines
// the thread's base-priority level.
//
// For more information, see https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority
func GetThreadPriority(hThread syscall.Handle) (int, error) {
	r1, _, err := syscall.SyscallN(getThreadPriority.Addr(),
		uintptr(hThread))

	if r1 == THREAD_PRIORITY_ERROR_RETURN {
		return 0, err // Use the error returned by SyscallN
	}
	return int(r1), nil
}
