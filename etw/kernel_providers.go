//go:build windows

package etw

import "strings"

// KernelNtFlag defines a bitmask for enabling a specific group of legacy kernel events.
// These flags are used with NewKernelRealTimeSession to configure the "NT Kernel Logger".
type KernelNtFlag uint32

// NT Kernel Logger flags (old)
const (
	NtKernelLogger = "NT Kernel Logger"
	//  0x9e814aad, 0x3204, 0x11d2, 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39

	// ALPC logs Advanced Local Procedure call events.
	// https://docs.microsoft.com/en-us/windows/win32/etw/alpc
	// GUID: {45d8cccd-539f-4b72-a8b7-5c683142609a}
	ALPC KernelNtFlag = EVENT_TRACE_FLAG_ALPC

	// DbgPrint logs debug output messages from kernel-mode components using DbgPrint/DbgPrintEx.
	// GUID: {13976d09-a327-438c-950b-7f03192815c7}
	DbgPrint KernelNtFlag = EVENT_TRACE_FLAG_DBGPRINT

	// DiskIo logs the completion of Physical disk activity.
	// https://docs.microsoft.com/en-us/windows/win32/etw/diskio
	// GUID: {3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}
	DiskIo KernelNtFlag = EVENT_TRACE_FLAG_DISK_IO

	// DiskIoInit logs the initialization of disk IO operations.
	// Generally not TOO volumous (typically less than 1K per second)
	// (Stacks associated with this)
	// GUID: {3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}
	DiskIoInit KernelNtFlag = EVENT_TRACE_FLAG_DISK_IO_INIT

	// Driver logs events for kernel-mode driver operations.
	// More info on https://learn.microsoft.com/en-us/windows/win32/etw/diskio
	// Driver* events.
	// GUID: {3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}
	Driver KernelNtFlag = EVENT_TRACE_FLAG_DRIVER

	// FileIo logs file operation end events (e.g., read, write, create) when they complete. (even ones that do not actually
	// cause Disk I/O).  (Vista+ only)
	// Generally not TOO volumous (typically less than 1K per second) (No stacks associated with these)
	// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
	// GUID: {90cbdc39-4a3e-11d1-84f4-0000f80464e3}
	FileIo KernelNtFlag = EVENT_TRACE_FLAG_FILE_IO

	// DiskFileIo logs the mapping of file IDs to actual (kernel) file names.
	// Rundown event with opcode 36 (EventType)
	// https://learn.microsoft.com/en-us/windows/win32/etw/fileio-name
	// FileObject is used to correlate with other FileIo events that reference the same file
	// FileKey persists across system reboots and can be used to track the same file over time
	// GUID: {90cbdc39-4a3e-11d1-84f4-0000f80464e3}
	DiskFileIo KernelNtFlag = EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO

	// FileIoInit logs the start of file I/O operations. (Vista+ only)
	// Generally not TOO volumous (typically less than 1K per second)
	// GUID: {90cbdc39-4a3e-11d1-84f4-0000f80464e3}
	FileIoInit KernelNtFlag = EVENT_TRACE_FLAG_FILE_IO_INIT

	// FileIoVAmap enables events for mapping and unmapping of files into memory. (Win8+)
	// Generally low volume.
	// GUID: {90cbdc39-4a3e-11d1-84f4-0000f80464e3}
	FileIoVAmap KernelNtFlag = EVENT_TRACE_FLAG_VAMAP

	// ImageLoad logs native modules loads (LoadLibrary), and unloads (FreeLibrary).
	// https://docs.microsoft.com/en-us/windows/win32/etw/image
	// GUID: {2cb15d1d-5fc1-11d2-abe1-00a0c911f518}
	ImageLoad KernelNtFlag = EVENT_TRACE_FLAG_IMAGE_LOAD

	// LMemoryPageFault logs all page faults (hard or soft). Can be high volume.
	// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
	// GUID: {3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}
	MemoryPageFault KernelNtFlag = EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS

	// Logs all page faults that must fetch the data from the disk (hard faults)
	// GUID: {3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}
	MemoryHardFault KernelNtFlag = EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS

	// Log Virtual Alloc calls and VirtualFree.   (Vista+ Only)
	// Generally not TOO volumous (typically less than 1K per second)
	// GUID: {3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}
	VirtualAlloc KernelNtFlag = EVENT_TRACE_FLAG_VIRTUAL_ALLOC

	// DPC logs Deferred Procedure Calls (Vista+).
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	// GUID: {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}
	DPC KernelNtFlag = EVENT_TRACE_FLAG_DPC

	// Interrupt logs hardware interrupts (Vista+).
	// https://learn.microsoft.com/es-es/windows/win32/etw/isr
	// GUID: {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}
	Interrupt KernelNtFlag = EVENT_TRACE_FLAG_INTERRUPT

	// Profile enables sampled-based profiling events (requires special privileges).
	// (expect 1K events per proc per second)
	// GUID: {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}
	Profile KernelNtFlag = EVENT_TRACE_FLAG_PROFILE

	// Syscall logs calls into the operating system (very high volume, Vista+).
	// GUID: {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}
	Syscall KernelNtFlag = EVENT_TRACE_FLAG_SYSTEMCALL

	// Process logs process starts and stops.
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	// GUID: {3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}
	Process KernelNtFlag = EVENT_TRACE_FLAG_PROCESS

	// ProcessCounters logs process performance counters (CPU, IO, etc).
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	// GUID: {3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}
	ProcessCounters KernelNtFlag = EVENT_TRACE_FLAG_PROCESS_COUNTERS

	// Registry logs activity to the windows registry. Can be high volume.
	// https://docs.microsoft.com/en-us/windows/win32/etw/registry
	// GUID: {ae53722e-c863-11d2-8659-00c04fa321a1}
	Registry KernelNtFlag = EVENT_TRACE_FLAG_REGISTRY

	// SplitIo logs Disk I/O that was split (e.g., for mirroring) (Vista+).
	// https://docs.microsoft.com/en-us/windows/win32/etw/splitio
	// GUID: {d837ca92-12b9-44a5-ad6a-3a65b3578aa8}
	SplitIo KernelNtFlag = EVENT_TRACE_FLAG_SPLIT_IO

	// TcpIp logs TCP/IP network send and receive events.
	// https://docs.microsoft.com/en-us/windows/win32/etw/tcpip
	// GUID: {9a280ac0-c8e0-11d1-84e2-00c04fb998a2}
	TcpIp KernelNtFlag = EVENT_TRACE_FLAG_NETWORK_TCPIP

	// Thread logs thread starts and stops.
	// https://docs.microsoft.com/en-us/windows/win32/etw/thread
	// GUID: {3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}
	Thread KernelNtFlag = EVENT_TRACE_FLAG_THREAD

	// CSwitch logs thread context switches. High volume.
	// (use with ReadyThread to get full context switches)
	// GUID: {3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}
	CSwitch KernelNtFlag = EVENT_TRACE_FLAG_CSWITCH

	// Dispatcher logs thread dispatcher activity (ReadyThread). High volume (Vista+).
	// GUID: {3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}
	Dispatcher KernelNtFlag = EVENT_TRACE_FLAG_DISPATCHER

	// UdpIp logs UDP/IP network send and receive events.
	// https://docs.microsoft.com/en-us/windows/win32/etw/udpip
	// GUID: {bf3a50c5-a9c9-4988-a005-2df0b7c80f80}
	UdpIp KernelNtFlag = EVENT_TRACE_FLAG_NETWORK_TCPIP // Note: Same flag as TcpIp

	// No SysConfig events, used to disable rundown events in the kernel session
	// More info on https://learn.microsoft.com/en-us/windows/win32/etw/hwconfig
	// More info on https://learn.microsoft.com/en-us/windows/win32/etw/systemconfig
	// GUID: {01853a65-418f-4f36-aefc-dc0f1d2fd235}
	NoSysConfig KernelNtFlag = EVENT_TRACE_FLAG_NO_SYSCONFIG
)

// All returns a combination of all kernel flags, suitable for a comprehensive trace.
// It excludes the high-volume Profile flag by default.
func (p KernelNtFlag) All() KernelNtFlag {
	return p | ALPC | DbgPrint | DiskIo | DiskIoInit | Driver | FileIo |
		DiskFileIo | FileIoInit | FileIoVAmap | ImageLoad | MemoryPageFault |
		MemoryHardFault | VirtualAlloc | DPC | Interrupt | Syscall |
		Process | ProcessCounters | Registry | SplitIo | TcpIp | Thread |
		CSwitch | Dispatcher | UdpIp
}

type KernelNtGUID *GUID

var (
	// https://learn.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace
	MSNTSystemTraceGuid KernelNtGUID = MustParseGUID("{9e814aad-3204-11d2-9a82-006008a86939}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
	FileIoGuid KernelNtGUID = MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/diskio
	DiskIoGuid KernelNtGUID = MustParseGUID("{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/alpc
	ALPCGuid KernelNtGUID = MustParseGUID("{45d8cccd-539f-4b72-a8b7-5c683142609a}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/image
	ImageLoadGuid KernelNtGUID = MustParseGUID("{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
	PageFaultGuid KernelNtGUID = MustParseGUID("{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/registry
	RegistryGuid KernelNtGUID = MustParseGUID("{ae53722e-c863-11d2-8659-00c04fa321a1}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/tcpip
	TcpIpGuid KernelNtGUID = MustParseGUID("{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/udpip
	UdpIpGuid KernelNtGUID = MustParseGUID("{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/thread
	ThreadGuid KernelNtGUID = MustParseGUID("{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://learn.microsoft.com/en-us/windows/win32/etw/systemconfig
	SystemConfigGuid KernelNtGUID = MustParseGUID("{01853a65-418f-4f36-aefc-dc0f1d2fd235}")
	// https://learn.microsoft.com/en-us/windows/win32/etw/hwconfig
	HwConfigGuid KernelNtGUID = MustParseGUID("{01853a65-418f-4f36-aefc-dc0f1d2fd235}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/splitio
	SplitIoGuid KernelNtGUID = MustParseGUID("{d837ca92-12b9-44a5-ad6a-3a65b3578aa8}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	ProcessGuid KernelNtGUID = MustParseGUID("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/dbgprint
	DbgPrintGuid KernelNtGUID = MustParseGUID("{13976d09-a327-438c-950b-7f03192815c7}")
	// https://learn.microsoft.com/en-us/windows/win32/etw/isr
	InterruptGuid KernelNtGUID = MustParseGUID("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	DPCGuid KernelNtGUID = MustParseGUID("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	ProfileGuid KernelNtGUID = MustParseGUID("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	SyscallGuid KernelNtGUID = MustParseGUID("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/process
	ProcessCountersGuid KernelNtGUID = MustParseGUID("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/driver
	DriverGuid KernelNtGUID = MustParseGUID("{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/fileio-name
	DiskFileIoGuid KernelNtGUID = MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
	FileIoInitGuid KernelNtGUID = MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
	FileIoVAmapGuid KernelNtGUID = MustParseGUID("{90cbdc39-4a3e-11d1-84f4-0000f80464e3}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
	MemoryPageFaultGuid KernelNtGUID = MustParseGUID("{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
	MemoryHardFaultGuid KernelNtGUID = MustParseGUID("{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
	VirtualAllocGuid KernelNtGUID = MustParseGUID("{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/cswitch
	CSwitchGuid KernelNtGUID = MustParseGUID("{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}")
	// https://docs.microsoft.com/en-us/windows/win32/etw/dispatcher
	DispatcherGuid KernelNtGUID = MustParseGUID("{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}")
)

// TODO: Delete these in 0.8
// Deprecated: Use the KernelFlag constants (e.g., etw.Process, etw.Thread) with
// NewKernelRealTimeSession instead. This struct will be removed in a future version.
type ProviderKernel struct {
	Name   string
	Kernel bool
	GUID   string
	Flags  uint32
}

// https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
var (

	// https://learn.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace
	//systemTraceControlGuid = MustParseGUIDFromString("{9E814AAD-3204-11D2-9A82-006008A86939}")
	// "Windows Kernel Trace" provider GUID (only one session can be running at any time)
	// If there is another session running that uses this GUID, the new session will stop the old one.
	systemTraceControlGuid = &GUID{ /* {9E814AAD-3204-11D2-9A82-006008A86939} */
		Data1: 0x9e814aad,
		Data2: 0x3204,
		Data3: 0x11d2,
		Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39},
	}

	// Most of these are Legacy events, using MOF.
	// Some providers for the kernel are very old and not parse well, like NetworkTCPIP, use the manifest providers
	// or the new SystemProvider on Windows 10 SDK build 20348 or later
	//
	// But they are still useful for some cases. like obtaining context switches.
	//
	// Deprecated: Use the KernelFlag constants (e.g., etw.Process, etw.Thread) with
	// NewKernelRealTimeSession instead. This slice will be removed in a future version.
	KernelProviders = []ProviderKernel{

		// Some comments where taken from https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs

		// Logs Advanced Local Procedure call events.
		// https://docs.microsoft.com/en-us/windows/win32/etw/alpc
		{Name: "ALPC",
			Kernel: true,
			GUID:   "{45d8cccd-539f-4b72-a8b7-5c683142609a}",
			Flags:  EVENT_TRACE_FLAG_ALPC},

		//{Name: "ApplicationVerifier", Kernel: true, GUID: "{78d14f17-0105-46d7-bfff-6fbea2f3f358}"},

		// Logs debug output messages from kernel-mode components using DbgPrint/DbgPrintEx
		{Name: "DbgPrint",
			Kernel: true,
			GUID:   "{13976d09-a327-438c-950b-7f03192815c7}",
			Flags:  EVENT_TRACE_FLAG_DBGPRINT},

		// Loads the completion of Physical disk activity.
		// https://docs.microsoft.com/en-us/windows/win32/etw/diskio
		{Name: "DiskIo",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISK_IO},

		// Logs the initialization of disk IO operations.
		// Generally not TOO volumous (typically less than 1K per second)
		// (Stacks associated with this)
		{Name: "DiskIoInit",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISK_IO_INIT},

		// Logs the completion of disk IO operations.
		// More info on https://learn.microsoft.com/en-us/windows/win32/etw/diskio
		// Driver* events.
		{Name: "Driver",
			Kernel: true,
			GUID:   "{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DRIVER},

		//{Name: "DiskPerf", Kernel: true, GUID: "{bdd865d1-d7c1-11d0-a501-00a0c9062910}"},
		//{Name: "DriverVerifier", Kernel: true, GUID: "{d56ca431-61bf-4904-a621-00e0381e4dde"},
		//{Name: "EventLog", Kernel: true, GUID: "{b16f9f5e-b3da-4027-9318-adf2b79df73b}"},

		// Unlike other NT Kernel Logger events, the kernel session automatically generates hardware configuration events;
		//  you do not enable these events when starting the NT Kernel Logger session.
		// More info on https://learn.microsoft.com/en-us/windows/win32/etw/hwconfig
		// More info on https://learn.microsoft.com/en-us/windows/win32/etw/systemconfig
		// Use flag EVENT_TRACE_FLAG_NO_SYSCONFIG to disable Windows Kernel/SystemConfig/* rundown events
		{Name: "EventTraceConfig",
			Kernel: true,
			GUID:   "{01853a65-418f-4f36-aefc-dc0f1d2fd235}"}, // No Flags, auto added by the kernel session

		// log file FileOperationEnd (has status code) when they complete (even ones that do not actually
		// cause Disk I/O).  (Vista+ only)
		// Generally not TOO volumous (typically less than 1K per second) (No stacks associated with these)
		// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
		{Name: "FileIo",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_FILE_IO},

		// Logs the mapping of file IDs to actual (kernel) file names.
		// Rundown event with opcode 36 (EventType)
		// https://learn.microsoft.com/en-us/windows/win32/etw/fileio-name
		// FileObject is used to correlate with other FileIo events that reference the same file
		// FileKey persists across system reboots and can be used to track the same file over time
		{Name: "DiskFileIo",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO},

		// log the start of the File I/O operation as well as the end. (Vista+ only)
		// Generally not TOO volumous (typically less than 1K per second)
		{Name: "FileIoInit",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_FILE_IO_INIT},

		// Enables the map and unmap (excluding image files) event type)
		// Log mapping of files into memory (Win8 and above Only)
		// Generally low volume.
		{Name: "FileIoVAmap",
			Kernel: true,
			GUID:   "{90cbdc39-4a3e-11d1-84f4-0000f80464e3}",
			Flags:  EVENT_TRACE_FLAG_VAMAP},

		//{Name: "GenericMessage", Kernel: true, GUID: "{8d40301f-ab4a-11d2-9a93-00805f85d7c6}"},
		//{Name: "GlobalLogger", Kernel: true, GUID: "{e8908abc-aa84-11d2-9a93-00805f85d7c6}"},
		//{Name: "HardFault", Kernel: true, GUID: "{3d6fa8d2-fe05-11d0-9dda-00c04fd7ba7c}"},

		// Logs native modules loads (LoadLibrary), and unloads (FreeLibrary).
		// https://docs.microsoft.com/en-us/windows/win32/etw/image
		{Name: "ImageLoad",
			Kernel: true,
			GUID:   "{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}",
			Flags:  EVENT_TRACE_FLAG_IMAGE_LOAD},

		//{Name: "MsSystemInformation", Kernel: true, GUID: "{98a2b9d7-94dd-496a-847e-67a5557a59f2}"},

		// Logs all page faults (hard or soft)
		// Can be pretty volumous (> 1K per second)
		// https://docs.microsoft.com/en-us/windows/win32/etw/pagefault-v2
		{Name: "MemoryPageFault",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS},

		// Logs all page faults that must fetch the data from the disk (hard faults)
		{Name: "MemoryHardFault",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS},

		// Log Virtual Alloc calls and VirtualFree.   (Vista+ Only)
		// Generally not TOO volumous (typically less than 1K per second)
		{Name: "VirtualAlloc",
			Kernel: true,
			GUID:   "{3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_VIRTUAL_ALLOC},

		// Device Driver logging (Vista+ only)
		// https://docs.microsoft.com/en-us/windows/win32/etw/process
		{Name: "DPC",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_DPC},

		// log hardware interrupts. (Vista+ only)
		// https://learn.microsoft.com/es-es/windows/win32/etw/isr
		{Name: "Interrupt",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_INTERRUPT},

		// Sampled based profiling (every msec)
		// (expect 1K events per proc per second)
		// requieres special privileges.
		{Name: "Profile",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_PROFILE},

		// log calls to the OS (Vista+ only)
		// This is VERY volumous (can be > 100K events per second)
		{Name: "Syscall",
			Kernel: true,
			GUID:   "{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
			Flags:  EVENT_TRACE_FLAG_SYSTEMCALL},

		// Logs process starts and stops.
		// https://docs.microsoft.com/en-us/windows/win32/etw/process
		{Name: "Process",
			Kernel: true,
			GUID:   "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_PROCESS},

		// Logs process performance counters (CPU, IO, etc).
		// https://docs.microsoft.com/en-us/windows/win32/etw/process
		{Name: "ProcessCounters",
			Kernel: true,
			GUID:   "{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_PROCESS_COUNTERS},

		// Logs activity to the windows registry.
		// Can be pretty volumous (> 1K per second)
		// https://docs.microsoft.com/en-us/windows/win32/etw/registry
		{Name: "Registry",
			Kernel: true,
			GUID:   "{ae53722e-c863-11d2-8659-00c04fa321a1}",
			Flags:  EVENT_TRACE_FLAG_REGISTRY},

		// Disk I/O that was split (eg because of mirroring requirements) (Vista+ only)
		// https://docs.microsoft.com/en-us/windows/win32/etw/splitio
		{Name: "SplitIo",
			Kernel: true,
			GUID:   "{d837ca92-12b9-44a5-ad6a-3a65b3578aa8}",
			Flags:  EVENT_TRACE_FLAG_SPLIT_IO},

		// Logs TCP/IP network send and receive events.
		// https://docs.microsoft.com/en-us/windows/win32/etw/tcpip
		{Name: "TcpIp",
			Kernel: true,
			GUID:   "{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
			Flags:  EVENT_TRACE_FLAG_NETWORK_TCPIP},
		//{Name: "ThermalZone", Kernel: true, GUID: "{a1bc18c0-a7c8-11d1-bf3c-00a0c9062910}"},

		// Logs thread starts and stops.
		// https://docs.microsoft.com/en-us/windows/win32/etw/thread
		{Name: "Thread",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_THREAD},

		// Logs thread context switches. (use with ReadyThread to get full context switches)
		// (can be > 10K events per second)
		{Name: "CSwitch",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_CSWITCH},

		// Thread Dispatcher (ReadyThread) (Vista+ only)
		// (can be > 10K events per second)
		{Name: "Dispatcher",
			Kernel: true,
			GUID:   "{3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}",
			Flags:  EVENT_TRACE_FLAG_DISPATCHER},

		//{Name: "TraceError", Kernel: true, GUID: "{398191dc-2da7-11d3-8b98-00805f85d7c6}"},

		// https://docs.microsoft.com/en-us/windows/win32/etw/udpip
		{Name: "UdpIp",
			Kernel: true,
			GUID:   "{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}",
			Flags:  EVENT_TRACE_FLAG_NETWORK_TCPIP},

		//{Name: "WmiEventLogger", Kernel: true, GUID: "{44608a51-1851-4456-98b2-b300e931ee41}"}
	}
)

var (
	// New System Provider GUIDs (replaces the old NT Kernel Logger)
	// Used in windows 11 or later

	SystemAlpcProviderGuid       = MustParseGUID("{fcb9baaf-e529-4980-92e9-ced1a6aadfdf}")
	SystemConfigProviderGuid     = MustParseGUID("{fef3a8b6-318d-4b67-a96a-3b0f6b8f18fe}")
	SystemCpuProviderGuid        = MustParseGUID("{c6c5265f-eae8-4650-aae4-9d48603d8510}")
	SystemHypervisorProviderGuid = MustParseGUID("{bafa072a-918a-4bed-b622-bc152097098f}")
	SystemInterruptProviderGuid  = MustParseGUID("{d4bbee17-b545-4888-858b-744169015b25}")
	SystemIoProviderGuid         = MustParseGUID("{3d5c43e3-0f1c-4202-b817-174c0070dc79}")
	SystemIoFilterProviderGuid   = MustParseGUID("{fbd09363-9e22-4661-b8bf-e7a34b535b8c}")
	SystemLockProviderGuid       = MustParseGUID("{721ddfd3-dacc-4e1e-b26a-a2cb31d4705a}")
	SystemMemoryProviderGuid     = MustParseGUID("{82958ca9-b6cd-47f8-a3a8-03ae85a4bc24}")
	SystemObjectProviderGuid     = MustParseGUID("{febd7460-3d1d-47eb-af49-c9eeb1e146f2}")
	SystemPowerProviderGuid      = MustParseGUID("{c134884a-32d5-4488-80e5-14ed7abb8269}")
	SystemProcessProviderGuid    = MustParseGUID("{151f55dc-467d-471f-83b5-5f889d46ff66}")
	SystemProfileProviderGuid    = MustParseGUID("{bfeb0324-1cee-496f-a409-2ac2b48a6322}")
	SystemRegistryProviderGuid   = MustParseGUID("{16156bd9-fab4-4cfa-a232-89d1099058e3}")
	SystemSchedulerProviderGuid  = MustParseGUID("{599a2a76-4d91-4910-9ac7-7d33f2e97a6c}")
	SystemSyscallProviderGuid    = MustParseGUID("{e4310a25-0b1f-4e6d-8c5d-6a7b5b0d5c3d}")
	SystemTimerProviderGuid      = MustParseGUID("{6a399ae0-4e0b-4d6d-8c5d-6a7b5b0d5c3d}")
)

// TODO: port this to new interface with KernelFlag constants
// GetKernelProviderFlags returns the flags for the given kernel provider names or GUIDs.
// It is case insensitive.
//
// Deprecated: Use the KernelFlag constants (e.g., etw.Process, etw.Thread) with
// NewKernelRealTimeSession instead. This function will be removed in a future version.
func GetKernelProviderFlags(terms ...string) (flags uint32) {
	for _, t := range terms {
		for _, pd := range KernelProviders {
			if strings.EqualFold(t, pd.Name) || t == pd.GUID {
				flags |= pd.Flags
			}
		}

	}
	return
}

// TODO: port this to new interface with KernelFlag constants
// IsKernelProvider checks if this is a system event trace provider.
//
// Deprecated: This function is no longer needed with the new KernelFlag constants.
// It will be removed in a future version.
func IsKernelProvider(term string) bool {
	for _, pd := range KernelProviders {
		if strings.EqualFold(term, pd.Name) || term == pd.GUID {
			return true
		}
	}
	return false
}

// v10.0.20348 evntrace.h
//
// System Provider Keywords (to be used with Provider MatchAnyKeyword or MatchAllKeyword).
//
// Source: Windows SDK build 20348.1
//
// For Windows 11+: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
const (
	// System ALPC Provider
	SYSTEM_ALPC_KW_GENERAL = 0x00000001

	// System Config Provider
	SYSTEM_CONFIG_KW_SYSTEM   = 0x00000001
	SYSTEM_CONFIG_KW_GRAPHICS = 0x00000002
	SYSTEM_CONFIG_KW_STORAGE  = 0x00000004
	SYSTEM_CONFIG_KW_NETWORK  = 0x00000008
	SYSTEM_CONFIG_KW_SERVICES = 0x00000010
	SYSTEM_CONFIG_KW_PNP      = 0x00000020
	SYSTEM_CONFIG_KW_OPTICAL  = 0x00000040

	// System CPU Provider
	SYSTEM_CPU_KW_CONFIG        = 0x00000001
	SYSTEM_CPU_KW_CACHE_FLUSH   = 0x00000002
	SYSTEM_CPU_KW_SPEC_CONTROL  = 0x00000004
	SYSTEM_CPU_KW_DOMAIN_CHANGE = 0x00000008

	// System Hypervisor Provider
	SYSTEM_HYPERVISOR_KW_PROFILE    = 0x00000001
	SYSTEM_HYPERVISOR_KW_CALLOUTS   = 0x00000002
	SYSTEM_HYPERVISOR_KW_VTL_CHANGE = 0x00000004

	// System Interrupt Provider
	SYSTEM_INTERRUPT_KW_GENERAL         = 0x00000001
	SYSTEM_INTERRUPT_KW_CLOCK_INTERRUPT = 0x00000002
	SYSTEM_INTERRUPT_KW_DPC             = 0x00000004
	SYSTEM_INTERRUPT_KW_DPC_QUEUE       = 0x00000008
	SYSTEM_INTERRUPT_KW_WDF_DPC         = 0x00000010
	SYSTEM_INTERRUPT_KW_WDF_INTERRUPT   = 0x00000020
	SYSTEM_INTERRUPT_KW_IPI             = 0x00000040

	// System IO Provider
	SYSTEM_IO_KW_DISK         = 0x00000001
	SYSTEM_IO_KW_DISK_INIT    = 0x00000002
	SYSTEM_IO_KW_FILENAME     = 0x00000004
	SYSTEM_IO_KW_SPLIT        = 0x00000008
	SYSTEM_IO_KW_FILE         = 0x00000010
	SYSTEM_IO_KW_OPTICAL      = 0x00000020
	SYSTEM_IO_KW_OPTICAL_INIT = 0x00000040
	SYSTEM_IO_KW_DRIVERS      = 0x00000080
	SYSTEM_IO_KW_CC           = 0x00000100
	SYSTEM_IO_KW_NETWORK      = 0x00000200
	SYSTEM_IO_KW_FILE_INIT    = 0x00000400
	SYSTEM_IO_KW_TIMER        = 0x00000800

	// System IO Filter Provider
	SYSTEM_IOFILTER_KW_GENERAL = 0x00000001
	SYSTEM_IOFILTER_KW_INIT    = 0x00000002
	SYSTEM_IOFILTER_KW_FASTIO  = 0x00000004
	SYSTEM_IOFILTER_KW_FAILURE = 0x00000008

	// System Lock Provider
	SYSTEM_LOCK_KW_SPINLOCK          = 0x00000001
	SYSTEM_LOCK_KW_SPINLOCK_COUNTERS = 0x00000002
	SYSTEM_LOCK_KW_SYNC_OBJECTS      = 0x00000004

	// System Memory Provider
	SYSTEM_MEMORY_KW_GENERAL       = 0x00000001
	SYSTEM_MEMORY_KW_HARD_FAULTS   = 0x00000002
	SYSTEM_MEMORY_KW_ALL_FAULTS    = 0x00000004
	SYSTEM_MEMORY_KW_POOL          = 0x00000008
	SYSTEM_MEMORY_KW_MEMINFO       = 0x00000010
	SYSTEM_MEMORY_KW_PFSECTION     = 0x00000020
	SYSTEM_MEMORY_KW_MEMINFO_WS    = 0x00000040
	SYSTEM_MEMORY_KW_HEAP          = 0x00000080
	SYSTEM_MEMORY_KW_WS            = 0x00000100
	SYSTEM_MEMORY_KW_CONTMEM_GEN   = 0x00000200
	SYSTEM_MEMORY_KW_VIRTUAL_ALLOC = 0x00000400
	SYSTEM_MEMORY_KW_FOOTPRINT     = 0x00000800
	SYSTEM_MEMORY_KW_SESSION       = 0x00001000
	SYSTEM_MEMORY_KW_REFSET        = 0x00002000
	SYSTEM_MEMORY_KW_VAMAP         = 0x00004000
	SYSTEM_MEMORY_KW_NONTRADEABLE  = 0x00008000

	// System Object Provider
	SYSTEM_OBJECT_KW_GENERAL = 0x00000001
	SYSTEM_OBJECT_KW_HANDLE  = 0x00000002

	// System Power Provider
	SYSTEM_POWER_KW_GENERAL          = 0x00000001
	SYSTEM_POWER_KW_HIBER_RUNDOWN    = 0x00000002
	SYSTEM_POWER_KW_PROCESSOR_IDLE   = 0x00000004
	SYSTEM_POWER_KW_IDLE_SELECTION   = 0x00000008
	SYSTEM_POWER_KW_PPM_EXIT_LATENCY = 0x00000010

	// System Process Provider
	SYSTEM_PROCESS_KW_GENERAL       = 0x00000001
	SYSTEM_PROCESS_KW_INSWAP        = 0x00000002
	SYSTEM_PROCESS_KW_FREEZE        = 0x00000004
	SYSTEM_PROCESS_KW_PERF_COUNTER  = 0x00000008
	SYSTEM_PROCESS_KW_WAKE_COUNTER  = 0x00000010
	SYSTEM_PROCESS_KW_WAKE_DROP     = 0x00000020
	SYSTEM_PROCESS_KW_WAKE_EVENT    = 0x00000040
	SYSTEM_PROCESS_KW_DEBUG_EVENTS  = 0x00000080
	SYSTEM_PROCESS_KW_DBGPRINT      = 0x00000100
	SYSTEM_PROCESS_KW_JOB           = 0x00000200
	SYSTEM_PROCESS_KW_WORKER_THREAD = 0x00000400
	SYSTEM_PROCESS_KW_THREAD        = 0x00000800
	SYSTEM_PROCESS_KW_LOADER        = 0x00001000

	// System Profile Provider
	SYSTEM_PROFILE_KW_GENERAL     = 0x00000001
	SYSTEM_PROFILE_KW_PMC_PROFILE = 0x00000002

	// System Registry Provider
	SYSTEM_REGISTRY_KW_GENERAL      = 0x00000001
	SYSTEM_REGISTRY_KW_HIVE         = 0x00000002
	SYSTEM_REGISTRY_KW_NOTIFICATION = 0x00000004

	// System Scheduler Provider
	SYSTEM_SCHEDULER_KW_XSCHEDULER            = 0x00000001
	SYSTEM_SCHEDULER_KW_DISPATCHER            = 0x00000002
	SYSTEM_SCHEDULER_KW_KERNEL_QUEUE          = 0x00000004
	SYSTEM_SCHEDULER_KW_SHOULD_YIELD          = 0x00000008
	SYSTEM_SCHEDULER_KW_ANTI_STARVATION       = 0x00000010
	SYSTEM_SCHEDULER_KW_LOAD_BALANCER         = 0x00000020
	SYSTEM_SCHEDULER_KW_AFFINITY              = 0x00000040
	SYSTEM_SCHEDULER_KW_PRIORITY              = 0x00000080
	SYSTEM_SCHEDULER_KW_IDEAL_PROCESSOR       = 0x00000100
	SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH        = 0x00000200
	SYSTEM_SCHEDULER_KW_COMPACT_CSWITCH       = 0x00000400
	SYSTEM_SCHEDULER_KW_SCHEDULE_THREAD       = 0x00000800
	SYSTEM_SCHEDULER_KW_READY_QUEUE           = 0x00001000
	SYSTEM_SCHEDULER_KW_CPU_PARTITION         = 0x00002000
	SYSTEM_SCHEDULER_KW_THREAD_FEEDBACK_READ  = 0x00004000
	SYSTEM_SCHEDULER_KW_WORKLOAD_CLASS_UPDATE = 0x00008000
	SYSTEM_SCHEDULER_KW_AUTOBOOST             = 0x00010000

	// System Syscall Provider
	SYSTEM_SYSCALL_KW_GENERAL = 0x00000001

	// System Timer Provider
	SYSTEM_TIMER_KW_GENERAL     = 0x00000001
	SYSTEM_TIMER_KW_CLOCK_TIMER = 0x00000002
)
