//go:build windows

package etw

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wmistr/ns-wmistr-_wnode_header
// v10.0.16299.0 /wmistr.h
//
// WNODE_HEADER flags are defined as follows
/*
   #define WNODE_FLAG_ALL_DATA        0x00000001 // set for WNODE_ALL_DATA
   #define WNODE_FLAG_SINGLE_INSTANCE 0x00000002 // set for WNODE_SINGLE_INSTANCE
   #define WNODE_FLAG_SINGLE_ITEM     0x00000004 // set for WNODE_SINGLE_ITEM
   #define WNODE_FLAG_EVENT_ITEM      0x00000008 // set for WNODE_EVENT_ITEM

                                               // Set if data block size is
                                               // identical for all instances
                                               // (used with  WNODE_ALL_DATA
                                               // only)
   #define WNODE_FLAG_FIXED_INSTANCE_SIZE 0x00000010

   #define WNODE_FLAG_TOO_SMALL           0x00000020 // set for WNODE_TOO_SMALL

                                   // Set when a data provider returns a
                                   // WNODE_ALL_DATA in which the number of
                                   // instances and their names returned
                                   // are identical to those returned from the
                                   // previous WNODE_ALL_DATA query. Only data
                                   // blocks registered with dynamic instance
                                   // names should use this flag.
   #define WNODE_FLAG_INSTANCES_SAME  0x00000040

                                   // Instance names are not specified in
                                   // WNODE_ALL_DATA; values specified at
                                   // registration are used instead. Always
                                   // set for guids registered with static
                                   // instance names
   #define WNODE_FLAG_STATIC_INSTANCE_NAMES 0x00000080

   #define WNODE_FLAG_INTERNAL      0x00000100  // Used internally by WMI

                                   // timestamp should not be modified by
                                   // a historical logger
   #define WNODE_FLAG_USE_TIMESTAMP 0x00000200

   #if (NTDDI_VERSION >= NTDDI_WINXP)
   #define WNODE_FLAG_PERSIST_EVENT 0x00000400
   #endif

   #define WNODE_FLAG_EVENT_REFERENCE 0x00002000

   // Set if Instance names are ansi. Only set when returning from
   // WMIQuerySingleInstanceA and WMIQueryAllDataA
   #define WNODE_FLAG_ANSI_INSTANCENAMES 0x00004000

   // Set if WNODE is a method call
   #define WNODE_FLAG_METHOD_ITEM     0x00008000

   // Set if instance names originated from a PDO
   #define WNODE_FLAG_PDO_INSTANCE_NAMES  0x00010000

   // The second byte, except the first bit is used exclusively for tracing
   #define WNODE_FLAG_TRACED_GUID   0x00020000 // denotes a trace

   #define WNODE_FLAG_LOG_WNODE     0x00040000 // request to log Wnode

   #define WNODE_FLAG_USE_GUID_PTR  0x00080000 // Guid is actually a pointer

   #define WNODE_FLAG_USE_MOF_PTR   0x00100000 // MOF data are dereferenced

   #if (NTDDI_VERSION >= NTDDI_WINXP)
   #define WNODE_FLAG_NO_HEADER     0x00200000 // Trace without header
   #endif

   #if (NTDDI_VERSION >= NTDDI_VISTA)
   #define WNODE_FLAG_SEND_DATA_BLOCK  0x00400000 // Data Block delivery
   #endif

   // Set for events that are WNODE_EVENT_REFERENCE
   // Mask for event severity level. Level 0xff is the most severe type of event
   #define WNODE_FLAG_SEVERITY_MASK 0xff000000
*/

// The WNODE_HEADER structure is the first member of all other WNODE_XXX structures. It contains information common to all such structures.
const (
	WNODE_FLAG_ALL_DATA              = 0x00000001
	WNODE_FLAG_SINGLE_INSTANCE       = 0x00000002
	WNODE_FLAG_SINGLE_ITEM           = 0x00000004
	WNODE_FLAG_EVENT_ITEM            = 0x00000008
	WNODE_FLAG_FIXED_INSTANCE_SIZE   = 0x00000010
	WNODE_FLAG_TOO_SMALL             = 0x00000020
	WNODE_FLAG_INSTANCES_SAME        = 0x00000040
	WNODE_FLAG_STATIC_INSTANCE_NAMES = 0x00000080
	WNODE_FLAG_INTERNAL              = 0x00000100
	WNODE_FLAG_USE_TIMESTAMP         = 0x00000200
	WNODE_FLAG_PERSIST_EVENT         = 0x00000400
	WNODE_FLAG_EVENT_REFERENCE       = 0x00002000
	WNODE_FLAG_ANSI_INSTANCENAMES    = 0x00004000
	WNODE_FLAG_METHOD_ITEM           = 0x00008000
	WNODE_FLAG_PDO_INSTANCE_NAMES    = 0x00010000
	WNODE_FLAG_TRACED_GUID           = 0x00020000
	WNODE_FLAG_ANSI_INSTANCENAwin32  = 0x00040000
	WNODE_FLAG_USE_GUID_PTR          = 0x00080000
	WNODE_FLAG_USE_MOF_PTR           = 0x00100000
	WNODE_FLAG_NO_HEADER             = 0x00200000
	WNODE_FLAG_SEND_DATA_BLOCK       = 0x00400000
	WNODE_FLAG_VERSIONED_PROPERTIES  = 0x00800000
	WNODE_FLAG_SEVERITY_MASK         = 0xff000000
)

//     10.0.16299.0 /evntrace.h

//
// predefined generic event types (0x00 to 0x09 reserved).
//
/*
   #define EVENT_TRACE_TYPE_INFO               0x00  // Info or point event
   #define EVENT_TRACE_TYPE_START              0x01  // Start event
   #define EVENT_TRACE_TYPE_END                0x02  // End event
   #define EVENT_TRACE_TYPE_STOP               0x02  // Stop event (WinEvent compatible)
   #define EVENT_TRACE_TYPE_DC_START           0x03  // Collection start marker
   #define EVENT_TRACE_TYPE_DC_END             0x04  // Collection end marker
   #define EVENT_TRACE_TYPE_EXTENSION          0x05  // Extension/continuation
   #define EVENT_TRACE_TYPE_REPLY              0x06  // Reply event
   #define EVENT_TRACE_TYPE_DEQUEUE            0x07  // De-queue event
   #define EVENT_TRACE_TYPE_RESUME             0x07  // Resume event (WinEvent compatible)
   #define EVENT_TRACE_TYPE_CHECKPOINT         0x08  // Generic checkpoint event
   #define EVENT_TRACE_TYPE_SUSPEND            0x08  // Suspend event (WinEvent compatible)
   #define EVENT_TRACE_TYPE_WINEVT_SEND        0x09  // Send Event (WinEvent compatible)
   #define EVENT_TRACE_TYPE_WINEVT_RECEIVE     0XF0  // Receive Event (WinEvent compatible)
*/
// Used in https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_header

const (
	// predefined generic event types (0x00 to 0x09 reserved).

	EVENT_TRACE_TYPE_INFO           = 0x00 // Info or point event
	EVENT_TRACE_TYPE_START          = 0x01 // Start event
	EVENT_TRACE_TYPE_END            = 0x02 // End event
	EVENT_TRACE_TYPE_STOP           = 0x02 // Stop event (WinEvent compatible)
	EVENT_TRACE_TYPE_DC_START       = 0x03 // Collection start marker
	EVENT_TRACE_TYPE_DC_END         = 0x04 // Collection end marker
	EVENT_TRACE_TYPE_EXTENSION      = 0x05 // Extension/continuation
	EVENT_TRACE_TYPE_REPLY          = 0x06 // Reply event
	EVENT_TRACE_TYPE_DEQUEUE        = 0x07 // De-queue event
	EVENT_TRACE_TYPE_RESUME         = 0x07 // Resume event (WinEvent compatible)
	EVENT_TRACE_TYPE_CHECKPOINT     = 0x08 // Generic checkpoint event
	EVENT_TRACE_TYPE_SUSPEND        = 0x08 // Suspend event (WinEvent compatible)
	EVENT_TRACE_TYPE_WINEVT_SEND    = 0x09 // Send Event (WinEvent compatible)
	EVENT_TRACE_TYPE_WINEVT_RECEIVE = 0xf0 // Receive Event (WinEvent compatible)

	// Event types for Process & Threads

	EVENT_TRACE_TYPE_LOAD      = 0x0a // Load image
	EVENT_TRACE_TYPE_TERMINATE = 0x0b // Terminate Process

	// Event types for IO subsystem

	EVENT_TRACE_TYPE_IO_READ       = 0x0a
	EVENT_TRACE_TYPE_IO_WRITE      = 0x0b
	EVENT_TRACE_TYPE_IO_READ_INIT  = 0x0c
	EVENT_TRACE_TYPE_IO_WRITE_INIT = 0x0d
	EVENT_TRACE_TYPE_IO_FLUSH      = 0x0e
	EVENT_TRACE_TYPE_IO_FLUSH_INIT = 0x0f

	// Event types for Memory subsystem

	EVENT_TRACE_TYPE_MM_TF  = 0x0a // Transition fault
	EVENT_TRACE_TYPE_MM_DZF = 0x0b // Demand Zero fault
	EVENT_TRACE_TYPE_MM_COW = 0x0c // Copy on Write
	EVENT_TRACE_TYPE_MM_GPF = 0x0d // Guard Page fault
	EVENT_TRACE_TYPE_MM_HPF = 0x0e // Hard page fault
	EVENT_TRACE_TYPE_MM_AV  = 0x0f // Access violation

	// Event types for Network subsystem, all protocols

	EVENT_TRACE_TYPE_SEND       = 0x0a // Send
	EVENT_TRACE_TYPE_RECEIVE    = 0x0b // Receive
	EVENT_TRACE_TYPE_CONNECT    = 0x0c // Connect
	EVENT_TRACE_TYPE_DISCONNECT = 0x0d // Disconnect
	EVENT_TRACE_TYPE_RETRANSMIT = 0x0e // ReTransmit
	EVENT_TRACE_TYPE_ACCEPT     = 0x0f // Accept
	EVENT_TRACE_TYPE_RECONNECT  = 0x10 // ReConnect
	EVENT_TRACE_TYPE_CONNFAIL   = 0x11 // Fail
	EVENT_TRACE_TYPE_COPY_TCP   = 0x12 // Copy in PendData
	EVENT_TRACE_TYPE_COPY_ARP   = 0x13 // NDIS_STATUS_RESOURCES Copy
	EVENT_TRACE_TYPE_ACKFULL    = 0x14 // A full data ACK
	EVENT_TRACE_TYPE_ACKPART    = 0x15 // A Partial data ACK
	EVENT_TRACE_TYPE_ACKDUP     = 0x16 // A Duplicate data ACK

	// Event Types for the Header (to handle internal event headers)

	EVENT_TRACE_TYPE_GUIDMAP    = 0x0a
	EVENT_TRACE_TYPE_CONFIG     = 0x0b
	EVENT_TRACE_TYPE_SIDINFO    = 0x0c
	EVENT_TRACE_TYPE_SECURITY   = 0x0d
	EVENT_TRACE_TYPE_DBGID_RSDS = 0x40

	// Event Types for Registry subsystem

	EVENT_TRACE_TYPE_REGCREATE             = 0x0A // NtCreateKey
	EVENT_TRACE_TYPE_REGOPEN               = 0x0B // NtOpenKey
	EVENT_TRACE_TYPE_REGDELETE             = 0x0C // NtDeleteKey
	EVENT_TRACE_TYPE_REGQUERY              = 0x0D // NtQueryKey
	EVENT_TRACE_TYPE_REGSETVALUE           = 0x0E // NtSetValueKey
	EVENT_TRACE_TYPE_REGDELETEVALUE        = 0x0F // NtDeleteValueKey
	EVENT_TRACE_TYPE_REGQUERYVALUE         = 0x10 // NtQueryValueKey
	EVENT_TRACE_TYPE_REGENUMERATEKEY       = 0x11 // NtEnumerateKey
	EVENT_TRACE_TYPE_REGENUMERATEVALUEKEY  = 0x12 // NtEnumerateValueKey
	EVENT_TRACE_TYPE_REGQUERYMULTIPLEVALUE = 0x13 // NtQueryMultipleValueKey
	EVENT_TRACE_TYPE_REGSETINFORMATION     = 0x14 // NtSetInformationKey
	EVENT_TRACE_TYPE_REGFLUSH              = 0x15 // NtFlushKey
	EVENT_TRACE_TYPE_REGKCBCREATE          = 0x16 // KcbCreate
	EVENT_TRACE_TYPE_REGKCBDELETE          = 0x17 // KcbDelete
	EVENT_TRACE_TYPE_REGKCBRUNDOWNBEGIN    = 0x18 // KcbRundownBegin
	EVENT_TRACE_TYPE_REGKCBRUNDOWNEND      = 0x19 // KcbRundownEnd
	EVENT_TRACE_TYPE_REGVIRTUALIZE         = 0x1A // VirtualizeKey
	EVENT_TRACE_TYPE_REGCLOSE              = 0x1B // NtClose (KeyObject)
	EVENT_TRACE_TYPE_REGSETSECURITY        = 0x1C // SetSecurityDescriptor (KeyObject)
	EVENT_TRACE_TYPE_REGQUERYSECURITY      = 0x1D // QuerySecurityDescriptor (KeyObject)
	EVENT_TRACE_TYPE_REGCOMMIT             = 0x1E // CmKtmNotification (TRANSACTION_NOTIFY_COMMIT)
	EVENT_TRACE_TYPE_REGPREPARE            = 0x1F // CmKtmNotification (TRANSACTION_NOTIFY_PREPARE)
	EVENT_TRACE_TYPE_REGROLLBACK           = 0x20 // CmKtmNotification (TRANSACTION_NOTIFY_ROLLBACK)
	EVENT_TRACE_TYPE_REGMOUNTHIVE          = 0x21 // NtLoadKey variations + system hives

	// Event types for system configuration records

	EVENT_TRACE_TYPE_CONFIG_CPU          = 0x0A // CPU Configuration
	EVENT_TRACE_TYPE_CONFIG_PHYSICALDISK = 0x0B // Physical Disk Configuration
	EVENT_TRACE_TYPE_CONFIG_LOGICALDISK  = 0x0C // Logical Disk Configuration
	EVENT_TRACE_TYPE_CONFIG_NIC          = 0x0D // NIC Configuration
	EVENT_TRACE_TYPE_CONFIG_VIDEO        = 0x0E // Video Adapter Configuration
	EVENT_TRACE_TYPE_CONFIG_SERVICES     = 0x0F // Active Services
	EVENT_TRACE_TYPE_CONFIG_POWER        = 0x10 // ACPI Configuration
	EVENT_TRACE_TYPE_CONFIG_NETINFO      = 0x11 // Networking Configuration
	EVENT_TRACE_TYPE_CONFIG_OPTICALMEDIA = 0x12 // Optical Media Configuration

	EVENT_TRACE_TYPE_CONFIG_IRQ             = 0x15 // IRQ assigned to devices
	EVENT_TRACE_TYPE_CONFIG_PNP             = 0x16 // PnP device info
	EVENT_TRACE_TYPE_CONFIG_IDECHANNEL      = 0x17 // Primary/Secondary IDE channel Configuration
	EVENT_TRACE_TYPE_CONFIG_NUMANODE        = 0x18 // Numa configuration
	EVENT_TRACE_TYPE_CONFIG_PLATFORM        = 0x19 // Platform Configuration
	EVENT_TRACE_TYPE_CONFIG_PROCESSORGROUP  = 0x1A // Processor Group Configuration
	EVENT_TRACE_TYPE_CONFIG_PROCESSORNUMBER = 0x1B // ProcessorIndex -> ProcNumber mapping
	EVENT_TRACE_TYPE_CONFIG_DPI             = 0x1C // Display DPI Configuration
	EVENT_TRACE_TYPE_CONFIG_CI_INFO         = 0x1D // Display System Code Integrity Information
	EVENT_TRACE_TYPE_CONFIG_MACHINEID       = 0x1E // SQM Machine Id

	// Event types for Optical IO subsystem

	EVENT_TRACE_TYPE_OPTICAL_IO_READ       = 0x37
	EVENT_TRACE_TYPE_OPTICAL_IO_WRITE      = 0x38
	EVENT_TRACE_TYPE_OPTICAL_IO_FLUSH      = 0x39
	EVENT_TRACE_TYPE_OPTICAL_IO_READ_INIT  = 0x3a
	EVENT_TRACE_TYPE_OPTICAL_IO_WRITE_INIT = 0x3b
	EVENT_TRACE_TYPE_OPTICAL_IO_FLUSH_INIT = 0x3c

	// Event types for Filter Manager

	EVENT_TRACE_TYPE_FLT_PREOP_INIT        = 0x60
	EVENT_TRACE_TYPE_FLT_POSTOP_INIT       = 0x61
	EVENT_TRACE_TYPE_FLT_PREOP_COMPLETION  = 0x62
	EVENT_TRACE_TYPE_FLT_POSTOP_COMPLETION = 0x63
	EVENT_TRACE_TYPE_FLT_PREOP_FAILURE     = 0x64
	EVENT_TRACE_TYPE_FLT_POSTOP_FAILURE    = 0x65

	// Enable flags for Kernel Events
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	EVENT_TRACE_FLAG_PROCESS    = 0x00000001 // process start & end
	EVENT_TRACE_FLAG_THREAD     = 0x00000002 // thread start & end
	EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004 // image load

	EVENT_TRACE_FLAG_DISK_IO      = 0x00000100 // Physical disk IO
	EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200 // Requires disk IO

	EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000 // All page faults
	EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000 // Hard faults only

	EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000 // TCP/IP send & receive

	EVENT_TRACE_FLAG_REGISTRY = 0x00020000 // Registry calls
	EVENT_TRACE_FLAG_DBGPRINT = 0x00040000 // DbgPrint(ex) Calls

	// Enable flags for Kernel Events on Vista and above

	EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008 // Process performance counters
	EVENT_TRACE_FLAG_CSWITCH          = 0x00000010 // Context switches
	EVENT_TRACE_FLAG_DPC              = 0x00000020 // Deferred procedure calls
	EVENT_TRACE_FLAG_INTERRUPT        = 0x00000040 // Interrupts
	EVENT_TRACE_FLAG_SYSTEMCALL       = 0x00000080 // System calls

	EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400 // Physical disk IO initiation
	EVENT_TRACE_FLAG_ALPC         = 0x00100000 // ALPC traces
	EVENT_TRACE_FLAG_SPLIT_IO     = 0x00200000 // Split IO traces (VolumeManager)

	EVENT_TRACE_FLAG_DRIVER       = 0x00800000 // Driver delays
	EVENT_TRACE_FLAG_PROFILE      = 0x01000000 // Sample-based profiling
	EVENT_TRACE_FLAG_FILE_IO      = 0x02000000 // File IO
	EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000 // File IO initiation

	// Enable flags for Kernel Events on Win7 and above

	EVENT_TRACE_FLAG_DISPATCHER    = 0x00000800 // scheduler (ReadyThread)
	EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x00004000 // VM operations

	// Enable flags for Kernel Events on Win8 and above

	EVENT_TRACE_FLAG_VAMAP        = 0x00008000 // map/unmap (excluding images)
	EVENT_TRACE_FLAG_NO_SYSCONFIG = 0x10000000 // Do not do sys config rundown

	// Enable flags for Kernel Events on Threshold and above

	EVENT_TRACE_FLAG_JOB          = 0x00080000 // job start & end
	EVENT_TRACE_FLAG_DEBUG_EVENTS = 0x00400000 // debugger events (break/continue/...)

	// Pre-defined Enable flags for everybody else

	EVENT_TRACE_FLAG_EXTENSION      = 0x80000000 // Indicates more flags
	EVENT_TRACE_FLAG_FORWARD_WMI    = 0x40000000 // Can forward to WMI
	EVENT_TRACE_FLAG_ENABLE_RESERVE = 0x20000000 // Reserved

	// Logger Mode flags
	EVENT_TRACE_FILE_MODE_NONE       = 0x00000000 // Logfile is off
	EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001 // Log sequentially
	EVENT_TRACE_FILE_MODE_CIRCULAR   = 0x00000002 // Log in circular manner
	EVENT_TRACE_FILE_MODE_APPEND     = 0x00000004 // Append sequential log

	EVENT_TRACE_REAL_TIME_MODE       = 0x00000100 // Real-time mode on
	EVENT_TRACE_DELAY_OPEN_FILE_MODE = 0x00000200 // Delay opening file
	EVENT_TRACE_BUFFERING_MODE       = 0x00000400 // Buffering mode only
	EVENT_TRACE_PRIVATE_LOGGER_MODE  = 0x00000800 // Process Private Logger
	EVENT_TRACE_ADD_HEADER_MODE      = 0x00001000 // Add a logfile header

	EVENT_TRACE_USE_GLOBAL_SEQUENCE = 0x00004000 // Use global sequence number
	EVENT_TRACE_USE_LOCAL_SEQUENCE  = 0x00008000 // Use local sequence number

	EVENT_TRACE_RELOG_MODE = 0x00010000 // Relogger

	EVENT_TRACE_USE_PAGED_MEMORY = 0x01000000 // Use pageable buffers

	// Logger Mode flags on XP and above

	EVENT_TRACE_FILE_MODE_NEWFILE     = 0x00000008 // Auto-switch log file
	EVENT_TRACE_FILE_MODE_PREALLOCATE = 0x00000020 // Pre-allocate mode

	// Logger Mode flags on Vista and above

	EVENT_TRACE_NONSTOPPABLE_MODE   = 0x00000040 // Session cannot be stopped (Autologger only)
	EVENT_TRACE_SECURE_MODE         = 0x00000080 // Secure session
	EVENT_TRACE_USE_KBYTES_FOR_SIZE = 0x00002000 // Use KBytes as file size unit
	EVENT_TRACE_PRIVATE_IN_PROC     = 0x00020000 // In process private logger

	EVENT_TRACE_MODE_RESERVED = 0x00100000 // Reserved bit, used to signal Heap/Critsec tracing

	// Logger Mode flags on Win7 and above

	EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000 // Use this for low frequency sessions.

	// Logger Mode flags on Win8 and above

	EVENT_TRACE_SYSTEM_LOGGER_MODE         = 0x02000000 // Receive events from SystemTraceProvider
	EVENT_TRACE_ADDTO_TRIAGE_DUMP          = 0x80000000 // Add ETW buffers to triage dumps
	EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN    = 0x00400000 // Stop on hybrid shutdown
	EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = 0x00800000 // Persist on hybrid shutdown

	// Logger Mode flags on Blue and above

	EVENT_TRACE_INDEPENDENT_SESSION_MODE = 0x08000000 // Independent logger session

	// ControlTrace Codes

	EVENT_TRACE_CONTROL_QUERY  = 0
	EVENT_TRACE_CONTROL_STOP   = 1
	EVENT_TRACE_CONTROL_UPDATE = 2

	// Flush ControlTrace Codes for XP and above

	EVENT_TRACE_CONTROL_FLUSH = 3 // Flushes all the buffers

	// ...

	// Flags to indicate to consumer which fields
	// in the EVENT_TRACE_HEADER are valid

	EVENT_TRACE_USE_PROCTIME  = 0x0001 // ProcessorTime field is valid
	EVENT_TRACE_USE_NOCPUTIME = 0x0002 // No Kernel/User/Processor Times
)

const (
	EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
	EVENT_CONTROL_CODE_ENABLE_PROVIDER  = 1
	EVENT_CONTROL_CODE_CAPTURE_STATE    = 2
)

// v10.0.16299.0 evntrace.h

const (
	// Predefined Event Tracing Levels for Software/Debug Tracing
	//
	// Trace Level is UCHAR and passed in through the EnableLevel parameter
	// in EnableTrace API. It is retrieved by the provider using the
	// GetTraceEnableLevel macro. It should be interpreted as an integer value
	// to mean everything at or below that level will be traced.
	//
	// Here are the possible Levels.

	TRACE_LEVEL_NONE        = 0 // Tracing is not on
	TRACE_LEVEL_CRITICAL    = 1 // Abnormal exit or termination
	TRACE_LEVEL_FATAL       = 1 // Deprecated name for Abnormal exit or termination
	TRACE_LEVEL_ERROR       = 2 // Severe errors that need logging
	TRACE_LEVEL_WARNING     = 3 // Warnings such as allocation failure
	TRACE_LEVEL_INFORMATION = 4 // Includes non-error cases(e.g.,Entry-Exit)
	TRACE_LEVEL_VERBOSE     = 5 // Detailed traces from intermediate steps
	TRACE_LEVEL_RESERVED6   = 6
	TRACE_LEVEL_RESERVED7   = 7
	TRACE_LEVEL_RESERVED8   = 8
	TRACE_LEVEL_RESERVED9   = 9
)

// evntcons.h
// used in ProcessTraceMode for
// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
const (
	PROCESS_TRACE_MODE_REAL_TIME     = 0x00000100
	PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000
	PROCESS_TRACE_MODE_EVENT_RECORD  = 0x10000000
)

// evntcons.h
// used in Flags for EVENT_HEADER
// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
const (
	EVENT_HEADER_FLAG_EXTENDED_INFO   = 0x0001
	EVENT_HEADER_FLAG_PRIVATE_SESSION = 0x0002
	EVENT_HEADER_FLAG_STRING_ONLY     = 0x0004
	EVENT_HEADER_FLAG_TRACE_MESSAGE   = 0x0008
	EVENT_HEADER_FLAG_NO_CPUTIME      = 0x0010
	EVENT_HEADER_FLAG_32_BIT_HEADER   = 0x0020
	EVENT_HEADER_FLAG_64_BIT_HEADER   = 0x0040
	EVENT_HEADER_FLAG_DECODE_GUID     = 0x0080
	EVENT_HEADER_FLAG_CLASSIC_HEADER  = 0x0100
	EVENT_HEADER_FLAG_PROCESSOR_INDEX = 0x0200
)

// evntcons.h
// used in ExtType for EVENT_HEADER_EXTENDED_DATA_ITEM
// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
const (
	EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001
	EVENT_HEADER_EXT_TYPE_SID                = 0x0002
	EVENT_HEADER_EXT_TYPE_TS_ID              = 0x0003
	EVENT_HEADER_EXT_TYPE_INSTANCE_INFO      = 0x0004
	EVENT_HEADER_EXT_TYPE_STACK_TRACE32      = 0x0005
	EVENT_HEADER_EXT_TYPE_STACK_TRACE64      = 0x0006
	EVENT_HEADER_EXT_TYPE_PEBS_INDEX         = 0x0007
	EVENT_HEADER_EXT_TYPE_PMC_COUNTERS       = 0x0008
	EVENT_HEADER_EXT_TYPE_PSM_KEY            = 0x0009
	EVENT_HEADER_EXT_TYPE_EVENT_KEY          = 0x000A
	EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL    = 0x000B
	EVENT_HEADER_EXT_TYPE_PROV_TRAITS        = 0x000C
	EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY  = 0x000D
	EVENT_HEADER_EXT_TYPE_CONTROL_GUID       = 0x000E
	EVENT_HEADER_EXT_TYPE_QPC_DELTA          = 0x000F
	EVENT_HEADER_EXT_TYPE_CONTAINER_ID       = 0x0010
	EVENT_HEADER_EXT_TYPE_STACK_KEY32        = 0x0011
	EVENT_HEADER_EXT_TYPE_STACK_KEY64        = 0x0012
	EVENT_HEADER_EXT_TYPE_MAX                = 0x0013
)

// evntcons.h
// used in EventProperty for EVENT_HEADER
// https://learn.microsoft.com/es-es/windows/win32/api/evntcons/ns-evntcons-event_header
const (
	EVENT_HEADER_PROPERTY_XML             = 0x0001
	EVENT_HEADER_PROPERTY_FORWARDED_XML   = 0x0002
	EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG = 0x0004
)

//////////////////////////////////////////////////////////////////

// https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
// v10.0.16299.0 /wmistr.h
/*
typedef struct _WNODE_HEADER
{
    ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
    ULONG ProviderId;    // Provider Id of driver returning this buffer
    union
    {
        ULONG64 HistoricalContext;  // Logger use
        struct
            {
            ULONG Version;           // Reserved
            ULONG Linkage;           // Linkage field reserved for WMI
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union
    {
        ULONG CountLost;         // Reserved
        HANDLE KernelHandle;     // Kernel handle for data block
        LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
                                 // since 1/1/1601
    } DUMMYUNIONNAME2;
    GUID Guid;                  // Guid for data block returned with results
    ULONG ClientContext;
    ULONG Flags;             // Flags, see WNODE_ flags above this.
} WNODE_HEADER, *PWNODE_HEADER;
*/
type WnodeHeader struct {
	BufferSize    uint32 // Size of entire buffer inclusive of this ULONG
	ProviderId    uint32 // Provider Id of driver returning this buffer
	Union1        uint64 // [Check C interface]
	Union2        int64  // [Check C interface]
	Guid          GUID   // Guid for data block returned with results
	ClientContext uint32
	Flags         uint32 // Flags, see WNODE_ flags above this.
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
// v10.0.19041.0 \evntrace.h
/*
typedef struct _EVENT_TRACE_PROPERTIES {
    WNODE_HEADER Wnode;
//
// data provided by caller
    ULONG BufferSize;                   // buffer size for logging (kbytes)
    ULONG MinimumBuffers;               // minimum to preallocate
    ULONG MaximumBuffers;               // maximum buffers allowed
    ULONG MaximumFileSize;              // maximum logfile size (in MBytes)
    ULONG LogFileMode;                  // sequential, circular
    ULONG FlushTimer;                   // buffer flush timer, in seconds
    ULONG EnableFlags;                  // trace enable flags
    union {
        LONG  AgeLimit;                 // unused
        LONG  FlushThreshold;           // Number of buffers to fill before flushing
    } DUMMYUNIONNAME;

// data returned to caller
    ULONG NumberOfBuffers;              // no of buffers in use
    ULONG FreeBuffers;                  // no of buffers free
    ULONG EventsLost;                   // event records lost
    ULONG BuffersWritten;               // no of buffers written to file
    ULONG LogBuffersLost;               // no of logfile write failures
    ULONG RealTimeBuffersLost;          // no of rt delivery failures
    HANDLE LoggerThreadId;              // thread id of Logger
    ULONG LogFileNameOffset;            // Offset to LogFileName
    ULONG LoggerNameOffset;             // Offset to LoggerName
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;
*/

// The EVENT_TRACE_PROPERTIES structure contains information about an event tracing session.
// You use this structure with APIs such as StartTrace and ControlTrace when defining, updating, or querying the properties of a session.
type EventTraceProperties struct {
	Wnode WnodeHeader // https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header

	// data provided by caller
	BufferSize      uint32 // buffer size for logging (kbytes)
	MinimumBuffers  uint32 // minimum to preallocate
	MaximumBuffers  uint32 // maximum buffers allowed
	MaximumFileSize uint32 // maximum logfile size (in MBytes)
	LogFileMode     uint32 // sequential, circular
	FlushTimer      uint32 // buffer flush timer, in seconds
	EnableFlags     uint32 // trace enable flags
	AgeLimit        int32  // union(AgeLimit // Not used , FlushThreshold // Number of buffers to fill before flushing)

	// data returned to caller
	NumberOfBuffers     uint32         // no of buffers in use
	FreeBuffers         uint32         // no of buffers free
	EventsLost          uint32         // event records lost
	BuffersWritten      uint32         // no of buffers written to file
	LogBuffersLost      uint32         // no of logfile write failures
	RealTimeBuffersLost uint32         // no of rt delivery failures
	LoggerThreadId      syscall.Handle // thread id of Logger
	LogFileNameOffset   uint32         // Offset to LogFileName
	LoggerNameOffset    uint32         // Offset to LoggerName
}

// The session name (LoggerName) is limited to 1,024 characters.
// The session name is case-insensitive.
// The log file name is limited to 1,024 characters.
// The log file name must follow the session name in memory
type EventTracePropertyData struct {
	EventTraceProperties
	LoggerName  [256]uint16  // max 1024 per microsoft doc, but 256 is enough
	LogFileName [1024]uint16 // max 1024 per microsoft doc
}

func NewEventTraceSessionProperties(sessionName string) (*EventTracePropertyData, uint32) {
	return &EventTracePropertyData{}, uint32(unsafe.Sizeof(EventTracePropertyData{}))
}

// Only if a name is present
// null terminated unicode string.
func (e *EventTracePropertyData) GetTraceName() *uint16 {
	if e.LoggerNameOffset == 0 || e.LoggerNameOffset >= e.Wnode.BufferSize {
		return nil
	}
	//return &e.LoggerName[0]
	return (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(e)) + uintptr(e.LoggerNameOffset)))
}

func (e *EventTracePropertyData) GetFileName() *uint16 {
	if e.Wnode.BufferSize >= e.LogFileNameOffset {
		return &e.LogFileName[0]
	} else {
		return nil
	}
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2
// v10.0.19041.0 - evntrace.h
/*
typedef struct _EVENT_TRACE_PROPERTIES_V2 {
    WNODE_HEADER Wnode;                  // Always have WNODE_FLAG_VERSIONED_PROPERTIES.
    //
    // data provided by caller
    ULONG BufferSize;                    // buffer size for logging (kbytes)
    ULONG MinimumBuffers;                // minimum to preallocate
    ULONG MaximumBuffers;                // maximum buffers allowed
    ULONG MaximumFileSize;               // maximum logfile size (in MBytes)
    ULONG LogFileMode;                   // sequential, circular
    ULONG FlushTimer;                    // buffer flush timer, in seconds
    ULONG EnableFlags;                   // trace enable flags
    union {
        LONG  AgeLimit;                  // unused
        LONG  FlushThreshold;            // Number of buffers to fill before flushing
    } DUMMYUNIONNAME;

    // data returned to caller
    ULONG NumberOfBuffers;               // no of buffers in use
    ULONG FreeBuffers;                   // no of buffers free
    ULONG EventsLost;                    // event records lost
    ULONG BuffersWritten;                // no of buffers written to file
    ULONG LogBuffersLost;                // no of logfile write failures
    ULONG RealTimeBuffersLost;           // no of rt delivery failures
    HANDLE LoggerThreadId;               // thread id of Logger
    ULONG LogFileNameOffset;             // Offset to LogFileName
    ULONG LoggerNameOffset;              // Offset to LoggerName

    // V2 data
    union {
        struct {
            ULONG VersionNumber : 8;     // Should be set to 2 for this version.
        } DUMMYSTRUCTNAME;
        ULONG V2Control;
    } DUMMYUNIONNAME2;
    ULONG FilterDescCount;               // Number of filters
    PEVENT_FILTER_DESCRIPTOR FilterDesc; // Only applicable for Private Loggers
    union {
        struct {
            ULONG Wow : 1; // Logger was started by a WOW64 process (output only).
            ULONG QpcDeltaTracking : 1; // QPC delta tracking events are enabled.
            ULONG LargeMdlPages : 1; // Buffers allocated via large MDL pages.
            ULONG ExcludeKernelStack : 1; // Exclude kernel stack from stack walk.
        } DUMMYSTRUCTNAME;
        ULONG64 V2Options;
    } DUMMYUNIONNAME3;
} EVENT_TRACE_PROPERTIES_V2, *PEVENT_TRACE_PROPERTIES_V2;
*/
type EventTraceProperties2 struct {
	Wnode WnodeHeader // https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
	// data provided by caller
	BufferSize      uint32 // buffer size for logging (kbytes)
	MinimumBuffers  uint32 // minimum to preallocate
	MaximumBuffers  uint32 // maximum buffers allowed
	MaximumFileSize uint32 // maximum logfile size (in MBytes)
	LogFileMode     uint32 // sequential, circular
	FlushTimer      uint32 // buffer flush timer, in seconds
	EnableFlags     uint32 // trace enable flags
	AgeLimit        int32  // AgeLimit (Not used) or FlushThreshold (Number of buffers to fill before flushing)

	// data returned to caller
	NumberOfBuffers     uint32         // no of buffers in use
	FreeBuffers         uint32         // no of buffers free
	EventsLost          uint32         // event records lost
	BuffersWritten      uint32         // no of buffers written to file
	LogBuffersLost      uint32         // no of logfile write failures
	RealTimeBuffersLost uint32         // no of rt delivery failures
	LoggerThreadId      syscall.Handle // thread id of Logger
	LogFileNameOffset   uint32         // Offset to LogFileName
	LoggerNameOffset    uint32         // Offset to LoggerName
	// Added on v2:
	V2Control       uint32                 // VersionNumber ( Should be set to 2 for this version.)
	FilterDescCount uint32                 // Number of filters
	FilterDesc      *EventFilterDescriptor // Only applicable for Private Loggers
	V2Options       uint64                 // (Wow, QpcDeltaTracking, LargeMdlPages, ExcludeKernelStack)
}

// This is wrapper for the EVENT_TRACE_PROPERTIES2
// used to handle the LoggerName and LogFileName more easily instead of using pointers/offsets/sizesof.
//
// The session name (LoggerName) is limited to 1,024 characters.
// The session name is case-insensitive.
//
// The log file name is limited to 1,024 characters.
// The log file name must follow the session name in memory.
//
// Both names can be set, ETW StartTrace will read it only if the offsets points
// to these fields.
//
// You must copy the log file name to the offset but you do not copy the session name to the offset.
// The StartTrace/ControlTrace function copies the name for you.
type EventTraceProperties2Wrapper struct {
	EventTraceProperties2
	LoggerName  [128]uint16
	LogFileName [1024]uint16
}

// This structure is supported starting with Windows 10 version 1703.
// When used with earlier versions of Windows,
// the additional fields (e.g. FilterDesc and V2Options) will be ignored
func NewEventTracePropertiesV2() (*EventTraceProperties2Wrapper, uint32) {
	return &EventTraceProperties2Wrapper{}, uint32(unsafe.Sizeof(EventTraceProperties2Wrapper{}))
}

func (e *EventTraceProperties2Wrapper) Clone() *EventTraceProperties2Wrapper {
	clone := new(EventTraceProperties2Wrapper)
	*clone = *e
	clone.FilterDesc = nil // ignore on copy.
	return clone
}

// null terminated unicode string.
func (e *EventTraceProperties2Wrapper) GetTraceName() *uint16 {
	return &e.LoggerName[0]
}

func (e *EventTraceProperties2Wrapper) GetTraceNameOffset() uint32 {
	return uint32(unsafe.Offsetof(EventTraceProperties2Wrapper{}.LogFileName))
}

func (e *EventTraceProperties2Wrapper) SetTraceName_old(name string) *uint16 {
	if len(name) >= ((cap(e.LoggerName) / 2) - 1) { // 1 for null terminator
		panic("LoggerName too long")
	}
	if e.Wnode.BufferSize >= e.LoggerNameOffset {
		loggerName, _ := syscall.UTF16PtrFromString(name)
		dst := unsafe.Slice((*byte)(unsafe.Pointer(&e.LoggerName[0])), len(name)*2)
		src := unsafe.Slice((*byte)(unsafe.Pointer(loggerName)), len(name)*2)
		copy(dst, src)
		return &e.LoggerName[0]
	} else {
		panic("Not enough buffer space for LoggerName")
	}
}

// Set the logger name
// NOTE: [StartTrace] will set it for us if we provide the LogNameOffset.
//
// This does NOT update the [EventTraceProperties2Wrapper.Prop.LogNameOffset] field.
// You have to set it manually.
func (e *EventTraceProperties2Wrapper) SetTraceName(name string) {
	loggerName, _ := syscall.UTF16FromString(name)
	if len(loggerName) > len(e.LoggerName) { // Does it fit in the fixed-size buffer?
		panic("LoggerName too long for the fixed-size buffer")
	}
	copy(e.LoggerName[:], loggerName) // Copy the string into the fixed-size buffer
}

// null terminated unicode string.
func (e *EventTraceProperties2Wrapper) GetLogFileName() *uint16 {
	if e.LogFileNameOffset == 0 || e.LogFileNameOffset >= e.Wnode.BufferSize {
		return nil
	}
	//return &e.LogFileName[0]
	return (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(e)) + uintptr(e.LogFileNameOffset)))
}

func (e *EventTraceProperties2Wrapper) SetLogFileName_old(fName string) *uint16 {
	if len(fName) >= ((cap(e.LogFileName) / 2) - 1) { // 1 for null terminator
		panic("LogFileName too long")
	}
	if e.Wnode.BufferSize >= uint32(unsafe.Sizeof(*e))+uint32(len(fName)*2) {
		logFileName, _ := syscall.UTF16PtrFromString(fName)
		dst := unsafe.Slice((*byte)(unsafe.Pointer(&e.LogFileName[0])), len(fName)*2)
		src := unsafe.Slice((*byte)(unsafe.Pointer(logFileName)), len(fName)*2)
		copy(dst, src)
		return &e.LogFileName[0]
	} else {
		panic("Not enough bugger space for LogFileName")
	}
}

// Set the log file name as a unicode string
// NOTE: [StartTrace] will set it for us if we provide the LogFileNameOffset.
// Same for ControlTrace when querying.
//
// This does NOT update the [EventTraceProperties2Wrapper.Prop.LogFileNameOffset] field.
// You have to set it manually.
func (e *EventTraceProperties2Wrapper) SetLogFileName(fName string) {
	logFileName, _ := syscall.UTF16FromString(fName)
	if len(logFileName) > len(e.LogFileName) {
		panic("LogFileName too long for the fixed-size buffer")
	}
	copy(e.LogFileName[:], logFileName)
}

func (e *EventTraceProperties2Wrapper) GetLogFileNameOffset() uint32 {
	return uint32(unsafe.Offsetof(EventTraceProperties2Wrapper{}.LogFileName))
}

// V2Control
func (e *EventTraceProperties2) GetVersionNumber() uint8 {
	// ( Should be set to 2 for this version.)
	return uint8(e.V2Control & 0xFF)
}

// V2Options
func (e *EventTraceProperties2) GetWow() bool {
	return (e.V2Options>>0)&1 == 1 // Bit 0
}

func (e *EventTraceProperties2) GetQpcDeltaTracking() bool {
	return (e.V2Options>>1)&1 == 1 // Bit 1
}

func (e *EventTraceProperties2) GetLargeMdlPages() bool {
	return (e.V2Options>>2)&1 == 1 // Bit 2
}

func (e *EventTraceProperties2) GetExcludeKernelStack() bool {
	return (e.V2Options>>3)&1 == 1 // Bit 3
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
// v10.0.16299.0 evntrace.h
/*
typedef struct _ENABLE_TRACE_PARAMETERS {
    ULONG                    Version;
    ULONG                    EnableProperty;
    ULONG                    ControlFlags;
    GUID                     SourceId;
    PEVENT_FILTER_DESCRIPTOR EnableFilterDesc;
    ULONG                    FilterDescCount;
} ENABLE_TRACE_PARAMETERS, *PENABLE_TRACE_PARAMETERS;
*/
type EnableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32 // Reserved. Set to 0.
	SourceId         GUID
	EnableFilterDesc *EventFilterDescriptor
	FilterDescCount  uint32
}

// From evntcons.h
// constants for https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
const (
	EVENT_ENABLE_PROPERTY_SID                       = 0x00000001
	EVENT_ENABLE_PROPERTY_TS_ID                     = 0x00000002
	EVENT_ENABLE_PROPERTY_STACK_TRACE               = 0x00000004
	EVENT_ENABLE_PROPERTY_PSM_KEY                   = 0x00000008
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0          = 0x00000010
	EVENT_ENABLE_PROPERTY_PROVIDER_GROUP            = 0x00000020
	EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0          = 0x00000040
	EVENT_ENABLE_PROPERTY_PROCESS_START_KEY         = 0x00000080
	EVENT_ENABLE_PROPERTY_EVENT_KEY                 = 0x00000100
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE         = 0x00000200
	EVENT_ENABLE_PROPERTY_ENABLE_SILOS              = 0x00000400
	EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING = 0x00000800
)

// from evntprov.h
const (
	EVENT_FILTER_TYPE_NONE               = 0x00000000
	EVENT_FILTER_TYPE_SCHEMATIZED        = 0x80000000 // Provider-side.
	EVENT_FILTER_TYPE_SYSTEM_FLAGS       = 0x80000001 // Internal use only.
	EVENT_FILTER_TYPE_TRACEHANDLE        = 0x80000002 // Initiate rundown.
	EVENT_FILTER_TYPE_PID                = 0x80000004 // Process ID.
	EVENT_FILTER_TYPE_EXECUTABLE_NAME    = 0x80000008 // EXE file name.
	EVENT_FILTER_TYPE_PACKAGE_ID         = 0x80000010 // Package ID.
	EVENT_FILTER_TYPE_PACKAGE_APP_ID     = 0x80000020 // Package Relative App Id (PRAID).
	EVENT_FILTER_TYPE_PAYLOAD            = 0x80000100 // TDH payload filter.
	EVENT_FILTER_TYPE_EVENT_ID           = 0x80000200 // Event IDs.
	EVENT_FILTER_TYPE_EVENT_NAME         = 0x80000400 // Event name (TraceLogging only).
	EVENT_FILTER_TYPE_STACKWALK          = 0x80001000 // Event IDs for stack.
	EVENT_FILTER_TYPE_STACKWALK_NAME     = 0x80002000 // Event name for stack (TraceLogging only).
	EVENT_FILTER_TYPE_STACKWALK_LEVEL_KW = 0x80004000 // Filter stack collection by level and keyword.
	EVENT_FILTER_TYPE_CONTAINER          = 0x80008000 // Filter by Container ID.
)

const (
	MAX_EVENT_FILTER_DATA_SIZE = 1024

	MAX_EVENT_FILTER_EVENT_ID_COUNT = 64
)

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
/*
EVENT_FILTER_EVENT_ID is used to pass EventId filter for
stack walk filters.

	typedef struct _EVENT_FILTER_EVENT_ID {
	    BOOLEAN FilterIn;
	    UCHAR Reserved;
	    USHORT Count;
	    USHORT Events[ANYSIZE_ARRAY];
	} EVENT_FILTER_EVENT_ID, *PEVENT_FILTER_EVENT_ID;
*/
type EventFilterEventID struct {
	FilterIn uint8
	Reserved uint8
	Count    uint16
	// it is easier to implement in Go with a fixed array size
	Events [1]uint16
}

func AllocEventFilterEventID_old(filter []uint16) (f *EventFilterEventID) {
	count := uint16(len(filter))
	size := max(4+len(filter)*2, int(unsafe.Sizeof(EventFilterEventID{})))
	buf := make([]byte, size)

	// buf[0] should always be valid
	f = (*EventFilterEventID)(unsafe.Pointer(&buf[0]))
	eid := unsafe.Pointer((&f.Events[0]))
	for i := 0; i < len(filter); i++ {
		*((*uint16)(eid)) = filter[i]
		eid = unsafe.Add(eid, 2)
	}
	f.Count = count
	return
}

// AllocEventFilterEventID allocates a buffer for an EVENT_FILTER_EVENT_ID structure
// with a flexible array member.
func AllocEventFilterEventID(filter []uint16) (f *EventFilterEventID) {
	count := uint16(len(filter))
	// The total size is the header (4 bytes: FilterIn, Reserved, Count)
	// plus the size of the event data (count * 2 bytes).
	size := 4 + uintptr(count)*unsafe.Sizeof(uint16(0))
	buf := make([]byte, size)

	// Cast the start of the buffer to our struct pointer.
	f = (*EventFilterEventID)(unsafe.Pointer(&buf[0]))
	f.Count = count
	if count > 0 {
		eventsSlice := unsafe.Slice(&f.Events[0], count)
		copy(eventsSlice, filter) // Copy the filter data into the flexible array member.
	}

	return
}

func (e *EventFilterEventID) Size() int {
	return 4 + int(e.Count)*2
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
// v10.0.16299.0 evntprov.h
/*
// EVENT_FILTER_DESCRIPTOR describes a filter data item for EnableTraceEx2.
typedef struct _EVENT_FILTER_DESCRIPTOR {

    ULONGLONG   Ptr;  // Pointer to filter data. Set to (ULONGLONG)(ULONG_PTR)pData.
    ULONG       Size; // Size of filter data in bytes.
    ULONG       Type; // EVENT_FILTER_TYPE value.

} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;
*/
// sizeof: 0x10 (OK)
type EventFilterDescriptor struct {
	Ptr  uint64 // Pointer to filter data. Set to (ULONGLONG)(ULONG_PTR)pData.
	Size uint32 // Size of filter data in bytes.
	Type uint32 // EVENT_FILTER_TYPE value.
}

/*
	typedef struct _FILETIME {
	  DWORD dwLowDateTime;
	  DWORD dwHighDateTime;
	} FILETIME, *PFILETIME, *LPFILETIME;
*/
type FileTime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
// v10.0.16299.0 /evntrace.h
/*
struct _EVENT_TRACE_LOGFILEW {
    LPWSTR                  LogFileName;      // Logfile Name
    LPWSTR                  LoggerName;       // LoggerName
    LONGLONG                CurrentTime;      // timestamp of last event
    ULONG                   BuffersRead;      // buffers read to date
    union {
        // Mode of the logfile
        ULONG               LogFileMode;
        // Processing flags used on Vista and above
        ULONG               ProcessTraceMode;
    } DUMMYUNIONNAME;
    EVENT_TRACE             CurrentEvent;     // Current Event from this stream.
    TRACE_LOGFILE_HEADER    LogfileHeader;    // logfile header structure
    PEVENT_TRACE_BUFFER_CALLBACKW             // callback before each buffer
                            BufferCallback;   // is read
    //
    // following variables are filled for BufferCallback.
    //
    ULONG                   BufferSize;
    ULONG                   Filled;
    ULONG                   EventsLost;
    //
    // following needs to be propagated to each buffer
    //
    union {
        // Callback with EVENT_TRACE
        PEVENT_CALLBACK         EventCallback;
        // Callback with EVENT_RECORD on Vista and above
        PEVENT_RECORD_CALLBACK  EventRecordCallback;
    } DUMMYUNIONNAME2;

    ULONG                   IsKernelTrace;    // TRUE for kernel logfile

    PVOID                   Context;          // reserved for internal use
};
*/

// The EVENT_TRACE_LOGFILE structure stores information about a trace data source.
//
// The EVENT_TRACE_LOGFILE structure is used when calling OpenTrace.
// The user provides an EVENT_TRACE_LOGFILE structure with information about the trace data source
// (either the name of an ETL file or the name of an active real-time logger session),
// trace processing flags, and the callback functions that will receive trace data.
// On success, OpenTrace fills in the remaining fields of the structure to return
// details about the trace data source.
//
// When ProcessTrace processes a buffer, it invokes the user-defined BufferCallback with a
//
//	EVENT_TRACE_LOGFILE structure to provide information about the event processing session and the buffer.
type EventTraceLogfile struct {
	LogFileName   *uint16            // Logfile Name
	LoggerName    *uint16            // LoggerName
	CurrentTime   int64              // (on output) timestamp of last event
	BuffersRead   uint32             // (on output) buffers read to date
	Union1        uint32             // (LogFileMode [NOT USED] | ProcessTraceMode)
	CurrentEvent  EventTrace         // (on output) Current Event from this stream.
	LogfileHeader TraceLogfileHeader // (on output) logfile header structure
	//BufferCallback *EventTraceBufferCallback

	BufferCallback uintptr // callback before each buffer is read

	// following variables are filled for BufferCallback.

	BufferSize uint32 // (on output) contains the size of each buffer, in bytes.
	Filled     uint32 // (on output) contains the number of bytes in the buffer that contain valid information.
	EventsLost uint32 // NOT USED

	// following needs to be propagated to each buffer

	Callback uintptr // (EventCallback | EventRecordCallback)
	// Callback with EVENT_TRACE or // Callback with EVENT_RECORD on Vista and above

	IsKernelTrace uint32 // (on output) TRUE for kernel logfile

	Context uintptr // reserved for internal use
}

func (e *EventTraceLogfile) GetProcessTraceMode() uint32 {
	return e.Union1
}

func (e *EventTraceLogfile) GetProcessTraceModeStrings() []string {
	var modes []string
	if e.Union1&PROCESS_TRACE_MODE_REAL_TIME != 0 {
		modes = append(modes, "REAL_TIME")
	}
	if e.Union1&PROCESS_TRACE_MODE_EVENT_RECORD != 0 {
		modes = append(modes, "EVENT_RECORD")
	}
	if e.Union1&PROCESS_TRACE_MODE_RAW_TIMESTAMP != 0 {
		modes = append(modes, "RAW_TIMESTAMP")
	}
	return modes
}

func (e *EventTraceLogfile) SetProcessTraceMode(ptm uint32) {
	e.Union1 = ptm
}

// * NOTE(tekert): Not used, instead they are using uintptr, wonder why
type EventCallback func(*EventTrace)
type EventRecordCallback func(*EventRecord) uintptr // New, replaces EventCallback
type EventTraceBufferCallback func(*EventTraceLogfile) uint32

// Clone creates a deep copy of the EventTraceLogfile struct.
// It allocates new memory for string pointers and copies all fields.
func (e *EventTraceLogfile) Clone() *EventTraceLogfile {
	if e == nil {
		return nil
	}

	// This correctly copies all members, including nested structs and unions.
	clone := *e

	// Reset function pointers to zero
	// These pointers are not valid after the trace session ends.
	clone.BufferCallback = 0
	clone.Callback = 0
	clone.Context = 0

	// Deep copy string pointers
	clone.LoggerName = CopyUTF16Ptr(e.LoggerName)
	clone.LogFileName = CopyUTF16Ptr(e.LogFileName)

	// No need to copy LogfileHeader.LoggerName and LogfileHeader.LogFileName
	// since they are not used according to Microsoft docs
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header
	clone.LogfileHeader.LoggerName = nil
	clone.LogfileHeader.LogFileName = nil

	return &clone
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
// v10.0.19041.0 \evntcons.h
/*
typedef struct _EVENT_RECORD {

    EVENT_HEADER        				EventHeader;
    ETW_BUFFER_CONTEXT  				BufferContext;
    USHORT              				ExtendedDataCount;
    USHORT              				UserDataLength;
    PEVENT_HEADER_EXTENDED_DATA_ITEM 	ExtendedData;
    PVOID               				UserData;
    PVOID               				UserContext;
} EVENT_RECORD, *PEVENT_RECORD;
*/
type EventRecord struct {
	EventHeader       EventHeader                  // Defines information about the event.
	BufferContext     EtwBufferContext             // Defines information such as the session that logged the event.
	ExtendedDataCount uint16                       // Number of extended data items in the ExtendedData member.
	UserDataLength    uint16                       // The size, in bytes, of the data in the UserData member.
	ExtendedData      *EventHeaderExtendedDataItem // One or more extended data items that ETW collects.
	UserData          uintptr                      // Event specific data in binary format.
	UserContext       uintptr                      // Context from OpenTrace
}

/*
Un-used uncomment if necessary
func (e *EventRecord) pointer() uintptr {
	return (uintptr)(unsafe.Pointer(e))
}

func (e *EventRecord) pointerOffset(offset uintptr) uintptr {
	return e.pointer() + offset
}
*/

// EventID returns the event ID of the event record.
// If the event is XML-based (manifest), it returns the EventDescriptor ID.
// If the event is MOF-based (old), it returns the BaseId (ProviderId) + EventDescriptor Opcode.
// If the event is neither, it returns 0.
func (e *EventRecord) EventID() uint16 {
	if e.IsXML() {
		return e.EventHeader.EventDescriptor.Id
	} else if e.IsMof() {
		if c, ok := MofClassMapping[e.EventHeader.ProviderId.Data1]; ok {
			return c.BaseId + uint16(e.EventHeader.EventDescriptor.Opcode)
		}
	}
	// not meaningful, cannot be used to identify event
	return 0
}

// The number of the CPU on which the provider process was running.
func (e *EventRecord) ProcessorNumber() uint16 {
	if e.EventHeader.Flags&EVENT_HEADER_FLAG_PROCESSOR_INDEX != 0 {
		return e.BufferContext.ProcessorIndex()
	}
	// If the flag is not set, we use the ProcessorNumber member.
	return uint16(e.BufferContext.ProcessorNumber())
}

// ExtendedDataItem returns the extended data item at index i.
// It returns an error if the index is out of bounds.
func (e *EventRecord) ExtendedDataItem(i uint16) (*EventHeaderExtendedDataItem, error) {
	if i >= e.ExtendedDataCount {
		err := fmt.Errorf("index %d out of bounds (len %d)", i, e.ExtendedDataCount)
		conlog.SampledErrorWithErrSig("etw", err).Msg("ExtendedDataItem index out of bounds")
		return nil, err
	}

	items := unsafe.Slice(e.ExtendedData, e.ExtendedDataCount)
	return &items[i], nil
}

// ExtRelatedActivityID returns the GUID of the related activity ID.
// This is used to correlate events that are part of the same activity.
// It returns a zero GUID if the related activity ID is not present in the event's extended data.
// Always available for XML-based events.
func (e *EventRecord) ExtRelatedActivityID() GUID {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID {
			g := (*GUID)(unsafe.Pointer(item.DataPtr))
			return *g
		}
	}
	return nullGUID
}

// ExtSid returns the security identifier (SID) of the user who logged the event.
// It returns nil if the SID is not present in the event's extended data.
// Use [etw.ConvertSidToStringSidGO] to convert the SID to a go string (it's fast).
// Enabled by using the EVENT_ENABLE_PROPERTY_SID flag on EnableProvider config.
func (e *EventRecord) ExtSid() *SID {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_SID {
			return (*SID)(unsafe.Pointer(item.DataPtr))
		}
	}
	return nil
}

// ExtTerminalSessionID returns the terminal session identifier of the user who logged the event.
// The boolean return value indicates whether the session ID was present in the event's extended data.
// Enabled by using the EVENT_ENABLE_PROPERTY_TS_ID flag on EnableProvider config.
func (e *EventRecord) ExtTerminalSessionID() (uint32, bool) {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_TS_ID {
			return *(*uint32)(unsafe.Pointer(item.DataPtr)), true
		}
	}
	return 0, false
}

// ExtProcessStartKey returns a unique identifier for the process that persists across boot sessions.
// This is more reliable for correlation than a PID, which can be reused.
// The boolean return value indicates whether the start key was present in the event's extended data.
// Enabled by using the EVENT_ENABLE_PROPERTY_PROCESS_START_KEY flag on EnableProvider config.
// Enabled by default for XML-based events.
func (e *EventRecord) ExtProcessStartKey() (uint64, bool) {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY {
			return *(*uint64)(unsafe.Pointer(item.DataPtr)), true
		}
	}
	return 0, false
}

// ExtEventKey returns a unique identifier for the event that is constant across trace sessions.
// This is useful for correlating events from the same provider across different traces.
// The boolean return value indicates whether the event key was present in the event's extended data.
// Enabled by using the EVENT_ENABLE_PROPERTY_EVENT_KEY flag on EnableProvider config.
func (e *EventRecord) ExtEventKey() (uint64, bool) {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_EVENT_KEY {
			return *(*uint64)(unsafe.Pointer(item.DataPtr)), true
		}
	}
	return 0, false
}

// ExtContainerID returns the GUID of the container in which the event provider is running.
// This is useful for tracing events in containerized environments.
// It returns a zero GUID if the container ID is not present in the event's extended data.
// Enabled by using the EVENT_HEADER_EXT_TYPE_CONTAINER_ID flag on EnableProvider config.
func (e *EventRecord) ExtContainerID() GUID {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err == nil && item.ExtType == EVENT_HEADER_EXT_TYPE_CONTAINER_ID {
			return *(*GUID)(unsafe.Pointer(item.DataPtr))
		}
	}
	return nullGUID
}

// EventStackTrace contains the call stack trace associated with an event.
// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64
type EventStackTrace struct {
	MatchID   uint64
	Addresses []uint64
}

// ExtStackTrace returns the call stack trace associated with an event, if one is present.
// A stack trace will only be present if the provider was enabled with the
// EVENT_ENABLE_PROPERTY_STACK_TRACE flag.
// The boolean return value indicates whether a stack trace was found.
// Enabled by using the EVENT_ENABLE_PROPERTY_STACK_TRACE flag on EnableProvider config.
func (e *EventRecord) ExtStackTrace() (EventStackTrace, bool) {
	for i := uint16(0); i < e.ExtendedDataCount; i++ {
		item, err := e.ExtendedDataItem(i)
		if err != nil {
			continue
		}

		switch item.ExtType {
		case EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			if item.DataSize < 8 {
				continue
			}
			matchID := *(*uint64)(unsafe.Pointer(item.DataPtr))
			addressCount := (item.DataSize - 8) / 4
			addresses32 := unsafe.Slice((*uint32)(unsafe.Pointer(item.DataPtr+8)), addressCount)
			addresses64 := make([]uint64, addressCount)
			for j, addr := range addresses32 {
				addresses64[j] = uint64(addr)
			}
			return EventStackTrace{
				MatchID:   matchID,
				Addresses: addresses64,
			}, true

		case EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
			if item.DataSize < 8 {
				continue
			}
			matchID := *(*uint64)(unsafe.Pointer(item.DataPtr))
			addressCount := (item.DataSize - 8) / 8
			addresses64 := unsafe.Slice((*uint64)(unsafe.Pointer(item.DataPtr+8)), addressCount)
			addrsCopy := make([]uint64, len(addresses64))
			copy(addrsCopy, addresses64)
			return EventStackTrace{
				MatchID:   matchID,
				Addresses: addrsCopy,
			}, true
		}
	}
	return EventStackTrace{}, false
}

// IsXML checks if the event is manifest-based (XML).
func (e *EventRecord) IsXML() bool {
	// If not classic/MOF and has provider, it's manifest-based
	return !e.IsMof() && !e.EventHeader.ProviderId.IsZero() // TODO(tekert): test this
}

// IsMof checks if the event is classic (MOF).
func (e *EventRecord) IsMof() bool {
	return e.EventHeader.Flags&EVENT_HEADER_FLAG_CLASSIC_HEADER != 0
}

// // Used for performance-critical slice length modification.
// type sliceHeader struct {
// 	Data uintptr
// 	Len  int
// 	Cap  int
// }

// GetEventInformation retrieves the event schema information for the given event record.
// It uses a provided buffer to store the information, resizing it if necessary.
func (e *EventRecord) GetEventInformation(buffer *[]byte) (tei *TraceEventInfo, err error) {
	if buffer == nil {
		var tempBuf []byte
		return e.GetEventInformation(&tempBuf)
	}
	if cap(*buffer) == 0 {
		// This should not happen with traceStorage, but as a safeguard:
		*buffer = make([]byte, 8192) // Default initial size
	}

	// Use the buffer's capacity to inform the C API of the total available memory.
	bufferSize := uint32(cap(*buffer))
	tei = (*TraceEventInfo)(unsafe.Pointer(unsafe.SliceData(*buffer)))
	err = TdhGetEventInformation(e, 0, nil, tei, &bufferSize)

	if err == ERROR_INSUFFICIENT_BUFFER {
		// The provided buffer was too small. Allocate a new one of the required size.
		*buffer = make([]byte, bufferSize)
		tei = (*TraceEventInfo)(unsafe.Pointer(unsafe.SliceData(*buffer)))
		err = TdhGetEventInformation(e, 0, nil, tei, &bufferSize)
	}
	if err != nil {
		if err == ERROR_NOT_FOUND {
			return nil, fmt.Errorf("the schema for the event was not found. %w", err)
		}
		return nil, fmt.Errorf("TdhGetEventInformation failed: %w", err)
	}

	// On success, update the slice's length to match the actual data written by the API.
	// This isn't strictly necessary, as we work with the pointer and capacity, but it's good practice.
	*buffer = (*buffer)[:bufferSize]

	return tei, nil
}

/*
// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO) malloc(MapSize);
        if (pMapInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the map info.

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else
    {
        if  (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
        }
    }

cleanup:

    return status;
}
*/

var eventMapInfoPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64)
		return &b // Store pointer
	},
}

type EventMapInfoBuffer struct {
	pMapInfo *EventMapInfo
	buff     *[]byte
}

func (emi EventMapInfoBuffer) Release() {
	eventMapInfoPool.Put(emi.buff)
}

func (e *EventRecord) GetMapInfo(pMapName *uint16, decodingSource uint32) (pMapInfoBuff *EventMapInfoBuffer, err error) {
	// Get buffer from pool (no need to clean it, it will be overwritten)
	buffPtr := eventMapInfoPool.Get().(*[]byte)

	mapSize := uint32(len(*buffPtr))
	pMapInfo := (*EventMapInfo)(unsafe.Pointer(&(*buffPtr)[0]))
	err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)

	if err == syscall.ERROR_INSUFFICIENT_BUFFER {
		// Need larger buffer
		if mapSize > uint32(len(*buffPtr)) {
			*buffPtr = make([]byte, mapSize)
			pMapInfo = (*EventMapInfo)(unsafe.Pointer(&(*buffPtr)[0]))
			err = TdhGetEventMapInformation(e, pMapName, pMapInfo, &mapSize)
		}
	}

	if err == nil {
		if DecodingSource(decodingSource) == DecodingSourceXMLFile {
			pMapInfo.RemoveTrailingSpace()
		}
	}

	if err == syscall.ERROR_NOT_FOUND {
		err = nil
	}
	pMapInfoBuff = &EventMapInfoBuffer{
		pMapInfo: pMapInfo,
		buff:     buffPtr,
	}
	return
}

func (e *EventRecord) PointerSize() uint32 {
	if e.EventHeader.Flags&EVENT_HEADER_FLAG_32_BIT_HEADER == EVENT_HEADER_FLAG_32_BIT_HEADER {
		return 4
	}
	return 8
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
// v10.0.19041.0 /evntcons.h
/*
typedef struct _EVENT_HEADER_EXTENDED_DATA_ITEM {

    USHORT      Reserved1;                      // Reserved for internal use
    USHORT      ExtType;                        // Extended info type
    struct {
        USHORT  Linkage             :  1;       // Indicates additional extended
                                                // data item
        USHORT  Reserved2           : 15;
    };
    USHORT      DataSize;                       // Size of extended info data
    ULONGLONG   DataPtr;                        // Pointer to extended info data

} EVENT_HEADER_EXTENDED_DATA_ITEM, *PEVENT_HEADER_EXTENDED_DATA_ITEM;
*/
type EventHeaderExtendedDataItem struct {
	Reserved1      uint16  // Reserved for internal use
	ExtType        uint16  // Extended info type
	InternalStruct uint16  // InternalStruct & 0x8000 = Indicates additional extended data item, InternalStruct & 0x7FFF = Reserved
	DataSize       uint16  // Size of extended info data
	DataPtr        uintptr // Pointer to extended info data
}

// https://learn.microsoft.com/en-en/windows/win32/api/evntcons/ns-evntcons-event_header
// v10.0.19041.0 /evntcons.h
/*
typedef struct _EVENT_HEADER {

    USHORT              Size;                   // Event Size
    USHORT              HeaderType;             // Header Type
    USHORT              Flags;                  // Flags
    USHORT              EventProperty;          // User given event property
    ULONG               ThreadId;               // Thread Id
    ULONG               ProcessId;              // Process Id
    LARGE_INTEGER       TimeStamp;              // Event Timestamp
    GUID                ProviderId;             // Provider Id
    EVENT_DESCRIPTOR    EventDescriptor;        // Event Descriptor
    union {
        struct {
            ULONG       KernelTime;             // Kernel Mode CPU ticks
            ULONG       UserTime;               // User mode CPU ticks
        } DUMMYSTRUCTNAME;
        ULONG64         ProcessorTime;          // Processor Clock
                                                // for private session events
    } DUMMYUNIONNAME;
    GUID                ActivityId;             // Activity Id

} EVENT_HEADER, *PEVENT_HEADER;
*/
type EventHeader struct {
	Size            uint16 // Event Size
	HeaderType      uint16 // Header Type
	Flags           uint16 // Flags
	EventProperty   uint16 // User given event property
	ThreadId        uint32 // Thread Id
	ProcessId       uint32 // Process Id
	TimeStamp       int64  // Event Timestamp
	ProviderId      GUID   // Provider Id
	EventDescriptor EventDescriptor
	ProcessorTime   uint64 // Processor Clock (KernelTime | UserTime)
	ActivityId      GUID   // Activity Id
}

// Low-order bytes are listed first in unions
// Example, Kernel time is listed first in the union, so it is the lower 32 bits.

func (e *EventHeader) GetKernelTime() uint32 {
	// Extract KernelTime (lower 32 bits)
	// (Little endian they are stored backwards)
	return uint32(e.ProcessorTime & 0xFFFFFFFF)
}

func (e *EventHeader) GetUserTime() uint32 {
	// Extract UserTime (higher 32 bits)
	return uint32(e.ProcessorTime >> 32)
}

// TODO(tekert): delete this, has worse performance when near second boundary
// the new UTCTimeStamp() has more consistent performance in all benchmark tests.
// precision was the same for both.
func (e *EventHeader) UTCTimeStamp_old() time.Time {
	nano := int64(10000000)
	sec := int64(float64(e.TimeStamp)/float64(nano) - 11644473600.0)
	nsec := ((e.TimeStamp - 11644473600*nano) - sec*nano) * 100
	return time.Unix(sec, nsec).UTC()
}

// UTCTimeStamp converts event timestamp to UTC time
func (e *EventHeader) UTCTimeStamp() time.Time {
	return UnixTimeStamp(e.TimeStamp).UTC()
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor
// v10.0.19041.0 /evntprov.h
//
// Ported comments from source file to go interface
/*
typedef struct _EVENT_DESCRIPTOR {
	USHORT Id;
  	UCHAR Version;
  	UCHAR Channel;
 	UCHAR Level;
  	UCHAR Opcode;
  	USHORT      Task;
  	ULONGLONG   Keyword;
  } EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;
*/
// EVENT_DESCRIPTOR describes and categorizes an event.
// Note that for TraceLogging events, the Id and Version fields are not
// meaningful and should be ignored.
type EventDescriptor struct {
	/*
		For manifest-based events, the Provider.Guid + Event.Id + Event.Version
		should uniquely identify an event. Once a manifest with a particular
		event Id+Version has been made public, the definition of that event
		(the types, ordering, and semantics of the fields) should never be
		changed. If an event needs to be changed, it must be given a new
		identity (usually by incrementing the Version), and the original event
		must remain in the manifest (so that older versions of the event can
		still be decoded with the new manifest). To change an event (e.g. to
		add/remove a field or to change a field type): duplicate the event in
		the manifest, then increment the event Version and make changes in the
		new copy.
		For manifest-free events (i.e. TraceLogging), Event.Id and
		Event.Version are not useful and should be ignored. Use Event name,
		level, keyword, and opcode for event filtering and identification. */
	Id uint16

	/*
	   For manifest-based events, the Provider.Guid + Event.Id + Event.Version
	   should uniquely identify an event. The Id+Version constitute a 24-bit
	   identifier. Generally, events with the same Id are semantically
	   related, and the Version is incremented as the event is refined over
	   time. */
	Version uint8

	/*
	   The meaning of the Channel field depends on the event consumer.
	   This field is most commonly used with events that will be consumed by
	   the Windows Event Log. Note that Event Log does not listen to all ETW
	   events, so setting a channel is not enough to make the event appear in
	   the Event Log. For an ETW event to be routed to Event Log, the
	   following must be configured:
	   - The provider and its channels must be defined in a manifest.
	   - The manifest must be compiled with the mc.exe tool, and the resulting
	     BIN files must be included into the resources of an EXE or DLL.
	   - The EXE or DLL containing the BIN data must be installed on the
	     machine where the provider will run.
	   - The manifest must be registered (using wevtutil.exe) on the machine
	     where the provider will run. The manifest registration process must
	     record the location of the EXE or DLL with the BIN data.
	   - The channel must be enabled in Event Log configuration.
	   - The provider must log an event with the channel and keyword set
	     correctly as defined in the manifest. (Note that the mc.exe code
	     generator will automatically define an implicit keyword for each
	     channel, and will automatically add the channel's implicit keyword to
	     each event that references a channel.) */
	Channel uint8

	/*
	   The event level defines the event's severity or importance and is a
	   primary means for filtering events. Microsoft-defined levels (in
	   evntrace.h and  winmeta.h) are 1 (critical/fatal), 2 (error),
	   3 (warning), 4 (information), and 5 (verbose). Levels 6-9 are reserved.
	   Level 0 means the event is always-on (will not be filtered by level).
	   For a provider, a lower level means the event is more important. An
	   event with level 0 will always pass any level-based filtering.
	   For a consumer, a lower level means the session's filter is more
	   restrictive. However, setting a session's level to 0 disables level
	   filtering (i.e. session level 0 is the same as session level 255). */
	Level uint8

	/*
	   The event opcode is used to mark events with special semantics that
	   may be used by event decoders to organize and correlate events.
	   Globally-recognized opcode values are defined in winmeta.h. A provider
	   can define its own opcodes. Most events use opcode 0 (information).
	   The opcodes 1 (start) and 2 (stop) are used to indicate the beginning
	   and end of an activity as follows:
	   - Generate a new activity Id (UuidCreate or EventActivityIdControl).
	   - Write an event with opcode = start, activity ID = (the generated
	     activity ID), and related activity ID = (the parent activity if any).
	   - Write any number of informational events with opcode = info, activity
	     ID = (the generated activity ID).
	   - Write a stop event with opcode = stop, activity ID = (the generated
	     activity ID).
	   Each thread has an implicit activity ID (in thread-local storage) that
	   will be applied to any event that does not explicitly specify an
	   activity ID. The implicit activity ID can be accessed using
	   EventActivityIdControl. It is intended that the thread-local activity
	   will be used to implement scope-based activities: on entry to a scope
	   (i.e. at the start of a function), a user will record the existing
	   value of the implicit activity ID, generate and set a new value, and
	   write a start event; on exit from the scope, the user will write a stop
	   event and restore the previous activity ID. Note that there is no enforcement
	   of this pattern, and an application must be aware that other code may
	   potentially overwrite the activity ID without restoring it. In
	   addition, the implicit activity ID does not work well with cross-thread
	   activities. For these reasons, it may be more appropriate to use
	   explicit activity IDs (explicitly pass a GUID to EventWriteTransfer)
	   instead of relying on the implicity activity ID. */
	Opcode uint8

	/*
	   The event task code can be used for any purpose as defined by the
	   provider. The task code 0 is the default, used to indicate that no
	   special task code has been assigned to the event. The ETW manifest
	   supports assigning localizable strings for each task code. The task
	   code might be used to group events into categories, or to simply
	   associate a task name with each event. */
	Task uint16

	/*
	   The event keyword defines membership in various categories and is an
	   important means for filtering events. The event's keyword is a set of
	   64 bits indicating the categories to which an event belongs. The
	   provider manifest may provide definitions for up to 48 keyword values,
	   each value defining the meaning of a single keyword bit (the upper 16
	   bits are reserved by Microsoft for special purposes). For example, if
	   the provider manifest defines keyword 0x0010 as "Networking", and
	   defines keyword 0x0020 as "Threading", an event with keyword 0x0030
	   would be in both "Networking" and "Threading" categories, while an
	   event with keyword 0x0001 would be in neither category. An event with
	   keyword 0 is treated as uncategorized.
	   Event consumers can use keyword masks to determine which events should
	   be included in the log. A session can define a KeywordAny mask and
	   a KeywordAll mask. An event will pass the session's keyword filtering
	   if the following expression is true:
	       event.Keyword == 0 || (
	       (event.Keyword & session.KeywordAny) != 0 &&
	       (event.Keyword & session.KeywordAll) == session.KeywordAll).
	   In other words, uncategorized events (events with no keywords set)
	   always pass keyword filtering, and categorized events pass if they
	   match any keywords in KeywordAny and match all keywords in KeywordAll.
	*/
	Keyword uint64
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace
// v10.0.16299.0 /evntrace.h
//
// An EVENT_TRACE consists of a fixed header (EVENT_TRACE_HEADER) and
// optionally a variable portion pointed to by MofData. The datablock
// layout of the variable portion is unknown to the Logger and must
// be obtained from WBEM CIMOM database.
/*
   typedef struct _EVENT_TRACE {
       EVENT_TRACE_HEADER      Header;             // Event trace header
       ULONG                   InstanceId;         // Instance Id of this event
       ULONG                   ParentInstanceId;   // Parent Instance Id.
       GUID                    ParentGuid;         // Parent Guid;
       PVOID                   MofData;            // Pointer to Variable Data
       ULONG                   MofLength;          // Variable Datablock Length
       union {
           ULONG               ClientContext;
           ETW_BUFFER_CONTEXT  BufferContext;
       } DUMMYUNIONNAME;
   } EVENT_TRACE, *PEVENT_TRACE;
*/
type EventTrace struct {
	Header           EventTraceHeader // Event trace header
	InstanceId       uint32           // Instance Id of this event
	ParentInstanceId uint32           // Parent Instance Id.
	ParentGuid       GUID             // Parent Guid;
	MofData          uintptr          // Pointer to Variable Data
	MofLength        uint32           // Variable Datablock Length
	UnionCtx         uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-etw_buffer_context
// v10.0.16299.0 /evntrace.h
/*
typedef struct _ETW_BUFFER_CONTEXT {
    union {
        struct {
            UCHAR ProcessorNumber;
            UCHAR Alignment;
        } DUMMYSTRUCTNAME;
        USHORT ProcessorIndex;
    } DUMMYUNIONNAME;
    USHORT  LoggerId;
} ETW_BUFFER_CONTEXT, *PETW_BUFFER_CONTEXT;
*/
// sizeof: 0x4 (OK)
type EtwBufferContext struct {
	Union1   uint16 // (ProcessorNumber, Alignment) or ProcessorIndex
	LoggerId uint16 // Identifier of the session that logged the event.
}

// ProcessorNumber returns the ProcessorNumber if the EVENT_HEADER_FLAG_PROCESSOR_INDEX flag is not set.
// The number of the CPU on which the provider process was running. The number is zero on a single processor computer.
func (e *EtwBufferContext) ProcessorNumber() uint8 {
	return uint8(e.Union1 & 0x00FF) // Extract the lower 8 bits
}

// Alignment returns the Alignment between events (always eight).
// if EVENT_HEADER_FLAG_PROCESSOR_INDEX flag is not set.
func (e *EtwBufferContext) Alignment() uint8 {
	return uint8((e.Union1 >> 8) & 0x00FF) // Extract the upper 8 bits
}

// ProcessorIndex returns the ProcessorIndex if the EVENT_HEADER_FLAG_PROCESSOR_INDEX flag is set.
func (e *EtwBufferContext) ProcessorIndex() uint16 {
	return e.Union1 // The full 16-bit value represents ProcessorIndex
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_header
// v10.0.16299.0 /evntrace.h
// Trace header for all legacy events.
/*
typedef struct _EVENT_TRACE_HEADER {        // overlays WNODE_HEADER
    USHORT          Size;                   // Size of entire record
    union {
        USHORT      FieldTypeFlags;         // Indicates valid fields
        struct {
            UCHAR   HeaderType;             // Header type - internal use only
            UCHAR   MarkerFlags;            // Marker - internal use only
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    union {
        ULONG       Version;
        struct {
            UCHAR   Type;                   // event type
            UCHAR   Level;                  // trace instrumentation level
            USHORT  Version;                // version of trace record
        } Class;
    } DUMMYUNIONNAME2;
    ULONG           ThreadId;               // Thread Id
    ULONG           ProcessId;              // Process Id
    LARGE_INTEGER   TimeStamp;              // time when event happens
    union {
        GUID        Guid;                   // Guid that identifies event
        ULONGLONG   GuidPtr;                // use with WNODE_FLAG_USE_GUID_PTR
    } DUMMYUNIONNAME3;
    union {
        struct {
            ULONG   KernelTime;             // Kernel Mode CPU ticks
            ULONG   UserTime;               // User mode CPU ticks
        } DUMMYSTRUCTNAME;
        ULONG64     ProcessorTime;          // Processor Clock
        struct {
            ULONG   ClientContext;          // Reserved
            ULONG   Flags;                  // Event Flags
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME4;
} EVENT_TRACE_HEADER, *PEVENT_TRACE_HEADER;
*/
// sizeof: 0x30 (48)
type EventTraceHeader struct {
	Size      uint16   // Size of entire record
	Union1    uint16   // (HeaderType, MarkerFlags)
	Union2    uint32   // (Type, Level, Version)
	ThreadId  uint32   // Thread Id
	ProcessId uint32   // Process Id
	TimeStamp int64    // time when event happens
	Union3    [16]byte // (Guid | GuidPtr)
	Union4    uint64   // (KernelTime, UserTime | ProcessorTime | ClientContext, Flags)
}

// Low-order bytes are listed first, top to bottom in unions.
// Example, Kernel time is listed first in the union, so it is the lower 32 bits.

func (e *EventTraceHeader) GetType() uint8 {
	// Extract Version (lower byte)
	return uint8(e.Union2 & 0xFF)
}

func (e *EventTraceHeader) GetLevel() uint8 {
	// Extract Level (middle byte)
	return uint8(e.Union2 >> 16)
}

func (e *EventTraceHeader) GetVersion() uint16 {
	// Extract Type (upper 2 bytes)
	return uint16((e.Union2 >> 16) & 0xFFFF)
}

func (e *EventTraceHeader) GetGuid() GUID {
	// Extract Guid
	return *(*GUID)(unsafe.Pointer(&e.Union3))
}

func (e *EventTraceHeader) GetGuidPtr() *GUID {
	// Extract GuidPtr
	return (*GUID)(unsafe.Pointer(&e.Union3))
}

func (e *EventTraceHeader) GetKernelTime() uint32 {
	// Extract KernelTime (lower 32 bits)
	// (Little endian they are stored backwards)
	return uint32(e.Union4 & 0xFFFFFFFF)
}

func (e *EventTraceHeader) GetUserTime() uint32 {
	// Extract UserTime (higher 32 bits)
	return uint32(e.Union4 >> 32)
}

func (e *EventTraceHeader) GetProcessorTime() uint64 {
	// Extract ProcessorTime
	return e.Union4
}

func (e *EventTraceHeader) GetClientContext() uint32 {
	// Extract Flags (lower 32 bits)
	return uint32(e.Union4 & 0xFFFFFFFF)
}

func (e *EventTraceHeader) GetFlags() uint32 {
	// Extract ClientContext (higher 32 bits)
	return uint32(e.Union4 >> 32)
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header
// v10.0.19041.0 /evntrace.h
//
// This is the header for every logfile. The memory for LoggerName
// and LogFileName must be contiguous adjacent to this structure
// Allows both user-mode and kernel-mode to understand the header.
//
// TRACE_LOGFILE_HEADER32 and TRACE_LOGFILE_HEADER64 structures
// are also provided to simplify cross platform decoding of the
// header event.
//
// More info at https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/evntrace.h
/*
typedef struct _TRACE_LOGFILE_HEADER {
    ULONG           BufferSize;         // Logger buffer size in Kbytes
    union {
        ULONG       Version;            // Logger version
        struct {
            UCHAR   MajorVersion;
            UCHAR   MinorVersion;
            UCHAR   SubVersion;
            UCHAR   SubMinorVersion;
        } VersionDetail;
    } DUMMYUNIONNAME;
    ULONG           ProviderVersion;    // defaults to NT version
    ULONG           NumberOfProcessors; // Number of Processors
    LARGE_INTEGER   EndTime;            // Time when logger stops
    ULONG           TimerResolution;    // assumes timer is constant!!!
    ULONG           MaximumFileSize;    // Maximum in Mbytes
    ULONG           LogFileMode;        // specify logfile mode
    ULONG           BuffersWritten;     // used to file start of Circular File
    union {
        GUID LogInstanceGuid;           // For RealTime Buffer Delivery
        struct {
            ULONG   StartBuffers;       // Count of buffers written at start.
            ULONG   PointerSize;        // Size of pointer type in bits
            ULONG   EventsLost;         // Events lost during log session
            ULONG   CpuSpeedInMHz;      // Cpu Speed in MHz
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME2;
#if defined(_WMIKM_)
    PWCHAR          LoggerName;
    PWCHAR          LogFileName;
    RTL_TIME_ZONE_INFORMATION TimeZone;
#else
    LPWSTR          LoggerName;
    LPWSTR          LogFileName;
    TIME_ZONE_INFORMATION TimeZone;
#endif
    LARGE_INTEGER   BootTime;
    LARGE_INTEGER   PerfFreq;           // Reserved
    LARGE_INTEGER   StartTime;          // Reserved
    ULONG           ReservedFlags;      // ClockType
    ULONG           BuffersLost;
} TRACE_LOGFILE_HEADER, *PTRACE_LOGFILE_HEADER;
*/
type TraceLogfileHeader struct {
	BufferSize         uint32   // Logger buffer size in Kbytes
	VersionUnion       uint32   // Logger version
	ProviderVersion    uint32   // defaults to NT version
	NumberOfProcessors uint32   // Number of Processors
	EndTime            int64    // Time when logger stops
	TimerResolution    uint32   // assumes timer is constant!!!
	MaximumFileSize    uint32   // Maximum in Mbytes
	LogFileMode        uint32   // specify logfile mode
	BuffersWritten     uint32   // used to file start of Circular File
	Union2             [16]byte // (LogInstanceGuid) | (StartBuffers, PointerSize, EventsLost, CpuSpeedInMHz)
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           TimeZoneInformation
	BootTime           int64
	PerfFreq           int64  // Reserved
	StartTime          int64  // Reserved
	ReservedFlags      uint32 // ClockType
	BuffersLost        uint32
}

// Version number of the operating system where the trace was collected.
// This is a roll-up of the members of VersionDetail.
// Starting with the low-order bytes, the first two bytes contain MajorVersion,
// the next two bytes contain MinorVersion, the next two bytes contain SubVersion,
// and the last two bytes contain SubMinorVersion.
// NOTE(tekert) (DOC is wrong, UCHAR = 1 byte)
func (t *TraceLogfileHeader) GetVersion() (major, minor, sub, subMinor uint8) {
	major = uint8(t.VersionUnion)
	minor = uint8(t.VersionUnion >> 8)
	sub = uint8(t.VersionUnion >> 16)
	subMinor = uint8(t.VersionUnion >> 24)
	return
}

// For RealTime Buffer Delivery (Reserved)
func (t *TraceLogfileHeader) GetLogInstanceGuid() GUID {
	return *(*GUID)(unsafe.Pointer(&t.Union2))
}

// Count of buffers written at start (Reserved)
func (t *TraceLogfileHeader) GetStartBuffers() uint32 {
	// (offset 0..3).
	return uint32(t.Union2[0]) |
		(uint32(t.Union2[1]) << 8) |
		(uint32(t.Union2[2]) << 16) |
		(uint32(t.Union2[3]) << 24)
}

// Size of pointer type in bits
func (t *TraceLogfileHeader) GetPointerSize() uint32 {
	// (offset 4..7).
	return uint32(t.Union2[4]) |
		(uint32(t.Union2[5]) << 8) |
		(uint32(t.Union2[6]) << 16) |
		(uint32(t.Union2[7]) << 24)
}

// Events losts during log session
func (t *TraceLogfileHeader) GetEventsLost() uint32 {
	// The EventsLost field is at offset 8..11 in the union
	// and is little-endian on Windows
	return uint32(t.Union2[8]) |
		(uint32(t.Union2[9]) << 8) |
		(uint32(t.Union2[10]) << 16) |
		(uint32(t.Union2[11]) << 24)
}

// CPU Speed in MHz
func (t *TraceLogfileHeader) GetCpuSpeedInMHz() uint32 {
	// (offset 12..15).
	return uint32(t.Union2[12]) |
		(uint32(t.Union2[13]) << 8) |
		(uint32(t.Union2[14]) << 16) |
		(uint32(t.Union2[15]) << 24)
}

// https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information
/*
typedef struct _TIME_ZONE_INFORMATION {
  LONG       Bias;
  WCHAR      StandardName[32];
  SYSTEMTIME StandardDate;
  LONG       StandardBias;
  WCHAR      DaylightName[32];
  SYSTEMTIME DaylightDate;
  LONG       DaylightBias;
} TIME_ZONE_INFORMATION, *PTIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION;
*/
type TimeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate SystemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate SystemTime
	DaylightBias  int32
}

// https://learn.microsoft.com/en-en/windows/win32/api/minwinbase/ns-minwinbase-systemtime
/*
typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
*/
// sizeof: 0x10 (OK)
type SystemTime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

// Helper to convert it to go time.
func (st *SystemTime) ToTime() time.Time {
	// Validate year range (1601-30827)
	if st.Year < 1601 || st.Year > 30827 {
		return time.Time{}
	}

	return time.Date(
		int(st.Year),
		time.Month(st.Month),
		int(st.Day),
		int(st.Hour),
		int(st.Minute),
		int(st.Second),
		int(st.Milliseconds)*1e6, // Convert ms to ns
		time.UTC,
	)
}

const (
	SDDL_REVISION_1 = 1
)

type SecurityDescriptorControl uint32

const (
	SE_OWNER_DEFAULTED       = SecurityDescriptorControl(0x0001)
	SE_GROUP_DEFAULTED       = SecurityDescriptorControl(0x0002)
	SE_DACL_PRESENT          = SecurityDescriptorControl(0x0004)
	SE_DACL_DEFAULTED        = SecurityDescriptorControl(0x0008)
	SE_SACL_PRESENT          = SecurityDescriptorControl(0x0010)
	SE_SACL_DEFAULTED        = SecurityDescriptorControl(0x0020)
	SE_DACL_AUTO_INHERIT_REQ = SecurityDescriptorControl(0x0100)
	SE_SACL_AUTO_INHERIT_REQ = SecurityDescriptorControl(0x0200)
	SE_DACL_AUTO_INHERITED   = SecurityDescriptorControl(0x0400)
	SE_SACL_AUTO_INHERITED   = SecurityDescriptorControl(0x0800)
	SE_DACL_PROTECTED        = SecurityDescriptorControl(0x1000)
	SE_SACL_PROTECTED        = SecurityDescriptorControl(0x2000)
	SE_RM_CONTROL_VALID      = SecurityDescriptorControl(0x4000)
	SE_SELF_RELATIVE         = SecurityDescriptorControl(0x8000)
)

type SecurityInformation uint32

const (
	OWNER_SECURITY_INFORMATION            = SecurityInformation(0x00000001)
	GROUP_SECURITY_INFORMATION            = SecurityInformation(0x00000002)
	DACL_SECURITY_INFORMATION             = SecurityInformation(0x00000004)
	SACL_SECURITY_INFORMATION             = SecurityInformation(0x00000008)
	LABEL_SECURITY_INFORMATION            = SecurityInformation(0x00000010)
	ATTRIBUTE_SECURITY_INFORMATION        = SecurityInformation(0x00000020)
	SCOPE_SECURITY_INFORMATION            = SecurityInformation(0x00000040)
	BACKUP_SECURITY_INFORMATION           = SecurityInformation(0x00010000)
	PROTECTED_DACL_SECURITY_INFORMATION   = SecurityInformation(0x80000000)
	PROTECTED_SACL_SECURITY_INFORMATION   = SecurityInformation(0x40000000)
	UNPROTECTED_DACL_SECURITY_INFORMATION = SecurityInformation(0x20000000)
	UNPROTECTED_SACL_SECURITY_INFORMATION = SecurityInformation(0x10000000)
)

// winnt.h
/*
//0x6 bytes (sizeof)
struct _SID_IDENTIFIER_AUTHORITY
{
    UCHAR Value[6];                                                         //0x0
};
*/

type SidIdentifierAuthority struct {
	Value [6]uint8 // Represents the top-level authority of a security identifier (SID).
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
/*
//0xc bytes (sizeof)
struct _SID
{
    UCHAR Revision;                                                         //0x0
    UCHAR SubAuthorityCount;                                                //0x1
    struct _SID_IDENTIFIER_AUTHORITY IdentifierAuthority;                   //0x2
    ULONG SubAuthority[1];                                                  //0x8
};
*/

type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority SidIdentifierAuthority
	SubAuthority        [1]uint32
}

// Access SubAuthority array
func (s *SID) SubAuthorities() []uint32 {
	if s == nil {
		return nil
	}
	return unsafe.Slice((*uint32)(&s.SubAuthority[0]), s.SubAuthorityCount)
}

/*
//0x8 bytes (sizeof)
struct _ACL
{
    UCHAR AclRevision;                                                      //0x0
    UCHAR Sbz1;                                                             //0x1
    USHORT AclSize;                                                         //0x2
    USHORT AceCount;                                                        //0x4
    USHORT Sbz2;                                                            //0x6
};
*/

type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
/*
typedef struct _SECURITY_DESCRIPTOR {
  BYTE                        Revision;
  BYTE                        Sbz1;
  SECURITY_DESCRIPTOR_CONTROL Control;
  PSID                        Owner;
  PSID                        Group;
  PACL                        Sacl;
  PACL                        Dacl;
} SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;
*/
type SecurityDescriptor struct {
	Revision byte
	Sbz1     byte
	Control  SecurityDescriptorControl
	Owner    *SID
	Group    *SID
	Sacl     *ACL
	Dacl     *ACL
}

/*
typedef enum {
    EventSecuritySetDACL,
    EventSecuritySetSACL,
    EventSecurityAddDACL,
    EventSecurityAddSACL,
    EventSecurityMax
  } EVENTSECURITYOPERATION;
*/

type EventSecurityOperation uint32

const (
	EventSecuritySetDACL = EventSecurityOperation(0)
	EventSecuritySetSACL = EventSecurityOperation(1)
	EventSecurityAddDACL = EventSecurityOperation(2)
	EventSecurityAddSACL = EventSecurityOperation(3)
	EventSecurityMax     = EventSecurityOperation(4)
)

// wmistr.h (v10.0.19041.0)
//
// used in: https://learn.microsoft.com/en-us/windows/win32/api/evntcons/nf-evntcons-eventaccesscontrol
//
// Specific rights for WMI guid objects. These are available from 0x0001 to
// 0xffff (ie up to 16 rights)

// Permissions for EventAccessControl API
const (
	WMIGUID_QUERY                 = 0x0001
	WMIGUID_SET                   = 0x0002
	WMIGUID_NOTIFICATION          = 0x0004
	WMIGUID_READ_DESCRIPTION      = 0x0008
	WMIGUID_EXECUTE               = 0x0010
	TRACELOG_CREATE_REALTIME      = 0x0020
	TRACELOG_CREATE_ONDISK        = 0x0040
	TRACELOG_GUID_ENABLE          = 0x0080
	TRACELOG_ACCESS_KERNEL_LOGGER = 0x0100
	TRACELOG_CREATE_INPROC        = 0x0200 // used pre-Vista
	TRACELOG_LOG_EVENT            = 0x0200 // used on Vista and greater
	TRACELOG_ACCESS_REALTIME      = 0x0400
	TRACELOG_REGISTER_GUIDS       = 0x0800
	TRACELOG_JOIN_GROUP           = 0x1000
	TRACELOG_ALL                  = TRACELOG_CREATE_REALTIME |
		TRACELOG_CREATE_ONDISK |
		TRACELOG_GUID_ENABLE |
		TRACELOG_LOG_EVENT |
		TRACELOG_ACCESS_REALTIME |
		TRACELOG_REGISTER_GUIDS
)
