//go:build windows

package etw

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

const (
	// AutologgerPath is the registry path where AutoLogger configurations are stored.
	// AutoLogger sessions are ETW sessions that start automatically during system boot,
	// allowing capture of events from early system startup before user-mode applications run.
	AutologgerPath = `HKLM\System\CurrentControlSet\Control\WMI\Autologger`

	regExe    = `C:\Windows\System32\reg.exe` // Path to Windows registry editor executable
	regDword  = "REG_DWORD"                   // Registry DWORD type for 32-bit integer values
	regQword  = "REG_QWORD"                   // Registry QWORD type for 64-bit integer values
	regSz     = "REG_SZ"                      // Registry string type
	regBinary = "REG_BINARY"                  // Registry binary type for filter data
)

func hexStr(i any) string {
	return fmt.Sprintf("0x%x", i)
}

// AutoLogger represents an ETW AutoLogger session configuration.
// AutoLogger sessions start automatically during system boot, making them useful
// for capturing events from early system startup, driver initialization, and
// other boot-time activities that occur before user-mode applications can start
// regular ETW sessions.
//
// The configuration is stored in the Windows registry and read by the ETW
// subsystem during boot. Once created, AutoLogger sessions persist across
// reboots until explicitly deleted.
//
// Reference: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
type AutoLogger struct {
	// Name is the unique identifier for this AutoLogger session.
	// This becomes the session name and the registry key name.
	Name string

	// GuidS is the string representation of the AutoLogger session GUID.
	// This GUID uniquely identifies the logging session.
	GuidS string

	// LogFileMode specifies the logging mode flags for the session.
	// Common values include EVENT_TRACE_FILE_MODE_SEQUENTIAL for sequential file logging
	// or EVENT_TRACE_REAL_TIME_MODE for real-time event delivery.
	LogFileMode uint32

	// BufferSize specifies the size of each trace buffer in kilobytes.
	// ETW events can be up to 64KB, so buffers must be at least this size.
	// Larger buffers improve efficiency but use more memory.
	BufferSize uint32

	// ClockType specifies the type of timestamp to use for events.
	// Common values: 1 = Performance Counter, 2 = System Time, 3 = CPU Cycle Counter
	ClockType uint32

	// MaxFileSize is the maximum file size of the log file, in megabytes.
	// For real-time sessions with RealtimePersistence, this is the maximum size of the backup file.
	//
	// Registry Behavior:
	// - If not set in registry: defaults to 100MB
	// - If set to 0 in registry: no limit (unlimited growth)
	// - If this field is 0: the MaxFileSize registry value is not configured
	// - If this field is > 0: the MaxFileSize registry value is set to this value
	MaxFileSize uint32
}

// Path returns the full registry path for this AutoLogger session configuration.
// The path follows the format: HKLM\System\CurrentControlSet\Control\WMI\Autologger\{SessionName}
func (a *AutoLogger) Path() string {
	return fmt.Sprintf(`%s\%s`, strings.TrimRight(AutologgerPath, `\`), strings.TrimLeft(a.Name, `\`))
}

// Create creates a new autologger session with the specified parameters.
// If the session already exists , it returns an error.
// If the session is successfully created, it returns nil.
func (a *AutoLogger) Create() (err error) {
	if a.Name == "" {
		return fmt.Errorf("AutoLogger name cannot be empty")
	}
	if a.GuidS == "" {
		return fmt.Errorf("AutoLogger GUID cannot be empty")
	}
	if a.Exists() {
		return fmt.Errorf("AutoLogger session '%s' already exists", a.Name)
	}

	sargs := [][]string{
		// ETWtrace parameters
		{a.Path(), "GUID", regSz, a.GuidS},
		{a.Path(), "Start", regDword, "0x1"},
		{a.Path(), "LogFileMode", regDword, hexStr(a.LogFileMode)},
		// ETWevent can be up to 64KB so buffer needs to be at least this size
		{a.Path(), "BufferSize", regDword, hexStr(a.BufferSize)},
		{a.Path(), "ClockType", regDword, hexStr(a.ClockType)},
	}

	if a.MaxFileSize > 0 {
		sargs = append(sargs, []string{a.Path(), "MaxFileSize", regDword, hexStr(a.MaxFileSize)})
	}

	for _, args := range sargs {
		if err = regAddValue(args[0], args[1], args[2], args[3]); err != nil {
			return
		}
	}

	return
}

// serializeFiltersForAutologger creates the binary data block for the FilterData registry value.
// The format is one or more EVENT_FILTER_DESCRIPTORs followed immediately by their corresponding data.
func serializeFiltersForAutologger(filters []ProviderFilter) (string, error) {
	if len(filters) == 0 {
		return "", nil
	}

	type filterInfo struct {
		desc EventFilterDescriptor
		data []byte
	}

	var infos []filterInfo
	var totalDataSize uint32

	// 1. Build descriptors and copy data for each filter.
	var keepAlives []any
	for _, f := range filters {
		desc, keepAlive := f.build()

		if desc.Type != EVENT_FILTER_TYPE_NONE {
			data := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(desc.Ptr))), desc.Size)
			// It's important to copy the data, as the original pointer might become invalid.
			dataCopy := make([]byte, desc.Size)
			copy(dataCopy, data)

			infos = append(infos, filterInfo{desc: desc, data: dataCopy})
			totalDataSize += desc.Size
			keepAlives = append(keepAlives, keepAlive)
		}

		// Cleanup must be called after we are done with the memory from build(),
		// but before the next loop iteration to avoid resource leaks.
		//_ = keepAlive
	}
	runtime.KeepAlive(keepAlives)

	if len(infos) == 0 {
		return "", nil
	}

	// 2. Create the final binary blob.
	descSize := uint32(unsafe.Sizeof(EventFilterDescriptor{}))
	totalDescSize := uint32(len(infos)) * descSize
	finalBuf := bytes.NewBuffer(make([]byte, 0, totalDescSize+totalDataSize))

	// 3. Write descriptors with updated Ptr offsets.
	currentDataOffset := totalDescSize
	for _, info := range infos {
		desc := info.desc
		desc.Ptr = uint64(currentDataOffset) // Ptr is offset from start of blob.
		if err := binary.Write(finalBuf, binary.LittleEndian, &desc); err != nil {
			return "", fmt.Errorf("failed to write descriptor: %w", err)
		}
		currentDataOffset += desc.Size
	}

	// 4. Write all filter data.
	for _, info := range infos {
		if _, err := finalBuf.Write(info.data); err != nil {
			return "", fmt.Errorf("failed to write filter data: %w", err)
		}
	}

	return hex.EncodeToString(finalBuf.Bytes()), nil
}

// EnableProvider enables a provider for this AutoLogger session by writing the necessary
// configuration to the registry.
func (a *AutoLogger) EnableProvider(p Provider) (err error) {
	path := fmt.Sprintf(`%s\%s`, a.Path(), p.GUID.StringU())

	sargs := [][]string{
		{path, "Enabled", regDword, "0x1"},
		{path, "EnableLevel", regDword, hexStr(p.EnableLevel)},
		{path, "MatchAnyKeyword", regQword, hexStr(p.MatchAnyKeyword)},
	}

	if p.MatchAllKeyword != 0 {
		sargs = append(sargs, []string{path, "MatchAllKeyword", regQword, hexStr(p.MatchAllKeyword)})
	}

	// As per documentation, all filters are serialized into a single REG_BINARY
	// value named "FilterData".
	if len(p.Filters) > 0 {
		var filterData string
		if filterData, err = serializeFiltersForAutologger(p.Filters); err != nil {
			return fmt.Errorf("failed to create binary filter data: %w", err)
		}
		if filterData != "" {
			sargs = append(sargs, []string{path, "FilterData", regBinary, filterData})
		}
	}

	// executing commands
	for _, args := range sargs {
		if err = regAddValue(args[0], args[1], args[2], args[3]); err != nil {
			return
		}
	}

	return
}

func (a *AutoLogger) Exists() bool {
	return execute(regExe, "QUERY", a.Path()) == nil
}

func (a *AutoLogger) Delete() error {
	return execute(regExe, "DELETE", a.Path(), "/f")
}

func execute(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("err:%s out:%s", err, string(out))
	}
	return nil
}

func regAddValue(path, valueName, valueType, value string) error {
	return execute(regExe, "ADD", path, "/v", valueName, "/t", valueType, "/d", value, "/f")
}
