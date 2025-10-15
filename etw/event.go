//go:build windows

package etw

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/tekert/goetw/internal/hexf"
)

const (
	// StructurePropertyName is the key used in the parsed event's for TODO:
	StructurePropertyName = "Structures"
)

// SystemMetadata holds all the structured metadata for an ETW event.
type SystemMetadata struct {
	Channel     string
	Computer    string
	EventID     uint16
	Version     uint8  `json:",omitempty"`
	EventType   string `json:",omitempty"`
	EventGuid   GUID
	Correlation struct {
		ActivityID        string
		RelatedActivityID string
	}
	Execution struct {
		ProcessID     uint32
		ThreadID      uint32
		ProcessorTime uint64 `json:",omitempty"`
		ProcessorID   uint16
		KernelTime    uint32
		UserTime      uint32
	}
	Keywords MarshalKeywords
	Level    struct {
		Value uint8
		Name  string
	}
	Opcode struct {
		Value uint8
		Name  string
	}
	Task struct {
		Value uint8
		Name  string
	}
	Provider struct {
		Guid GUID
		Name string
	}
	TimeCreated struct {
		SystemTime time.Time
	}
}

// MarshalKeywords provides a high-performance, custom JSON marshaler for the Keywords struct,
// ensuring the mask is always represented as a zero-padded hex string.
type MarshalKeywords struct {
	Mask uint64
	Name []string
}

// AppendText appends the JSON representation of the keywords to the buffer.
func (k MarshalKeywords) AppendText(buf []byte) []byte {
	// Write JSON structure, appending the zero-padded hex mask directly to the buffer.
	buf = append(buf, `{"Mask":"0x`...)
	buf = hexf.AppendUint64PaddedU(buf, k.Mask)
	buf = append(buf, `","Name":[`...)

	// Write names array
	for i, name := range k.Name {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '"')
		buf = append(buf, name...)
		buf = append(buf, '"')
	}

	buf = append(buf, "]}"...)
	return buf
}

// MarshalJSON implements the json.Marshaler interface.
func (k MarshalKeywords) MarshalJSON() ([]byte, error) {
	// Pre-calculate buffer size. A uint64 hex string is always 16 chars + "0x".
	size := 26 + 18 // {"Mask":"0x...","Name":[]}
	if len(k.Name) > 0 {
		size += len(k.Name) * 2 // quotes for each name
		size += len(k.Name) - 1 // commas between names (n-1 commas needed)
		for _, name := range k.Name {
			size += len(name) // actual name length
		}
	}
	// Create buffer
	buf := make([]byte, 0, size)
	buf = k.AppendText(buf)

	return buf, nil
}

// AppendText manually marshals the SystemMetadata to a byte buffer, avoiding reflection
// for maximum performance.
func (m *SystemMetadata) AppendText(buf []byte) []byte {
	buf = append(buf, `{"Channel":"`...)
	buf = append(buf, m.Channel...)
	buf = append(buf, `","Computer":"`...)
	buf = append(buf, m.Computer...)
	buf = append(buf, `","EventID":`...)
	buf = strconv.AppendUint(buf, uint64(m.EventID), 10)

	if m.Version != 0 {
		buf = append(buf, `,"Version":`...)
		buf = strconv.AppendUint(buf, uint64(m.Version), 10)
	}
	if m.EventType != "" {
		buf = append(buf, `,"EventType":"`...)
		buf = append(buf, m.EventType...)
		buf = append(buf, '"')
	}

	buf = append(buf, `,"EventGuid":"`...)
	buf = m.EventGuid.AppendText(buf)
	buf = append(buf, '"')

	buf = append(buf, `,"Correlation":{"ActivityID":"`...)
	buf = append(buf, m.Correlation.ActivityID...)
	buf = append(buf, `","RelatedActivityID":"`...)
	buf = append(buf, m.Correlation.RelatedActivityID...)
	buf = append(buf, `"}`...)

	buf = append(buf, `,"Execution":{"ProcessID":`...)
	buf = strconv.AppendUint(buf, uint64(m.Execution.ProcessID), 10)
	buf = append(buf, `,"ThreadID":`...)
	buf = strconv.AppendUint(buf, uint64(m.Execution.ThreadID), 10)
	if m.Execution.ProcessorTime != 0 {
		buf = append(buf, `,"ProcessorTime":`...)
		buf = strconv.AppendUint(buf, m.Execution.ProcessorTime, 10)
	}
	buf = append(buf, `,"ProcessorID":`...)
	buf = strconv.AppendUint(buf, uint64(m.Execution.ProcessorID), 10)
	buf = append(buf, `,"KernelTime":`...)
	buf = strconv.AppendUint(buf, uint64(m.Execution.KernelTime), 10)
	buf = append(buf, `,"UserTime":`...)
	buf = strconv.AppendUint(buf, uint64(m.Execution.UserTime), 10)
	buf = append(buf, '}')

	buf = append(buf, `,"Keywords":`...)
	buf = m.Keywords.AppendText(buf)

	buf = append(buf, `,"Level":{"Value":`...)
	buf = strconv.AppendUint(buf, uint64(m.Level.Value), 10)
	buf = append(buf, `,"Name":"`...)
	buf = append(buf, m.Level.Name...)
	buf = append(buf, `"}`...)

	buf = append(buf, `,"Opcode":{"Value":`...)
	buf = strconv.AppendUint(buf, uint64(m.Opcode.Value), 10)
	buf = append(buf, `,"Name":"`...)
	buf = append(buf, m.Opcode.Name...)
	buf = append(buf, `"}`...)

	buf = append(buf, `,"Task":{"Value":`...)
	buf = strconv.AppendUint(buf, uint64(m.Task.Value), 10)
	buf = append(buf, `,"Name":"`...)
	buf = append(buf, m.Task.Name...)
	buf = append(buf, `"}`...)

	buf = append(buf, `,"Provider":{"Guid":"`...)
	buf = m.Provider.Guid.AppendText(buf)
	buf = append(buf, `","Name":"`...)
	buf = append(buf, m.Provider.Name...)
	buf = append(buf, `"}`...)

	buf = append(buf, `,"TimeCreated":{"SystemTime":"`...)
	buf, _ = m.TimeCreated.SystemTime.AppendText(buf)
	buf = append(buf, `"}`...)

	buf = append(buf, '}')
	return buf
}

// MarshalJSON implements the json.Marshaler interface for EventRecordHelper.
// It provides the highest-performance, lowest-allocation method to serialize an event
// directly to JSON by writing into a reusable internal buffer.
func (e *EventRecordHelper) MarshalJSON() ([]byte, error) {
	if err := e.PrepareAll(); err != nil {
		return nil, err
	}

	// Use the reusable dataBuffer for the entire JSON output.
	buf := e.storage.dataBuffer[:0]
	buf = append(buf, '{')

	// Marshal EventData / UserData
	buf, eventDataWritten, err := e.appendEventDataJSON(buf)
	if err != nil {
		return nil, err
	}

	// If any event properties were written, add a comma before the System block.
	if eventDataWritten {
		buf = append(buf, ',')
	}

	// Marshal System Metadata
	e.setSystemMetadata(&e.storage.system)
	buf = append(buf, `"System":`...)
	buf = e.storage.system.AppendText(buf)

	buf = append(buf, '}') // Close main object

	// WARNING: The returned byte slice is a view into a reusable internal buffer.
	// It is only valid until the next call to MarshalJSON or until the callback returns.
	// If we need to retain the data, we MUST make a copy.
	// Example: `dataCopy := make([]byte, len(jsonData)); copy(dataCopy, jsonData)`
	e.storage.dataBuffer = buf
	return e.storage.dataBuffer, nil
}

// appendEventDataJSON marshals the EventData or UserData section of the event.
// It returns the updated buffer, a boolean indicating if any data was written,
// and an error if one occurred.
func (e *EventRecordHelper) appendEventDataJSON(buf []byte) ([]byte, bool, error) {
	// This logic correctly handles commas and empty property sets by only creating
	// the EventData/UserData object when the first valid property is encountered.
	firstProp := true
	appendAndMaybeStartObject := func() {
		if firstProp {
			// This is the first property we are actually writing.
			isUserData := (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA
			if isUserData {
				buf = append(buf, `"UserData":{`...)
			} else {
				buf = append(buf, `"EventData":{`...)
			}
			firstProp = false
		} else {
			// This is a subsequent property, so just add a comma.
			buf = append(buf, ',')
		}
	}

	names := e.getCachedPropNames()

	// Simple Properties
	for i, p := range *e.PropertiesByIndex {
		if p == nil || !e.shouldParse(names[i]) {
			continue
		}
		appendAndMaybeStartObject()
		// Use fast, manual quoting for property names (assumed to be safe).
		buf = append(buf, '"')
		buf = append(buf, names[i]...)
		buf = append(buf, `":`...)

		var err error
		buf, err = p.AppendToJSON(buf)
		if err != nil {
			buf = append(buf, `"failed to parse"`...)
		}
	}

	// Custom Properties
	for name, p := range e.PropertiesCustom {
		if !e.shouldParse(name) {
			continue
		}
		appendAndMaybeStartObject()
		// Use fast, manual quoting for property names.
		buf = append(buf, '"')
		buf = append(buf, name...)
		buf = append(buf, `":`...)
		// Use standard library quoter for guaranteed correctness.
		buf = strconv.AppendQuote(buf, p.value)
	}

	// Complex Properties (Arrays/Structs)
	for _, i := range e.storage.usedArrayIndices {
		pname := names[i]
		if !e.shouldParse(pname) {
			continue
		}
		props := *(*e.ArrayProperties)[i]

		appendAndMaybeStartObject()
		buf = append(buf, '"')
		buf = append(buf, pname...)
		buf = append(buf, `":[`...)

		for j, p := range props {
			if j > 0 {
				buf = append(buf, ',')
			}
			// Array elements are always quoted strings in JSON
			var err error
			buf, err = p.AppendToJSON(buf)
			if err != nil {
				buf = append(buf, `"failed to parse"`...)
			}
		}
		buf = append(buf, ']')
	}

	for _, i := range e.storage.usedStructArrIndices {
		name := names[i]
		if !e.shouldParse(name) {
			continue
		}
		appendAndMaybeStartObject()
		buf = append(buf, '"')
		buf = append(buf, name...)
		buf = append(buf, `":`...)

		var err error
		buf, err = e.appendStructsJSON(buf, (*e.StructArrays)[i])
		if err != nil {
			// If marshaling a struct fails, we can't continue.
			return buf, false, err
		}
	}

	if len(*e.StructSingle) > 0 && e.shouldParse(StructurePropertyName) {
		appendAndMaybeStartObject()
		buf = append(buf, '"')
		buf = append(buf, StructurePropertyName...)
		buf = append(buf, `":`...)

		var err error
		buf, err = e.appendStructsJSON(buf, *e.StructSingle)
		if err != nil {
			return buf, false, err
		}
	}

	// After all property loops, if we started the object, we must close it.
	if !firstProp {
		buf = append(buf, '}') // Close EventData/UserData
		return buf, true, nil
	}

	return buf, false, nil
}

// appendStructsJSON manually marshals an array of property-maps to a JSON
// array of objects, writing directly to the buffer. It sorts the fields of
// each struct alphabetically to ensure a consistent and predictable JSON output.
func (e *EventRecordHelper) appendStructsJSON(buf []byte, structs []map[string]*Property) ([]byte, error) {
	buf = append(buf, '[') // Start of array

	var keys []string // Reused for sorting keys of each struct to minimize allocations.

	for i, propStruct := range structs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, '{') // Start of object

		// To ensure consistent JSON output, we must sort the map keys.
		// The 'keys' slice capacity is reused across iterations of this loop.
		keys = keys[:0]
		for k := range propStruct {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for j, field := range keys {
			if j > 0 {
				buf = append(buf, ',')
			}

			// Get the property from the original map using the sorted key.
			prop := propStruct[field]

			// Append key
			buf = append(buf, '"')
			buf = append(buf, field...)
			buf = append(buf, `":`...)

			// Append value using the zero-allocation property decoder.
			var err error
			buf, err = prop.AppendToJSON(buf)
			if err != nil {
				// The buffer is in a partial state, but we return the error
				// assuming the caller will discard the result.
				return buf, fmt.Errorf("failed to marshal struct field %s: %w", field, err)
			}
		}
		buf = append(buf, '}') // End of object
	}

	buf = append(buf, ']') // End of array
	return buf, nil
}

// TODO: delete
// formatStructs parses a array of name:props into an array of name:value
func (e *EventRecordHelper) formatStructs(structs []map[string]*Property,
	name string) ([]map[string]string, error) {

	// NOTE: this is only used when parsing to json event, using reusable memory maybe it's not ideal.
	result := make([]map[string]string, 0, len(structs))
	var err error

	for _, propStruct := range structs {
		s := make(map[string]string)
		for field, prop := range propStruct {
			if s[field], err = prop.ToString(); err != nil {
				return nil, fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsingTdh, name, field, err)
			}
		}
		result = append(result, s)
	}
	return result, nil
}
