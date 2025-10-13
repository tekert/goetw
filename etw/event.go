//go:build windows

package etw

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/tekert/goetw/internal/hexf"
)

var (
	eventPool = sync.Pool{
		New: func() any {
			return &Event{
				EventData:    make([]EventProperty, 0, 32),
				UserData:     make([]EventProperty, 0, 8),
				ExtendedData: make([]string, 0, 4),
				// Add a 0.5KB arena for string data per event.
				dataBuffer: make([]byte, 0, 512),
			}
		},
	}
)

// TODO: maybe just make eventrecordhelper marsheable, similar to Event.
// and delete this Event..
// make EventRecordHelper 

type EventID uint16

// ValueType indicates the type of data held by an EventProperty.
type ValueType uint8

const (
	OutTypeNull ValueType = iota
	OutTypeString
	OutTypeInt
	OutTypeUint
	OutTypeFloat
	OutTypeBool
	OutTypeHex64
	OutTypeOther // For arrays, structs, etc.
)

// EventProperty holds a single key-value pair from an ETW event's data.
// It uses typed fields to avoid heap allocations from interface boxing.
type EventProperty struct {
	Name        string
	Type        ValueType
	StringValue string
	IntValue    int64
	UintValue   uint64
	FloatValue  float64
	BoolValue   bool
	OtherValue  any // Fallback for complex types like arrays/structs
}

// Properties is a slice of EventProperty that marshals to a JSON object (map).
type Properties []EventProperty

// MarshalJSON implements a custom marshaler for Properties to produce a JSON object
// instead of an array of objects, preserving the original output format.
func (p Properties) MarshalJSON() ([]byte, error) {
	if len(p) == 0 {
		return []byte("null"), nil
	}

	buf := make([]byte, 0, 512) // Start with a reasonable buffer

	buf = append(buf, '{')

	for i, prop := range p {
		if i > 0 {
			buf = append(buf, ',')
		}

		// Marshal property name
		buf = append(buf, '"')
		buf = append(buf, prop.Name...)
		buf = append(buf, `":`...)

		// Marshal property value based on its type.
		switch prop.Type {
		case OutTypeString:
			buf = strconv.AppendQuote(buf, prop.StringValue)
		case OutTypeInt:
			buf = strconv.AppendInt(buf, prop.IntValue, 10)
		case OutTypeUint:
			buf = strconv.AppendUint(buf, prop.UintValue, 10)
		case OutTypeHex64:
			// For pointers and other hex values, format as a quoted hex string.
			buf = append(buf, '"')
			buf = hexf.AppendNUm64p(buf, prop.UintValue, true)
			buf = append(buf, '"')
		case OutTypeFloat:
			buf = strconv.AppendFloat(buf, prop.FloatValue, 'g', -1, 64)
		case OutTypeBool:
			buf = strconv.AppendBool(buf, prop.BoolValue)
		case OutTypeOther:
			// For all other types (arrays, structs), we fall back to the standard
			// marshaler. This is less frequent and acceptable.
			valBytes, err := json.Marshal(prop.OtherValue)
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
		case OutTypeNull:
			buf = append(buf, "null"...)
		}
	}

	buf = append(buf, '}')
	return buf, nil
}

type Event struct {
	Flags struct {
		// Use to flag event as being skippable for performance reason
		Skippable bool
	} `json:"-"`

	EventData Properties `json:",omitempty"`
	UserData  Properties `json:",omitempty"`
	System    struct {
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
		// Keywords struct {
		// 	Mask string
		// 	Name []string
		// }
		Level struct {
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
	ExtendedData []string `json:",omitempty"`

	// dataBuffer is a per-event arena for allocating all property strings.
	dataBuffer []byte
}

// So to print the mask in hex mode.
type MarshalKeywords struct {
	Mask uint64
	Name []string
}

// Better performance.
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

	// Write JSON structure, appending the zero-padded hex mask directly to the buffer.
	buf = append(buf, `{"Mask":"0x`...)
	buf = hexf.AppendUint64PaddedU(buf, k.Mask) // Use our new library function.
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

	return buf, nil
}

func NewEvent() *Event {
	e := eventPool.Get().(*Event)
	// Ensure slices have 0 length but retain capacity.
	e.reset()
	return e
}

func (e *Event) reset() {
	// Ensure slices have 0 length but retain capacity.
	e.EventData = e.EventData[:0]
	e.UserData = e.UserData[:0]
	e.ExtendedData = e.ExtendedData[:0]
	e.dataBuffer = e.dataBuffer[:0] // Reset the arena buffer
	//e.System is overwritten on each event, no need to reset.
	e.Flags.Skippable = false
}

func (e *Event) Release() {
	eventPool.Put(e)
}

// getValue reconstructs the 'any' value from the typed fields for generic access.
func (ep *EventProperty) getValue() any {
	switch ep.Type {
	case OutTypeString:
		return ep.StringValue
	case OutTypeInt:
		return ep.IntValue
	case OutTypeUint:
		return ep.UintValue
	case OutTypeHex64:
		// For generic access, format it to the expected string representation.
		return hexf.NUm64p(ep.UintValue, true)
	case OutTypeFloat:
		return ep.FloatValue
	case OutTypeBool:
		return ep.BoolValue
	case OutTypeOther:
		return ep.OtherValue
	default: // TypeNil
		return nil
	}
}

func (e *Event) GetProperty(name string) (any, bool) {
	// Linear scan is fast enough for the small number of properties
	// typical in an ETW event.
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			return e.EventData[i].getValue(), true
		}
	}

	for i := range e.UserData {
		if e.UserData[i].Name == name {
			return e.UserData[i].getValue(), true
		}
	}

	return nil, false
}

func (e *Event) GetPropertyString(name string) (string, bool) {
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			prop := &e.EventData[i]
			if prop.Type == OutTypeString {
				return prop.StringValue, true
			}
			// For any other type, format it to a string.
			return fmt.Sprint(prop.getValue()), true
		}
	}
	for i := range e.UserData {
		if e.UserData[i].Name == name {
			prop := &e.UserData[i]
			if prop.Type == OutTypeString {
				return prop.StringValue, true
			}
			return fmt.Sprint(prop.getValue()), true
		}
	}
	return "", false
}

// GetPropertyInt retrieves a property value directly as an int64, if possible.
// Returns false if the property does not exist, is not a number, or overflows.
func (e *Event) GetPropertyInt(name string) (int64, bool) {
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			prop := &e.EventData[i]
			switch prop.Type {
			case OutTypeInt:
				return prop.IntValue, true
			case OutTypeUint:
				if prop.UintValue <= math.MaxInt64 {
					return int64(prop.UintValue), true
				}
			}
			return 0, false
		}
	}
	for i := range e.UserData {
		if e.UserData[i].Name == name {
			prop := &e.UserData[i]
			switch prop.Type {
			case OutTypeInt:
				return prop.IntValue, true
			case OutTypeUint:
				if prop.UintValue <= math.MaxInt64 {
					return int64(prop.UintValue), true
				}
			}
			return 0, false
		}
	}
	return 0, false
}

// GetPropertyUInt retrieves a property value directly as a uint64, if possible.
// Returns false if the property does not exist, is not a number, or would be negative.
func (e *Event) GetPropertyUInt(name string) (uint64, bool) {
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			prop := &e.EventData[i]
			switch prop.Type {
			case OutTypeUint:
				return prop.UintValue, true
			case OutTypeInt:
				if prop.IntValue >= 0 {
					return uint64(prop.IntValue), true
				}
			}
			return 0, false
		}
	}
	for i := range e.UserData {
		if e.UserData[i].Name == name {
			prop := &e.UserData[i]
			switch prop.Type {
			case OutTypeUint:
				return prop.UintValue, true
			case OutTypeInt:
				if prop.IntValue >= 0 {
					return uint64(prop.IntValue), true
				}
			}
			return 0, false
		}
	}
	return 0, false
}

// GetPropertyFloat retrieves a property value directly as a float64, if possible.
// Returns false if the property does not exist or is not a float.
func (e *Event) GetPropertyFloat(name string) (float64, bool) {
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			if e.EventData[i].Type == OutTypeFloat {
				return e.EventData[i].FloatValue, true
			}
			return 0, false
		}
	}
	for i := range e.UserData {
		if e.UserData[i].Name == name {
			if e.UserData[i].Type == OutTypeFloat {
				return e.UserData[i].FloatValue, true
			}
			return 0, false
		}
	}
	return 0, false
}
