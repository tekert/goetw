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
				EventData:    make([]EventProperty, 0, 32), // Pre-allocate capacity
				UserData:     make([]EventProperty, 0, 8),  // Pre-allocate capacity
				ExtendedData: make([]string, 0, 4),
			}
		},
	}
)

type EventID uint16

// EventProperty holds a single key-value pair from an ETW event's data.
type EventProperty struct {
	Name  string
	Value any
}

// Properties is a slice of EventProperty that marshals to a JSON object (map).
type Properties []EventProperty

// MarshalJSON implements a custom marshaler for Properties to produce a JSON object
// instead of an array of objects, preserving the original output format.
func (p Properties) MarshalJSON() ([]byte, error) {
	if len(p) == 0 {
		return []byte("null"), nil
	}

	// Using a pre-allocated byte buffer is more efficient than strings.Builder.
	// We estimate a starting size to reduce re-allocations.
	// Average property: "name": "value", -> ~15 chars + name len + value len
	estimatedSize := 2 + len(p)*15
	for _, prop := range p {
		estimatedSize += len(prop.Name)
		if s, ok := prop.Value.(string); ok {
			estimatedSize += len(s) + 2 // +2 for quotes
		} else {
			estimatedSize += 64 // A rough guess for other types like arrays
		}
	}
	if estimatedSize < 512 {
		estimatedSize = 512
	}

	buf := make([]byte, 0, estimatedSize)
	buf = append(buf, '{')

	for i, prop := range p {
		if i > 0 {
			buf = append(buf, ',')
		}
		// Marshal property name
		buf = append(buf, '"')
		buf = append(buf, prop.Name...)
		buf = append(buf, `":`...)

		// Marshal property value.
		switch v := prop.Value.(type) {
		case string:
			// strconv.AppendQuote is significantly faster than json.Marshal for strings
			// as it avoids reflection.
			buf = strconv.AppendQuote(buf, v)
		case int64:
			buf = strconv.AppendInt(buf, v, 10)
		case uint64:
			buf = strconv.AppendUint(buf, v, 10)
		case float64:
			buf = strconv.AppendFloat(buf, v, 'g', -1, 64)
		case bool:
			buf = strconv.AppendBool(buf, v)
		default:
			// For all other types (arrays, structs), we fall back to the standard
			// marshaler. This is less frequent and acceptable.
			valBytes, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
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
	buf = hexf.AppendUint64(buf, k.Mask) // Use our new library function.
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
	e.EventData = e.EventData[:0]
	e.UserData = e.UserData[:0]
	e.ExtendedData = e.ExtendedData[:0]
	return e
}

func (e *Event) reset() {
	// Slices are reset to zero length in NewEvent, which is called before reuse.
	// We only need to zero the other fields.
	*e = Event{
		EventData:    e.EventData,
		UserData:     e.UserData,
		ExtendedData: e.ExtendedData,
	}
}

func (e *Event) Release() {
	e.reset()
	eventPool.Put(e)
}

func (e *Event) GetProperty(name string) (i any, ok bool) {
	// Linear scan is fast enough for the small number of properties
	// typical in an ETW event.
	for i := range e.EventData {
		if e.EventData[i].Name == name {
			return e.EventData[i].Value, true
		}
	}

	for i := range e.UserData {
		if e.UserData[i].Name == name {
			return e.UserData[i].Value, true
		}
	}

	return nil, false
}

func (e *Event) GetPropertyString(name string) (string, bool) {
	if i, ok := e.GetProperty(name); ok {
		// Handle both eager-parsed strings and lazily-parsed properties.
		switch v := i.(type) {
		case string:
			return v, true
		default:
			// For any other type, format it to a string.
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

// GetPropertyInt retrieves a property value directly as an int64, if possible.
// It provides fast, direct conversion from binary for scalar properties that were
// lazily parsed. Returns false if the property does not exist or is not a number.
func (e *Event) GetPropertyInt(name string) (int64, bool) {
	if val, ok := e.GetProperty(name); ok {
		switch v := val.(type) {
		case int64:
			return v, true
		case uint64:
			if v <= math.MaxInt64 {
				return int64(v), true
			}
		}
	}
	return 0, false
}

// GetPropertyUInt retrieves a property value directly as a uint64, if possible.
// It provides fast, direct conversion from binary for scalar properties that were
// lazily parsed. Returns false if the property does not exist or is not a number.
func (e *Event) GetPropertyUInt(name string) (uint64, bool) {
	if val, ok := e.GetProperty(name); ok {
		switch v := val.(type) {
		case uint64:
			return v, true
		case int64:
			if v >= 0 {
				return uint64(v), true
			}
		}
	}
	return 0, false
}

// GetPropertyFloat retrieves a property value directly as a float64, if possible.
// It provides fast, direct conversion from binary for scalar properties that were
// lazily parsed. Returns false if the property does not exist or is not a number.
func (e *Event) GetPropertyFloat(name string) (float64, bool) {
	if val, ok := e.GetProperty(name); ok {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0, false
}
