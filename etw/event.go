//go:build windows

package etw

import (
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

type Event struct {
	Flags struct {
		// Use to flag event as being skippable for performance reason
		Skippable bool
	} `json:"-"`

	EventData []EventProperty `json:",omitempty"`
	UserData  []EventProperty `json:",omitempty"`
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
	maskString := hexf.NUm64p(k.Mask, false)
	// Calculate buffer size
	size := 26 // {"Mask":"","Name":[]}
	size += len(maskString)

	if len(k.Name) > 0 {
		size += len(k.Name) * 2 // quotes for each name
		size += len(k.Name) - 1 // commas between names (n-1 commas needed)
		for _, name := range k.Name {
			size += len(name) // actual name length
		}
	}

	// Create buffer
	buf := make([]byte, 0, size)

	// Write JSON structure
	buf = append(buf, `{"Mask":"`...)
	buf = append(buf, maskString...)
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
	return eventPool.Get().(*Event)
}

func (e *Event) reset() {
	// Resetting slices is much faster than clearing maps.
	e.EventData = e.EventData[:0]
	e.UserData = e.UserData[:0]

	// Zero all fields except maps/slices
	*e = Event{
		EventData:    e.EventData,
		UserData:     e.UserData,
		ExtendedData: e.ExtendedData[:0],
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
		if s, ok := i.(string); ok {
			return s, ok
		}
	}
	return "", false
}
