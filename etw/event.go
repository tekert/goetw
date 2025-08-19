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
				EventData:    make(map[string]any),
				UserData:     make(map[string]any),
				ExtendedData: make([]string, 0),
			}
		},
	}
)

type EventID uint16

type Event struct {
	Flags struct {
		// Use to flag event as being skippable for performance reason
		Skippable bool
	} `json:"-"`

	EventData map[string]any `json:",omitempty"`
	UserData  map[string]any `json:",omitempty"`
	System    struct {
		Channel     string
		Computer    string
		EventID     uint16
		Version     uint8  `json:",omitempty"`
		EventType   string `json:",omitempty"`
		EventGuid   GUID   `json:",omitempty"`
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
		size += len(k.Name) * 2    // quotes for each name
		size += len(k.Name) - 1    // commas between names (n-1 commas needed)
		for _, name := range k.Name {
			size += len(name)      // actual name length
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
	// Clear contents
	clear(e.EventData)
	clear(e.UserData)

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

	if e.EventData != nil {
		if i, ok = e.EventData[name]; ok {
			return
		}
	}

	if e.UserData != nil {
		if i, ok = e.UserData[name]; ok {
			return
		}
	}

	return
}

func (e *Event) GetPropertyString(name string) (string, bool) {
	if i, ok := e.GetProperty(name); ok {
		if s, ok := i.(string); ok {
			return s, ok
		}
	}
	return "", false
}
