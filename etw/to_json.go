package etw

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"

	"github.com/tekert/goetw/internal/hexf"
)

// This is called only for static analysis purposes, so it's not used often
// enconding/json is slow but it does the job

// JsonLogfile is a JSON-safe version of EventTraceLogfile
type JsonLogfile struct {
	LogFileName   string
	LoggerName    string
	CurrentTime   time.Time
	BuffersRead   uint32
	ProcessMode   []string // From Union1 uint32 to array strings
	LogfileHeader JsonLogHeader
	BufferSize    uint32
	Filled        uint32
	EventsLost    uint32
	IsKernelTrace uint32
}

type JsonLogHeader struct {
	BufferSize         string
	Version            string
	ProviderVersion    string
	NumberOfProcessors uint32
	EndTime            time.Time
	TimerResolution    uint32
	MaxFileSize        uint32
	LogFileMode        string
	BuffersWritten     uint32
	StartBuffers       uint32 // From Union2[0-3]
	PointerSize        uint32 // From Union2[4-7]
	EventsLost         uint32 // From Union2[8-11]
	CpuSpeedInMHz      uint32 // From Union2[12-15]
	LoggerName         string `json:",omitempty"`
	LogFileName        string `json:",omitempty"`
	TimeZone           JsonTimeZoneInfo
	BootTime           time.Time
	PerfFreq           int64
	StartTime          time.Time
	ReservedFlags      uint32
	BuffersLost        uint32
}

type JsonTime time.Time
type JsonTimeZoneInfo struct {
	Bias         int32
	StandardName string
	StandardDate JsonTime `json:",omitzero"`
	StandardBias int32    `json:",omitempty"`
	DaylightName string
	DaylightDate JsonTime `json:",omitzero"`
	DaylightBias int32    `json:",omitempty"`
}

type JsonEventPropertyInfo struct {
	Name                string        `json:"Name"`
	Flags               PropertyFlags `json:"Flags"`
	InType              TdhInType     `json:"InType,omitempty"`
	OutType             TdhOutType    `json:"OutType,omitempty"`
	MapName             string        `json:"MapName,omitempty"`
	StructStartIndex    uint16        `json:"StructStartIndex,omitempty"`
	NumOfStructMembers  uint16        `json:"NumOfStructMembers,omitempty"`
	Count               uint16        `json:"Count"`
	CountPropertyIndex  uint16        `json:"CountPropertyIndex,omitempty"`
	Length              uint16        `json:"Length"`
	LengthPropertyIndex uint16        `json:"LengthPropertyIndex,omitempty"`
}

func (epi *EventPropertyInfo) ToJSON(t *TraceEventInfo) JsonEventPropertyInfo {
	prop := JsonEventPropertyInfo{
		Name:   t.cleanStringAt(uintptr(epi.NameOffset)),
		Flags:  epi.Flags,
		Count:  epi.Count(),
		Length: epi.Length(),
	}
	if (epi.Flags & PropertyStruct) != 0 {
		prop.StructStartIndex = epi.StructStartIndex()
		prop.NumOfStructMembers = epi.NumOfStructMembers()
	} else {
		prop.InType = epi.InType()
		prop.OutType = epi.OutType()
		if epi.MapNameOffset() > 0 {
			prop.MapName = t.cleanStringAt(uintptr(epi.MapNameOffset()))
		}
	}
	if (epi.Flags & PropertyParamCount) != 0 {
		prop.CountPropertyIndex = epi.CountPropertyIndex()
	}
	if (epi.Flags & PropertyParamLength) != 0 {
		prop.LengthPropertyIndex = epi.LengthPropertyIndex()
	}
	return prop
}

func (t JsonTime) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil // Return null for zero time
	}

	// Format time directly to avoid recursive json.Marshal
	b := make([]byte, 0, 26) // len(`"2006-01-02T15:04:05Z07:00"`)
	b = append(b, '"')
	b = tt.AppendFormat(b, time.RFC3339)
	b = append(b, '"')
	return b, nil
}

// MarshalJSON implements json.Marshaler for EventTraceLogfile
func (etl *EventTraceLogfile) MarshalJSON() ([]byte, error) {
	safe, err := etl.ToJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(safe) // slow, but this is not used repeatedly (if it is remove this)
}

// ToJSON converts TraceLogfileHeader to a JSON-safe struct
func (h *TraceLogfileHeader) ToJSON() (JsonLogHeader, error) {
	if h == nil {
		return JsonLogHeader{}, nil
	}

	major, minor, sub, subMinor := h.GetVersion()

	return JsonLogHeader{
		BufferSize:         fmt.Sprintf("%d KB", h.BufferSize),
		Version:            fmt.Sprintf("%d.%d.%d.%d", major, minor, sub, subMinor),
		ProviderVersion:    fmt.Sprintf("Build version: %d", h.ProviderVersion),
		NumberOfProcessors: h.NumberOfProcessors,
		EndTime:            FromFiletime(h.EndTime).UTC(),
		TimerResolution:    h.TimerResolution,
		MaxFileSize:        h.MaximumFileSize,
		LogFileMode:        hexf.NUm32p(h.LogFileMode, false),
		BuffersWritten:     h.BuffersWritten,
		StartBuffers:       h.GetStartBuffers(),
		PointerSize:        h.GetPointerSize(),
		EventsLost:         h.GetEventsLost(),
		CpuSpeedInMHz:      h.GetCpuSpeedInMHz(),
		BootTime:           FromFiletime(h.BootTime).UTC(),
		PerfFreq:           h.PerfFreq,
		StartTime:          FromFiletime(h.StartTime).UTC(),
		ReservedFlags:      h.ReservedFlags,
		BuffersLost:        h.BuffersLost,
		TimeZone: JsonTimeZoneInfo{
			Bias:         h.TimeZone.Bias,
			StandardName: FromUTF16Slice(h.TimeZone.StandardName[:]),
			StandardDate: JsonTime(h.TimeZone.StandardDate.ToTime()),
			StandardBias: h.TimeZone.StandardBias,
			DaylightName: FromUTF16Slice(h.TimeZone.DaylightName[:]),
			DaylightDate: JsonTime(h.TimeZone.DaylightDate.ToTime()),
			DaylightBias: h.TimeZone.DaylightBias,
		},
	}, nil
}

// toMarsheableLogFile converts EventTraceLogfile to a JSON-safe struct
func (etl *EventTraceLogfile) ToJSON() (*JsonLogfile, error) {
	if etl == nil {
		return nil, nil
	}

	header, err := etl.LogfileHeader.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert header: %w", err)
	}

	safe := &JsonLogfile{
		CurrentTime:   FromFiletime(etl.CurrentTime).UTC(),
		BuffersRead:   etl.BuffersRead,
		ProcessMode:   etl.GetProcessTraceModeStrings(),
		LogfileHeader: header,
		BufferSize:    etl.BufferSize,
		Filled:        etl.Filled,
		EventsLost:    etl.EventsLost,
		IsKernelTrace: etl.IsKernelTrace,
	}

	if etl.LogFileName != nil {
		safe.LogFileName = FromUTF16Pointer(etl.LogFileName)
	}
	if etl.LoggerName != nil {
		safe.LoggerName = FromUTF16Pointer(etl.LoggerName)
	}

	return safe, nil
}

func (e *EventHeader) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Size            uint16          `json:"Size"`
		HeaderType      uint16          `json:"HeaderType"`
		Flags           uint16          `json:"Flags"`
		EventProperty   uint16          `json:"EventProperty"`
		ThreadId        uint32          `json:"ThreadId"`
		ProcessId       uint32          `json:"ProcessId"`
		TimeStampRaw    int64           `json:"TimeStamp"`
		ProviderId      string          `json:"ProviderId"`
		EventDescriptor EventDescriptor `json:"EventDescriptor"`
		KernelTime      uint32          `json:"KernelTime"`
		UserTime        uint32          `json:"UserTime"`
		ProcessorTime   uint64          `json:"ProcessorTime"`
		ActivityId      string          `json:"ActivityId"`
	}{
		Size:            e.Size,
		HeaderType:      e.HeaderType,
		Flags:           e.Flags,
		EventProperty:   e.EventProperty,
		ThreadId:        e.ThreadId,
		ProcessId:       e.ProcessId,
		TimeStampRaw:    e.TimestampRaw(),
		ProviderId:      e.ProviderId.StringU(),
		EventDescriptor: e.EventDescriptor,
		KernelTime:      e.GetKernelTime(),
		UserTime:        e.GetUserTime(),
		ProcessorTime:   e.ProcessorTime,
		ActivityId:      e.ActivityId.StringU(),
	})
}

func (e *EtwBufferContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProcessorNumber uint8  `json:"ProcessorNumber"`
		Alignment       uint8  `json:"Alignment"`
		ProcessorIndex  uint16 `json:"ProcessorIndex"`
		LoggerId        uint16 `json:"LoggerId"`
	}{
		ProcessorNumber: e.ProcessorNumber(),
		Alignment:       e.Alignment(),
		ProcessorIndex:  e.ProcessorIndex(),
		LoggerId:        e.LoggerId,
	})
}

func (er *EventRecord) MarshalJSON() (b []byte, err error) {
	// Use defer and recover to catch any panics from unsafe memory access.
	defer func() {
		if r := recover(); r != nil {
			// If a panic occurred, return a safe JSON object with the error.
			err = fmt.Errorf("panic recovered while marshaling EventRecord: %v", r)
			b, _ = json.Marshal(map[string]any{
				"error":         "failed to marshal event record due to panic",
				"panic_details": fmt.Sprintf("%v", r),
				"eventHeader":   er.EventHeader, // EventHeader is usually safe to access
			})
		}
	}()

	var extData []EventHeaderExtendedDataItem
	if er.ExtendedDataCount > 0 {
		extData = unsafe.Slice(er.ExtendedData, er.ExtendedDataCount)
	}

	// TODO(tekert): only do this if trace level is set.
	var userDataHex string
	if er.UserDataLength > 0 {
		userDataSlice := unsafe.Slice((*byte)(unsafe.Pointer(er.UserData)), er.UserDataLength)
		userDataHex = hex.EncodeToString(userDataSlice)
	}

	var sidStr string
	if sid := er.ExtSid(); sid != nil {
		sidStr, _ = ConvertSidToStringSidGO(sid)
	}

	tsid, hasTsid := er.ExtTerminalSessionID()
	pStartKey, hasPStartKey := er.ExtProcessStartKey()
	evtKey, hasEvtKey := er.ExtEventKey()
	containerID := er.ExtContainerID()
	stackTrace, hasStackTrace := er.ExtStackTrace()
	relatedActivityID := er.ExtRelatedActivityID()

	aux := struct {
		EventHeader          EventHeader                   `json:"EventHeader"`
		CorrectTimeStamp     time.Time                     `json:"TimeStamp"`
		BufferContext        EtwBufferContext              `json:"BufferContext"`
		ExtendedDataCount    uint16                        `json:"ExtendedDataCount"`
		UserDataLength       uint16                        `json:"UserDataLength"`
		ExtendedData         []EventHeaderExtendedDataItem `json:"ExtendedData,omitempty"`
		UserData             string                        `json:"UserData,omitempty"`
		EventID              uint16                        `json:"EventID"`
		IsMof                bool                          `json:"IsMof"`
		ProcessorNumber      uint16                        `json:"ProcessorNumber"`
		RelatedActivityID    string                        `json:"RelatedActivityID"`
		ExtSID               string                        `json:"SID,omitempty"`
		ExtTerminalSessionID *uint32                       `json:"TerminalSessionID,omitempty"`
		ExtProcessStartKey   *uint64                       `json:"ProcessStartKey,omitempty"`
		ExtEventKey          *uint64                       `json:"EventKey,omitempty"`
		ExtContainerID       string                        `json:"ContainerID,omitempty"`
		ExtStackTrace        *EventStackTrace              `json:"StackTrace,omitempty"`
	}{
		EventHeader:       er.EventHeader,
		CorrectTimeStamp:  er.Timestamp(),
		BufferContext:     er.BufferContext,
		ExtendedDataCount: er.ExtendedDataCount,
		UserDataLength:    er.UserDataLength,
		ExtendedData:      extData,
		UserData:          userDataHex,
		EventID:           er.EventID(),
		IsMof:             er.IsMof(),
		ProcessorNumber:   er.ProcessorNumber(),
		RelatedActivityID: (&relatedActivityID).StringU(),
		ExtSID:            sidStr,
	}

	if hasTsid {
		aux.ExtTerminalSessionID = &tsid
	}
	if hasPStartKey {
		aux.ExtProcessStartKey = &pStartKey
	}
	if hasEvtKey {
		aux.ExtEventKey = &evtKey
	}
	if !containerID.IsZero() {
		aux.ExtContainerID = containerID.StringU()
	}
	if hasStackTrace {
		aux.ExtStackTrace = &stackTrace
	}

	return json.Marshal(aux)
}

func (t *TraceEventInfo) MarshalJSON() (b []byte, err error) {
	// Use defer and recover to catch any panics from unsafe memory access.
	defer func() {
		if r := recover(); r != nil {
			// If a panic occurred, return a safe JSON object with the error.
			err = fmt.Errorf("panic recovered while marshaling TraceEventInfo: %v", r)
			b, _ = json.Marshal(map[string]any{
				"error":           "failed to marshal TraceEventInfo due to panic",
				"panic_details":   fmt.Sprintf("%v", r),
				"eventDescriptor": t.EventDescriptor, // EventDescriptor is usually safe to access
			})
		}
	}()

	var properties []JsonEventPropertyInfo
	if t.PropertyCount > 0 {
		properties = make([]JsonEventPropertyInfo, t.PropertyCount)
		for i := uint32(0); i < t.PropertyCount; i++ {
			epi := t.GetEventPropertyInfoAt(i)
			properties[i] = epi.ToJSON(t)
		}
	}

	return json.Marshal(struct {
		ProviderGUID          string                  `json:"ProviderGUID"`
		EventGUID             string                  `json:"EventGUID"`
		EventDescriptor       EventDescriptor         `json:"EventDescriptor"`
		DecodingSource        DecodingSource          `json:"DecodingSource"`
		ProviderName          string                  `json:"ProviderName"`
		LevelName             string                  `json:"LevelName"`
		ChannelName           string                  `json:"ChannelName"`
		KeywordsName          []string                `json:"KeywordsName"`
		TaskName              string                  `json:"TaskName"`
		OpcodeName            string                  `json:"OpcodeName"`
		EventMessage          string                  `json:"EventMessage"`
		ProviderMessage       string                  `json:"ProviderMessage"`
		EventName             string                  `json:"EventName"`
		ActivityIDName        string                  `json:"ActivityIDName"`
		EventAttributes       string                  `json:"EventAttributes"`
		RelatedActivityIDName string                  `json:"RelatedActivityIDName"`
		PropertyCount         uint32                  `json:"PropertyCount"`
		TopLevelPropertyCount uint32                  `json:"TopLevelPropertyCount"`
		Flags                 TemplateFlags           `json:"Flags"`
		Properties            []JsonEventPropertyInfo `json:"Properties,omitempty"`
	}{
		ProviderGUID:          t.ProviderGUID.StringU(),
		EventGUID:             t.EventGUID.StringU(),
		EventDescriptor:       t.EventDescriptor,
		DecodingSource:        t.DecodingSource,
		ProviderName:          t.ProviderName(),
		LevelName:             t.LevelName(),
		ChannelName:           t.ChannelName(),
		KeywordsName:          t.KeywordsName(),
		TaskName:              t.TaskName(),
		OpcodeName:            t.OpcodeName(),
		EventMessage:          t.EventMessage(),
		ProviderMessage:       t.ProviderMessage(),
		EventName:             t.EventName(),
		ActivityIDName:        t.ActivityIDName(),
		EventAttributes:       t.EventAttributes(),
		RelatedActivityIDName: t.RelatedActivityIDName(),
		PropertyCount:         t.PropertyCount,
		TopLevelPropertyCount: t.TopLevelPropertyCount,
		Flags:                 t.Flags,
		Properties:            properties,
	})
}
