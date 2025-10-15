//go:build windows

package etw

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"syscall"
	"unsafe"
)

type Property struct {
	erh         *EventRecordHelper
	traceInfo   *TraceEventInfo
	evtPropInfo *EventPropertyInfo

	name  string
	value string

	// Size of the property, in bytes.
	// Note that variable-sized types such as strings and binary data
	// have a length of zero unless the property has length attribute
	// to explicitly indicate its real length. Structures have a length of zero.
	//
	// NOTE: For tdh to work this field has to be 0 on those cases.
	// For the actual size when length is 0 refer to [sizeBytes].
	length uint16

	// Size of the property in bytes (will always have the real size)
	sizeBytes uint32

	// Pointer to the blob of unparsed data inside UserData.
	pValue uintptr

	// Distance in bytes between this prop pointer and the end of UserData.
	userDataRemaining uint16

	pointerSize uint32 // 4 or 8
}

func (p *Property) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}

	var jsonEvtPropInfo any
	if p.evtPropInfo != nil && p.erh != nil && p.traceInfo != nil {
		jsonEvtPropInfo = p.evtPropInfo.ToJSON(p.traceInfo)
	} else if p.evtPropInfo != nil {
		// Fallback to marshaling the raw struct if we don't have TraceInfo
		// to resolve names. This is better than nothing.
		jsonEvtPropInfo = p.evtPropInfo
	}

	// Ensure the string value is populated for JSON marshaling.
	valueStr := p.value
	if valueStr == "" && p.Parseable() {
		valueStr, _ = p.ToString()
	}

	return json.Marshal(struct {
		Name              string `json:"Name"`
		Value             string `json:"Value,omitempty"`
		Length            uint16 `json:"Length"`
		SizeBytes         uint32 `json:"SizeBytes"`
		UserDataRemaining uint16 `json:"UserDataRemainingBytes"`
		PValue            string `json:"PValue"`
		EventPropertyInfo any    `json:"EventPropertyInfo,omitempty"`
	}{
		Name:              p.name,
		Value:             valueStr,
		Length:            p.length,
		SizeBytes:         p.sizeBytes,
		UserDataRemaining: p.userDataRemaining,
		PValue:            fmt.Sprintf("0x%x", p.pValue),
		EventPropertyInfo: jsonEvtPropInfo,
	})
}

// The global propertyPool is no longer used. Properties are now managed in
// blocks by the EventRecordHelper for much higher performance.

// Sets all fields of the struct to zero/empty values.
// This is called by the helper before a property is reused.
func (p *Property) reset() {
	//*p = Property{} // this is expensive, 5-6% performance drop.

	// This is a targeted reset. Fields like erh, traceInfo, pointerSize,
	// evtPropInfo, name, pValue, and userDataRemaining are guaranteed to be
	// overwritten in newProperty() and prepareProperty(). We only need to
	// clear the fields that hold calculated results.
	p.length = 0
	p.sizeBytes = 0
	p.value = ""
}

func (p *Property) Parseable() bool {
	return p.erh != nil && p.evtPropInfo != nil && p.pValue > 0
}

// ToInt returns the property value as int64.
// Filetime intypes are returned as int64 nanoseconds.
// Only if the data is a scalar InType
func (p *Property) ToInt() (int64, error) {
	if !p.Parseable() {
		return 0, fmt.Errorf("property not parseable")
	}
	v, signed, err := p.decodeScalarIntype()
	if err != nil {
		return 0, err
	}
	if signed {
		return int64(v), nil
	}
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("unsigned value %d overflows int64", v)
	}
	return int64(v), nil
}

// ToUInt returns the property value as uint64.
// Filetime intypes are returned as uint64 nanoseconds.
// Only if the data is a scalar InType
func (p *Property) ToUInt() (uint64, error) {
	if !p.Parseable() {
		return 0, fmt.Errorf("property not parseable")
	}
	v, signed, err := p.decodeScalarIntype()
	if err != nil {
		return 0, err
	}
	if !signed {
		return v, nil
	}
	if int64(v) < 0 {
		return 0, fmt.Errorf("negative value %d cannot be converted to uint64", int64(v))
	}
	return v, nil
}

// ToFloat returns the property value as float64
// Only if the data is a float InType
func (p *Property) ToFloat() (float64, error) {
	if !p.Parseable() {
		return 0, fmt.Errorf("property not parseable")
	}
	return p.decodeFloatIntype()
}

// ToGUID returns the property value as a pointer to GUID (live data)
// This is mostly used for comparing GUIDs so that's why we return a pointer.
// Only if the data is a GUID InType
func (p *Property) ToGUID() (*GUID, error) {
	if !p.Parseable() {
		return nil, fmt.Errorf("property not parseable")
	}
	return p.decodeGUIDIntype()
}

// AppendText appends the textual representation of the property to the end of b
// and returns the updated slice. It is a zero-allocation method.
// The appended data is only valid for the lifecycle of the buffer.
func (p *Property) AppendText(buf []byte) ([]byte, error) {
	if !p.Parseable() {
		return buf, fmt.Errorf("property not parseable")
	}

	// For properties with value maps, we MUST use the TDH-based formatter.
	if p.evtPropInfo.MapNameOffset() > 0 {
		val, _, err := p.formatToStringTdh()
		if err != nil {
			return buf, err
		}
		return append(buf, val...), nil
	}

	// For all other properties, try the high-performance internal appender first.
	res, err := p.decodeToString(buf)
	if err == nil {
		return res, nil
	}

	// On failure, fallback to the TDH-based formatter.
	conlog.SampledTraceWithErrSig("decodeToString", err).
		Msg("failed to parse property with custom parser, falling back to TDH")
	val, _, err := p.formatToStringTdh()
	if err != nil {
		return buf, err
	}
	return append(buf, val...), nil
}

// AppendToJSON appends the JSON representation of the property to the end of b
// and returns the updated slice. It is a zero-allocation method that handles
// JSON-specific formatting like quoting strings.
func (p *Property) AppendToJSON(buf []byte) ([]byte, error) {
	if !p.Parseable() {
		return buf, fmt.Errorf("property not parseable")
	}

	// For properties with value maps, we MUST use the TDH-based formatter.
	// The result of a map is always a string, so it must be quoted.
	if p.evtPropInfo.MapNameOffset() > 0 {
		val, _, err := p.formatToStringTdh()
		if err != nil {
			return buf, err
		}
		return strconv.AppendQuote(buf, val), nil
	}

	// For all other properties, try the high-performance internal JSON appender first.
	res, err := p.decodeToJSON(buf)
	if err == nil {
		return res, nil
	}

	// On failure, fallback to the TDH-based formatter and quote the result.
	conlog.SampledTraceWithErrSig("decodeToJSON", err).
		Msg("failed to parse property with custom JSON parser, falling back to TDH")
	val, _, err := p.formatToStringTdh()
	if err != nil {
		return buf, err
	}
	return strconv.AppendQuote(buf, val), nil
}

// ToString formats the property to a string.
// This method is a convenient, safe wrapper around AppendText. It allocates a new
// string for the result, making it safe to store. For performance-critical paths,
// use AppendText with a reusable buffer.
func (p *Property) ToString() (string, error) {
	if p.value != "" {
		return p.value, nil
	}
	if !p.Parseable() {
		return "", nil
	}

	// Use the helper's reusable buffer for the temporary formatting.
	start := len(p.erh.storage.dataBuffer)
	buf, err := p.AppendText(p.erh.storage.dataBuffer)
	if err != nil {
		// On error, rewind the buffer to its original state.
		p.erh.storage.dataBuffer = p.erh.storage.dataBuffer[:start]
		return "", err
	}

	// Create a safe, independent copy of the formatted string for the user.
	appended := buf[start:]
	p.value = string(appended) // Cache the safe copy.

	// Rewind the reusable buffer so it can be used by the next property.
	p.erh.storage.dataBuffer = p.erh.storage.dataBuffer[:start]

	return p.value, nil
}

// FormatToString is deprecated. Use ToString() for a safe string copy, or
// AppendText() for a high-performance, zero-allocation append to a buffer.
//
// Deprecated: This method will be removed in a future version.
func (p *Property) FormatToString() (string, error) {
	return p.ToString()

	// var err error

	// if p.value == "" && p.Parseable() {
	// 	// Use tdh if we have map info, else try custom parser first.
	// 	if p.evtPropInfo.MapNameOffset() > 0 {
	// 		p.value, _, err = p.formatToStringTdh() // use tdh for maps
	// 	} else {
	// 		var buf []byte
	// 		buf, err = p.decodeToString(buf)
	// 		if err == nil {
	// 			p.value = string(buf)
	// 		} else {
	// 			conlog.SampledTraceWithErrSig("decodeToString", err).
	// 				Msg("failed to parse property with custom parser")
	// 			// fallback to tdh parser
	// 			p.value, _, err = p.formatToStringTdh()
	// 			// error and p.evtRecordHelper.addPropError() already handled inside.
	// 		}
	// 	}
	// }

	// return p.value, err
}

// FormatToStringTdh formats the property data value to a string representation.
// Uses TDH functions to parse the property (very slow, uses cgo for each prop)
//
// Deprecated: This method will be made private in a future version.
func (p *Property) FormatToStringTdh() (string, error) {
	var err error

	if p.value == "" && p.Parseable() {
		// we parse only if not already done
		p.value, _, err = p.formatToStringTdh()
	}

	return p.value, err
}

// formatToStringTdh converts the pValue pointer to to a string using tdh (slow on golang).
// used as fallback when the custom decoder fails.
// Returns: (parsed string, User Data consumed, error)
func (p *Property) formatToStringTdh() (value string, udc uint16, err error) {
	var pMapInfo *EventMapInfo

	// Get the name/value mapping if the property specifies a value map.
	if p.evtPropInfo.MapNameOffset() > 0 {
		switch p.evtPropInfo.InType() {
		case TDH_INTYPE_UINT8,
			TDH_INTYPE_UINT16,
			TDH_INTYPE_UINT32,
			TDH_INTYPE_HEXINT32:
			pMapName := (*uint16)(unsafe.Pointer(p.traceInfo.pointerOffset(uintptr(p.evtPropInfo.MapNameOffset()))))
			decSrc := p.traceInfo.DecodingSource
			var mapInfoBuffer *EventMapInfoBuffer
			mapInfoBuffer, err = p.erh.EventRec.GetMapInfo(pMapName, uint32(decSrc))
			if mapInfoBuffer != nil {
				defer mapInfoBuffer.Release()
			}
			if err != nil {
				err = fmt.Errorf("failed to get map info: %s", err)
				return
			}
			pMapInfo = mapInfoBuffer.pMapInfo
		}
	}

	buffPtr := tdhBufferPool.Get().(*[]uint16)
	defer tdhBufferPool.Put(buffPtr)
	(*buffPtr)[0] = 0
	buffSize := uint32(cap(*buffPtr))

	for {
		if p.length == 0 && p.evtPropInfo.InType() == TDH_INTYPE_NULL {
			// TdhFormatProperty doesn't handle INTYPE_NULL.
			(*buffPtr)[0] = 0
			p.erh.addPropError()
			err = nil
		} else if p.length == 0 &&
			(p.evtPropInfo.Flags&(PropertyParamLength|PropertyParamFixedLength)) != 0 &&
			(p.evtPropInfo.InType() == TDH_INTYPE_UNICODESTRING ||
				p.evtPropInfo.InType() == TDH_INTYPE_ANSISTRING) {
			// TdhFormatProperty doesn't handle zero-length counted strings.
			(*buffPtr)[0] = 0
			p.erh.addPropError()
			err = nil
		} else {
			err = TdhFormatProperty(
				p.traceInfo,
				pMapInfo,
				p.pointerSize,
				uint16(p.evtPropInfo.InType()),
				uint16(p.evtPropInfo.OutType()),
				p.length,
				p.userDataRemaining,
				(*byte)(unsafe.Pointer(p.pValue)),
				&buffSize,
				&(*buffPtr)[0],
				&udc)
		}

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			// Increase buffer size and try again, discard old buffer
			*buffPtr = make([]uint16, buffSize)
			continue
		}

		if err == ERROR_EVT_INVALID_EVENT_DATA {
			if pMapInfo == nil {
				break
			}
			pMapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		// ERROR_BUFFER_OVERFLOW most likely

		// If TdhFormatProperty failed and this is a MOF property, try to format it as a string.
		// We have to manually check wich props fail with TDH functions and try to parse them manually.
		//
		// This happens when TdhGetProperty/TdhGetPropertySize error with ERROR_EVT_INVALID_EVENT_DATA:
		// "The event data raised by the publisher is not compatible with the event template
		// definition in the publisher's manifest.
		// Seems some kernel properties can't be parsed with Tdh, maybe is a pointer to kernel memory?
		// UPDATE: the MOF classes types are wrong, this is not usuable for kernel events.
		// TODO: remove this now that we have MOF parsing in the custom parser?
		if p.traceInfo.IsMof() {
			if value = p.fixMOFProp(); value != "" {
				err = nil
				return
			}
		}

		conlog.Debug().Interface("property", p).
			Interface("traceInfo", p.traceInfo).
			Bool("isMof", p.traceInfo.IsMof()).
			Bool("isXML", p.traceInfo.IsXML()).
			Msg("failed to format property using thd")

		p.erh.addPropError()
		perr := fmt.Errorf("%w: tdh toString failed: %v", ErrPropertyParsingTdh, err)
		err = &ParseError{p: p, Err: perr}
		return "", udc, err

	}

	value = FromUTF16Slice(*buffPtr)

	return
}

// "TcpIp" or "UdpIp" /*9a280ac0-c8e0-11d1-84e2-00c04fb998a2*/
var gFixTcpIpGuid = MustParseGUID("9a280ac0-c8e0-11d1-84e2-00c04fb998a2")

// temporary measures to handle legacy MOF events (Kernel events)
// UPDATE: connid is always 0 for users, only the kernel knows.
// https://stackoverflow.com/questions/48844533/etw-connid-in-network-events-always-zero/79351348#79351348
func (p *Property) fixMOFProp() string {
	if p.evtPropInfo.InType() == TDH_INTYPE_POINTER {
		// "TcpIp" or "UdpIp"
		if p.traceInfo.EventGUID.Equals(gFixTcpIpGuid) {
			// most likely a pointer to a uint32 connid;
			return fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(p.pValue)))
			// "connid" is always 0 for some reason, the same with "seqnum" prop
		}
	}
	return ""
}
