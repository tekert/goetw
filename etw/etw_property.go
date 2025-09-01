//go:build windows

package etw

import (
	"encoding/json"
	"fmt"
	"math"
	"syscall"
	"unsafe"
)

type Property struct {
	erh         *EventRecordHelper
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
}

func (p *Property) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}

	var jsonEvtPropInfo any
	if p.evtPropInfo != nil && p.erh != nil && p.erh.TraceInfo != nil {
		jsonEvtPropInfo = p.evtPropInfo.ToJSON(p.erh.TraceInfo)
	} else if p.evtPropInfo != nil {
		// Fallback to marshaling the raw struct if we don't have TraceInfo
		// to resolve names. This is better than nothing.
		jsonEvtPropInfo = p.evtPropInfo
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
		Value:             p.value,
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
	//*p = Property{}
	// This is a performance optimization. Instead of zeroing the entire struct
	// with `*p = Property{}`, we only reset the fields that are critical
	// for correctness when reusing a Property object from the pool.
	//
	// - `value` must be cleared so `FormatToString` knows to parse the property.
	// - `pValue` must be cleared to ensure `Parseable()` returns false initially.
	//   `prepareProperty` will set it to a non-zero value for parseable properties.
	//
	// All other fields are guaranteed to be overwritten in `prepareProperty`.
	p.value = ""
	p.pValue = 0
}

func (p *Property) Parseable() bool {
	return p.erh != nil && p.evtPropInfo != nil && p.pValue > 0
}

// GetInt returns the property value as int64.
// Only if the data is a scalar InType
func (p *Property) GetInt() (int64, error) {
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

// GetUInt returns the property value as uint64.
// Only if the data is a scalar InType
func (p *Property) GetUInt() (uint64, error) {
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

// GetFloat returns the property value as float64
// Only if the data is a float InType
func (p *Property) GetFloat() (float64, error) {
	return p.decodeFloatIntype()
}

// FormatToString formats the property data value to a string representation.
// Uses a Custom parser (improves performance by 30%, fallbacks to tdh on error)
func (p *Property) FormatToString() (string, error) {
	var err error

	if p.value == "" && p.Parseable() {
		// Use tdh if we have map info, else try custom parser first.
		if p.evtPropInfo.MapNameOffset() > 0 {
			p.value, _, err = p.formatToStringTdh() // use tdh for maps
		} else {
			p.value, err = p.decodeToString(p.evtPropInfo.OutType())
			if err != nil {
				conlog.SampledTraceWithErrSig("decodeToString", err).
					Msg("failed to parse property with custom parser")
				// fallback to tdh parser
				p.value, _, err = p.formatToStringTdh()
				// error and p.evtRecordHelper.addPropError() already handled inside.
			}
		}
	}

	return p.value, err
}

// FormatToStringTdh formats the property data value to a string representation.
// Uses TDH functions to parse the property (very slow, uses cgo for each prop)
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
			pMapName := (*uint16)(unsafe.Pointer(p.erh.TraceInfo.pointerOffset(uintptr(p.evtPropInfo.MapNameOffset()))))
			decSrc := p.erh.TraceInfo.DecodingSource
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
				p.erh.TraceInfo,
				pMapInfo,
				p.erh.EventRec.PointerSize(),
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
		if p.erh.TraceInfo.IsMof() {
			if value = p.fixMOFProp(); value != "" {
				err = nil
				return
			}
		}

		conlog.Debug().Interface("property", p).
			Interface("traceInfo", p.erh.TraceInfo).
			Bool("isMof", p.erh.TraceInfo.IsMof()).
			Bool("isXML", p.erh.TraceInfo.IsXML()).
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
		if p.erh.TraceInfo.EventGUID.Equals(gFixTcpIpGuid) {
			// most likely a pointer to a uint32 connid;
			return fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(p.pValue)))
			// "connid" is always 0 for some reason, the same with "seqnum" prop
		}
	}
	return ""
}
