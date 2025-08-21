//go:build windows

package etw

// Custom Parser that mimics the TdhFormatProperty function from the Windows API
// Improves performance by 30% or more when called from go, (cgo is slow)
// if this fails, the Tdh is used internally.

// Very useful link:
// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers#property-qualifiers

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/tekert/goetw/internal/hexf"
)

// decodeToString attempts to parse the property value based on OutType.
// If OutType is not set, it will infer OutType from InType.
// Call [FormatToString] to use this func.
func (p *Property) decodeToString(outType TdhOutType) (string, error) {
	if !p.Parseable() {
		return "", fmt.Errorf("property not parseable")
	}

	inType := p.evtPropInfo.InType()

	switch outType {
	case TDH_OUTTYPE_STRING:
		switch inType {
		case TDH_INTYPE_INT8, TDH_INTYPE_UINT8, TDH_INTYPE_ANSICHAR:
			// Single ANSI character
			b := *(*uint8)(unsafe.Pointer(p.pValue))
			return string(rune(b)), nil

		case TDH_INTYPE_UINT16, TDH_INTYPE_UNICODECHAR:
			// Single UTF-16 character
			w := *(*uint16)(unsafe.Pointer(p.pValue))
			return string(rune(w)), nil

		case TDH_INTYPE_SID, TDH_INTYPE_WBEMSID:
			sidStr, err := p.decodeSIDIntype()
			return sidStr, err

		case TDH_INTYPE_UNICODESTRING,
			TDH_INTYPE_ANSISTRING,
			TDH_INTYPE_COUNTEDSTRING,
			TDH_INTYPE_REVERSEDCOUNTEDSTRING,
			TDH_INTYPE_NONNULLTERMINATEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_COUNTEDANSISTRING,
			TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
			return p.decodeStringIntype()

		default:
			return "", fmt.Errorf("invalid string InType: %v", inType)
		}

	case TDH_OUTTYPE_PID, TDH_OUTTYPE_TID:
		if inType != TDH_INTYPE_UINT32 {
			return "", fmt.Errorf("invalid PID/TID InType: %v", inType)
		}
		v := *(*uint32)(unsafe.Pointer(p.pValue))
		return strconv.FormatUint(uint64(v), 10), nil

	case TDH_OUTTYPE_BYTE:
		if inType != TDH_INTYPE_INT8 {
			return "", fmt.Errorf("invalid BYTE InType: %v", inType)
		}
		v := *(*int8)(unsafe.Pointer(p.pValue))
		return strconv.FormatInt(int64(v), 10), nil

	case TDH_OUTTYPE_UNSIGNEDBYTE:
		if inType != TDH_INTYPE_UINT8 {
			return "", fmt.Errorf("invalid UNSIGNEDBYTE InType: %v", inType)
		}
		v := *(*uint8)(unsafe.Pointer(p.pValue))
		return strconv.FormatUint(uint64(v), 10), nil

	case TDH_OUTTYPE_SHORT:
		if inType != TDH_INTYPE_INT16 {
			return "", fmt.Errorf("invalid SHORT InType: %v", inType)
		}
		v := *(*int16)(unsafe.Pointer(p.pValue))
		return strconv.FormatInt(int64(v), 10), nil

	case TDH_OUTTYPE_UNSIGNEDSHORT:
		if inType != TDH_INTYPE_UINT16 {
			return "", fmt.Errorf("invalid UNSIGNEDSHORT InType: %v", inType)
		}
		v := *(*uint16)(unsafe.Pointer(p.pValue))
		return strconv.FormatUint(uint64(v), 10), nil

	case TDH_OUTTYPE_INT:
		if inType != TDH_INTYPE_INT32 {
			return "", fmt.Errorf("invalid INT InType: %v", inType)
		}
		v := *(*int32)(unsafe.Pointer(p.pValue))
		return strconv.FormatInt(int64(v), 10), nil

	case TDH_OUTTYPE_UNSIGNEDINT:
		if inType != TDH_INTYPE_UINT32 {
			return "", fmt.Errorf("invalid UNSIGNEDINT InType: %v", inType)
		}
		v := *(*uint32)(unsafe.Pointer(p.pValue))
		return strconv.FormatUint(uint64(v), 10), nil

	case TDH_OUTTYPE_LONG:
		if inType != TDH_INTYPE_INT64 &&
			inType != TDH_INTYPE_POINTER &&
			inType != TDH_INTYPE_INT32 {
			return "", fmt.Errorf("invalid LONG InType: %v", inType)
		}
		v := *(*int64)(unsafe.Pointer(p.pValue))
		return strconv.FormatInt(v, 10), nil

	case TDH_OUTTYPE_UNSIGNEDLONG:
		if inType != TDH_INTYPE_UINT64 &&
			inType != TDH_INTYPE_POINTER &&
			inType != TDH_INTYPE_UINT32 {
			return "", fmt.Errorf("invalid UNSIGNEDLONG InType: %v", inType)
		}
		v := *(*uint64)(unsafe.Pointer(p.pValue))
		return strconv.FormatUint(v, 10), nil

	case TDH_OUTTYPE_FLOAT:
		if inType != TDH_INTYPE_FLOAT {
			return "", fmt.Errorf("invalid FLOAT InType: %v", inType)
		}
		v := *(*float32)(unsafe.Pointer(p.pValue))
		return strconv.FormatFloat(float64(v), 'g', -1, 32), nil

	case TDH_OUTTYPE_DOUBLE:
		if inType != TDH_INTYPE_DOUBLE {
			return "", fmt.Errorf("invalid DOUBLE InType: %v", inType)
		}
		v := *(*float64)(unsafe.Pointer(p.pValue))
		return strconv.FormatFloat(v, 'g', -1, 64), nil

	case TDH_OUTTYPE_BOOLEAN:
		if inType != TDH_INTYPE_BOOLEAN &&
			inType != TDH_INTYPE_UINT8 {
			return "", fmt.Errorf("invalid BOOLEAN InType: %v", inType)
		}
		v := *(*int32)(unsafe.Pointer(p.pValue)) // ETW boolean is 4 bytes
		if v != 0 {
			return "true", nil
		}
		return "false", nil

	case TDH_OUTTYPE_IPV4:
		// IPV4 uses uint32 as InType (4 bytes)
		if inType != TDH_INTYPE_UINT32 {
			return "", fmt.Errorf("invalid IPv4 InType: %v", inType)
		}
		//v := *(*uint32)(unsafe.Pointer(p.pValue))
		//ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))

		// ETW stores IPv4 addresses as uint32 in network byte order (big-endian)
		ip := net.IP(unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), 4))
		return ip.String(), nil

	case TDH_OUTTYPE_IPV6:
		// Update to include all BINARY types
		switch inType {
		case TDH_INTYPE_BINARY,
			TDH_INTYPE_MANIFEST_COUNTEDBINARY:
			if p.length != 16 {
				return "", fmt.Errorf("invalid IPv6 address length: %d", p.length)
			}
			ip := net.IP(unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), 16))
			return ip.String(), nil
		default:
			return "", fmt.Errorf("invalid IPv6 InType: %v", inType)
		}

	case TDH_OUTTYPE_PORT:
		// Port uses UINT16 as InType
		if inType != TDH_INTYPE_UINT16 {
			return "", fmt.Errorf("invalid Port InType: %v", inType)
		}
		port := *(*uint16)(unsafe.Pointer(p.pValue))
		port = Swap16(port) // Convert from network byte order
		return strconv.FormatUint(uint64(port), 10), nil

	case TDH_OUTTYPE_SOCKETADDRESS:
		switch inType {
		case TDH_INTYPE_BINARY,
			TDH_INTYPE_MANIFEST_COUNTEDBINARY:
			sockaddr := (*syscall.RawSockaddrAny)(unsafe.Pointer(p.pValue))
			return formatSockAddr(sockaddr)
		default:
			return "", fmt.Errorf("invalid SocketAddress InType: %v", inType)
		}

	case TDH_OUTTYPE_HEXBINARY:
		switch inType {
		case TDH_INTYPE_BINARY,
			TDH_INTYPE_HEXDUMP,
			TDH_INTYPE_MANIFEST_COUNTEDBINARY:
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.length)
			return hexf.EncodeToStringUPrefix(bytes), nil
		default:
			return "", fmt.Errorf("invalid HEXBINARY InType: %v", inType)
		}

	case TDH_OUTTYPE_HEXINT8:
		if inType != TDH_INTYPE_UINT8 {
			return "", fmt.Errorf("invalid HEXINT8 InType: %v", inType)
		}
		v := *(*uint8)(unsafe.Pointer(p.pValue))
		return hexf.NUm8p(v, true), nil

	case TDH_OUTTYPE_HEXINT16:
		if inType != TDH_INTYPE_UINT16 {
			return "", fmt.Errorf("invalid HEXINT16 InType: %v", inType)
		}
		v := *(*uint16)(unsafe.Pointer(p.pValue))
		return hexf.NUm16p(v, true), nil

	case TDH_OUTTYPE_HEXINT32:
		if inType != TDH_INTYPE_UINT32 &&
			inType != TDH_INTYPE_HEXINT32 {
			return "", fmt.Errorf("invalid HEXINT32 InType: %v", inType)
		}
		v := *(*uint32)(unsafe.Pointer(p.pValue))
		return hexf.NUm32p(v, true), nil

	case TDH_OUTTYPE_HEXINT64:
		if inType != TDH_INTYPE_UINT64 &&
			inType != TDH_INTYPE_HEXINT64 &&
			inType != TDH_INTYPE_POINTER {
			return "", fmt.Errorf("invalid HEXINT64 InType: %v", inType)
		}
		v := *(*uint64)(unsafe.Pointer(p.pValue))
		return hexf.NUm64p(v, true), nil

	case TDH_OUTTYPE_GUID:
		if inType != TDH_INTYPE_GUID {
			return "", fmt.Errorf("invalid GUID InType: %v", inType)
		}
		guid := (*GUID)(unsafe.Pointer(p.pValue))
		return guid.String(), nil

	case TDH_OUTTYPE_DATETIME,
		TDH_OUTTYPE_DATETIME_UTC,
		TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME:
		switch inType {
		//case TDH_INTYPE_UINT64: // (WmiTime)
			// This is in different formats depending on Session WnodeHeader.ClientContext settings
			// IF ClientContext is 0: WmiTime object = FILETIME
			// TODO: if we can read ClientContext from the session, what do we do?
		case TDH_INTYPE_FILETIME:
			ft := (*syscall.Filetime)(unsafe.Pointer(p.pValue))
			t := time.Unix(0, ft.Nanoseconds())

			// Handle timezone based on OutType
			switch p.evtPropInfo.OutType() {
			case TDH_OUTTYPE_DATETIME_UTC,
				TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME:
				t = t.UTC()
			case TDH_OUTTYPE_DATETIME:
				// For FILETIME, default to UTC as per docs recommendation
				t = t.UTC()
			}
			// Use RFC3339 for culture-insensitive format
			return t.Format(time.RFC3339), nil

		case TDH_INTYPE_SYSTEMTIME:
			st := (*syscall.Systemtime)(unsafe.Pointer(p.pValue))
			// Handle timezone based on OutType
			tz := time.UTC // Default to UTC for DATETIME_UTC and CULTURE_INSENSITIVE
			if p.evtPropInfo.OutType() == TDH_OUTTYPE_DATETIME {
				tz = time.Local
			}
			t := time.Date(int(st.Year), time.Month(st.Month), int(st.Day),
				int(st.Hour), int(st.Minute), int(st.Second),
				int(st.Milliseconds)*1e6, tz)

			return t.Format(time.RFC3339), nil

		default:
			return "", fmt.Errorf("invalid datetime InType: %v", inType)
		}

	case TDH_OUTTYPE_XML, TDH_OUTTYPE_JSON:
		switch inType {
		case TDH_INTYPE_UNICODESTRING,
			TDH_INTYPE_ANSISTRING,
			TDH_INTYPE_COUNTEDSTRING,
			TDH_INTYPE_REVERSEDCOUNTEDSTRING,
			TDH_INTYPE_NONNULLTERMINATEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_COUNTEDANSISTRING,
			TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
			return p.decodeStringIntype()
		default:
			return "", fmt.Errorf("invalid XML/JSON InType: %v", inType)
		}

	case TDH_OUTTYPE_UTF8:
		switch inType {
		case TDH_INTYPE_ANSISTRING,
			TDH_INTYPE_COUNTEDANSISTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
			return p.decodeStringIntype()
		default:
			return "", fmt.Errorf("invalid UTF8 InType: %v", inType)
		}

	case TDH_OUTTYPE_PKCS7_WITH_TYPE_INFO:
		switch inType {
		case TDH_INTYPE_BINARY,
			TDH_INTYPE_MANIFEST_COUNTEDBINARY:
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.length)
			return hexf.EncodeToStringUPrefix(bytes), nil
		default:
			return "", fmt.Errorf("invalid PKCS7 InType: %v", inType)
		}

	case TDH_OUTTYPE_CODE_POINTER:
		switch inType {
		case TDH_INTYPE_UINT32,
			TDH_INTYPE_UINT64,
			TDH_INTYPE_HEXINT32,
			TDH_INTYPE_HEXINT64,
			TDH_INTYPE_POINTER:
			v, err := p.GetUInt()
			if err != nil {
				return "", err
			}
			return hexf.NUm64p(v, false), nil
		default:
			return "", fmt.Errorf("invalid CODE_POINTER InType: %v", inType)
		}

	case TDH_OUTTYPE_WIN32ERROR, TDH_OUTTYPE_NTSTATUS:
		if inType != TDH_INTYPE_UINT32 &&
			inType != TDH_INTYPE_HEXINT32 {
			return "", fmt.Errorf("invalid error code InType: %v", inType)
		}
		v, err := p.GetUInt() // uint32
		if err != nil {
			return "", err
		}
		return hexf.NUm32p(uint32(v), false), nil

	case TDH_OUTTYPE_HRESULT:
		if inType != TDH_INTYPE_INT32 {
			return "", fmt.Errorf("invalid HRESULT InType: %v", inType)
		}
		v, err := p.GetInt() // int32
		if err != nil {
			return "", err
		}
		return hexf.NUm32p(int32(v), false), nil

	case TDH_OUTTYPE_ERRORCODE:
		if inType != TDH_INTYPE_UINT32 {
			return "", fmt.Errorf("invalid ERRORCODE InType: %v", inType)
		}
		v := *(*uint32)(unsafe.Pointer(p.pValue))
		return hexf.NUm32p(v, false), nil

	case TDH_OUTTYPE_NOPRINT:
		// Return empty string for NOPRINT as spec indicates field should not be shown
		return "", nil

	// TODO: CIMDATETIME and ETWTIME are rarely used and can fallback to default handling

	// Default OutType mappings when OutType is NULL:
	// Reference: Windows Event Tracing API tdh.h
	case TDH_OUTTYPE_NULL:
		// Get InType and map to default OutType
		switch inType {
		// String Types -> TDH_OUTTYPE_STRING:
		//   - TDH_INTYPE_UNICODESTRING
		//   - TDH_INTYPE_ANSISTRING
		//   - TDH_INTYPE_COUNTEDSTRING
		//   - TDH_INTYPE_REVERSEDCOUNTEDSTRING
		//   - TDH_INTYPE_NONNULLTERMINATEDSTRING
		//   - TDH_INTYPE_MANIFEST_COUNTEDSTRING
		//   - TDH_INTYPE_MANIFEST_COUNTEDANSISTRING
		//   - TDH_INTYPE_COUNTEDANSISTRING
		//   - TDH_INTYPE_NONNULLTERMINATEDANSISTRING
		case TDH_INTYPE_UNICODESTRING,
			TDH_INTYPE_ANSISTRING,
			TDH_INTYPE_COUNTEDSTRING,
			TDH_INTYPE_REVERSEDCOUNTEDSTRING,
			TDH_INTYPE_NONNULLTERMINATEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_COUNTEDANSISTRING,
			TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
			return p.decodeToString(TDH_OUTTYPE_STRING)

		// Character Types -> TDH_OUTTYPE_STRING:
		//   - TDH_INTYPE_UNICODECHAR
		//   - TDH_INTYPE_ANSICHAR
		case TDH_INTYPE_UNICODECHAR, TDH_INTYPE_ANSICHAR:
			return p.decodeToString(TDH_OUTTYPE_STRING)

		// Integer Types:
		//   - TDH_INTYPE_INT8 -> TDH_OUTTYPE_BYTE
		//   - TDH_INTYPE_UINT8 -> TDH_OUTTYPE_UNSIGNEDBYTE
		//   - TDH_INTYPE_INT16 -> TDH_OUTTYPE_SHORT
		//   - TDH_INTYPE_UINT16 -> TDH_OUTTYPE_UNSIGNEDSHORT
		//   - TDH_INTYPE_INT32 -> TDH_OUTTYPE_INT
		//   - TDH_INTYPE_UINT32 -> TDH_OUTTYPE_UNSIGNEDINT
		//   - TDH_INTYPE_INT64 -> TDH_OUTTYPE_LONG
		//   - TDH_INTYPE_UINT64 -> TDH_OUTTYPE_UNSIGNEDLONG
		case TDH_INTYPE_INT8:
			return p.decodeToString(TDH_OUTTYPE_BYTE)
		case TDH_INTYPE_UINT8:
			return p.decodeToString(TDH_OUTTYPE_UNSIGNEDBYTE)
		case TDH_INTYPE_INT16:
			return p.decodeToString(TDH_OUTTYPE_SHORT)
		case TDH_INTYPE_UINT16:
			return p.decodeToString(TDH_OUTTYPE_UNSIGNEDSHORT)
		case TDH_INTYPE_INT32:
			return p.decodeToString(TDH_OUTTYPE_INT)
		case TDH_INTYPE_UINT32:
			return p.decodeToString(TDH_OUTTYPE_UNSIGNEDINT)
		case TDH_INTYPE_INT64:
			return p.decodeToString(TDH_OUTTYPE_LONG)
		case TDH_INTYPE_UINT64:
			return p.decodeToString(TDH_OUTTYPE_UNSIGNEDLONG)

		// Float Types:
		//   - TDH_INTYPE_FLOAT -> TDH_OUTTYPE_FLOAT
		//   - TDH_INTYPE_DOUBLE -> TDH_OUTTYPE_DOUBLE
		case TDH_INTYPE_FLOAT:
			return p.decodeToString(TDH_OUTTYPE_FLOAT)
		case TDH_INTYPE_DOUBLE:
			return p.decodeToString(TDH_OUTTYPE_DOUBLE)

		// Binary Types -> TDH_OUTTYPE_HEXBINARY:
		//   - TDH_INTYPE_BINARY
		//   - TDH_INTYPE_HEXDUMP
		//   - TDH_INTYPE_MANIFEST_COUNTEDBINARY
		case TDH_INTYPE_BINARY, TDH_INTYPE_HEXDUMP, TDH_INTYPE_MANIFEST_COUNTEDBINARY:
			return p.decodeToString(TDH_OUTTYPE_HEXBINARY)

		// Special Types:
		//   - TDH_INTYPE_BOOLEAN -> TDH_OUTTYPE_BOOLEAN
		//   - TDH_INTYPE_GUID -> TDH_OUTTYPE_GUID
		//   - TDH_INTYPE_POINTER -> TDH_OUTTYPE_HEXINT32/64 (arch dependent)
		//   - TDH_INTYPE_FILETIME -> TDH_OUTTYPE_DATETIME
		//   - TDH_INTYPE_SYSTEMTIME -> TDH_OUTTYPE_DATETIME
		//   - TDH_INTYPE_SID -> TDH_OUTTYPE_STRING
		//   - TDH_INTYPE_WBEMSID -> TDH_OUTTYPE_STRING
		//   - TDH_INTYPE_HEXINT32 -> TDH_OUTTYPE_HEXINT32
		//   - TDH_INTYPE_HEXINT64 -> TDH_OUTTYPE_HEXINT64
		//   - TDH_INTYPE_SIZET -> TDH_OUTTYPE_HEXINT64
		case TDH_INTYPE_BOOLEAN:
			return p.decodeToString(TDH_OUTTYPE_BOOLEAN)
		case TDH_INTYPE_GUID:
			return p.decodeToString(TDH_OUTTYPE_GUID)
		case TDH_INTYPE_POINTER:
			//* Handle special MOF case
			if p.erh.TraceInfo.IsMof() {
				if t, ok := MofClassMapping[p.erh.TraceInfo.EventGUID.Data1]; ok {
					// "TcpIp" or "UdpIp" /*9a280ac0-c8e0-11d1-84e2-00c04fb998a2*/
					if t.BaseId == 4845 || t.BaseId == 5865 {
						// most likely a pointer to a uint32 connid;
						v := *(*uint32)(unsafe.Pointer(p.pValue))
						return strconv.FormatUint(uint64(v), 10), nil
					}
				}
			}
			if p.erh.EventRec.PointerSize() == 8 {
				return p.decodeToString(TDH_OUTTYPE_HEXINT64)
			} else {
				return p.decodeToString(TDH_OUTTYPE_HEXINT32)
			}
		case TDH_INTYPE_FILETIME, TDH_INTYPE_SYSTEMTIME:
			return p.decodeToString(TDH_OUTTYPE_DATETIME)
		case TDH_INTYPE_SID, TDH_INTYPE_WBEMSID:
			return p.decodeToString(TDH_OUTTYPE_STRING)
		case TDH_INTYPE_HEXINT32:
			return p.decodeToString(TDH_OUTTYPE_HEXINT32)
		case TDH_INTYPE_HEXINT64,
			TDH_INTYPE_SIZET:
			return p.decodeToString(TDH_OUTTYPE_HEXINT64)

		// NULL
		case TDH_INTYPE_NULL:
			return "", fmt.Errorf("null InType")
		}
	}

	// Default to Parse_WithTdh parsing for unhandled OutTypes
	return "", fmt.Errorf("unsupported OutType, Using TDH as Fallback: %v", outType)
}

// Fast helper to convert bigendian network data to little endian
func Swap16(n uint16) uint16 {
	return (n << 8) | (n >> 8)
}

// Helper to format socket address
func formatSockAddr(sa *syscall.RawSockaddrAny) (string, error) {
	// Convert RawSockaddrAny to actual address
	switch sa.Addr.Family {
	case syscall.AF_INET:
		addr4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		ip := net.IP(addr4.Addr[:])
		port := Swap16(addr4.Port)
		return ip.String() + ":" + strconv.Itoa(int(port)), nil

	case syscall.AF_INET6:
		addr6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		ip := net.IP(addr6.Addr[:])
		port := Swap16(addr6.Port)
		return "[" + ip.String() + "]:" + strconv.Itoa(int(port)), nil

	default:
		return "", fmt.Errorf("unsupported address family: %d", sa.Addr.Family)
	}
}

// Parses the property value to a string based on the property's InType and OutType
func (p *Property) decodeSIDIntype() (string, error) {
	if !p.Parseable() {
		return "", fmt.Errorf("property not parseable")
	}

	// Add validation for minimum SID size (8 bytes header)
	if int(p.userDataRemaining) < 8 {
		return "", fmt.Errorf("invalid SID: data too small for header")
	}

	// For WBEMSID, skip pointer-sized TOKEN_USER structure
	// (8 bytes on 64-bit, 4 bytes on 32-bit)
	sidPtr := p.pValue
	if p.evtPropInfo.InType() == TDH_INTYPE_WBEMSID {
		if p.erh.EventRec.PointerSize() == 8 {
			sidPtr += 16 // 2 pointers (8 bytes each)
		} else {
			sidPtr += 8 // 2 pointers (4 bytes each)
		}
	}
	// Validate Max SID
	sid := (*SID)(unsafe.Pointer(sidPtr))
	if sid.SubAuthorityCount > 15 { // SID_MAX_SUB_AUTHORITIES
		return "", fmt.Errorf("invalid SID: too many sub-authorities")
	}
	// Calculate expected size (p.sizeBytes already has it too)
	expectedSize := 8 + (4 * int(sid.SubAuthorityCount)) // 8 bytes header + 4 bytes per sub-authority
	if expectedSize > int(p.userDataRemaining) {
		return "", fmt.Errorf("invalid SID: insufficient data")
	}
	// Convert SID to string
	//sidStr, err := ConvertSidToStringSidW(sid) // cgo is slow
	sidStr, err := ConvertSidToStringSidGO(sid)
	if err != nil {
		// rawBytes := unsafe.Slice((*byte)(unsafe.Pointer(sidPtr)), p.userDataLength)
		// fmt.Printf("Raw bytes: %x\n", rawBytes[:expectedSize])
		// sidStr = fmt.Sprintf("0x%X", rawBytes)
		return "", fmt.Errorf("failed to convert SID to string: %w", err)
	}
	return sidStr, nil
}

func (p *Property) decodeStringIntype() (string, error) {
	if !p.Parseable() {
		return "", fmt.Errorf("property not parseable")
	}

	// p.length has already been set from either:
	// - Length field
	// - LengthPropertyIndex field (PropertyParamLength)
	// - PropertyParamFixedLength

	// p.length will be 0 for some string types.

	// p.sizeBytes already has the size for length = 0 string,
	// but we calculate it again here for testing.

	switch p.evtPropInfo.InType() {
	case TDH_INTYPE_UNICODESTRING:
		// Handle nul-terminated, fixed length or param length
		if (p.evtPropInfo.Flags & PropertyParamLength) != 0 {
			// Length from another property (in WCHARs)
			wcharCount := p.length
			wchars := unsafe.Slice((*uint16)(unsafe.Pointer(p.pValue)), wcharCount)
			return UTF16SliceToString(wchars), nil
		} else if (p.evtPropInfo.Flags&(PropertyParamFixedLength)) != 0 || p.length > 0 {
			// Fixed length (in WCHARs)
			wchars := unsafe.Slice((*uint16)(unsafe.Pointer(p.pValue)), p.length)
			return UTF16SliceToString(wchars), nil
		} else {
			if (p.evtPropInfo.Flags & (PropertyParamFixedLength)) != 0 {
				return "", nil
			}
			// Null terminated with fallback
			// For non-null terminated strings, especially at end of event data,
			// use remaining data length as string length
			wcharCount := p.userDataRemaining / 2
			wchars := unsafe.Slice((*uint16)(unsafe.Pointer(p.pValue)), wcharCount)
			// Try to find null terminator first
			for i, w := range wchars {
				if w == 0 {
					return UTF16SliceToString(wchars[:i]), nil
				}
			}
			// No null terminator found, use entire remaining buffer
			return UTF16SliceToString(wchars), nil
		}

	case TDH_INTYPE_ANSISTRING:
		// Handle nul-terminated, fixed length or param length
		if (p.evtPropInfo.Flags & PropertyParamLength) != 0 {
			// Length from another property (in bytes)
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.length)
			return string(bytes), nil
		} else if (p.evtPropInfo.Flags&(PropertyParamFixedLength)) != 0 || p.length > 0 {
			// Fixed length (in bytes)
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.length)
			return string(bytes), nil
		} else {
			if (p.evtPropInfo.Flags & (PropertyParamFixedLength)) != 0 {
				return "", nil
			}
			// Null terminated
			// For non-null terminated strings, especially at end of event data,
			// use remaining data length as string length
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.userDataRemaining)
			// Try to find null terminator first
			for i, b := range bytes {
				if b == 0 {
					return string(bytes[:i]), nil
				}
			}
			// No null terminator found, use entire remaining buffer
			return string(bytes), nil
		}

	case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
		// Same as COUNTEDSTRING but for manifests
		// Contains little-endian 16-bit bytecount followed by UTF16 string
		byteLen := *(*uint16)(unsafe.Pointer(p.pValue))
		wcharCount := byteLen / 2
		wchars := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), wcharCount)
		return UTF16SliceToString(wchars), nil

	case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:
		// Same as COUNTEDANSISTRING but for manifests
		// Contains little-endian 16-bit bytecount followed by ANSI string
		byteLen := *(*uint16)(unsafe.Pointer(p.pValue))
		bytes := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), byteLen)
		return string(bytes), nil

	// WBEM data types

	case TDH_INTYPE_COUNTEDSTRING:
		// First 2 bytes contain length in bytes of following string
		byteLen := *(*uint16)(unsafe.Pointer(p.pValue))
		wcharCount := byteLen / 2
		wchars := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), wcharCount)
		return UTF16SliceToString(wchars), nil

	case TDH_INTYPE_COUNTEDANSISTRING:
		// First 2 bytes contain length in bytes of following string
		byteLen := *(*uint16)(unsafe.Pointer(p.pValue))
		bytes := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), byteLen)
		return string(bytes), nil

	case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
		// Like COUNTEDSTRING but length is big-endian
		byteLen := Swap16(*(*uint16)(unsafe.Pointer(p.pValue)))
		wcharCount := byteLen / 2
		wchars := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), wcharCount)
		return UTF16SliceToString(wchars), nil

	case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
		// Like COUNTEDANSISTRING but length is big-endian
		byteLen := Swap16(*(*uint16)(unsafe.Pointer(p.pValue)))
		bytes := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(p.pValue), 2)), byteLen)
		return string(bytes), nil

	case TDH_INTYPE_NONNULLTERMINATEDSTRING:
		// String takes up remaining event bytes
		wcharCount := p.userDataRemaining / 2
		wchars := unsafe.Slice((*uint16)(unsafe.Pointer(p.pValue)), wcharCount)
		return UTF16SliceToString(wchars), nil

	case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
		// String takes up remaining event bytes
		bytes := unsafe.Slice((*byte)(unsafe.Pointer(p.pValue)), p.userDataRemaining)
		return string(bytes), nil
	}

	return "", fmt.Errorf("not a string type: %v", p.evtPropInfo.InType())
}

func (p *Property) decodeFloatIntype() (float64, error) {
	if !p.Parseable() {
		return 0, fmt.Errorf("property not parseable")
	}

	switch p.evtPropInfo.InType() {
	case TDH_INTYPE_FLOAT:
		return (float64)(*(*float32)(unsafe.Pointer(p.pValue))), nil
	case TDH_INTYPE_DOUBLE:
		return *(*float64)(unsafe.Pointer(p.pValue)), nil
	}

	return 0, fmt.Errorf("cannot be convert type %v to float64", p.evtPropInfo.InType())
}

// decodeScalarIntype returns numeric value as uint64 with a flag indicating if it
// should be interpreted as signed
// Returns (uint64Value, isSigned, error)
func (p *Property) decodeScalarIntype() (uint64, bool, error) {
	if !p.Parseable() {
		return 0, false, fmt.Errorf("property not parseable")
	}

	switch p.evtPropInfo.InType() {
	// Signed integers - return as uint64 with signed flag
	case TDH_INTYPE_INT8:
		return uint64(*(*int8)(unsafe.Pointer(p.pValue))), true, nil
	case TDH_INTYPE_INT16:
		return uint64(*(*int16)(unsafe.Pointer(p.pValue))), true, nil
	case TDH_INTYPE_INT32:
		return uint64(*(*int32)(unsafe.Pointer(p.pValue))), true, nil
	case TDH_INTYPE_INT64:
		return uint64(*(*int64)(unsafe.Pointer(p.pValue))), true, nil

	// Unsigned integers - return as is
	case TDH_INTYPE_UINT8:
		return uint64(*(*uint8)(unsafe.Pointer(p.pValue))), false, nil
	case TDH_INTYPE_UINT16:
		return uint64(*(*uint16)(unsafe.Pointer(p.pValue))), false, nil
	case TDH_INTYPE_UINT32:
		return uint64(*(*uint32)(unsafe.Pointer(p.pValue))), false, nil
	case TDH_INTYPE_UINT64:
		return *(*uint64)(unsafe.Pointer(p.pValue)), false, nil

	// Special cases
	case TDH_INTYPE_BOOLEAN:
		if *(*int32)(unsafe.Pointer(p.pValue)) != 0 {
			return 1, true, nil
		}
		return 0, true, nil

	case TDH_INTYPE_POINTER:
		if p.erh.EventRec.PointerSize() == 8 {
			return *(*uint64)(unsafe.Pointer(p.pValue)), false, nil
		}
		return uint64(*(*uint32)(unsafe.Pointer(p.pValue))), false, nil

	case TDH_INTYPE_HEXINT32:
		return uint64(*(*uint32)(unsafe.Pointer(p.pValue))), false, nil
	case TDH_INTYPE_HEXINT64:
		return *(*uint64)(unsafe.Pointer(p.pValue)), false, nil

	case TDH_INTYPE_SIZET:
		if p.erh.EventRec.PointerSize() == 8 {
			return *(*uint64)(unsafe.Pointer(p.pValue)), false, nil
		}
		return uint64(*(*uint32)(unsafe.Pointer(p.pValue))), false, nil

	case TDH_INTYPE_FILETIME:
		ft := (*syscall.Filetime)(unsafe.Pointer(p.pValue))
		return uint64(ft.Nanoseconds()), true, nil
	}

	return 0, false, fmt.Errorf("type %v cannot be converted to integer", p.evtPropInfo.InType())
}
