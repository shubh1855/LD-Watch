package proto

import (
	"bytes"
)

// event type consts matches LDW_EVENT_* in audit.h
const (
	EventSOLoad   uint8 = 0
	EventSymBind  uint8 = 1
	EventSOSearch uint8 = 2
)

// mechanism type consts mactches LDW_EMCH_* in audit.h
const (
	MechStandard  uint8 = 0
	MechLDPreload uint8 = 1
	MechDLibPath  uint8 = 2
	MechRPath     uint8 = 3
)

// EventSize is same byte size of ld_watch_event_t struct. Any changes require update in audit.h
const EventSize = 408

// C layout (408 bytes):
//   offset   0 : pid            uint32
//   offset   4 : event_type     uint8
//   offset   5 : mechanism      uint8
//   offset   6 : _pad           [2]byte
//   offset   8 : so_path        [256]byte
//   offset 264 : symbol         [128]byte
//   offset 392 : resolved_addr  uint64
//   offset 400 : timestamp_ns   uint64

type Event struct {
	PID          uint32
	EventType    uint8
	Mechanism    uint8
	_            [2]byte // padding for C struct _pad[2]
	SOPath       [256]byte
	Symbol       [128]byte
	ResolvedAddr uint64
	TimeStamNs   uint64
}

// SOPathStr returns the SO path as a Go string.
func (e *Event) SOPathStr() string {
	return cstrToString(e.SOPath[:])
}

// SymbolStr returns symbol name as a Go string.
func (e *Event) SymbolStr() string {
	return cstrToString(e.Symbol[:])
}

// EventTypeName returns event type string
func (e *Event) EventTypeName() string {
	switch e.EventType {
	case EventSOLoad:
		return "SO_LOAD"
	case EventSymBind:
		return "SYM_BIND"
	case EventSOSearch:
		return "SO_SEARCH"
	default:
		return "UNKNOWN"
	}
}

func (e *Event) MechanismName() string {
	switch e.Mechanism {
	case MechStandard:
		return "standard"
	case MechLDPreload:
		return "LD_PRELOAD"
	case MechDLibPath:
		return "LD_LIBRARY_PATH"
	case MechRPath:
		return "RPATH"
	default:
		return "unknown"
	}
}

func cstrToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}
