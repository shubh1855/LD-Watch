package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	WireVersion = 1
	EventSize   = 1024
)

const (
	EventSOSearch    uint8 = 1
	EventSOLoad      uint8 = 2
	EventSymBind     uint8 = 3
	EventObjectClose uint8 = 4
)

const (
	MechUnknown   uint8 = 0
	MechStandard  uint8 = 1
	MechLDPreload uint8 = 2
	MechDLibPath  uint8 = 3
	MechRPath     uint8 = 4
	MechConfig    uint8 = 5
	MechSecure    uint8 = 6
)

const (
	FlagExeTruncated     uint16 = 1 << 0
	FlagSubjectTruncated uint16 = 1 << 1
	FlagRelatedTruncated uint16 = 1 << 2
	FlagSymbolTruncated  uint16 = 1 << 3
	FlagExeUnresolved    uint16 = 1 << 4
	FlagStartUnresolved  uint16 = 1 << 5
	FlagObjectUnresolved uint16 = 1 << 6
	knownFlags                  = FlagExeTruncated | FlagSubjectTruncated | FlagRelatedTruncated |
		FlagSymbolTruncated | FlagExeUnresolved | FlagStartUnresolved | FlagObjectUnresolved
)

// Event is the decoded semantic record. Peer fields are populated by the
// listener and are never part of the sender wire record.
type Event struct {
	PID               uint32
	TID               uint32
	EventType         uint8
	Mechanism         uint8
	Flags             uint16
	ProcessStartTicks uint64
	NamespaceID       uint64
	TimestampNs       uint64
	TimeStamNs        uint64 // compatibility alias for existing store callers
	ResolvedAddr      uint64
	ExePath           [256]byte
	SOPath            [384]byte
	RelatedPath       [256]byte
	Symbol            [64]byte
	PeerPID           int32
	PeerUID           uint32
	PeerGID           uint32
}

func Decode(record []byte) (*Event, error) {
	if len(record) != EventSize {
		return nil, fmt.Errorf("invalid record length %d (want %d)", len(record), EventSize)
	}
	if string(record[0:4]) != "LDW1" {
		return nil, fmt.Errorf("invalid wire magic")
	}
	if binary.LittleEndian.Uint16(record[4:6]) != WireVersion {
		return nil, fmt.Errorf("unsupported wire version %d", binary.LittleEndian.Uint16(record[4:6]))
	}
	if int(binary.LittleEndian.Uint16(record[6:8])) != EventSize {
		return nil, fmt.Errorf("invalid declared record length")
	}
	if record[8] < EventSOSearch || record[8] > EventObjectClose {
		return nil, fmt.Errorf("invalid event type %d", record[8])
	}
	if record[9] > MechSecure {
		return nil, fmt.Errorf("invalid origin %d", record[9])
	}
	flags := binary.LittleEndian.Uint16(record[10:12])
	if flags & ^knownFlags != 0 {
		return nil, fmt.Errorf("unknown flags %#x", flags & ^knownFlags)
	}
	for i, b := range record[52:64] {
		if b != 0 {
			return nil, fmt.Errorf("non-zero reserved byte %d", i)
		}
	}

	e := &Event{
		EventType:         record[8],
		Mechanism:         record[9],
		Flags:             flags,
		PID:               binary.LittleEndian.Uint32(record[12:16]),
		TID:               binary.LittleEndian.Uint32(record[16:20]),
		ProcessStartTicks: binary.LittleEndian.Uint64(record[20:28]),
		NamespaceID:       binary.LittleEndian.Uint64(record[28:36]),
		TimestampNs:       binary.LittleEndian.Uint64(record[36:44]),
		ResolvedAddr:      binary.LittleEndian.Uint64(record[44:52]),
	}
	e.TimeStamNs = e.TimestampNs
	copy(e.ExePath[:], record[64:320])
	copy(e.SOPath[:], record[320:704])
	copy(e.RelatedPath[:], record[704:960])
	copy(e.Symbol[:], record[960:1024])
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Event) Validate() error {
	if e == nil || e.PID == 0 || e.TID == 0 {
		return fmt.Errorf("missing process or thread identity")
	}
	switch e.EventType {
	case EventSOSearch, EventSOLoad, EventObjectClose:
		if e.SOPathStr() == "" || e.SymbolStr() != "" || e.ResolvedAddr != 0 {
			return fmt.Errorf("invalid fields for event type %s (subject=%q symbol=%q addr=%#x)", e.EventTypeName(), e.SOPathStr(), e.SymbolStr(), e.ResolvedAddr)
		}
	case EventSymBind:
		if e.SOPathStr() == "" || e.RelatedPathStr() == "" || e.SymbolStr() == "" || e.ResolvedAddr == 0 {
			return fmt.Errorf("incomplete symbol binding")
		}
	}
	return nil
}

func (e *Event) SOPathStr() string      { return cstrToString(e.SOPath[:]) }
func (e *Event) RelatedPathStr() string { return cstrToString(e.RelatedPath[:]) }
func (e *Event) SymbolStr() string      { return cstrToString(e.Symbol[:]) }
func (e *Event) ExePathStr() string     { return cstrToString(e.ExePath[:]) }

func (e *Event) EventTypeName() string {
	switch e.EventType {
	case EventSOSearch:
		return "SEARCH"
	case EventSOLoad:
		return "LOAD"
	case EventSymBind:
		return "SYMBOL_BIND"
	case EventObjectClose:
		return "OBJECT_CLOSE"
	default:
		return "UNKNOWN"
	}
}

func (e *Event) MechanismName() string {
	switch e.Mechanism {
	case MechUnknown:
		return "unknown"
	case MechStandard:
		return "standard"
	case MechLDPreload:
		return "LD_PRELOAD"
	case MechDLibPath:
		return "LD_LIBRARY_PATH"
	case MechRPath:
		return "RPATH"
	case MechConfig:
		return "ldconfig"
	case MechSecure:
		return "secure"
	default:
		return "unknown"
	}
}

func (e *Event) MarshalBinary() []byte {
	record := make([]byte, EventSize)
	copy(record[0:4], "LDW1")
	binary.LittleEndian.PutUint16(record[4:6], WireVersion)
	binary.LittleEndian.PutUint16(record[6:8], EventSize)
	record[8], record[9] = e.EventType, e.Mechanism
	binary.LittleEndian.PutUint16(record[10:12], e.Flags)
	binary.LittleEndian.PutUint32(record[12:16], e.PID)
	binary.LittleEndian.PutUint32(record[16:20], e.TID)
	binary.LittleEndian.PutUint64(record[20:28], e.ProcessStartTicks)
	binary.LittleEndian.PutUint64(record[28:36], e.NamespaceID)
	timestamp := e.TimestampNs
	if timestamp == 0 {
		timestamp = e.TimeStamNs
	}
	binary.LittleEndian.PutUint64(record[36:44], timestamp)
	binary.LittleEndian.PutUint64(record[44:52], e.ResolvedAddr)
	copy(record[64:320], e.ExePath[:])
	copy(record[320:704], e.SOPath[:])
	copy(record[704:960], e.RelatedPath[:])
	copy(record[960:1024], e.Symbol[:])
	return record
}

func cstrToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}
