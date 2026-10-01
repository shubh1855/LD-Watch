package proto

import "testing"

func TestDecodeV1Record(t *testing.T) {
	e := &Event{PID: 11, TID: 12, EventType: EventSOLoad, Mechanism: MechUnknown}
	copy(e.SOPath[:], "/lib/libc.so.6")
	decoded, err := Decode(e.MarshalBinary())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.PID != e.PID || decoded.TID != e.TID || decoded.SOPathStr() != e.SOPathStr() {
		t.Fatalf("decoded event does not preserve identity/path: %#v", decoded)
	}
}

func TestDecodeRejectsLegacyRecord(t *testing.T) {
	if _, err := Decode(make([]byte, 408)); err == nil {
		t.Fatal("Decode accepted the legacy 408-byte record")
	}
}

func TestDecodeRejectsInvalidReservedBytes(t *testing.T) {
	e := &Event{PID: 11, TID: 12, EventType: EventSOLoad}
	record := e.MarshalBinary()
	record[52] = 1
	if _, err := Decode(record); err == nil {
		t.Fatal("Decode accepted non-zero reserved bytes")
	}
}
