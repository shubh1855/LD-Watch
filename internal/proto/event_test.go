package proto

import (
    "testing"
    "unsafe"
)

func TestEventSize(t *testing.T) {
    var e Event
    size := int(unsafe.Sizeof(e))
    if size != EventSize {
        t.Errorf("Event size mismatch: got %d bytes, expected %d bytes", size, EventSize)
    } else {
        t.Logf("PASS — proto.Event is %d bytes, matches C struct", size)
    }
}
