package store

import (
	"context"
	"testing"

	"github.com/shubh1855/ld-watch/internal/proto"
)

// newTestStore creates an in-memory SQLite store for the duration of a test.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// makeSOEvent returns a minimal proto.Event for SO-load testing.
func makeSOEvent(pid uint32, soPath, mechanism string, ts uint64) *proto.Event {
	e := &proto.Event{
		PID:        pid,
		EventType:  proto.EventSOLoad,
		TimeStamNs: ts,
	}
	copy(e.SOPath[:], soPath)
	switch mechanism {
	case "LD_PRELOAD":
		e.Mechanism = proto.MechLDPreload
	case "LD_LIBRARY_PATH":
		e.Mechanism = proto.MechDLibPath
	case "RPATH":
		e.Mechanism = proto.MechRPath
	default:
		e.Mechanism = proto.MechStandard
	}
	return e
}

// makeSymbolEvent returns a minimal proto.Event for symbol-bind testing.
func makeSymbolEvent(pid uint32, soPath, symbol string, addr uint64, ts uint64) *proto.Event {
	e := &proto.Event{
		PID:          pid,
		EventType:    proto.EventSymBind,
		ResolvedAddr: addr,
		TimeStamNs:   ts,
	}
	copy(e.SOPath[:], soPath)
	copy(e.Symbol[:], symbol)
	return e
}

func TestInsertAndQuerySOEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ev := makeSOEvent(1234, "/lib/x86_64-linux-gnu/libc.so.6", "standard", 1_000_000)
	if err := s.WriteSOEvent(ctx, ev); err != nil {
		t.Fatalf("WriteSOEvent: %v", err)
	}

	rows, err := s.ListSOEventsForPID(ctx, 1234)
	if err != nil {
		t.Fatalf("ListSOEventsForPID: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	got := rows[0]
	if got.Pid != 1234 {
		t.Errorf("pid: got %d, want 1234", got.Pid)
	}
	if got.SoPath != "/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("so_path: got %q, want /lib/x86_64-linux-gnu/libc.so.6", got.SoPath)
	}
	if got.Mechanism != "standard" {
		t.Errorf("mechanism: got %q, want standard", got.Mechanism)
	}
	if got.Timestamp != 1_000_000 {
		t.Errorf("timestamp: got %d, want 1000000", got.Timestamp)
	}
}

func TestInsertAndQuerySymbolEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ev := makeSymbolEvent(5678, "/usr/lib/libssl.so.3", "SSL_read", 0xdeadbeef, 2_000_000)
	if err := s.WriteSymbolEvent(ctx, ev); err != nil {
		t.Fatalf("WriteSymbolEvent: %v", err)
	}

	rows, err := s.ListSymbolEventsForPID(ctx, 5678)
	if err != nil {
		t.Fatalf("ListSymbolEventsForPID: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}

	got := rows[0]
	if got.Pid != 5678 {
		t.Errorf("pid: got %d, want 5678", got.Pid)
	}
	if got.SymbolName != "SSL_read" {
		t.Errorf("symbol_name: got %q, want SSL_read", got.SymbolName)
	}
	if got.ResolvedAddr != "deadbeef" {
		t.Errorf("resolved_addr: got %s, want deadbeef", got.ResolvedAddr)
	}
}
