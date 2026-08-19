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
	if got.ResolvedAddr != 0xdeadbeef {
		t.Errorf("resolved_addr: got %#x, want 0xdeadbeef", got.ResolvedAddr)
	}
}

func TestInsertAndQueryAlert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	alert, err := s.WriteAlert(ctx, AlertParams{
		Severity:    "high",
		Rule:        "ld_preload_injection",
		PID:         9999,
		Exe:         "/usr/bin/ssh",
		Detail:      "LD_PRELOAD set to /tmp/evil.so",
		TimestampNs: 3_000_000,
	})
	if err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}
	if alert.ID == 0 {
		t.Fatal("expected non-zero alert ID after insert")
	}

	alerts, err := s.QueryAlerts(ctx, 10)
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	got := alerts[0]
	if got.Severity != "high" {
		t.Errorf("severity: got %q, want high", got.Severity)
	}
	if got.Rule != "ld_preload_injection" {
		t.Errorf("rule: got %q, want ld_preload_injection", got.Rule)
	}
	if got.Pid != 9999 {
		t.Errorf("pid: got %d, want 9999", got.Pid)
	}
	if got.Detail != "LD_PRELOAD set to /tmp/evil.so" {
		t.Errorf("detail: got %q", got.Detail)
	}
}

func TestListAlertsBySeverity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	inserts := []AlertParams{
		{Severity: "low", Rule: "r1", PID: 1, Exe: "/bin/a", Detail: "d1", TimestampNs: 100},
		{Severity: "high", Rule: "r2", PID: 2, Exe: "/bin/b", Detail: "d2", TimestampNs: 200},
		{Severity: "high", Rule: "r3", PID: 3, Exe: "/bin/c", Detail: "d3", TimestampNs: 300},
		{Severity: "critical", Rule: "r4", PID: 4, Exe: "/bin/d", Detail: "d4", TimestampNs: 400},
	}
	for _, p := range inserts {
		if _, err := s.WriteAlert(ctx, p); err != nil {
			t.Fatalf("WriteAlert(%q): %v", p.Rule, err)
		}
	}

	// Expect exactly 2 high-severity alerts, ordered newest first.
	highs, err := s.QueryAlertsBySeverity(ctx, "high", 10)
	if err != nil {
		t.Fatalf("QueryAlertsBySeverity: %v", err)
	}
	if len(highs) != 2 {
		t.Fatalf("expected 2 high alerts, got %d", len(highs))
	}
	if highs[0].Timestamp < highs[1].Timestamp {
		t.Errorf("alerts not ordered newest-first: %d < %d", highs[0].Timestamp, highs[1].Timestamp)
	}

	// Respect the limit param.
	one, err := s.QueryAlertsBySeverity(ctx, "high", 1)
	if err != nil {
		t.Fatalf("QueryAlertsBySeverity limit=1: %v", err)
	}
	if len(one) != 1 {
		t.Fatalf("expected 1 alert with limit=1, got %d", len(one))
	}

	// Severity filter is exclusive.
	lows, err := s.QueryAlertsBySeverity(ctx, "low", 10)
	if err != nil {
		t.Fatalf("QueryAlertsBySeverity(low): %v", err)
	}
	if len(lows) != 1 {
		t.Fatalf("expected 1 low alert, got %d", len(lows))
	}
}
