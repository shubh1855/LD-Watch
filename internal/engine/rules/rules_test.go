package rules

import (
	"testing"

	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
)

func makeSOEvent(pid uint32, path string) *proto.Event {
	ev := &proto.Event{PID: pid, EventType: proto.EventSOLoad, TimeStamNs: 100}
	copy(ev.SOPath[:], path)
	return ev
}

func makeSymbolEvent(pid uint32, soPath, symbol string) *proto.Event {
	ev := &proto.Event{PID: pid, EventType: proto.EventSymBind, TimeStamNs: 200}
	copy(ev.SOPath[:], soPath)
	copy(ev.Symbol[:], symbol)
	return ev
}

func TestUnknownSORuleReturnsNilForKnownSO(t *testing.T) {
	rule := &UnknownSORule{KnownSO: map[string]bool{"/lib/libc.so.6": true}}
	alert := rule.Evaluate(makeSOEvent(1234, "/lib/libc.so.6"))
	if alert != nil {
		t.Fatalf("expected nil alert for known SO, got %#v", alert)
	}
}

func TestUnknownSORuleFiresForUnknownSO(t *testing.T) {
	rule := &UnknownSORule{KnownSO: map[string]bool{"/lib/libc.so.6": true}}
	alert := rule.Evaluate(makeSOEvent(1234, "/tmp/evil.so"))
	if alert == nil {
		t.Fatal("expected alert for unknown SO")
	}
	if alert.Rule != "UNKNOWN_SO" {
		t.Errorf("rule: got %q, want UNKNOWN_SO", alert.Rule)
	}
	if alert.Severity != engine.SeverityHigh {
		t.Errorf("severity: got %q, want HIGH", alert.Severity)
	}
	if alert.Detail["so_path"] != "/tmp/evil.so" {
		t.Errorf("so_path: got %q", alert.Detail["so_path"])
	}
}

func TestPathHijackRuleFiresForWrongPath(t *testing.T) {
	rule := &PathHijackRule{ExpectedPath: map[string]string{"/tmp/libcrypto.so.3": "/usr/lib/libcrypto.so.3"}}
	alert := rule.Evaluate(makeSOEvent(2222, "/tmp/libcrypto.so.3"))
	if alert == nil {
		t.Fatal("expected alert for wrong library path")
	}
	if alert.Rule != "PATH_HIJACK" {
		t.Errorf("rule: got %q, want PATH_HIJACK", alert.Rule)
	}
	if alert.Severity != engine.SeverityCritical {
		t.Errorf("severity: got %q, want CRITICAL", alert.Severity)
	}
	if alert.Detail["expected_path"] != "/usr/lib/libcrypto.so.3" {
		t.Errorf("expected_path: got %q", alert.Detail["expected_path"])
	}
	if alert.Detail["actual_path"] != "/tmp/libcrypto.so.3" {
		t.Errorf("actual_path: got %q", alert.Detail["actual_path"])
	}
}

func TestSymbolInterpositionRuleFiresForWrongSO(t *testing.T) {
	rule := &SymbolInterposeRule{ExpectedSO: map[string]string{"open": "/lib/libc.so.6"}}
	alert := rule.Evaluate(makeSymbolEvent(3333, "/tmp/evil.so", "open"))
	if alert == nil {
		t.Fatal("expected alert for symbol interposition")
	}
	if alert.Rule != "SYMBOL_INTERPOSITION" {
		t.Errorf("rule: got %q, want SYMBOL_INTERPOSITION", alert.Rule)
	}
	if alert.Severity != engine.SeverityCritical {
		t.Errorf("severity: got %q, want CRITICAL", alert.Severity)
	}
	if alert.Detail["symbol"] != "open" {
		t.Errorf("symbol: got %q", alert.Detail["symbol"])
	}
	if alert.Detail["actual_so"] != "/tmp/evil.so" {
		t.Errorf("actual_so: got %q", alert.Detail["actual_so"])
	}
}
