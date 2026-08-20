package rules

import (
	"path/filepath"

	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// SymbolInterposeRule alerts when a symbol resolves from an unexpected shared object.
type SymbolInterposeRule struct {
	ExpectedSO map[string]string
}

func (r *SymbolInterposeRule) Name() string { return "SYMBOL_INTERPOSE" }

func (r *SymbolInterposeRule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev.EventType != proto.EventSymBind {
		return nil
	}

	symbol := ev.SymbolStr()
	actual := ev.SOPathStr()
	expected := r.ExpectedSO[symbol]
	if expected == "" || sameSharedObject(expected, actual) {
		return nil
	}

	return &engine.Alert{
		Severity: engine.SeverityCritical,
		Rule:     r.Name(),
		PID:      ev.PID,
		Detail: map[string]string{
			"symbol":      symbol,
			"expected_so": expected,
			"actual_so":   actual,
		},
		Timestamp: int64(ev.TimeStamNs),
	}
}

func sameSharedObject(expected, actual string) bool {
	return expected == actual || filepath.Base(expected) == filepath.Base(actual)
}

func baseName(path string) string {
	return filepath.Base(path)
}
