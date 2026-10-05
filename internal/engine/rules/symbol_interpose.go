package rules

import (
	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// SymbolInterposeRule alerts when a symbol resolves from an unexpected shared object.
type SymbolInterposeRule struct {
	ExpectedSO map[string]string
}

func (r *SymbolInterposeRule) Name() string { return "SYMBOL_INTERPOSITION" }

func (r *SymbolInterposeRule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev == nil || ev.EventType != proto.EventSymBind {
		return nil
	}

	symbol := ev.SymbolStr()
	actual := ev.SOPathStr()
	expected := r.ExpectedSO[symbol]
	if expected == "" || identity.SameLibrary(expected, actual) {
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
