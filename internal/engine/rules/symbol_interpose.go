package rules

import (
	"slices"
	"strings"

	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// SymbolInterposeRule alerts when a symbol resolves from an unexpected shared object.
type SymbolInterposeRule struct {
	// ExpectedSO contains all approved provider identities for each tracked symbol.
	ExpectedSO map[string][]string
}

func (r *SymbolInterposeRule) Name() string { return "SYMBOL_INTERPOSITION" }

func (r *SymbolInterposeRule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev == nil || ev.EventType != proto.EventSymBind {
		return nil
	}

	symbol := ev.SymbolStr()
	actual := ev.SOPathStr()
	expected := r.ExpectedSO[symbol]
	if len(expected) == 0 {
		return nil
	}
	for _, provider := range expected {
		if identity.SameLibrary(provider, actual) {
			return nil
		}
	}
	// Stable diagnostics must not depend on baseline entry order or mutate policy.
	expected = slices.Clone(expected)
	slices.Sort(expected)

	return &engine.Alert{
		Severity: engine.SeverityCritical,
		Rule:     r.Name(),
		PID:      ev.PID,
		Detail: map[string]string{
			"symbol":      symbol,
			"expected_so": strings.Join(expected, ", "),
			"actual_so":   actual,
		},
		Timestamp: int64(ev.TimeStamNs),
	}
}
