package rules

import (
	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// PathHijackRule alerts when a library path resolves to a different path than expected.
type PathHijackRule struct {
	ExpectedPath map[string]string
}

func (r *PathHijackRule) Name() string { return "PATH_HIJACK" }

func (r *PathHijackRule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev.EventType != proto.EventSOLoad && ev.EventType != proto.EventSOSearch {
		return nil
	}

	actual := ev.SOPathStr()
	expected := r.ExpectedPath[baseName(actual)]
	if expected == "" || expected == actual {
		return nil
	}

	return &engine.Alert{
		Severity: engine.SeverityCritical,
		Rule:     r.Name(),
		PID:      ev.PID,
		Detail: map[string]string{
			"expected_path": expected,
			"actual_path":   actual,
		},
		Timestamp: int64(ev.TimeStamNs),
	}
}
