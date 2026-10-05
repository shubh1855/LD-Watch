package rules

import (
	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// UnknownSORule alerts when a confirmed library load is absent from the baseline.
type UnknownSORule struct {
	KnownSO map[string]bool
}

func (r *UnknownSORule) Name() string { return "UNKNOWN_SO" }

func (r *UnknownSORule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev == nil || ev.EventType != proto.EventSOLoad {
		return nil
	}

	soPath := ev.SOPathStr()
	if soPath == "" || r.KnownSO[identity.Library(soPath)] {
		return nil
	}

	return &engine.Alert{
		Severity: engine.SeverityHigh,
		Rule:     r.Name(),
		PID:      ev.PID,
		Detail: map[string]string{
			"so_path": soPath,
		},
		Timestamp: int64(ev.TimeStamNs),
	}
}
