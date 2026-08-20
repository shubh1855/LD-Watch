package rules

import (
	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// UnknownSORule alerts when an SO load/search is absent from the known baseline.
type UnknownSORule struct {
	KnownSO map[string]bool
}

func (r *UnknownSORule) Name() string { return "UNKNOWN_SO" }

func (r *UnknownSORule) Evaluate(ev *proto.Event) *engine.Alert {
	if ev.EventType != proto.EventSOLoad && ev.EventType != proto.EventSOSearch {
		return nil
	}

	soPath := ev.SOPathStr()
	if soPath == "" || r.KnownSO[soPath] {
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
