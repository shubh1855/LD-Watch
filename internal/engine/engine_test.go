package engine

import (
	"testing"

	"github.com/shubh1855/ld-watch/internal/proto"
)

type testRule struct {
	name  string
	alert *Alert
}

func (r testRule) Name() string { return r.name }
func (r testRule) Evaluate(ev *proto.Event) *Alert {
	return r.alert
}

func TestEngineEvaluateReturnsAlertsFromAllRules(t *testing.T) {
	ev := &proto.Event{PID: 1234}
	e := New([]Rule{
		testRule{name: "no-alert"},
		testRule{name: "alert-1", alert: &Alert{Rule: "alert-1", PID: 1234}},
		testRule{name: "alert-2", alert: &Alert{Rule: "alert-2", PID: 1234}},
	})

	alerts := e.Evaluate(ev)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].Rule != "alert-1" || alerts[1].Rule != "alert-2" {
		t.Fatalf("unexpected alert order: %#v", alerts)
	}
}
