package engine

import "github.com/shubh1855/ld-watch/internal/proto"

// Rule is the method shape every detection rule must implement.
// This lives here to avoid an import cycle between engine and engine/rules.
type Rule interface {
	Name() string
	Evaluate(ev *proto.Event) *Alert
}

// Engine orchestrates rule evaluation for each decoded event.
type Engine struct {
	rules []Rule
}

// New creates an Engine with the provided rule set.
func New(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate runs all rules against an event and returns any alerts.
func (e *Engine) Evaluate(ev *proto.Event) []*Alert {
	var alerts []*Alert
	for _, r := range e.rules {
		if a := r.Evaluate(ev); a != nil {
			alerts = append(alerts, a)
		}
	}
	return alerts
}
