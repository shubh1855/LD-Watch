package rules

import (
	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// Rule is the interface every detection rule implements.
// Evaluate returns an Alert if the event triggers the rule, nil otherwise.
type Rule interface {
	Name() string
	Evaluate(ev *proto.Event) *engine.Alert
}
