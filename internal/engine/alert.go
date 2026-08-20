package engine

const (
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Alert is emitted when an event matches a detection rule.
type Alert struct {
	Severity  string
	Rule      string
	PID       uint32
	Detail    map[string]string
	Timestamp int64
}
