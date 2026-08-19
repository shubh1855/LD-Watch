package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/shubh1855/ld-watch/internal/proto"
)

// Store is the high-level interface over the SQLite database.
// It embeds the sqlc-generated Queries so callers can also use
// generated methods directly when needed.
type Store struct {
	db *sql.DB
	*Queries
}

// NewStore opens the database at path, runs migrations, and returns a ready Store.
func NewStore(path string) (*Store, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("store.NewStore: open: %w", err)
	}
	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("store.NewStore: migrate: %w", err)
	}
	// New is the sqlc-generated constructor for Queries.
	return &Store{db: db, Queries: New(db)}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// CreateTables explicitly (re-)runs the schema DDL.
// Calling New already runs this; expose it for completeness / testing.
func (s *Store) CreateTables() error {
	return Migrate(s.db)
}

// WriteSOEvent persists an SO-load or SO-search event.
// The exe path is looked up from /proc/<pid>/exe at call time when the
// event itself does not carry it (SOPath doubles as the loaded library).
func (s *Store) WriteSOEvent(ctx context.Context, event *proto.Event) error {
	return s.InsertSOEvent(ctx, InsertSOEventParams{
		Pid:       int64(event.PID),
		Exe:       event.SOPathStr(), // exe not in wire format yet; use SOPath as placeholder
		SoPath:    event.SOPathStr(),
		Mechanism: event.MechanismName(),
		Timestamp: int64(event.TimeStamNs),
	})
}

// WriteSymbolEvent persists a symbol-bind event.
func (s *Store) WriteSymbolEvent(ctx context.Context, event *proto.Event) error {
	return s.InsertSymbolEvent(ctx, InsertSymbolEventParams{
		Pid:          int64(event.PID),
		Exe:          event.SOPathStr(),
		SymbolName:   event.SymbolStr(),
		ResolvedSo:   event.SOPathStr(),
		ResolvedAddr: int64(event.ResolvedAddr),
		Timestamp:    int64(event.TimeStamNs),
	})
}

// AlertParams carries the fields needed to persist a detection alert.
type AlertParams struct {
	Severity string // "low" | "medium" | "high" | "critical"
	Rule     string // rule / detector name that fired
	PID      int32
	Exe      string
	Detail   string
	// TimestampNs is nanoseconds since Unix epoch; 0 means "now" is not
	// automatically filled here — callers should pass event.TimeStamNs.
	TimestampNs int64
}

// WriteAlert persists a detection alert and returns the stored row.
func (s *Store) WriteAlert(ctx context.Context, p AlertParams) (Alert, error) {
	return s.InsertAlert(ctx, InsertAlertParams{
		Severity:  p.Severity,
		Rule:      p.Rule,
		Pid:       int64(p.PID),
		Exe:       p.Exe,
		Detail:    p.Detail,
		Timestamp: p.TimestampNs,
	})
}

// QueryAlerts returns the most-recent limit alerts across all severities.
// Intended for CLI use.
func (s *Store) QueryAlerts(ctx context.Context, limit int64) ([]Alert, error) {
	return s.ListAlerts(ctx, limit)
}

// QueryAlertsBySeverity filters alerts by severity level.
func (s *Store) QueryAlertsBySeverity(ctx context.Context, severity string, limit int64) ([]Alert, error) {
	return s.ListAlertsBySeverity(ctx, ListAlertsBySeverityParams{
		Severity: severity,
		Limit:    limit,
	})
}
