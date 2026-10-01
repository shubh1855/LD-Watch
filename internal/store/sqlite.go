package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shubh1855/ld-watch/internal/proto"
)

type Store struct {
	db *sql.DB
	*Queries
}

func NewStore(path string) (*Store, error) {
	db, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	if err := Migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store migrate: %w", err)
	}
	return &Store{db: db, Queries: New(db)}, nil
}
func (s *Store) Close() error        { return s.db.Close() }
func (s *Store) CreateTables() error { return Migrate(s.db) }

func (s *Store) writeSourceEvent(ctx context.Context, ev *proto.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}
	exe, status := SourceExecutable(ev)
	return s.PersistEvent(ctx, ev, exe, status)
}
func (s *Store) WriteSOEvent(ctx context.Context, ev *proto.Event) error {
	if ev == nil || (ev.EventType != proto.EventSOLoad && ev.EventType != proto.EventSOSearch) {
		return fmt.Errorf("expected load or search")
	}
	return s.writeSourceEvent(ctx, ev)
}
func (s *Store) WriteSymbolEvent(ctx context.Context, ev *proto.Event) error {
	if ev == nil || ev.EventType != proto.EventSymBind {
		return fmt.Errorf("expected symbol binding")
	}
	return s.writeSourceEvent(ctx, ev)
}

type AlertParams struct {
	ID               string
	Severity         string
	Rule             string
	ProcessKey       string
	PID              int32
	Exe              string
	Detail           string
	TimestampNs      int64
	DeduplicationKey string
}

// WriteAlert requires the canonical T01 fields. Legacy alert rows are archived
// separately; arbitrary old rule names and plaintext detail are not promoted.
func (s *Store) WriteAlert(ctx context.Context, p AlertParams) (Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	id, err := uuid.Parse(p.ID)
	if err != nil || id.String() != p.ID || id.Variant() != uuid.RFC4122 {
		return Alert{}, fmt.Errorf("alert ID must be a lowercase RFC 4122 UUID")
	}
	if p.ProcessKey == "" || p.DeduplicationKey == "" {
		return Alert{}, fmt.Errorf("alert requires process and deduplication keys")
	}
	var detail map[string]json.RawMessage
	if err := json.Unmarshal([]byte(p.Detail), &detail); err != nil {
		return Alert{}, fmt.Errorf("alert detail: %w", err)
	}
	for _, key := range []string{"event_type", "process_instance", "executable", "observed", "baseline", "origin", "flags"} {
		if _, ok := detail[key]; !ok {
			return Alert{}, fmt.Errorf("alert detail missing %s", key)
		}
	}
	return s.InsertAlert(ctx, InsertAlertParams{ID: p.ID, Severity: p.Severity, Rule: p.Rule, ProcessKey: p.ProcessKey, Pid: int64(p.PID), Exe: p.Exe, Detail: p.Detail, Timestamp: p.TimestampNs, DeduplicationKey: p.DeduplicationKey})
}
func (s *Store) QueryAlerts(ctx context.Context, limit int64) ([]Alert, error) {
	return s.ListAlerts(ctx, limit)
}
func (s *Store) QueryAlertsBySeverity(ctx context.Context, severity string, limit int64) ([]Alert, error) {
	return s.ListAlertsBySeverity(ctx, ListAlertsBySeverityParams{Severity: strings.ToUpper(severity), Limit: limit})
}
