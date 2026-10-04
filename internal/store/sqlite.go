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
	a, _, err := s.Queries.PersistAlert(ctx, p)
	return a, err
}

// PersistAlert inserts one canonical alert. Duplicate deduplication keys are
// successful no-ops and return the existing row with inserted=false.
func (q *Queries) PersistAlert(ctx context.Context, p AlertParams) (Alert, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	id, err := uuid.Parse(p.ID)
	if err != nil || id.String() != p.ID || id.Variant() != uuid.RFC4122 {
		return Alert{}, false, fmt.Errorf("alert ID must be a lowercase RFC 4122 UUID")
	}
	if p.ProcessKey == "" || p.DeduplicationKey == "" {
		return Alert{}, false, fmt.Errorf("alert requires process and deduplication keys")
	}
	var detail map[string]json.RawMessage
	if err := json.Unmarshal([]byte(p.Detail), &detail); err != nil {
		return Alert{}, false, fmt.Errorf("alert detail: %w", err)
	}
	for _, key := range []string{"event_type", "process_instance", "executable", "observed", "baseline", "origin", "flags"} {
		if _, ok := detail[key]; !ok {
			return Alert{}, false, fmt.Errorf("alert detail missing %s", key)
		}
	}
	res, err := q.db.ExecContext(ctx, `INSERT INTO alerts(id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(deduplication_key) DO NOTHING`, p.ID, p.Severity, p.Rule, p.ProcessKey, int64(p.PID), p.Exe, p.Detail, p.TimestampNs, p.DeduplicationKey)
	if err != nil {
		return Alert{}, false, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return Alert{}, false, err
	}
	var a Alert
	err = q.db.QueryRowContext(ctx, `SELECT id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key FROM alerts WHERE deduplication_key=?`, p.DeduplicationKey).Scan(
		&a.ID, &a.Severity, &a.Rule, &a.ProcessKey, &a.Pid, &a.Exe, &a.Detail, &a.Timestamp, &a.DeduplicationKey,
	)
	return a, changed == 1, err
}
func (s *Store) QueryAlerts(ctx context.Context, limit int64) ([]Alert, error) {
	return s.ListAlerts(ctx, limit)
}
func (s *Store) QueryAlertsBySeverity(ctx context.Context, severity string, limit int64) ([]Alert, error) {
	return s.ListAlertsBySeverity(ctx, ListAlertsBySeverityParams{Severity: strings.ToUpper(severity), Limit: limit})
}
