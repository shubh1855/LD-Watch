package baseline

import (
	"context"
	"database/sql"

	"github.com/shubh1855/ld-watch/internal/proto"
)

const ddl = `
CREATE TABLE IF NOT EXISTS baseline_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pid           INTEGER NOT NULL,
    event_type    INTEGER NOT NULL,
    so_path       TEXT,
    symbol_name   TEXT,
    resolved_so   TEXT,
    resolved_addr INTEGER,
    timestamp     INTEGER NOT NULL
);
`

// Profiler records observed-good events during learn mode.
type Profiler struct {
	db *sql.DB
}

// New creates a baseline profiler backed by db.
func New(db *sql.DB) *Profiler {
	return &Profiler{db: db}
}

// CreateTables creates baseline tables used by learn mode.
func (p *Profiler) CreateTables(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, ddl)
	return err
}

// Learn records one event into the baseline table.
func (p *Profiler) Learn(ctx context.Context, ev *proto.Event) error {
	_, err := p.db.ExecContext(ctx, `
INSERT INTO baseline_events (pid, event_type, so_path, symbol_name, resolved_so, resolved_addr, timestamp)
VALUES (?, ?, ?, ?, ?, ?, ?)
`,
		ev.PID,
		ev.EventType,
		ev.SOPathStr(),
		ev.SymbolStr(),
		ev.SOPathStr(),
		ev.ResolvedAddr,
		ev.TimeStamNs,
	)
	return err
}

// KnownSOs returns all SO paths observed in learn mode.
func (p *Profiler) KnownSOs(ctx context.Context) (map[string]bool, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT DISTINCT so_path FROM baseline_events
WHERE so_path IS NOT NULL AND so_path != ''
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	known := make(map[string]bool)
	for rows.Next() {
		var soPath string
		if err := rows.Scan(&soPath); err != nil {
			return nil, err
		}
		known[soPath] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return known, nil
}
