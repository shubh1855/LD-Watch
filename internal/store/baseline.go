package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/proto"
)

var ErrNoActiveBaseline = errors.New("MISSING_BASELINE: no selected approved baseline")

type BaselinePolicy struct {
	Exe, EnvironmentKey, EntryType, Identity, Symbol string
	Optional                                         int64
}

// LearnBaselineEvents consumes only identified, confirmed LOAD and SYMBOL_BIND
// rows. Its durable cursor makes repeated profiling idempotent.
func (q *Queries) LearnBaselineEvents(ctx context.Context, exe, environmentKey string) error {
	if exe == "" || environmentKey == "" {
		return fmt.Errorf("executable and environment key are required")
	}
	db, ok := q.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return fmt.Errorf("baseline learning requires a transaction-capable database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tq := q.WithTx(tx)
	var cursor int64
	err = tx.QueryRowContext(ctx, `SELECT event_id FROM baseline_learning_cursors WHERE exe=? AND environment_key=?`, exe, environmentKey).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == sql.ErrNoRows {
		cursor = 0
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,event_type,subject_path,related_path,symbol FROM loader_events WHERE id>? AND exe=? AND identity_status='source' AND ((event_type='LOAD' AND (flags & ?)=0) OR (event_type='SYMBOL_BIND' AND (flags & ?)=0)) ORDER BY id`, cursor, exe, int64(proto.FlagSubjectTruncated|proto.FlagObjectUnresolved), int64(proto.FlagRelatedTruncated|proto.FlagSymbolTruncated|proto.FlagObjectUnresolved))
	if err != nil {
		return err
	}
	type observation struct {
		id                             int64
		kind, subject, related, symbol string
	}
	var observations []observation
	for rows.Next() {
		var o observation
		if err := rows.Scan(&o.id, &o.kind, &o.subject, &o.related, &o.symbol); err != nil {
			rows.Close()
			return err
		}
		observations = append(observations, o)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, o := range observations {
		if o.id > cursor {
			cursor = o.id
		}
		var kind, ident, symbol string
		if o.kind == "LOAD" {
			if o.subject == "" {
				continue
			}
			kind, ident = "LOAD", identity.Library(o.subject)
		} else {
			if o.related == "" || o.symbol == "" {
				continue
			}
			kind, ident, symbol = "SYMBOL_PROVIDER", identity.Library(o.related), o.symbol
		}
		if ident == "" || (kind == "SYMBOL_PROVIDER" && symbol == "") {
			continue
		}
		if err := tq.UpsertBaselineCandidate(ctx, UpsertBaselineCandidateParams{Exe: exe, EnvironmentKey: environmentKey, EntryType: kind, Identity: ident, Symbol: symbol}); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO baseline_learning_cursors(exe,environment_key,event_id) VALUES(?,?,?) ON CONFLICT(exe,environment_key) DO UPDATE SET event_id=excluded.event_id`, exe, environmentKey, cursor); err != nil {
		return err
	}
	return tx.Commit()
}

func (q *Queries) SetBaselineCandidateOptional(ctx context.Context, p BaselinePolicy) error {
	if p.Exe == "" || p.EnvironmentKey == "" || p.Identity == "" {
		return fmt.Errorf("executable, environment key, and identity are required")
	}
	var exists int
	err := q.db.QueryRowContext(ctx, `SELECT 1 FROM baseline_candidates WHERE exe=? AND environment_key=? AND entry_type=? AND identity=? AND symbol=?`, p.Exe, p.EnvironmentKey, p.EntryType, p.Identity, p.Symbol).Scan(&exists)
	if err != nil {
		return err
	}
	return q.UpsertBaselineCandidatePolicy(ctx, UpsertBaselineCandidatePolicyParams{Exe: p.Exe, EnvironmentKey: p.EnvironmentKey, EntryType: p.EntryType, Identity: p.Identity, Symbol: p.Symbol, Optional: p.Optional})
}

// ApproveBaseline atomically freezes the candidate observations into a numbered version.
func (q *Queries) ApproveBaseline(ctx context.Context, exe, environmentKey string) (BaselineVersion, error) {
	if exe == "" || environmentKey == "" {
		return BaselineVersion{}, fmt.Errorf("executable and environment key are required")
	}
	db, ok := q.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return BaselineVersion{}, fmt.Errorf("baseline approval requires a transaction-capable database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return BaselineVersion{}, err
	}
	defer tx.Rollback()
	tq := q.WithTx(tx)
	candidates, err := tq.ListBaselineCandidates(ctx, ListBaselineCandidatesParams{Exe: exe, EnvironmentKey: environmentKey})
	if err != nil {
		return BaselineVersion{}, err
	}
	if len(candidates) == 0 {
		return BaselineVersion{}, fmt.Errorf("no candidates for %s (%s)", exe, environmentKey)
	}
	var version int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM baseline_versions WHERE exe=? AND environment_key=?`, exe, environmentKey).Scan(&version); err != nil {
		return BaselineVersion{}, err
	}
	v, err := tq.InsertBaselineVersion(ctx, InsertBaselineVersionParams{Exe: exe, EnvironmentKey: environmentKey, Version: version, ApprovalState: "approved", Metadata: "{}"})
	if err != nil {
		return BaselineVersion{}, err
	}
	policies, err := tq.ListBaselineCandidatePolicies(ctx, ListBaselineCandidatePoliciesParams{Exe: exe, EnvironmentKey: environmentKey})
	if err != nil {
		return BaselineVersion{}, err
	}
	optional := make(map[string]int64, len(policies))
	for _, p := range policies {
		optional[policyKey(p.EntryType, p.Identity, p.Symbol)] = p.Optional
	}
	for _, c := range candidates {
		if err := tq.InsertBaselineEntry(ctx, InsertBaselineEntryParams{BaselineID: v.ID, EntryType: c.EntryType, Identity: c.Identity, Symbol: c.Symbol, Optional: optional[policyKey(c.EntryType, c.Identity, c.Symbol)]}); err != nil {
			return BaselineVersion{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return BaselineVersion{}, err
	}
	return v, nil
}

func (q *Queries) ActiveBaseline(ctx context.Context, exe, environmentKey string) (BaselineVersion, []BaselineEntry, error) {
	v, err := q.GetActiveBaseline(ctx, GetActiveBaselineParams{Exe: exe, EnvironmentKey: environmentKey})
	if err == sql.ErrNoRows {
		return BaselineVersion{}, nil, ErrNoActiveBaseline
	}
	if err != nil {
		return BaselineVersion{}, nil, err
	}
	entries, err := q.ListBaselineEntries(ctx, v.ID)
	return v, entries, err
}

func (q *Queries) SelectBaseline(ctx context.Context, exe, environmentKey string, version int64) error {
	if exe == "" || environmentKey == "" || version < 1 {
		return fmt.Errorf("executable, environment key, and positive version are required")
	}
	if err := q.UpsertActiveBaseline(ctx, UpsertActiveBaselineParams{Exe: exe, EnvironmentKey: environmentKey, Version: version}); err != nil {
		return err
	}
	var selected int
	err := q.db.QueryRowContext(ctx, `SELECT 1 FROM baseline_active a JOIN baseline_versions v ON v.id=a.baseline_id WHERE a.exe=? AND a.environment_key=? AND v.version=? AND v.approval_state='approved'`, exe, environmentKey, version).Scan(&selected)
	if err == sql.ErrNoRows {
		return fmt.Errorf("approved baseline %s (%s) v%d not found", exe, environmentKey, version)
	}
	return err
}

func policyKey(kind, identity, symbol string) string {
	return kind + "\x00" + identity + "\x00" + symbol
}
