// Baseline query methods complement the sqlc-generated methods. Their SQL is
// kept in queries.sql alongside the generated baseline API.
package store

import (
	"context"
)

const listBaselineCandidatePoliciesSQL = `SELECT exe,environment_key,entry_type,identity,symbol,optional FROM baseline_candidate_policies WHERE exe=? AND environment_key=? ORDER BY entry_type,identity,symbol`

type ListBaselineCandidatePoliciesParams struct{ Exe, EnvironmentKey string }

func (q *Queries) ListBaselineCandidatePolicies(ctx context.Context, a ListBaselineCandidatePoliciesParams) ([]BaselinePolicy, error) {
	rows, err := q.db.QueryContext(ctx, listBaselineCandidatePoliciesSQL, a.Exe, a.EnvironmentKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselinePolicy{}
	for rows.Next() {
		var p BaselinePolicy
		if err := rows.Scan(&p.Exe, &p.EnvironmentKey, &p.EntryType, &p.Identity, &p.Symbol, &p.Optional); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type UpsertBaselineCandidatePolicyParams struct {
	Exe, EnvironmentKey, EntryType, Identity, Symbol string
	Optional                                         int64
}

func (q *Queries) UpsertBaselineCandidatePolicy(ctx context.Context, a UpsertBaselineCandidatePolicyParams) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO baseline_candidate_policies(exe,environment_key,entry_type,identity,symbol,optional) VALUES(?,?,?,?,?,?) ON CONFLICT(exe,environment_key,entry_type,identity,symbol) DO UPDATE SET optional=excluded.optional`, a.Exe, a.EnvironmentKey, a.EntryType, a.Identity, a.Symbol, a.Optional)
	return err
}

type GetActiveBaselineParams struct{ Exe, EnvironmentKey string }

func (q *Queries) GetActiveBaseline(ctx context.Context, a GetActiveBaselineParams) (BaselineVersion, error) {
	var v BaselineVersion
	err := q.db.QueryRowContext(ctx, `SELECT v.id,v.exe,v.environment_key,v.version,v.approval_state,v.metadata FROM baseline_active a JOIN baseline_versions v ON v.id=a.baseline_id WHERE a.exe=? AND a.environment_key=? AND v.approval_state='approved'`, a.Exe, a.EnvironmentKey).Scan(&v.ID, &v.Exe, &v.EnvironmentKey, &v.Version, &v.ApprovalState, &v.Metadata)
	return v, err
}

type UpsertActiveBaselineParams struct {
	Exe, EnvironmentKey string
	Version             int64
}

func (q *Queries) UpsertActiveBaseline(ctx context.Context, a UpsertActiveBaselineParams) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO baseline_active(exe,environment_key,baseline_id) SELECT exe,environment_key,id FROM baseline_versions WHERE exe=? AND environment_key=? AND version=? AND approval_state='approved' ON CONFLICT(exe,environment_key) DO UPDATE SET baseline_id=excluded.baseline_id`, a.Exe, a.EnvironmentKey, a.Version)
	return err
}

type GetLatestBaselineVersionParams struct{ Exe, EnvironmentKey string }

func (q *Queries) GetLatestBaselineVersion(ctx context.Context, a GetLatestBaselineVersionParams) (int64, error) {
	var version int64
	err := q.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM baseline_versions WHERE exe=? AND environment_key=?`, a.Exe, a.EnvironmentKey).Scan(&version)
	return version, err
}

func (q *Queries) InspectApprovedBaseline(ctx context.Context, exe, environmentKey string, version int64) (BaselineVersion, []BaselineEntry, error) {
	v, err := q.GetApprovedBaseline(ctx, GetApprovedBaselineParams{Exe: exe, EnvironmentKey: environmentKey, Version: version})
	if err != nil {
		return BaselineVersion{}, nil, err
	}
	entries, err := q.ListBaselineEntries(ctx, v.ID)
	return v, entries, err
}
