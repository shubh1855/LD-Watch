// Package baseline provides executable and environment scoped profile workflows.
package baseline

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/store"
)

var ErrNoBaseline = store.ErrNoActiveBaseline

type Profiler struct{ queries *store.Queries }

func New(db *sql.DB) *Profiler                           { return &Profiler{queries: store.New(db)} }
func (p *Profiler) CreateTables(_ context.Context) error { return nil } // store.Migrate owns this schema.

type Library struct {
	Identity string
	Optional bool
}
type Symbol struct{ Name, Provider string }
type Profile struct {
	ID                         int64
	Executable, EnvironmentKey string
	Version                    int
	Status, Metadata           string
	Libraries                  []Library
	Symbols                    []Symbol
}

// ProfileExecutable learns incrementally from the collector's confirmed event store.
func (p *Profiler) ProfileExecutable(ctx context.Context, exe, environmentKey string) error {
	return p.queries.LearnBaselineEvents(ctx, exe, environmentKey)
}

func (p *Profiler) Candidate(ctx context.Context, exe, environmentKey string) (*Profile, error) {
	if exe == "" || environmentKey == "" {
		return nil, errors.New("executable and environment key are required")
	}
	candidates, err := p.queries.ListBaselineCandidates(ctx, store.ListBaselineCandidatesParams{Exe: exe, EnvironmentKey: environmentKey})
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, sql.ErrNoRows
	}
	version, err := p.queries.GetLatestBaselineVersion(ctx, store.GetLatestBaselineVersionParams{Exe: exe, EnvironmentKey: environmentKey})
	if err != nil {
		return nil, err
	}
	policies, err := p.queries.ListBaselineCandidatePolicies(ctx, store.ListBaselineCandidatePoliciesParams{Exe: exe, EnvironmentKey: environmentKey})
	if err != nil {
		return nil, err
	}
	optional := make(map[string]bool, len(policies))
	for _, v := range policies {
		optional[candidateKey(v.EntryType, v.Identity, v.Symbol)] = v.Optional != 0
	}
	v := &Profile{Executable: exe, EnvironmentKey: environmentKey, Version: int(version + 1), Status: "candidate"}
	for _, c := range candidates {
		switch c.EntryType {
		case "LOAD":
			v.Libraries = append(v.Libraries, Library{Identity: c.Identity, Optional: optional[candidateKey(c.EntryType, c.Identity, c.Symbol)]})
		case "SYMBOL_PROVIDER":
			v.Symbols = append(v.Symbols, Symbol{Name: c.Symbol, Provider: c.Identity})
		}
	}
	return v, nil
}

func (p *Profiler) Inspect(ctx context.Context, exe, environmentKey string, version int) (*Profile, error) {
	v, entries, err := p.queries.InspectApprovedBaseline(ctx, exe, environmentKey, int64(version))
	if err != nil {
		return nil, err
	}
	return fromStore(v, entries), nil
}

func (p *Profiler) SetOptional(ctx context.Context, exe, environmentKey, library string, optional bool) error {
	return p.queries.SetBaselineCandidateOptional(ctx, store.BaselinePolicy{Exe: exe, EnvironmentKey: environmentKey, EntryType: "LOAD", Identity: identity.Library(library), Optional: boolInt(optional)})
}

func (p *Profiler) Approve(ctx context.Context, exe, environmentKey string) (int, error) {
	v, err := p.queries.ApproveBaseline(ctx, exe, environmentKey)
	return int(v.Version), err
}
func (p *Profiler) Activate(ctx context.Context, exe, environmentKey string, version int) error {
	return p.queries.SelectBaseline(ctx, exe, environmentKey, int64(version))
}
func (p *Profiler) Reload(ctx context.Context, exe, environmentKey string) (*Profile, error) {
	v, entries, err := p.queries.ActiveBaseline(ctx, exe, environmentKey)
	if err != nil {
		return nil, err
	}
	return fromStore(v, entries), nil
}

func (v *Profile) DetectionPolicy() Policy {
	out := Policy{KnownSO: map[string]bool{}, OptionalSO: map[string]bool{}, ExpectedSO: map[string]string{}}
	for _, l := range v.Libraries {
		out.KnownSO[l.Identity] = true
		if l.Optional {
			out.OptionalSO[l.Identity] = true
		}
	}
	for _, s := range v.Symbols {
		out.ExpectedSO[s.Name] = s.Provider
	}
	return out
}

type Policy struct {
	KnownSO, OptionalSO map[string]bool
	ExpectedSO          map[string]string
}

func (v *Profile) ExpectedLibraries() []Library { return append([]Library(nil), v.Libraries...) }
func (v *Profile) SymbolProviders() []Symbol    { return append([]Symbol(nil), v.Symbols...) }
func fromStore(v store.BaselineVersion, entries []store.BaselineEntry) *Profile {
	out := &Profile{ID: v.ID, Executable: v.Exe, EnvironmentKey: v.EnvironmentKey, Version: int(v.Version), Status: v.ApprovalState, Metadata: v.Metadata}
	for _, e := range entries {
		switch e.EntryType {
		case "LOAD":
			out.Libraries = append(out.Libraries, Library{Identity: e.Identity, Optional: e.Optional != 0})
		case "SYMBOL_PROVIDER":
			out.Symbols = append(out.Symbols, Symbol{Name: e.Symbol, Provider: e.Identity})
		}
	}
	return out
}
func candidateKey(kind, ident, symbol string) string { return kind + "\x00" + ident + "\x00" + symbol }
func boolInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func (v *Profile) String() string {
	return fmt.Sprintf("%s (%s) v%d [%s]", v.Executable, v.EnvironmentKey, v.Version, v.Status)
}
