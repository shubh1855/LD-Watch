// Package collector enriches, persists, and evaluates decoded audit events.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shubh1855/ld-watch/internal/engine"
	"github.com/shubh1855/ld-watch/internal/engine/rules"
	"github.com/shubh1855/ld-watch/internal/identity"
	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

type Stats struct {
	Persisted, PersistenceFailures, UnresolvedIdentity, AttributionDegraded uint64
	AlertsPersisted, DuplicateAlerts, DetectionFailures, MissingBaselines   uint64
}

type Processor struct {
	queries        *store.Queries
	persisted      atomic.Uint64
	failures       atomic.Uint64
	unresolved     atomic.Uint64
	degraded       atomic.Uint64
	alerts         atomic.Uint64
	duplicates     atomic.Uint64
	detectErrs     atomic.Uint64
	missing        atomic.Uint64
	environmentKey string
}

// NewProcessor binds detections to an explicit baseline environment label.
// The default label supports existing local deployments; production profile
// workflows should pass the same label used when approving the baseline.
func NewProcessor(queries *store.Queries, environmentKey ...string) *Processor {
	env := "default"
	if len(environmentKey) > 0 && strings.TrimSpace(environmentKey[0]) != "" {
		env = environmentKey[0]
	}
	return &Processor{queries: queries, environmentKey: env}
}

func (p *Processor) Stats() Stats {
	return Stats{
		Persisted: p.persisted.Load(), PersistenceFailures: p.failures.Load(),
		UnresolvedIdentity: p.unresolved.Load(), AttributionDegraded: p.degraded.Load(),
		AlertsPersisted: p.alerts.Load(), DuplicateAlerts: p.duplicates.Load(),
		DetectionFailures: p.detectErrs.Load(), MissingBaselines: p.missing.Load(),
	}
}

func (p *Processor) Process(ctx context.Context, ev *proto.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}
	exe, status := EnrichExecutable(ev)
	if status == "unresolved" { p.unresolved.Add(1) }
	if ev.Flags&(proto.FlagObjectUnresolved|proto.FlagSubjectTruncated|proto.FlagRelatedTruncated|proto.FlagSymbolTruncated) != 0 {
		p.degraded.Add(1)
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	stored, err := p.queries.PersistEventWithIdentity(ctx, ev, exe, status)
	if err != nil {
		p.failures.Add(1)
		return fmt.Errorf("persist pid=%d: %w", ev.PID, err)
	}
	p.persisted.Add(1)
	if err := p.detectAndPersist(ctx, ev, stored); err != nil {
		p.detectErrs.Add(1)
		return fmt.Errorf("evaluate pid=%d: %w", ev.PID, err)
	}
	return nil
}

func (p *Processor) detectAndPersist(ctx context.Context, ev *proto.Event, stored store.PersistedIdentity) error {
	if ev.EventType != proto.EventSOLoad && ev.EventType != proto.EventSymBind { return nil }
	if ev.EventType == proto.EventSOLoad && ev.Flags&(proto.FlagSubjectTruncated|proto.FlagObjectUnresolved) != 0 {
		return nil
	}
	if ev.EventType == proto.EventSymBind && ev.Flags&(proto.FlagSubjectTruncated|proto.FlagRelatedTruncated|proto.FlagSymbolTruncated|proto.FlagObjectUnresolved) != 0 {
		return nil
	}
	// Unknown executable identity cannot safely select a profile. The source
	// event remains persisted with uncertainty; it is never treated as clean.
	if stored.IdentityStatus != "source" || stored.Executable == "" { return nil }
	version, entries, err := p.queries.ActiveBaseline(ctx, stored.Executable, p.environmentKey)
	if err == store.ErrNoActiveBaseline {
		p.missing.Add(1)
		return p.persistDetectionAlert(ctx, ev, stored, 0, "MISSING_BASELINE", engine.SeverityHigh,
			map[string]any{"identity": identity.Library(ev.SOPathStr()), "symbol": ev.SymbolStr()},
			map[string]any{"status": "no_approved_baseline", "environment": p.environmentKey})
	}
		if err != nil {
			return fmt.Errorf("load approved baseline for %s (%s): %w", stored.Executable, p.environmentKey, err)
		}
	known := make(map[string]bool)
	expectedSymbols := make(map[string]string)
	pathsByName := make(map[string][]string)
	for _, entry := range entries {
		switch entry.EntryType {
		case "LOAD":
			path := identity.Library(entry.Identity)
			known[path] = true
			pathsByName[baseName(path)] = append(pathsByName[baseName(path)], path)
		case "SYMBOL_PROVIDER":
			expectedSymbols[entry.Symbol] = identity.Library(entry.Identity)
		}
	}
	if ev.EventType == proto.EventSOLoad {
		actual := identity.Library(ev.SOPathStr())
		// A same-name, different-path object is a path deviation. It is never
		// considered equal to the approved object; ambiguous aliases stay UNKNOWN_SO.
		candidates := pathsByName[baseName(actual)]
		if len(candidates) == 1 && !identity.SameLibrary(candidates[0], actual) {
			a := (&rules.PathHijackRule{ExpectedPath: map[string]string{actual: candidates[0]}}).Evaluate(ev)
			if a != nil {
				return p.persistDetectionAlert(ctx, ev, stored, version.Version, a.Rule, a.Severity, map[string]any{"path": actual}, map[string]any{"path": candidates[0]})
			}
		}
		a := (&rules.UnknownSORule{KnownSO:known}).Evaluate(ev)
		if a != nil {
			return p.persistDetectionAlert(ctx, ev, stored, version.Version, a.Rule, a.Severity, map[string]any{"path": actual}, map[string]any{"approved_libraries": sortedKeys(known)})
		}
		return nil
	}
	a := (&rules.SymbolInterposeRule{ExpectedSO:expectedSymbols}).Evaluate(ev)
	if a != nil {
		return p.persistDetectionAlert(ctx, ev, stored, version.Version, a.Rule, a.Severity,
			map[string]any{"symbol": ev.SymbolStr(), "provider": identity.Library(ev.SOPathStr()), "requester": identity.Library(ev.RelatedPathStr())},
			map[string]any{"provider": expectedSymbols[ev.SymbolStr()]})
	}
	return nil
}

func (p *Processor) persistDetectionAlert(ctx context.Context, ev *proto.Event, stored store.PersistedIdentity, version int64, rule, severity string, observed, baselineValue any) error {
	detail := map[string]any{
		"event_type": ev.EventTypeName(), "process_instance": stored.ProcessKey,
		"executable": stored.Executable, "observed": observed,
		"baseline": map[string]any{"version": version, "value": baselineValue},
		"origin": ev.MechanismName(), "flags": ev.Flags,
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	observedBytes, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(rule + "\x00" + stored.ProcessKey + "\x00" + fmt.Sprint(version) + "\x00" + string(observedBytes)))
	timestamp := ev.TimestampNs
	if timestamp == 0 {
		timestamp = ev.TimeStamNs
	}
	_, inserted, err := p.queries.PersistAlert(ctx, store.AlertParams{
		Severity: severity, Rule: rule, ProcessKey: stored.ProcessKey,
		PID: int32(ev.PID), Exe: stored.Executable, Detail: string(body),
		TimestampNs: int64(timestamp), DeduplicationKey: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return err
	}
	if inserted {
		p.alerts.Add(1)
	} else {
		p.duplicates.Add(1)
	}
	return nil
}

func baseName(path string) string { return path[strings.LastIndex(path, "/")+1:] }

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// EnrichExecutable trusts only the source snapshot in the wire event.
func EnrichExecutable(ev *proto.Event) (string, string) { return store.SourceExecutable(ev) }
