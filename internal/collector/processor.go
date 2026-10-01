package collector

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

type Stats struct {
	Persisted           uint64
	PersistenceFailures uint64
	UnresolvedIdentity  uint64
	AttributionDegraded uint64
}

type Processor struct {
	queries    *store.Queries
	persisted  atomic.Uint64
	failures   atomic.Uint64
	unresolved atomic.Uint64
	degraded   atomic.Uint64
}

func NewProcessor(queries *store.Queries) *Processor {
	return &Processor{queries: queries}
}

func (p *Processor) Stats() Stats {
	return Stats{p.persisted.Load(), p.failures.Load(), p.unresolved.Load(), p.degraded.Load()}
}

func (p *Processor) Process(ctx context.Context, ev *proto.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}
	exe, status := EnrichExecutable(ev)
	if status == "unresolved" {
		p.unresolved.Add(1)
	}
	if ev.Flags&(proto.FlagObjectUnresolved|proto.FlagSubjectTruncated|proto.FlagRelatedTruncated|proto.FlagSymbolTruncated) != 0 {
		p.degraded.Add(1)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := p.queries.PersistEvent(ctx, ev, exe, status); err != nil {
		p.failures.Add(1)
		return fmt.Errorf("persist pid=%d: %w", ev.PID, err)
	}
	p.persisted.Add(1)
	return nil
}

// EnrichExecutable uses the source snapshot captured before a short-lived
// process exits. Truncated or missing identity remains explicitly unresolved;
// a later PID lookup cannot establish which executable produced an old event.
func EnrichExecutable(ev *proto.Event) (string, string) {
	return store.SourceExecutable(ev)
}
