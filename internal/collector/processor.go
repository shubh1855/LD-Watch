// Package collector receives decoded audit events from the socket listener
// and persists them to the SQLite store.
package collector

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"

	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

// ExeResolver resolves a PID to an executable path.
type ExeResolver func(pid uint32) string

// Processor routes decoded audit events into the store.
type Processor struct {
	queries    *store.Queries
	resolveExe ExeResolver

	// exeMu protects exeCache — held during resolution so only one goroutine
	// resolves a given PID, preventing race where all 4 workers miss the cache
	// simultaneously and some call /proc after the process has exited.
	exeMu    sync.Mutex
	exeCache map[uint32]string
}

// NewProcessor creates an event processor. If resolveExe is nil, ResolveExe is used.
func NewProcessor(queries *store.Queries, resolveExe ExeResolver) *Processor {
	if resolveExe == nil {
		resolveExe = ResolveExe
	}
	return &Processor{
		queries:    queries,
		resolveExe: resolveExe,
		exeCache:   make(map[uint32]string),
	}
}

// cachedExe returns the exe path for a PID.
// Holds the lock during /proc resolution so only one goroutine resolves
// per PID — subsequent goroutines wait and then hit the cache.
func (p *Processor) cachedExe(pid uint32) string {
	p.exeMu.Lock()
	defer p.exeMu.Unlock()

	if exe, ok := p.exeCache[pid]; ok {
		return exe
	}

	exe := p.resolveExe(pid)
	// Only cache real paths — not "pid:N" fallbacks
	if exe != fmt.Sprintf("pid:%d", pid) {
		p.exeCache[pid] = exe
	}
	return exe
}

// Process stores one decoded audit event.
func (p *Processor) Process(ctx context.Context, ev *proto.Event) error {
	exe := p.cachedExe(ev.PID)

	if err := p.queries.InsertProcess(ctx, store.InsertProcessParams{
		Pid:       int64(ev.PID),
		Exe:       exe,
		Cmdline:   sql.NullString{Valid: false},
		FirstSeen: int64(ev.TimeStamNs),
	}); err != nil {
		return fmt.Errorf("insert process pid=%d: %w", ev.PID, err)
	}

	switch ev.EventType {

	case proto.EventSOLoad:
		soPath := ev.SOPathStr()
		if soPath == "" {
			return nil
		}
		return p.queries.InsertSOEvent(ctx, store.InsertSOEventParams{
			Pid:       int64(ev.PID),
			Exe:       exe,
			SoPath:    soPath,
			Mechanism: ev.MechanismName(),
			Timestamp: int64(ev.TimeStamNs),
		})

	case proto.EventSOSearch:
		// Only store LD_LIBRARY_PATH searches — standard searches are noise
		if ev.Mechanism != proto.MechDLibPath {
			return nil
		}
		return p.queries.InsertSOEvent(ctx, store.InsertSOEventParams{
			Pid:       int64(ev.PID),
			Exe:       exe,
			SoPath:    ev.SOPathStr(),
			Mechanism: ev.MechanismName(),
			Timestamp: int64(ev.TimeStamNs),
		})

	case proto.EventSymBind:
		return p.queries.InsertSymbolEvent(ctx, store.InsertSymbolEventParams{
			Pid:          int64(ev.PID),
			Exe:          exe,
			SymbolName:   ev.SymbolStr(),
			ResolvedSo:   ev.SOPathStr(),
			ResolvedAddr: int64(ev.ResolvedAddr),
			Timestamp:    int64(ev.TimeStamNs),
		})

	case proto.EventObjectClose:
		// Object lifecycle persistence is introduced with the T05 schema. The
		// ingress path accepts the valid event now without misclassifying it.
		return nil

	default:
		return fmt.Errorf("unknown event type %d from pid=%d", ev.EventType, ev.PID)
	}
}

// ResolveExe resolves the executable path for a PID via /proc.
// Falls back to "pid:<n>" when the process has already exited.
func ResolveExe(pid uint32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Sprintf("pid:%d", pid)
	}
	return path
}
