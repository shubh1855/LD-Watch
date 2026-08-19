package collector

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

// ExeResolver resolves a PID to an executable path.
type ExeResolver func(pid uint32) string

// Processor routes decoded audit events into the store.
type Processor struct {
	queries    *store.Queries
	resolveExe ExeResolver
}

// NewProcessor creates an event processor. If resolveExe is nil, ResolveExe is used.
func NewProcessor(queries *store.Queries, resolveExe ExeResolver) *Processor {
	if resolveExe == nil {
		resolveExe = ResolveExe
	}
	return &Processor{queries: queries, resolveExe: resolveExe}
}

// Process stores one decoded audit event.
func (p *Processor) Process(ctx context.Context, ev *proto.Event) error {
	exe := p.resolveExe(ev.PID)

	if err := p.queries.InsertProcess(ctx, store.InsertProcessParams{
		Pid:       int64(ev.PID),
		Exe:       exe,
		Cmdline:   sql.NullString{Valid: false},
		FirstSeen: int64(ev.TimeStamNs),
	}); err != nil {
		return fmt.Errorf("insert process pid=%d: %w", ev.PID, err)
	}

	switch ev.EventType {
	case proto.EventSOLoad, proto.EventSOSearch:
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
	default:
		return fmt.Errorf("unknown event type %d from pid=%d", ev.EventType, ev.PID)
	}
}

// ResolveExe resolves the executable path for a PID via /proc.
// Falls back to "pid:<n>" when the process already exited or /proc is unavailable.
func ResolveExe(pid uint32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Sprintf("pid:%d", pid)
	}
	return path
}
