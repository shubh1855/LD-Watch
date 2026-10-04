package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shubh1855/ld-watch/internal/proto"
)

// SourceExecutable is the shared interpretation of initialization metadata.
// Missing or truncated paths stay uncertain, and never become library paths.
func SourceExecutable(ev *proto.Event) (string, string) {
	if ev == nil || ev.ExePathStr() == "" || ev.Flags&(proto.FlagExeTruncated|proto.FlagExeUnresolved) != 0 {
		return "", "unresolved"
	}
	return ev.ExePathStr(), "source"
}

// PersistEvent writes the process registry and event in the same transaction.
// Executable metadata is explicit; callers cannot substitute a library path.
type PersistedIdentity struct {
	ProcessKey     string
	Executable     string
	IdentityStatus string
	Timestamp      int64
}

func (q *Queries) PersistEvent(ctx context.Context, ev *proto.Event, exe, status string) error {
	_, err := q.PersistEventWithIdentity(ctx, ev, exe, status)
	return err
}

// PersistEventWithIdentity writes an event and returns the exact process-instance
// identity used by that transaction for downstream detection and alert linkage.
func (q *Queries) PersistEventWithIdentity(ctx context.Context, ev *proto.Event, exe, status string) (PersistedIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if ev == nil {
		return PersistedIdentity{}, fmt.Errorf("nil event")
	}
	switch status {
	case "source":
		if observed, sourceStatus := SourceExecutable(ev); sourceStatus != "source" || exe != observed {
			return PersistedIdentity{}, fmt.Errorf("identified event requires its complete source executable")
		}
	case "unresolved":
		if exe != "" {
			return PersistedIdentity{}, fmt.Errorf("unresolved event must have empty executable")
		}
	default:
		return PersistedIdentity{}, fmt.Errorf("invalid identity status %q", status)
	}
	kind := ev.EventTypeName()
	if kind == "UNKNOWN" {
		return PersistedIdentity{}, fmt.Errorf("unknown event type %d", ev.EventType)
	}
	db, ok := q.db.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return PersistedIdentity{}, fmt.Errorf("event persistence requires transaction-capable database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return PersistedIdentity{}, err
	}
	defer tx.Rollback()
	tq := q.WithTx(tx)
	ticks := ev.ProcessStartTicks
	if ev.Flags&proto.FlagStartUnresolved != 0 {
		ticks = 0
	}
	key := fmt.Sprintf("%d:%d", ev.PID, ticks)
	if ticks == 0 {
		key = "unresolved:" + uuid.NewString()
	}
	timestamp := ev.TimestampNs
	if timestamp == 0 {
		timestamp = ev.TimeStamNs
	}
	if timestamp > math.MaxInt64 {
		return PersistedIdentity{}, fmt.Errorf("timestamp exceeds SQLite signed nanosecond range")
	}
	flags := ev.Flags
	if status == "unresolved" {
		flags |= proto.FlagExeUnresolved
	}
	if ticks == 0 {
		flags |= proto.FlagStartUnresolved
	}
	registryExe, registryStatus := exe, status
	if timestamp == 0 {
		// The event retains its source identity, but cannot select the registry's
		// executable snapshot without a known observation time.
		registryExe, registryStatus = "", "unresolved"
	}
	err = tq.UpsertProcessInstance(ctx, UpsertProcessInstanceParams{
		ProcessKey: key, Pid: int64(ev.PID), StartTicks: strconv.FormatUint(ticks, 10), Exe: registryExe,
		IdentityStatus: registryStatus, FirstSeen: int64(timestamp), LastSeen: int64(timestamp),
	})
	if err != nil {
		return PersistedIdentity{}, err
	}
	err = tq.InsertLoaderEvent(ctx, InsertLoaderEventParams{
		ProcessKey: key, Pid: int64(ev.PID), Tid: int64(ev.TID), Exe: exe, WireExe: ev.ExePathStr(), IdentityStatus: status,
		EventType: kind, Origin: ev.MechanismName(), Flags: int64(flags), NamespaceID: strconv.FormatUint(ev.NamespaceID, 10),
		SubjectPath: ev.SOPathStr(), RelatedPath: ev.RelatedPathStr(), Symbol: ev.SymbolStr(), ResolvedAddr: strconv.FormatUint(ev.ResolvedAddr, 16),
		Timestamp: int64(timestamp), PeerPid: int64(ev.PeerPID), PeerUid: int64(ev.PeerUID), PeerGid: int64(ev.PeerGID),
	})
	if err != nil {
		return PersistedIdentity{}, err
	}
	if err := tx.Commit(); err != nil {
		return PersistedIdentity{}, err
	}
	return PersistedIdentity{ProcessKey: key, Executable: exe, IdentityStatus: status, Timestamp: int64(timestamp)}, nil
}

// RetainEvents explicitly removes one bounded batch of old telemetry. It never
// deletes baselines, alerts, legacy evidence, or process registry entries.
func (s *Store) RetainEvents(ctx context.Context, beforeNs, batch int64) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if beforeNs <= 0 || batch < 1 || batch > 10000 {
		return 0, fmt.Errorf("retention requires positive cutoff and batch 1..10000")
	}
	return s.DeleteExpiredEvents(ctx, DeleteExpiredEventsParams{Timestamp: beforeNs, Limit: batch})
}
