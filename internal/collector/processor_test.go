package collector

import (
	"context"
	"testing"

	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

func TestLifetimeAttributionAndEventVocabulary(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := NewProcessor(s.Queries)
	ctx := context.Background()
	ev := &proto.Event{PID: 42, TID: 43, ProcessStartTicks: 100, TimestampNs: 20, EventType: proto.EventSOLoad, PeerPID: 42, PeerUID: 123, PeerGID: 456, NamespaceID: ^uint64(0)}
	copy(ev.ExePath[:], "/bin/old")
	copy(ev.SOPath[:], "/lib/a.so")
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Exec replacement retains lifetime but updates event-time executable identity.
	ev.TimestampNs = 30
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/new")
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// A delayed pre-exec record must not revert the registry's latest metadata.
	ev.TimestampNs = 10
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/old")
	ev.EventType = proto.EventSOSearch
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	ev.ExePath = [256]byte{}
	copy(ev.ExePath[:], "/bin/new")
	ev.TimestampNs = 40
	ev.EventType = proto.EventObjectClose
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// PID reuse is a different process instance.
	ev.ProcessStartTicks = 200
	ev.EventType = proto.EventSymBind
	copy(ev.Symbol[:], "read")
	copy(ev.RelatedPath[:], "<main>")
	ev.ResolvedAddr = ^uint64(0)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Missing lifetime is never merged with a certain instance or each other.
	ev.ProcessStartTicks = 0
	ev.ExePath = [256]byte{}
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLoaderEvents(ctx, store.ListLoaderEventsParams{Limit: 100})
	if err != nil || len(rows) != 7 {
		t.Fatalf("events %d %v", len(rows), err)
	}
	if rows[0].Exe != "/bin/old" || rows[1].Exe != "/bin/new" || rows[2].EventType != "SEARCH" || rows[3].EventType != "OBJECT_CLOSE" {
		t.Fatalf("event identity changed: %+v", rows)
	}
	if rows[0].ProcessKey == rows[4].ProcessKey || rows[5].ProcessKey == rows[6].ProcessKey || rows[5].Exe != "" {
		t.Fatal("process lifetime alias")
	}
	if rows[0].NamespaceID != "18446744073709551615" || rows[4].ResolvedAddr != "ffffffffffffffff" || rows[0].PeerUid != 123 || rows[0].Tid != 43 {
		t.Fatal("metadata lost")
	}
	proc, err := s.GetProcessInstance(ctx, "42:100")
	if err != nil || proc.Exe != "/bin/new" || proc.FirstSeen != 10 || proc.LastSeen != 40 {
		t.Fatalf("registry: %+v %v", proc, err)
	}
	// A delayed pre-exec search did not revert the latest registry identity.
	loads, err := s.ListSOEventsForPID(ctx, 42)
	if err != nil || len(loads) != 2 {
		t.Fatal("search or close treated as load")
	}
	if p.Stats().Persisted != 7 || p.Stats().UnresolvedIdentity != 2 {
		t.Fatalf("health: %+v", p.Stats())
	}
	s.Close()
	if err := p.Process(ctx, ev); err == nil || p.Stats().PersistenceFailures != 1 {
		t.Fatal("write failure not reported")
	}
}

func TestTruncationRemainsUncertain(t *testing.T) {
	for _, flags := range []uint16{proto.FlagExeTruncated, proto.FlagExeUnresolved} {
		ev := &proto.Event{PID: 999999, ProcessStartTicks: 1, Flags: flags}
		copy(ev.ExePath[:], "/partial/path")
		if exe, status := EnrichExecutable(ev); exe != "" || status != "unresolved" {
			t.Fatalf("uncertain path accepted: %q %q", exe, status)
		}
	}
}
