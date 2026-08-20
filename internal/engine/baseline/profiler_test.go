package baseline

import (
	"context"
	"testing"

	"github.com/shubh1855/ld-watch/internal/proto"
	"github.com/shubh1855/ld-watch/internal/store"
)

func makeEvent(pid uint32, soPath string) *proto.Event {
	ev := &proto.Event{PID: pid, EventType: proto.EventSOLoad, TimeStamNs: 12345}
	copy(ev.SOPath[:], soPath)
	return ev
}

func TestProfilerLearnsKnownSO(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	profiler := New(db)
	if err := profiler.CreateTables(ctx); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}

	if err := profiler.Learn(ctx, makeEvent(1234, "/lib/libc.so.6")); err != nil {
		t.Fatalf("Learn: %v", err)
	}

	known, err := profiler.KnownSOs(ctx)
	if err != nil {
		t.Fatalf("KnownSOs: %v", err)
	}
	if !known["/lib/libc.so.6"] {
		t.Fatalf("expected /lib/libc.so.6 in known SO baseline")
	}
}
