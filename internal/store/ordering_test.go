package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestUnknownTimestampsDoNotEstablishRegistryOrdering(t *testing.T) {
	tests := []struct {
		name                string
		times               []uint64
		wantFirst, wantLast int64
		wantExe             string
	}{
		{"unknown first", []uint64{0, 20, 10, 30}, 10, 30, "/bin/d"},
		{"unknown between", []uint64{20, 0, 10, 30}, 10, 30, "/bin/d"},
		{"unknown last", []uint64{20, 10, 30, 0}, 10, 30, "/bin/c"},
		{"only unknown", []uint64{0, 0, 0}, 0, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			for i, ts := range tt.times {
				ev := makeSOEvent(42, "/lib/a.so", "standard", ts)
				ev.ProcessStartTicks = 100
				copy(ev.ExePath[:], "/bin/"+string(rune('a'+i)))
				if err := s.WriteSOEvent(ctx, ev); err != nil {
					t.Fatal(err)
				}
			}
			proc, err := s.GetProcessInstance(ctx, "42:100")
			if err != nil {
				t.Fatal(err)
			}
			if proc.FirstSeen != tt.wantFirst || proc.LastSeen != tt.wantLast || proc.Exe != tt.wantExe {
				t.Fatalf("registry: %+v; want first=%d last=%d exe=%q", proc, tt.wantFirst, tt.wantLast, tt.wantExe)
			}
			if tt.wantExe == "" && proc.IdentityStatus != "unresolved" {
				t.Fatal("unknown observations selected registry identity")
			}
			rows, err := s.ListEventsForProcess(ctx, ListEventsForProcessParams{ProcessKey: "42:100", Limit: 100})
			if err != nil || len(rows) != len(tt.times) {
				t.Fatalf("events %d %v", len(rows), err)
			}
			for i, row := range rows {
				if row.Timestamp != int64(tt.times[i]) || row.Exe != "/bin/"+string(rune('a'+i)) || row.IdentityStatus != "source" {
					t.Fatalf("event evidence changed: %+v", row)
				}
			}
		})
	}
}

func TestMigrationRepairsUnknownTimestampRegistry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, row := range []struct {
		pid uint32
		ts  uint64
		exe string
	}{
		{42, 20, "/bin/known"}, {42, 0, "/bin/unknown"}, {43, 0, "/bin/only-unknown"},
	} {
		ev := makeSOEvent(row.pid, "/lib/a.so", "standard", row.ts)
		ev.ProcessStartTicks = 100
		copy(ev.ExePath[:], row.exe)
		if err := s.WriteSOEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.ListLoaderEvents(ctx, ListLoaderEventsParams{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce registries left by the old zero-time MIN/MAX and metadata logic.
	if _, err = s.db.Exec(`DROP TABLE baseline_candidate_policies;
 DROP TABLE baseline_learning_cursors;
 DROP TABLE baseline_active;
	 DELETE FROM schema_migrations WHERE version IN (3,4,5);
 UPDATE process_instances SET first_seen=0, exe='/bin/unknown', identity_status='source' WHERE pid=42;
 UPDATE process_instances SET exe='/bin/only-unknown', identity_status='source' WHERE pid=43;`); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(s.db); err != nil {
		t.Fatal(err)
	}
	proc, err := s.GetProcessInstance(ctx, "42:100")
	if err != nil || proc.FirstSeen != 20 || proc.LastSeen != 20 || proc.Exe != "/bin/known" || proc.IdentityStatus != "source" {
		t.Fatalf("repair: %+v %v", proc, err)
	}
	unknown, err := s.GetProcessInstance(ctx, "43:100")
	if err != nil || unknown.FirstSeen != 0 || unknown.LastSeen != 0 || unknown.Exe != "" || unknown.IdentityStatus != "unresolved" {
		t.Fatalf("unknown repair: %+v %v", unknown, err)
	}
	after, err := s.ListLoaderEvents(ctx, ListLoaderEventsParams{Limit: 100})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("migration altered raw events: %v", err)
	}
	if err = Migrate(s.db); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationRejectsInvalidHistory(t *testing.T) {
	tests := []struct {
		name    string
		markers []int
	}{
		{"missing first", []int{2}}, {"missing middle", []int{1, 3}},
		{"zero", []int{0}}, {"negative", []int{-1}},
		{"future", []int{1, 2, 3, 4, 5, 6}}, {"duplicate", []int{1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// No uniqueness constraint lets the duplicate-marker case simulate corrupt DDL.
			if _, err = db.Exec("CREATE TABLE schema_migrations(version INTEGER)"); err != nil {
				t.Fatal(err)
			}
			for _, marker := range tt.markers {
				if _, err = db.Exec("INSERT INTO schema_migrations(version) VALUES (?)", marker); err != nil {
					t.Fatal(err)
				}
			}
			err = Migrate(db)
			if err == nil || (!strings.Contains(err.Error(), "migration history") && !strings.Contains(err.Error(), "unsupported schema version")) {
				t.Fatalf("expected history rejection, got %v", err)
			}
			var count int
			if err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='so_events' OR name='process_instances'").Scan(&count); err != nil || count != 0 {
				t.Fatalf("schema mutated before rejection: %d %v", count, err)
			}
			if err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil || count != len(tt.markers) {
				t.Fatalf("markers changed: %d %v", count, err)
			}
		})
	}
}
