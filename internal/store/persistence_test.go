package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestMigrateLegacyAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := migrations.ReadFile("migrations/001_legacy.sql")
	if _, err = db.Exec(string(old)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO so_events(pid,exe,so_path,mechanism,timestamp) VALUES(12,'/wrong/placeholder','/lib/test.so','standard',7);
 INSERT INTO alerts(severity,rule,pid,exe,detail,timestamp) VALUES('high','old',12,'/bin/old','old detail',8);
 CREATE TABLE baseline_events(id INTEGER PRIMARY KEY, so_path TEXT);
 INSERT INTO baseline_events VALUES(1,'/legacy/provider');`); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(db); err != nil {
		t.Fatal(err)
	}
	var kind, exe string
	if err = db.QueryRow("SELECT event_type,exe FROM loader_events").Scan(&kind, &exe); err != nil {
		t.Fatal(err)
	}
	if kind != "LEGACY_LOAD_OR_SEARCH" || exe != "" {
		t.Fatalf("legacy incorrectly promoted: %s %q", kind, exe)
	}
	for _, table := range []string{"so_events", "legacy_alerts", "legacy_baseline_events"} {
		var count int
		if err = db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM baseline_versions").Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy baseline promoted")
	}
	db.Close()
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestMigrationRollbackAndInitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE process_instances(bad TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := NewStore(path); err == nil {
		s.Close()
		t.Fatal("expected migration failure")
	}
	// No partially renamed alerts table or version marker survives failure.
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='schema_migrations' OR name='legacy_alerts'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial migration: %d %v", count, err)
	}
	db.Close()
	if err := os.Rename(path, path+".closed"); err != nil {
		t.Fatalf("failed initialization leaked file: %v", err)
	}
}

func TestAtomicEventFailureAndRetention(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.Exec("CREATE TRIGGER fail_event BEFORE INSERT ON loader_events BEGIN SELECT RAISE(ABORT,'fixture failure'); END"); err != nil {
		t.Fatal(err)
	}
	ev := makeSOEvent(1, "/lib/a.so", "standard", 100)
	ev.ProcessStartTicks = 2
	copy(ev.ExePath[:], "/bin/a")
	if err := s.WriteSOEvent(ctx, ev); err == nil {
		t.Fatal("expected write failure")
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM process_instances").Scan(&count)
	if count != 0 {
		t.Fatal("event failure left orphan process")
	}
	s.db.Exec("DROP TRIGGER fail_event")
	if err := s.WriteSOEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RetainEvents(ctx, 101, 1); err != nil || n != 1 {
		t.Fatalf("retention %d %v", n, err)
	}
	if _, err := s.RetainEvents(ctx, 101, 10001); err == nil {
		t.Fatal("unbounded retention accepted")
	}
}

func TestBoundedBusyAndDiskFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	ev := makeSOEvent(1, "/lib/a.so", "standard", 1)
	if err = s.WriteSOEvent(context.Background(), ev); err == nil {
		t.Fatal("expected busy error")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("unbounded lock wait")
	}
	other.Exec("ROLLBACK")
	var pages int
	if err = s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	// Force SQLite's actual SQLITE_FULL path without exhausting the host disk.
	if _, err = s.db.Exec("PRAGMA max_page_count=" + strconv.Itoa(pages)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("CREATE TABLE disk_fixture(x BLOB)"); err == nil {
		_, err = s.db.Exec("INSERT INTO disk_fixture VALUES(zeroblob(1048576))")
	}
	if err == nil {
		t.Fatal("expected SQLITE_FULL")
	}
	if err = s.WriteSOEvent(context.Background(), ev); err != nil {
		t.Fatalf("failed write poisoned connection: %v", err)
	}
}

func TestCanonicalAlertsAndBaselines(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	ev := makeSOEvent(9, "/lib/a.so", "standard", 1)
	ev.ProcessStartTicks = 10
	copy(ev.ExePath[:], "/bin/a")
	if err := s.WriteSOEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	detail := `{"event_type":"LOAD","process_instance":"9:10","executable":"/bin/a","observed":{},"baseline":{},"origin":"unknown","flags":0}`
	p := AlertParams{Severity: "HIGH", Rule: "UNKNOWN_SO", ProcessKey: "9:10", PID: 9, Exe: "/bin/a", Detail: detail, TimestampNs: 2, DeduplicationKey: "fixture"}
	alert, err := s.WriteAlert(ctx, p)
	if err != nil || alert.ID == "" {
		t.Fatalf("insert alert: %v", err)
	}
	if _, err = s.WriteAlert(ctx, p); err != nil {
		t.Fatalf("duplicate alert should be an idempotent no-op: %v", err)
	}
	rows, err := s.QueryAlertsBySeverity(ctx, "HIGH", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("alerts: %v %v", rows, err)
	}
	p.DeduplicationKey = "bad"
	p.Detail = "plaintext"
	if _, err = s.WriteAlert(ctx, p); err == nil {
		t.Fatal("invalid detail accepted")
	}
	candidate := UpsertBaselineCandidateParams{Exe: "/bin/a", EnvironmentKey: "fixture", EntryType: "LOAD", Identity: "/lib/a.so"}
	if err = s.UpsertBaselineCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err = s.UpsertBaselineCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	candidates, err := s.ListBaselineCandidates(ctx, ListBaselineCandidatesParams{Exe: "/bin/a", EnvironmentKey: "fixture"})
	if err != nil || len(candidates) != 1 || candidates[0].ObservationCount != 2 {
		t.Fatalf("candidates: %v %v", candidates, err)
	}
	version, err := s.InsertBaselineVersion(ctx, InsertBaselineVersionParams{Exe: "/bin/a", EnvironmentKey: "fixture", Version: 1, ApprovalState: "approved", Metadata: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InsertBaselineEntry(ctx, InsertBaselineEntryParams{BaselineID: version.ID, EntryType: "LOAD", Identity: "/lib/a.so", Optional: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetApprovedBaseline(ctx, GetApprovedBaselineParams{Exe: "/bin/b", EnvironmentKey: "fixture", Version: 1}); err == nil {
		t.Fatal("cross-executable profile returned")
	}
}

func TestEventSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := makeSOEvent(123, "/lib/a.so", "standard", 500)
	copy(ev.ExePath[:], "/bin/short-lived")
	ev.ProcessStartTicks = 456
	if err := s.WriteSOEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.ListEventsForProcess(context.Background(), ListEventsForProcessParams{ProcessKey: "123:456", Limit: 100})
	if err != nil || len(rows) != 1 || rows[0].Exe != "/bin/short-lived" {
		t.Fatalf("restart: %+v %v", rows, err)
	}
}
