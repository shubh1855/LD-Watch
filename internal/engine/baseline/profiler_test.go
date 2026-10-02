package baseline

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/shubh1855/ld-watch/internal/store"
)

func TestProfilesAreScopedApprovedSelectedAndPersistent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "profiles.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	seed := func(key, exe, kind, subject, related, symbol, status string, at int64) {
		t.Helper()
		if _, err := db.Exec(`INSERT OR IGNORE INTO process_instances(process_key,pid,start_ticks,exe,identity_status,first_seen,last_seen) VALUES(?,1,'1',?,'source',?,?)`, key, exe, at, at); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO loader_events(process_key,pid,tid,exe,wire_exe,identity_status,event_type,origin,flags,namespace_id,subject_path,related_path,symbol,resolved_addr,timestamp,peer_pid,peer_uid,peer_gid) VALUES(?,1,1,?,? ,? ,?,'unknown',0,'1',?,?,?,'0',?,1,1,1)`, key, exe, exe, status, kind, subject, related, symbol, at); err != nil {
			t.Fatal(err)
		}
	}
	seed("1:1", "/usr/bin/alpha", "LOAD", "/lib/libalpha.so", "", "", "source", 10)
	seed("1:1", "/usr/bin/alpha", "SYMBOL_BIND", "/lib/requester.so", "/lib/libc.so.6", "open", "source", 11)
	seed("1:1", "/usr/bin/alpha", "SEARCH", "/tmp/unconfirmed.so", "", "", "source", 12)
	seed("2:1", "/usr/bin/beta", "LOAD", "/lib/libbeta.so", "", "", "source", 13)
	seed("3:1", "/usr/bin/alpha", "LOAD", "/tmp/legacy.so", "", "", "legacy", 14)
	p := New(db)
	if err := p.ProfileExecutable(ctx, "/usr/bin/alpha", "production"); err != nil {
		t.Fatal(err)
	}
	if err := p.ProfileExecutable(ctx, "/usr/bin/alpha", "production"); err != nil {
		t.Fatal(err)
	} // cursor makes this idempotent
	if err := p.ProfileExecutable(ctx, "/usr/bin/beta", "production"); err != nil {
		t.Fatal(err)
	}
	a, err := p.Candidate(ctx, "/usr/bin/alpha", "production")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Candidate(ctx, "/usr/bin/beta", "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Libraries) != 1 || len(a.Symbols) != 1 || a.Libraries[0].Identity != "/lib/libalpha.so" || a.Symbols[0].Provider != "/lib/libc.so.6" {
		t.Fatalf("unexpected confirmed profile: %#v", a)
	}
	if len(b.Libraries) != 1 || b.Libraries[0].Identity == a.Libraries[0].Identity {
		t.Fatal("candidate events crossed executable identities")
	}
	if err := p.ProfileExecutable(ctx, "/usr/bin/alpha", "staging"); err != nil {
		t.Fatal(err)
	}
	staging, err := p.Candidate(ctx, "/usr/bin/alpha", "staging")
	if err != nil || staging.EnvironmentKey != "staging" || staging.Version != 1 {
		t.Fatalf("environment scope not isolated: %#v %v", staging, err)
	}
	if _, err := p.Reload(ctx, "/usr/bin/alpha", "production"); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("unselected candidate visible: %v", err)
	}
	if err := p.SetOptional(ctx, "/usr/bin/alpha", "production", "/lib/libalpha.so", true); err != nil {
		t.Fatal(err)
	}
	version, err := p.Approve(ctx, "/usr/bin/alpha", "production")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("approved version=%d, want 1", version)
	}
	if err := p.Activate(ctx, "/usr/bin/alpha", "production", version); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p = New(db)
	active, err := p.Reload(ctx, "/usr/bin/alpha", "production")
	if err != nil {
		t.Fatal(err)
	}
	if active.Version != 1 || !active.Libraries[0].Optional || active.DetectionPolicy().ExpectedSO["open"] != "/lib/libc.so.6" {
		t.Fatalf("unexpected persisted profile: %#v", active)
	}
	if _, err := p.Reload(ctx, "/usr/bin/beta", "production"); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("unapproved executable returned a profile: %v", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO process_instances(process_key,pid,start_ticks,exe,identity_status,first_seen,last_seen) VALUES('4:1',4,'1','/usr/bin/alpha','source',20,20)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO loader_events(process_key,pid,tid,exe,wire_exe,identity_status,event_type,origin,flags,namespace_id,subject_path,related_path,symbol,resolved_addr,timestamp,peer_pid,peer_uid,peer_gid) VALUES('4:1',4,4,'/usr/bin/alpha','/usr/bin/alpha','source','LOAD','unknown',0,'1','/lib/libnew.so','','','0',20,4,1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := p.ProfileExecutable(ctx, "/usr/bin/alpha", "production"); err != nil {
		t.Fatal(err)
	}
	active, err = p.Reload(ctx, "/usr/bin/alpha", "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Libraries) != 1 {
		t.Fatal("new observations changed an approved active version")
	}
	candidate, err := p.Candidate(ctx, "/usr/bin/alpha", "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Libraries) != 2 {
		t.Fatalf("expected a separate candidate for post-approval observations, got %#v", candidate.Libraries)
	}
}
