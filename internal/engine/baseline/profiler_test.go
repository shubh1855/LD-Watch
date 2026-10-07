package baseline

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shubh1855/ld-watch/internal/proto"
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
	seed("1:1", "/usr/bin/alpha", "SYMBOL_BIND", "/lib/libc.so.6", "/lib/requester.so", "open", "source", 11)
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
	if active.Version != 1 || !active.Libraries[0].Optional || !reflect.DeepEqual(active.DetectionPolicy().ExpectedSO["open"], []string{"/lib/libc.so.6"}) {
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

func TestSymbolLearningUsesCompleteWireProvider(t *testing.T) {
	for _, tt := range []struct {
		name  string
		flags uint16
		want  int
	}{
		{"complete binding", 0, 1},
		{"truncated provider", proto.FlagSubjectTruncated, 0},
		{"truncated requester", proto.FlagRelatedTruncated, 0},
		{"truncated symbol", proto.FlagSymbolTruncated, 0},
		{"unresolved object", proto.FlagObjectUnresolved, 0},
		{"truncated executable", proto.FlagExeTruncated, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := store.Migrate(db); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			ev := &proto.Event{PID: 42, TID: 43, ProcessStartTicks: 100, TimestampNs: 10, EventType: proto.EventSymBind, ResolvedAddr: 123, Flags: tt.flags}
			copy(ev.ExePath[:], "/usr/bin/alpha")
			// Match the C source and wire contract: subject is the provider,
			// related is the requester.
			copy(ev.SOPath[:], "/lib/libc.so.6")
			copy(ev.RelatedPath[:], "/lib/requester.so")
			copy(ev.Symbol[:], "open")
			decoded, err := proto.Decode(ev.MarshalBinary())
			if err != nil {
				t.Fatal(err)
			}
			q := store.New(db)
			exe, status := store.SourceExecutable(decoded)
			if err := q.PersistEvent(ctx, decoded, exe, status); err != nil {
				t.Fatal(err)
			}
			p := New(db)
			// Repeated learning must not double-count an accepted binding.
			for i := 0; i < 2; i++ {
				if err := p.ProfileExecutable(ctx, "/usr/bin/alpha", "production"); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := q.ListBaselineCandidates(ctx, store.ListBaselineCandidatesParams{Exe: "/usr/bin/alpha", EnvironmentKey: "production"})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != tt.want {
				t.Fatalf("candidate count = %d, want %d: %#v", len(rows), tt.want, rows)
			}
			if tt.want == 0 {
				return
			}
			if rows[0].Identity != "/lib/libc.so.6" || rows[0].Symbol != "open" || rows[0].ObservationCount != 1 {
				t.Fatalf("incorrect learned binding: %#v", rows[0])
			}
			version, err := p.Approve(ctx, "/usr/bin/alpha", "production")
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Activate(ctx, "/usr/bin/alpha", "production", version); err != nil {
				t.Fatal(err)
			}
			active, err := p.Reload(ctx, "/usr/bin/alpha", "production")
			if err != nil {
				t.Fatal(err)
			}
			if got := active.DetectionPolicy().ExpectedSO["open"]; !reflect.DeepEqual(got, []string{"/lib/libc.so.6"}) {
				t.Fatalf("approved providers = %v, want /lib/libc.so.6", got)
			}
		})
	}
}

func TestDetectionPolicyPreservesAllSymbolProviders(t *testing.T) {
	for _, symbols := range [][]Symbol{
		{{Name: "open", Provider: "/lib/libc.so.6"}, {Name: "open", Provider: "/opt/libalternate.so"}},
		{{Name: "open", Provider: "/opt/libalternate.so"}, {Name: "open", Provider: "/lib/libc.so.6"}},
		{{Name: "open", Provider: "/lib/./libc.so.6"}, {Name: "open", Provider: "/opt/libalternate.so"}, {Name: "open", Provider: "/lib/libc.so.6"}},
	} {
		profile := &Profile{Executable: "/bin/app", EnvironmentKey: "production", Symbols: symbols}
		got := profile.DetectionPolicy().ExpectedSO["open"]
		want := []string{"/lib/libc.so.6", "/opt/libalternate.so"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("approved providers = %v, want %v", got, want)
		}
	}
}
