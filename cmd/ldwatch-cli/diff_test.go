package main

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/shubh1855/ld-watch/internal/store"
)

func TestDiffHonorsOptionalBaselineLibraries(t *testing.T) {
	const exe = "/usr/bin/diff-fixture"
	const required = "/lib/required.so"
	const optional = "/lib/optional.so"
	const unexpected = "/tmp/unexpected.so"
	for _, tc := range []struct {
		name     string
		observed []string
		want     []string
	}{
		{name: "optional absent", observed: []string{required}},
		{name: "optional present", observed: []string{required, optional}},
		{name: "required absent", observed: []string{optional}, want: []string{"MISSING\t" + required}},
		{name: "unexpected present", observed: []string{required, unexpected}, want: []string{"UNEXPECTED\t" + unexpected}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "events.db")
			db, err := store.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := store.Migrate(db); err != nil {
				t.Fatal(err)
			}
			q := store.New(db)
			ctx := context.Background()
			for i, library := range []string{required, optional} {
				if err := q.PersistEvent(ctx, reportLoadEvent(exe, library, uint64(i+1)), exe, "source"); err != nil {
					t.Fatal(err)
				}
			}
			if err := q.LearnBaselineEvents(ctx, exe, "test"); err != nil {
				t.Fatal(err)
			}
			if err := q.SetBaselineCandidateOptional(ctx, store.BaselinePolicy{
				Exe: exe, EnvironmentKey: "test", EntryType: "LOAD", Identity: optional, Optional: 1,
			}); err != nil {
				t.Fatal(err)
			}
			version, err := q.ApproveBaseline(ctx, exe, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := q.SelectBaseline(ctx, exe, "test", version.Version); err != nil {
				t.Fatal(err)
			}
			seedRows, err := q.ListLoaderEvents(ctx, store.ListLoaderEventsParams{Limit: 100})
			if err != nil || len(seedRows) != 2 {
				t.Fatalf("baseline seed rows: count=%d err=%v", len(seedRows), err)
			}
			// Exclude training observations so they cannot hide an absent library.
			cursor := seedRows[len(seedRows)-1].ID
			for i, library := range tc.observed {
				if err := q.PersistEvent(ctx, reportLoadEvent(exe, library, uint64(i+3)), exe, "source"); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			out, code := invokeCLI("diff", "--db", dbPath, "--source", "events", "--exe", exe,
				"--environment-key", "test", "--since-id", strconv.FormatInt(cursor, 10))
			if code != 0 {
				t.Fatalf("diff: exit=%d output=%q", code, out)
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if lines[0] != "source=events baseline=v1 executable="+exe {
				t.Fatalf("unexpected diff header: %q", out)
			}
			got := lines[1:]
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("diff findings: got %q, want %q", got, tc.want)
			}
		})
	}
}
