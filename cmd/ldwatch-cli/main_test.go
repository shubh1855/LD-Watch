package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shubh1855/ld-watch/internal/store"
)

func TestAlertsReportAndErrorCases(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "events.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	q := store.New(db)
	ctx := context.Background()
	if err := q.UpsertProcessInstance(ctx, store.UpsertProcessInstanceParams{ProcessKey: "41:900", Pid: 41, StartTicks: "900", Exe: "/usr/bin/curl", IdentityStatus: "source", FirstSeen: 1735732800000000000, LastSeen: 1735732800000000000}); err != nil {
		t.Fatal(err)
	}
	for i, severity := range []string{"HIGH", "CRITICAL"} {
		_, err := q.InsertAlert(ctx, store.InsertAlertParams{ID: severity, Severity: severity, Rule: "UNKNOWN_SO", ProcessKey: "41:900", Pid: 41, Exe: "/usr/bin/curl", Detail: `{"path":"/tmp/untrusted.so"}`, Timestamp: 1735732800000000000 + int64(i), DeduplicationKey: severity})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	out, code := invokeCLI("alerts", "--db", dbPath, "--severity", "CRITICAL")
	if code != 0 || !strings.Contains(out, "CRITICAL") || strings.Contains(out, "HIGH") {
		t.Fatalf("severity filter: exit=%d output=%q", code, out)
	}
	out, code = invokeCLI("report", "--db", dbPath, "--output", "-", "--since", "2025-01-01", "--until", "2025-01-02")
	if code != 0 {
		t.Fatalf("report: exit=%d output=%q", code, out)
	}
	var alerts []store.Alert
	if err := json.Unmarshal([]byte(out), &alerts); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, out)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected two report rows, got %d", len(alerts))
	}
	out, code = invokeCLI("report", "--db", dbPath, "--output", "-", "--since", "2025-02-01", "--until", "2025-02-02")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty report: exit=%d output=%q", code, out)
	}
	for _, args := range [][]string{
		{"alerts", "--db", dbPath, "--severity", "urgent"},
		{"report", "--db", dbPath, "--output", "-", "--since", "2025-99-01"},
		{"report", "--db", dbPath, "--output", "-", "--since", "2025-02-01", "--until", "2025-01-01"},
		{"alerts", "--db", filepath.Join(t.TempDir(), "missing-parent", "events.db")},
	} {
		_, code = invokeCLI(args...)
		if code != 2 && code != 1 {
			t.Fatalf("expected usage or runtime failure for %v, got %d", args, code)
		}
	}
}

func TestEmptyDatabaseAlertAndReport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	out, code := invokeCLI("alerts", "--db", dbPath)
	if code != 0 || out != "" {
		t.Fatalf("empty alerts: exit=%d output=%q", code, out)
	}
	out, code = invokeCLI("report", "--db", dbPath, "--output", "-")
	if code != 0 || strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty report: exit=%d output=%q", code, out)
	}
}

func invokeCLI(args ...string) (string, int) {
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	os.Stdout, os.Stderr = w, w
	code := run(args)
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	b, _ := io.ReadAll(r)
	r.Close()
	return string(b), code
}
