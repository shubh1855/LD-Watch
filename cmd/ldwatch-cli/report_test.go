package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shubh1855/ld-watch/internal/store"
)

func seedReportAlerts(t *testing.T, count int) (string, *sql.DB, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO process_instances VALUES ('1:1',1,'1','/bin/test','source',?,?)`, base, base); err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO alerts VALUES (?,?,'UNKNOWN_SO','1:1',1,'/bin/test','{}',?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := 0; i < count; i++ {
		severity := "HIGH"
		if i%2 != 0 {
			severity = "CRITICAL"
		}
		id := fmt.Sprintf("alert-%05d", i)
		if _, err := stmt.Exec(id, severity, base+int64(i)*int64(time.Second), id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return path, db, base
}

func TestReportExportsAllFilteredAlerts(t *testing.T) {
	path, _, _ := seedReportAlerts(t, 10050)
	for _, tc := range []struct {
		name  string
		flags []string
		want  int
	}{
		{"unbounded", nil, 10050},
		{"severity", []string{"--severity", "HIGH"}, 5025},
		{"historical", []string{"--since", "2025-01-01T00:00:10Z", "--until", "2025-01-01T00:00:30Z"}, 20},
		{"historical severity", []string{"--severity", "HIGH", "--since", "2025-01-01T00:00:10Z", "--until", "2025-01-01T00:00:30Z"}, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report.json")
			args := append([]string{"report", "--db", path, "--output", output}, tc.flags...)
			if code := run(args); code != 0 {
				t.Fatalf("report exit=%d", code)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var alerts []store.Alert
			if err := json.Unmarshal(data, &alerts); err != nil {
				t.Fatal(err)
			}
			if len(alerts) != tc.want {
				t.Fatalf("count=%d want=%d", len(alerts), tc.want)
			}
			seen := map[string]bool{}
			for _, alert := range alerts {
				if seen[alert.ID] {
					t.Fatalf("duplicate alert %s", alert.ID)
				}
				seen[alert.ID] = true
			}
		})
	}
}

type concurrentReportDB struct {
	*sql.DB
	writer *sql.DB
	base   int64
	wrote  bool
}

func (db *concurrentReportDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	rows, err := db.DB.QueryContext(ctx, query, args...)
	if err != nil || db.wrote || !strings.Contains(query, "ListAlertsForReport") {
		return rows, err
	}
	// The reader has started; a separate collector connection now inserts a
	// newer alert. WAL lets the write commit while the read cursor stays open.
	db.wrote = true
	_, err = db.writer.ExecContext(ctx, `INSERT INTO alerts VALUES ('new','HIGH','UNKNOWN_SO','1:1',1,'/bin/test','{}',?,'new')`, db.base+int64(20000)*int64(time.Second))
	if err != nil {
		rows.Close()
		return nil, err
	}
	return rows, nil
}

func TestReportRetainsSnapshotDuringCollectorInsert(t *testing.T) {
	path, db, base := seedReportAlerts(t, 2001)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	writer, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader := &concurrentReportDB{DB: db, writer: writer, base: base}
	alerts, err := reportRows(context.Background(), store.New(reader), "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reader.wrote {
		t.Fatal("collector insert did not execute")
	}
	if len(alerts) != 2001 {
		t.Fatalf("snapshot count=%d want=2001", len(alerts))
	}
	seen := map[string]bool{}
	for _, alert := range alerts {
		if seen[alert.ID] || alert.ID == "new" {
			t.Fatalf("duplicate or post-snapshot alert: %s", alert.ID)
		}
		seen[alert.ID] = true
	}
	var count int
	if err := writer.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count); err != nil || count != 2002 {
		t.Fatalf("collector commit count=%d err=%v", count, err)
	}
}
