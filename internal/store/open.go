package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	_ "modernc.org/sqlite"
	"time"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open bounds SQLite lock waits and serializes writes.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err == nil {
		_, err = db.ExecContext(ctx, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=250;")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Migrate atomically applies versions and markers; v1 adopts unversioned DBs.
func Migrate(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)"); err != nil {
		return err
	}
	names := []string{"001_legacy.sql", "002_attribution.sql", "003_unknown_timestamps.sql", "004_baseline_selection.sql"}
	rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return err
	}
	version := 0
	for rows.Next() {
		var marker int
		if err := rows.Scan(&marker); err != nil {
			rows.Close()
			return fmt.Errorf("invalid migration marker: %w", err)
		}
		if marker > len(names) {
			rows.Close()
			return fmt.Errorf("unsupported schema version %d", marker)
		}
		if marker != version+1 {
			rows.Close()
			return fmt.Errorf("invalid migration history: expected version %d, got %d", version+1, marker)
		}
		version = marker
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for i, name := range names {
		if i+1 <= version {
			continue
		}
		ddl, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(ddl)); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version) VALUES (?)", i+1); err != nil {
			return err
		}
	}
	return tx.Commit()
}
