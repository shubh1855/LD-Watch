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
	var version int
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	names := []string{"001_legacy.sql", "002_attribution.sql"}
	if version > len(names) {
		return fmt.Errorf("unsupported schema version %d", version)
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
