package store

import (
	"database/sql"
	_ "embed"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var ddl string

// Open opens (or creates) the SQLite database at path and verifies connectivity.
// MaxOpenConns is capped at 1: SQLite serialises writes, and :memory: databases
// are per-connection (a second connection would see a different, empty DB).
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

// Migrate runs the CREATE TABLE IF NOT EXISTS DDL statements from schema.sql.
func Migrate(db *sql.DB) error {
	_, err := db.Exec(ddl)
	return err
}
