-- name: InsertSOEvent :exec
INSERT INTO so_events (pid, exe, so_path, mechanism, timestamp)
VALUES (?, ?, ?, ?, ?);

-- name: InsertSymbolEvent :exec
INSERT INTO symbol_events (pid, exe, symbol_name, resolved_so, resolved_addr, timestamp)
VALUES (?, ?, ?, ?, ?, ?);

-- name: InsertProcess :exec
INSERT OR IGNORE INTO processes (pid, exe, cmdline, first_seen)
VALUES (?, ?, ?, ?);

-- name: InsertAlert :one
INSERT INTO alerts (severity, rule, pid, exe, detail, timestamp)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListAlerts :many
SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?;

-- name: ListAlertsBySeverity :many
SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?;

-- name: ListSOEventsForPID :many
SELECT * FROM so_events WHERE pid = ? ORDER BY timestamp ASC;

-- name: ListSymbolEventsForPID :many
SELECT * FROM symbol_events WHERE pid = ? ORDER BY timestamp ASC;
