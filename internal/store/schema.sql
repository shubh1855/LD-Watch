CREATE TABLE IF NOT EXISTS so_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pid         INTEGER NOT NULL,
    exe         TEXT    NOT NULL,
    so_path     TEXT    NOT NULL,
    mechanism   TEXT    NOT NULL,
    timestamp   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS symbol_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pid           INTEGER NOT NULL,
    exe           TEXT    NOT NULL,
    symbol_name   TEXT    NOT NULL,
    resolved_so   TEXT    NOT NULL,
    resolved_addr INTEGER NOT NULL,
    timestamp     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    pid        INTEGER PRIMARY KEY,
    exe        TEXT    NOT NULL,
    cmdline    TEXT,
    first_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    severity  TEXT    NOT NULL,
    rule      TEXT    NOT NULL,
    pid       INTEGER NOT NULL,
    exe       TEXT    NOT NULL,
    detail    TEXT    NOT NULL,
    timestamp INTEGER NOT NULL
);
