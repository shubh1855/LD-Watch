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

CREATE TABLE IF NOT EXISTS legacy_alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    severity  TEXT    NOT NULL,
    rule      TEXT    NOT NULL,
    pid       INTEGER NOT NULL,
    exe       TEXT    NOT NULL,
    detail    TEXT    NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS legacy_baseline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    event_type INTEGER NOT NULL,
    so_path TEXT,
    symbol_name TEXT,
    resolved_so TEXT,
    resolved_addr INTEGER,
    timestamp INTEGER NOT NULL
);

CREATE TABLE process_instances (
    process_key TEXT PRIMARY KEY,
    pid INTEGER NOT NULL,
    start_ticks TEXT NOT NULL,
    exe TEXT NOT NULL,
    identity_status TEXT NOT NULL CHECK(identity_status IN ('source', 'unresolved', 'legacy')),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX process_pid_start ON process_instances(pid, start_ticks);

CREATE TABLE loader_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_key TEXT NOT NULL REFERENCES process_instances(process_key),
    pid INTEGER NOT NULL,
    tid INTEGER NOT NULL,
    exe TEXT NOT NULL,
    wire_exe TEXT NOT NULL,
    identity_status TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN ('SEARCH','LOAD','SYMBOL_BIND','OBJECT_CLOSE','LEGACY_LOAD_OR_SEARCH','LEGACY_SYMBOL')),
    origin TEXT NOT NULL,
    flags INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    subject_path TEXT NOT NULL,
    related_path TEXT NOT NULL,
    symbol TEXT NOT NULL,
    resolved_addr TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    peer_pid INTEGER NOT NULL,
    peer_uid INTEGER NOT NULL,
    peer_gid INTEGER NOT NULL
);
CREATE INDEX loader_process_cursor ON loader_events(process_key, id);
CREATE INDEX loader_pid_cursor ON loader_events(pid, id);
CREATE INDEX loader_timestamp ON loader_events(timestamp);

CREATE TABLE baseline_candidates (
    exe TEXT NOT NULL CHECK(exe != ''),
    environment_key TEXT NOT NULL CHECK(environment_key != ''),
    entry_type TEXT NOT NULL CHECK(entry_type IN ('LOAD','SYMBOL_PROVIDER')),
    identity TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '',
    observation_count INTEGER NOT NULL CHECK(observation_count > 0),
    PRIMARY KEY(exe, environment_key, entry_type, identity, symbol)
);
CREATE TABLE baseline_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exe TEXT NOT NULL CHECK(exe != ''),
    environment_key TEXT NOT NULL CHECK(environment_key != ''),
    version INTEGER NOT NULL CHECK(version > 0),
    approval_state TEXT NOT NULL CHECK(approval_state IN ('candidate','approved','retired')),
    metadata TEXT NOT NULL CHECK(json_valid(metadata)),
    UNIQUE(exe, environment_key, version)
);
CREATE TABLE baseline_entries (
    baseline_id INTEGER NOT NULL REFERENCES baseline_versions(id),
    entry_type TEXT NOT NULL CHECK(entry_type IN ('LOAD','SYMBOL_PROVIDER')),
    identity TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '',
    optional INTEGER NOT NULL CHECK(optional IN (0,1)),
    PRIMARY KEY(baseline_id, entry_type, identity, symbol)
);
CREATE TABLE baseline_active (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    baseline_id INTEGER NOT NULL REFERENCES baseline_versions(id),
    PRIMARY KEY(exe, environment_key)
);
CREATE TABLE baseline_learning_cursors (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    event_id INTEGER NOT NULL CHECK(event_id >= 0),
    PRIMARY KEY(exe, environment_key)
);
CREATE TABLE baseline_candidate_policies (
    exe TEXT NOT NULL,
    environment_key TEXT NOT NULL,
    entry_type TEXT NOT NULL CHECK(entry_type IN ('LOAD','SYMBOL_PROVIDER')),
    identity TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '',
    optional INTEGER NOT NULL CHECK(optional IN (0,1)),
    PRIMARY KEY(exe,environment_key,entry_type,identity,symbol)
);
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    rule TEXT NOT NULL CHECK(rule IN ('UNKNOWN_SO','PATH_HIJACK','SYMBOL_INTERPOSITION','MISSING_BASELINE')),
    process_key TEXT NOT NULL REFERENCES process_instances(process_key),
    pid INTEGER NOT NULL,
    exe TEXT NOT NULL,
    detail TEXT NOT NULL CHECK(json_valid(detail)),
    timestamp INTEGER NOT NULL,
    deduplication_key TEXT NOT NULL UNIQUE
);
CREATE INDEX alerts_timestamp ON alerts(timestamp);
CREATE INDEX alerts_severity_timestamp ON alerts(severity, timestamp);
