ALTER TABLE alerts RENAME TO legacy_alerts;

-- Preserve the old global profiler observations without approving them.
CREATE TABLE IF NOT EXISTS baseline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    event_type INTEGER NOT NULL,
    so_path TEXT,
    symbol_name TEXT,
    resolved_so TEXT,
    resolved_addr INTEGER,
    timestamp INTEGER NOT NULL
);
ALTER TABLE baseline_events RENAME TO legacy_baseline_events;

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
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    rule TEXT NOT NULL CHECK(rule IN ('UNKNOWN_SO','PATH_HIJACK','SYMBOL_INTERPOSITION')),
    process_key TEXT NOT NULL REFERENCES process_instances(process_key),
    pid INTEGER NOT NULL,
    exe TEXT NOT NULL,
    detail TEXT NOT NULL CHECK(json_valid(detail)),
    timestamp INTEGER NOT NULL,
    deduplication_key TEXT NOT NULL UNIQUE
);
CREATE INDEX alerts_timestamp ON alerts(timestamp);
CREATE INDEX alerts_severity_timestamp ON alerts(severity, timestamp);

-- Old SO rows cannot distinguish searches from loads. Keep their original
-- tables and executable strings as archival evidence, and import uncertain
-- observations without treating those strings as executable identity.
INSERT INTO process_instances
SELECT 'legacy:' || pid, pid, '0', '', 'legacy', MIN(timestamp), MAX(timestamp)
FROM (SELECT pid, timestamp FROM so_events UNION ALL SELECT pid, timestamp FROM symbol_events)
GROUP BY pid;
INSERT INTO loader_events(process_key,pid,tid,exe,wire_exe,identity_status,event_type,origin,flags,namespace_id,subject_path,related_path,symbol,resolved_addr,timestamp,peer_pid,peer_uid,peer_gid)
SELECT 'legacy:' || pid,pid,0,'','','legacy','LEGACY_LOAD_OR_SEARCH',mechanism,48,'0',so_path,'','','0',timestamp,0,0,0 FROM so_events;
INSERT INTO loader_events(process_key,pid,tid,exe,wire_exe,identity_status,event_type,origin,flags,namespace_id,subject_path,related_path,symbol,resolved_addr,timestamp,peer_pid,peer_uid,peer_gid)
SELECT 'legacy:' || pid,pid,0,'','','legacy','LEGACY_SYMBOL','unknown',48,'0',resolved_so,'',symbol_name,printf('%x', resolved_addr),timestamp,0,0,0 FROM symbol_events;
