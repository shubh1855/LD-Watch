CREATE TABLE alerts_v5 (
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
INSERT INTO alerts_v5(id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key)
SELECT id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key FROM alerts;
DROP TABLE alerts;
ALTER TABLE alerts_v5 RENAME TO alerts;
CREATE INDEX alerts_timestamp ON alerts(timestamp);
CREATE INDEX alerts_severity_timestamp ON alerts(severity, timestamp);
