-- name: UpsertProcessInstance :exec
INSERT INTO process_instances(process_key,pid,start_ticks,exe,identity_status,first_seen,last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(process_key) DO UPDATE SET
first_seen=MIN(first_seen,excluded.first_seen), last_seen=MAX(last_seen,excluded.last_seen),
exe=CASE WHEN excluded.exe != '' AND excluded.last_seen >= last_seen THEN excluded.exe ELSE exe END,
identity_status=CASE WHEN excluded.exe != '' AND excluded.last_seen >= last_seen THEN excluded.identity_status ELSE identity_status END;

-- name: InsertLoaderEvent :exec
INSERT INTO loader_events(process_key,pid,tid,exe,wire_exe,identity_status,event_type,origin,flags,namespace_id,subject_path,related_path,symbol,resolved_addr,timestamp,peer_pid,peer_uid,peer_gid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetProcessInstance :one
SELECT * FROM process_instances WHERE process_key = ?;

-- name: ListLoaderEvents :many
SELECT * FROM loader_events WHERE id > ? ORDER BY id LIMIT ?;

-- name: ListEventsForProcess :many
SELECT * FROM loader_events WHERE process_key = ? AND id > ? ORDER BY id LIMIT ?;

-- name: ListSOEventsForPID :many
SELECT id,pid,exe,subject_path AS so_path,origin AS mechanism,timestamp FROM loader_events
WHERE pid = ? AND event_type = 'LOAD' ORDER BY timestamp, id;

-- name: ListSymbolEventsForPID :many
SELECT id,pid,exe,symbol AS symbol_name,subject_path AS resolved_so,resolved_addr,timestamp FROM loader_events
WHERE pid = ? AND event_type = 'SYMBOL_BIND' ORDER BY timestamp, id;

-- name: UpsertBaselineCandidate :exec
INSERT INTO baseline_candidates(exe,environment_key,entry_type,identity,symbol,observation_count)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(exe,environment_key,entry_type,identity,symbol)
DO UPDATE SET observation_count=observation_count+1;

-- name: ListBaselineCandidates :many
SELECT * FROM baseline_candidates WHERE exe = ? AND environment_key = ? ORDER BY entry_type,identity,symbol;

-- name: InsertBaselineVersion :one
INSERT INTO baseline_versions(exe,environment_key,version,approval_state,metadata)
VALUES (?, ?, ?, ?, ?) RETURNING *;

-- name: InsertBaselineEntry :exec
INSERT INTO baseline_entries(baseline_id,entry_type,identity,symbol,optional) VALUES (?, ?, ?, ?, ?);

-- name: GetApprovedBaseline :one
SELECT * FROM baseline_versions WHERE exe = ? AND environment_key = ? AND version = ? AND approval_state = 'approved';

-- name: ListBaselineEntries :many
SELECT * FROM baseline_entries WHERE baseline_id = ? ORDER BY entry_type,identity,symbol;

-- name: InsertAlert :one
INSERT INTO alerts(id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: ListAlerts :many
SELECT * FROM alerts ORDER BY timestamp DESC, id LIMIT ?;

-- name: ListAlertsBySeverity :many
SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC, id LIMIT ?;

-- name: DeleteExpiredEvents :execrows
DELETE FROM loader_events WHERE id IN (SELECT id FROM loader_events WHERE loader_events.timestamp > 0 AND loader_events.timestamp < ? AND event_type IN ('SEARCH','LOAD','SYMBOL_BIND','OBJECT_CLOSE') ORDER BY loader_events.timestamp LIMIT ?);
