-- name: UpsertProcessInstance :exec
INSERT INTO process_instances(process_key,pid,start_ticks,exe,identity_status,first_seen,last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(process_key) DO UPDATE SET
first_seen=CASE WHEN excluded.first_seen = 0 THEN first_seen WHEN first_seen = 0 THEN excluded.first_seen ELSE MIN(first_seen,excluded.first_seen) END,
last_seen=CASE WHEN excluded.last_seen = 0 THEN last_seen WHEN last_seen = 0 THEN excluded.last_seen ELSE MAX(last_seen,excluded.last_seen) END,
exe=CASE WHEN excluded.exe != '' AND excluded.last_seen > 0 AND excluded.last_seen >= last_seen THEN excluded.exe ELSE exe END,
identity_status=CASE WHEN excluded.exe != '' AND excluded.last_seen > 0 AND excluded.last_seen >= last_seen THEN excluded.identity_status ELSE identity_status END;

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

-- name: ListBaselineCandidatePolicies :many
SELECT exe,environment_key,entry_type,identity,symbol,optional FROM baseline_candidate_policies
WHERE exe = ? AND environment_key = ? ORDER BY entry_type,identity,symbol;

-- name: UpsertBaselineCandidatePolicy :exec
INSERT INTO baseline_candidate_policies(exe,environment_key,entry_type,identity,symbol,optional)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(exe,environment_key,entry_type,identity,symbol) DO UPDATE SET optional=excluded.optional;

-- name: GetActiveBaseline :one
SELECT v.id,v.exe,v.environment_key,v.version,v.approval_state,v.metadata
FROM baseline_active a JOIN baseline_versions v ON v.id=a.baseline_id
WHERE a.exe = ? AND a.environment_key = ? AND v.approval_state='approved';

-- name: UpsertActiveBaseline :exec
INSERT INTO baseline_active(exe,environment_key,baseline_id)
SELECT exe,environment_key,id FROM baseline_versions
WHERE exe = ? AND environment_key = ? AND version = ? AND approval_state='approved'
ON CONFLICT(exe,environment_key) DO UPDATE SET baseline_id=excluded.baseline_id;

-- name: GetLatestBaselineVersion :one
SELECT COALESCE(MAX(version),0) FROM baseline_versions WHERE exe = ? AND environment_key = ?;

-- name: InspectApprovedBaseline :one
SELECT id,exe,environment_key,version,approval_state,metadata FROM baseline_versions
WHERE exe = ? AND environment_key = ? AND version = ? AND approval_state='approved';

-- name: InsertAlert :one
INSERT INTO alerts(id,severity,rule,process_key,pid,exe,detail,timestamp,deduplication_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: ListAlerts :many
SELECT * FROM alerts ORDER BY timestamp DESC, id LIMIT ?;

-- name: ListAlertsBySeverity :many
SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC, id LIMIT ?;

-- name: ListAlertsForReport :many
SELECT * FROM alerts
WHERE (? = '' OR severity = ?)
  AND (? = 0 OR timestamp >= ?)
  AND (? = 0 OR timestamp < ?)
ORDER BY timestamp DESC, id
LIMIT ? OFFSET ?;

-- name: DeleteExpiredEvents :execrows
DELETE FROM loader_events WHERE id IN (SELECT id FROM loader_events WHERE loader_events.timestamp > 0 AND loader_events.timestamp < ? AND event_type IN ('SEARCH','LOAD','SYMBOL_BIND','OBJECT_CLOSE') ORDER BY loader_events.timestamp LIMIT ?);
