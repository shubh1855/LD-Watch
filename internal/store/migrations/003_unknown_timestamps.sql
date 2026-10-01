-- Reconstruct registry ordering from known event times. Zero-timestamp rows
-- remain intact as evidence but cannot choose boundaries or executable metadata.
UPDATE process_instances
SET first_seen = COALESCE((
        SELECT MIN(timestamp) FROM loader_events
        WHERE loader_events.process_key = process_instances.process_key AND timestamp > 0
    ), 0),
    last_seen = COALESCE((
        SELECT MAX(timestamp) FROM loader_events
        WHERE loader_events.process_key = process_instances.process_key AND timestamp > 0
    ), 0);

-- Legacy executable strings remain unresolved; only canonical, identified
-- observations may reconstruct an executable snapshot.
UPDATE process_instances
SET exe = COALESCE((
        SELECT exe FROM loader_events
        WHERE loader_events.process_key = process_instances.process_key
          AND timestamp > 0 AND exe != '' AND identity_status = 'source'
        ORDER BY timestamp DESC, id DESC LIMIT 1
    ), ''),
    identity_status = CASE WHEN EXISTS (
        SELECT 1 FROM loader_events
        WHERE loader_events.process_key = process_instances.process_key
          AND timestamp > 0 AND exe != '' AND identity_status = 'source'
    ) THEN 'source' ELSE 'unresolved' END
WHERE identity_status != 'legacy';
