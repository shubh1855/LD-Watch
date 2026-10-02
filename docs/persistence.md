# T05 persistence and attribution

Implemented and locally verified on Linux, 2026-10-01. The collector's
canonical telemetry source is now `loader_events`, with `process_instances` as
its lifetime registry. `schema.sql` describes the final schema for sqlc;
`migrations/001_legacy.sql`, `002_attribution.sql`,
`003_unknown_timestamps.sql`, and `004_baseline_selection.sql` are the runtime
migrations.

## Migration and compatibility

Fresh and unversioned databases migrate transactionally to version 4. Version
markers are stored in `schema_migrations`; reruns do not duplicate imported
rows. Markers must form a contiguous sequence starting at version 1; gaps,
duplicates, non-positive markers, and newer versions are rejected before any
migrations are applied. Version 3 repairs process registry boundaries from
positive event timestamps and rebuilds executable metadata from identified,
timestamped observations. Historical event evidence is preserved.
A migration failure rolls back both
DDL and version markers, and failed store initialization closes its connection.

Existing `so_events`, `symbol_events`, and PID-only `processes` remain archival
source tables. Old alerts move to `legacy_alerts`; old global profiler rows move
to `legacy_baseline_events`. Original strings and details are preserved there.
Old SO and symbol rows are additionally imported into `loader_events` with
`LEGACY_LOAD_OR_SEARCH` / `LEGACY_SYMBOL` and `legacy` identity status. They have
empty executable identity and unresolved lifetime flags. Old rows never become
confirmed loads, candidates, approved baselines, or canonical alerts.

The old global profiler observations remain archival evidence and are never
approved automatically. T06 uses the shared candidate, version, and entry
queries over identified `loader_events`. Migration 004 adds durable learning
cursors, candidate optionality, and selected-version state scoped by executable
and explicit environment key. Approval freezes candidate entries into a numbered
version; reload returns only the selected approved version.

Symbol-provider learning uses `SYMBOL_BIND.subject_path` as the provider and
`related_path` as the requester. Truncated provider, requester, or symbol fields
and unresolved object attribution cannot train a candidate. Regression tests
exercise decoded wire records through persistence, learning, approval, and reload.

Profiles learned with the initial T06 implementation may contain requester paths
as providers. This correction does not rewrite existing candidates or immutable
approved versions. Re-profile retained telemetry under a new explicit environment
label, inspect and approve the corrected candidate, then select that version.
Retained telemetry must cover the intended profile; deleted observations cannot
be recovered by re-profiling.

## Identity and queries

Certain process keys are `pid:start_ticks`. Missing lifetime produces a unique
`unresolved:<UUID>` key for each observation: no unproven coalescing across PID
reuse, restart, or two unresolved records. Each event keeps PID, TID, executable
snapshot/status, raw `wire_exe`, origin, flags, namespace, provider/requester,
symbol, timestamp, and peer credential snapshot.

Executable enrichment uses initialization metadata in the wire record. There is
no PID cache or later PID-only lookup. A missing or truncated path remains
unresolved, preserving its raw string and flags. This survives short-lived
process exit and avoids attributing an old record to a replacement executable.
Executable path identity remains source-supplied evidence, as defined in T01.

Process registry first/last seen values use positive event timestamps. Zero is
an unknown sentinel until a timestamped event establishes each boundary; later
zero-time events cannot change either boundary or select executable metadata.
An instance observed only at unknown times retains an unresolved registry
executable, while its events retain their individual source identities. The latest
identified snapshot updates registry metadata; delayed earlier records cannot
revert it. Historical events keep their own identity across executable
replacement. Timestamp-zero records cannot establish time ordering.

All searches are stored as `SEARCH`; only `LOAD` enters the loaded-object query.
`SYMBOL_BIND` and `OBJECT_CLOSE` remain separate observations. No inferred
search-to-load origin correlation is performed. Close records preserve the
process, namespace and subject tuple for consumers to reconstruct object
lifecycle; persistence does not maintain a second active-object cache.

Use `ListLoaderEvents` / `ListEventsForProcess` with an event-ID cursor and a
caller-supplied limit. `ListSOEventsForPID` and `ListSymbolEventsForPID` are
compatibility convenience queries over new confirmed telemetry; lifetime-aware
consumers should use the process-key query. Baseline queries scope executable,
explicit environment label, and selected approved version. Alert storage uses
UUIDs, canonical uppercase severity/rule constraints, JSON detail, a process
foreign key, and a unique deduplication key. `WriteAlert` requires the T01 detail
keys. It reports errors and does not silently fabricate a stored alert.

Start ticks and namespace IDs are decimal text; addresses are lowercase
hexadecimal text without `0x`, preserving the entire unsigned 64-bit range in
SQLite. Timestamps use signed Unix nanoseconds; overflowing wire values are
rejected rather than wrapped. A zero timestamp remains unknown.

## Failure and retention policy

Each event and its process registry update commit in one transaction. A failed
event insert rolls back registry changes. SQLite serializes writes through one
connection and waits at most 250ms on lock contention. Processor work and high-level event, alert and retention writes have a
2-second context deadline; initialization/migration use 5/10-second deadlines.
There is no application retry loop. Disk-full, busy, and other write errors are
returned, counted, and the event is dropped; the collector continues accepting
subsequent events. No success counter is incremented on failure.

Processor health snapshots report persisted records, persistence failures,
unresolved executable identity and degraded object attribution. Failure logs
cover the first five failures and every hundredth failure; the full snapshot is
logged at shutdown. These counters are in memory and reset at collector restart.
There is no durable overflow spool or automatic deletion on disk-full.

Retention is disabled by default. The explicit `Store.RetainEvents` API accepts
a positive cutoff in Unix nanoseconds and a batch of 1..10,000 rows. Each call
removes at most that batch of new, timestamped telemetry older than the cutoff.
Unknown timestamps, legacy evidence, process registry entries, baselines, and
alerts are retained. Database size therefore still needs operator monitoring;
retention does not reclaim filesystem space with automatic VACUUM. No journal
or batching tuning is claimed without workload measurements (T09).

Indexes support lifetime lookup, process/PID event cursors, retention by time,
alert time/severity filtering, and executable/environment/version baseline
selection. Ingress connection and queue limits remain the T04 policy.

## Evidence

- `internal/store/persistence_test.go`: fresh/unversioned migration, legacy
  preservation, repeat migration, restart persistence, rollback on failed
  initialization, atomic write failure, bounded lock wait, actual SQLite
  disk-full simulation using `max_page_count`, retention validation, canonical
  alert/deduplication and scoped baseline queries.
- `internal/collector/processor_test.go`: process lifetime/PID reuse,
  executable replacement, delayed records, searches and closes, unresolved
  instances, full-range namespace/address values, peer/TID metadata, and health.
- `internal/store/ordering_test.go`: unknown times before, between, and after
  timestamped events, all-unknown instances, repair of previously corrupt
  registry values without altering event evidence, and rejection of sparse or
  invalid migration history before schema changes.
- `tests/integration/persistence_test.go`: builds the real audit library into
  an owned temporary directory, runs `/bin/true` with `LD_AUDIT`, and verifies
  actual C records persist through the socket and four collector workers with
  executable, lifetime and peer identity. Build/runtime fixtures are isolated.
- SQL sources regenerated using pinned sqlc v1.31.1. Go runtime checks use the
  installed Go 1.26.1 Linux toolchain; sqlc's isolated tool invocation selected
  Go 1.26.8. Required checks: `go test -race ./...`, `go vet ./...`.

This acceptance evidence establishes local persistence, not full detection,
sustained throughput, universal no-loss behavior, or production certification.
