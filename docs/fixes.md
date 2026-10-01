# LD-Watch remediation and implementation plans

Review date: 2026-09-29. These are proposed changes, not implemented fixes.

See [issues](issues.md) for evidence and impact. Execute through [pending tasks](pending-tasks.md), which is the single completion checklist. Do not implement these sections independently in document order: several share a protocol, schema or lifecycle dependency.

## F01 — Agree on contracts before implementation

Addresses I05, I06, I07, I11, I14, I15, I17, I21, I24.

Write one protocol and data-model decision covering:

- Supported Linux loader and architecture; wire version, field lengths and byte order.
- Distinct load, search and symbol-binding event types.
- PID versus TID, process lifetime, executable replacement, and unresolved attribution.
- Executable and library identity, normalization and legitimate aliases.
- Origin evidence: standard, preload, library-path, or unknown; never invent certainty from a search attempt.
- Agreed endpoint configuration and trust boundary.
- Executable-scoped baseline versions and approval state.
- One canonical rule name, uppercase severity vocabulary, JSON detail schema, alert ID format and timestamp unit.

Choose either an explicitly incompatible protocol upgrade with a clear rejection message or a documented compatibility strategy. Do not silently reinterpret existing 408-byte records. Decide transport framing and fork behavior together with peer attribution; connection credentials alone do not identify every sender on an inherited socket.

**Acceptance:** The decision includes example records, schema mappings, lifecycle transitions and compatibility rules. C, collector, store, engine and CLI owners use the same contract.

## F02 — Make audit transport bounded and observable

Addresses I02, I15, I17.

- Implement bounded fail-open behavior so telemetry failure does not block application execution indefinitely.
- Suppress socket SIGPIPE locally without changing the application's global signal policy.
- Define interrupted-write, backpressure, partial-record and reconnect behavior.
- Set close-on-exec and implement the agreed fork connection policy.
- Preserve message integrity across concurrent callbacks; avoid introducing loader-lock deadlocks through naive synchronization.
- Use the agreed endpoint configuration and explicit wire encoding/version validation.
- Track dropped records and reconnect failures using a safe, bounded mechanism.
- Make verbose stderr output optional and document its performance implications.

**Acceptance:** Benign Linux fixtures keep their expected behavior with the collector absent, slow or restarted; records remain decodable; loss is visible. No unbounded retry loop runs inside an audit callback.

## F03 — Repair hook identity and object lifecycle

Addresses I05, I11, I12, I13, I17.

- Emit PID consistently; emit TID separately if retained in the contract.
- Add lifecycle-safe object identifiers and unload cleanup. Include namespace context where required by the identity model.
- Handle map capacity visibly instead of silently losing attribution.
- Preserve actual load versus search semantics and report unknown origin when proof is unavailable.
- Detect path/symbol truncation according to the contract.
- Size decimal uint64 formatting for 20 digits plus terminator; prefixed hexadecimal for 16 digits, prefix and terminator.

**Acceptance:** Threaded and repeated benign load/unload fixtures retain correct identity; full-range formatter checks pass; capacity and truncation produce explicit degraded status.

## F04 — Harden collector lifecycle and ingress

Addresses I03, I04, I05, I10, I16.

- Validate worker counts before opening the database or socket.
- Check an existing socket path's type, ownership and active-instance status. Reject unrelated paths and active collectors.
- Apply the documented socket ownership/access policy and collect OS peer credentials.
- Validate incoming records before inserting process or event rows.
- Enforce connection/resource bounds without using an idle timeout that silently disables legitimate long-running clients.
- Track active connections. On shutdown, stop accepting, drain within a deadline, close remaining clients, drain accepted work and close the event channel exactly once.
- Propagate cancellation and expose rejected, dropped and unresolved-event counts.

**Acceptance:** Shutdown is bounded with idle clients; a second collector cannot displace an active one; invalid configuration and records fail clearly; valid multi-user collection follows the chosen policy.

## F05 — Implement the shared schema and attribution layer once

Addresses I05, I06, I07, I14, I18, I19, I24.

- Add versioned migrations rather than relying solely on `CREATE TABLE IF NOT EXISTS`.
- Preserve event type, process-instance identity, executable identity and uncertainty.
- Replace the PID-only forever-cache and process registry semantics.
- Capture executable metadata early enough for short-lived processes; document any remaining attribution limits.
- Make high-level storage helpers require enriched metadata; remove SO-path executable placeholders.
- Define candidate/approved baseline tables and canonical alert fields in this migration series.
- Add indexes justified by event, baseline and CLI query patterns.
- Close database resources on every initialization failure.
- Define bounded retries, persistence-failure reporting, retention and disk-full behavior. Benchmark before selecting transaction batching or journal changes.
- Edit SQL sources first and regenerate sqlc output; do not maintain conflicting handwritten generated queries.

**Acceptance:** Fresh and existing databases migrate correctly; existing data is preserved or explicitly marked legacy/unresolved; failed initialization releases resources; executable attribution is not inferred from a library path.

## F06 — Complete approved baseline learning

Addresses I06, I07.

- Learn confirmed loads and observed symbol providers for a specified executable/environment.
- Separate raw observations from approved policy; detection never updates approved baselines automatically.
- Support candidate inspection and explicit promotion/version selection.
- Retrieve expected library identities, paths and symbol providers independently.
- Define optional-library handling and missing-baseline behavior.
- Implement the documented profiling entry point only after this API is stable.

**Acceptance:** Two executable profiles remain isolated, searches do not become approved loads, baselines survive restart, and unprofiled programs are reported explicitly.

## F07 — Correct rules and connect detection

Addresses I01, I06, I08, I11, I21, I24.

- Evaluate loaded-library rules on confirmed load events.
- Resolve baselines through enriched executable identity.
- Replace basename-only symbol-provider equality with the agreed object identity policy.
- Normalize legitimate aliases consistently across learning and detection.
- Connect validation, enrichment, baseline lookup, rule evaluation and alert persistence.
- Serialize canonical JSON details and include executable/process identity.
- Define missing-baseline, duplicate-alert and storage-failure behavior explicitly.
- Implement `PRELOAD_PRIVILEGED` only if trustworthy origin and privilege metadata are available within declared scope; otherwise document it as deferred bonus work.

**Acceptance:** Real C-source telemetry reaches persisted alerts; an approved clean fixture produces no unexpected alert; failed searches do not trigger load deviations; distinct same-named objects remain distinguishable.

## F08 — Implement CLI on stable queries

Addresses I20, I24.

| Command | Required behavior |
| --- | --- |
| `alerts` | Severity validation/filtering, bounded results, stable ordering and structured output |
| `baseline --exe` | Approved version, expected libraries/providers and explicit missing-profile status |
| `watch --pid` | New-event cursor, process-instance distinction, cancellation and no repeated historical rows |
| `diff` | Explicit source of current observations and comparison against a selected baseline; no implicit execution of arbitrary programs |
| `report` | Valid JSON, validated date filters, coverage/baseline metadata and safe output handling |

Share database configuration, errors, timestamp formatting and exit-code conventions. Reuse store/engine APIs rather than reimplementing rule logic in commands.

**Acceptance:** Commands operate against data produced by the integrated collector. Filter boundaries, pagination, empty results, missing baselines and output failures are covered.

## F09 — Make setup and demonstrations non-destructive

Addresses I09, I15, I23, I25.

- Use dedicated temporary demo/test data and endpoints, supported by both sender and collector.
- Make reset explicit and restricted to a verified demo directory; refuse to disrupt active services.
- Use unique temporary directories and cleanup traps in shell tests.
- Align the exact supported Go toolchain across setup, Docker, module requirements and CI.
- Verify downloaded toolchain artifacts before replacement and avoid removing a usable installation before validation.
- Remove unnecessary container capabilities and seccomp exceptions from routine fixtures.
- Prefer read-only source mounts with separate writable build/runtime output where practical.

**Acceptance:** Repeating setup preserves existing telemetry by default; a clean checkout can build using the documented toolchain; routine demo fixtures need no unexplained extra privileges.

## F10 — Establish evidence and truthful documentation

Addresses I22, I23, I24 and validates all fixes.

- Add regression checks alongside each owning fix, not only at the end.
- Add actual C-to-Go protocol checks, real-source Linux detection tests and lifecycle tests.
- Use harmless fixtures for controlled deviations; no credential collection or concealment behavior is needed to prove detection.
- Measure overhead, sustained event throughput and losses with stated hardware/workloads.
- Build all binaries in CI; require expected test suites and artifacts to exist.
- Avoid rerunning the same suite redundantly under misleading unit/integration labels.
- Update README, architecture, protocol, threat model and demo instructions from the implemented contracts.
- Verify bibliography and remote repository settings separately; do not claim they were checked by the source review.

**Acceptance:** A fresh Linux checkout passes required gates and produces a reproducible report. Documentation distinguishes tested behavior, limitations and deferred work.

## F05 implementation evidence (2026-10-01)

T05 is implemented and locally verified. Versioned migrations and generated
shared queries now supply lifetime-aware events, baseline storage primitives,
and canonical alert persistence. The collector uses event-time executable
metadata with explicit uncertainty, commits registry/event updates atomically,
and reports bounded persistence failures. Legacy observations stay archival.
See [persistence.md](persistence.md) for schema compatibility, retention,
disk-full behavior, validation and remaining limits, and the T05 evidence
record in [pending-tasks.md](pending-tasks.md). Baseline workflows and actual
rule-to-alert integration remain F06/F07.
