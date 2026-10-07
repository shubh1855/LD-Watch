# LD-Watch ordered pending tasks

Created: 2026-09-29. Documentation only: none of the implementation tasks below has been performed by creating this checklist.

Use [issues](issues.md) for findings and [fixes](fixes.md) for implementation detail. This file is the single source of completion status. Check a task only after its acceptance evidence is recorded.

## Working rules to prevent rework

1. Complete stages in order. Do not start a dependent stage until its gate passes.
2. Assign one owner to each task and one reviewer from another component. Ownership below names components, not particular people.
3. Decide shared contracts in T01; implement the schema in T05 and regenerate queries once per agreed migration. Do not invent separate formats in the CLI, rules or profiler.
4. Include regression validation with the owning fix. T09 adds cross-component evidence rather than replacing those checks.
5. Keep one canonical identity resolver, baseline API, event vocabulary and alert serializer. The CLI consumes them.
6. Record new findings under a new issue ID; update the existing task when it already owns the affected behavior.
7. Do not mark a feature done because a synthetic event passed a unit test. Distinguish implemented, locally tested and end-to-end verified.
8. Preserve existing user changes and telemetry; perform builds and fixtures in isolated output/runtime directories.

Dependency chain: **T01 → T02 → T03 → T04 → T05 → T06 → T07 → T08 → T09 → T10 → T11**.

Some small fixes could technically run independently, but this default sequence minimizes simultaneous changes to shared interfaces.

## T01 — Freeze scope and shared contracts

Owner: all components; nominate one contract editor. Plan: F01. Issues: I05–I08, I11, I14, I15, I17, I21, I24.

- [x] State supported platform/architecture and observation scope.
- [x] Decide transport/framing, endpoint configuration, versioning, byte order and truncation behavior.
- [x] Define PID/TID, process lifetime, executable replacement, fork attribution and object identity.
- [x] Separate searches, loads and symbol events; define mechanism confidence.
- [x] Agree baseline approval/versioning and alert vocabulary/JSON contract.
- [x] Decide whether privileged-preload detection is in scope or deferred bonus work.
- [x] Record schema, query and compatibility requirements for later owners.

**Gate:** Passed 2026-10-01. [`contract.md`](contract.md) supplies the shared examples, lifecycle rules, schema mapping, and compatibility policy; `PRELOAD_PRIVILEGED` is explicitly deferred.

## T02 — Prepare safe development and fix local C formatting

Owner: tooling + audit. Plans: F03, F09. Issues: I09, I13, I23, I25.

- [x] Remove automatic deletion of shared demo telemetry; make reset explicit and safe.
- [x] Replace fixed shell-test temporary directories with unique owned directories and cleanup traps.
- [x] Align the toolchain version and validate downloads before replacement.
- [x] Restrict routine containers to necessary capabilities and isolate build/runtime outputs.
- [x] Correct full-range numeric buffer sizes and validate formatting.

**Gate:** Passed 2026-10-01. Demo setup preserves telemetry by default, `--reset` is guarded, shell fixtures use owned temporary directories, and formatter boundaries are covered. Configurable end-to-end demo wiring waits for T03/T04.

## T03 — Stabilize the C event source

Owner: audit. Plans: F02, F03. Issues: I02, I05, I11, I12, I15, I17.

- [x] Implement the T01 wire format and endpoint configuration.
- [x] Implement bounded transport, local SIGPIPE handling, close-on-exec and reconnect/loss behavior.
- [x] Implement fork/concurrent-callback record integrity according to the contract.
- [x] Separate PID/TID and emit lifecycle/identity metadata.
- [x] Add unload cleanup, capacity reporting and truncation handling.
- [x] Report origin honestly and make verbose stderr output optional.
- [x] Validate benign C fixtures for transport and lifecycle behavior against a controlled receiver.

**Gate:** Passed 2026-10-01. The C source emits explicit v1 1,024-byte little-endian records over bounded `SOCK_SEQPACKET`, supports endpoint override/fork reconnect, cleans object state, reports degraded attribution, and passes the controlled receiver suite. Collector decoding remains T04.

## T04 — Stabilize collector ingress and shutdown

Owner: collector. Plan: F04. Issues: I03, I04, I05, I10, I16, I17.

- [x] Decode and validate the T03 protocol; reject incompatible versions.
- [x] Validate configuration before creating resources.
- [x] Add safe socket ownership, active-instance protection and peer attribution.
- [x] Bound connection/resource use.
- [x] Implement active-connection tracking, cancellation and bounded shutdown.
- [x] Validate actual C-source records and idle-client shutdown.

**Gate:** Passed 2026-10-01. The collector rejects legacy/invalid v1 packets, protects unrelated and active socket paths, captures peer credentials, bounds connections, closes idle clients within the drain deadline, and persists actual C-source load records. Persistence migration follows in T05.

## T05 — Implement schema, enrichment and persistence

Owner: store + collector. Plan: F05. Issues: I05, I06, I07, I14, I18, I19, I24.

- [x] Create versioned migrations for events, process instances, baselines and alerts agreed in T01.
- [x] Implement lifecycle-aware executable enrichment and replace the forever PID cache.
- [x] Preserve searches distinctly and uncertainty explicitly.
- [x] Remove executable placeholders from storage helpers.
- [x] Implement shared queries and regenerate sqlc code.
- [x] Add justified indexes, bounded failure handling and health counters.
- [x] Close resources on initialization failures; define retention and disk-full behavior.
- [x] Verify fresh/existing database migration and real-source telemetry persistence.

**Gate:** Passed locally 2026-10-01. Versioned transactional migrations preserve legacy evidence; lifecycle-aware telemetry and uncertainty persist through the real C/socket/collector path (9 records, 4 loads). Shared queries are regenerated for baseline, rules and CLI work. See [`persistence.md`](persistence.md) for policy, validation and limits.

## T06 — Complete baseline learning and approval

Owner: engine/baseline. Plan: F06. Issues: I06, I07.

- [x] Implement executable-scoped candidate learning from confirmed events.
- [x] Implement inspection, approval, version selection and reload.
- [x] Implement expected-library and symbol-provider retrieval using shared identity rules.
- [x] Define and implement optional-library and missing-baseline policy.
- [x] Provide a profiling entry point without duplicating collector/store logic.
- [x] Verify cross-executable isolation and persistence across restart.

**Gate:** Approved profiles can be retrieved deterministically; normal detection cannot change them.

**Gate passed locally 2026-10-02.** Candidate learning consumes only complete,
source-identified `LOAD` and `SYMBOL_BIND` rows through the shared store query
layer, keyed by executable and explicit environment label. Version approval
copies observations and optionality into immutable entries; a separate active
selection controls reload. Missing selection returns `MISSING_BASELINE`.
Focused baseline/store/CLI tests and the full Go suite passed, including
cross-executable isolation, idempotent profiling, approved-profile immutability,
and persistence across database restart. End-to-end detection and alert
integration remain T07 work.

### T06 evidence record

```text
Task ID: T06
Owner / reviewer: Engine + baseline / implementation review pending
Implementation reference: executable/environment scoped candidate, approval, selection, and reload APIs; baseline CLI profile/inspect/approve/use workflows
Environment and toolchain: Linux local checkout; Go 1.26.1; SQLite migrations 001–004
Validation performed and result: focused baseline/store/CLI tests passed; full Go suite passed including Unix-socket integration tests
Affected issue IDs and disposition: I06 and I07 baseline learning/versioning behavior implemented; alert evaluation and canonical alert persistence completed in T07
Remaining limitations at T06 gate: detection and alert integration were deferred to T07 and are now merged
Gate passed on: 2026-10-02 (local acceptance)
```

## T07 — Repair rules and connect alerts

Owner: engine + collector. Plan: F07. Issues: I01, I06, I08, I11, I21, I24.

- [x] Restrict loaded-library deviation checks to confirmed loads.
- [x] Use approved executable-specific baselines and verified provider identity.
- [x] Connect enriched events to rule evaluation and JSON alert persistence.
- [x] Implement explicit missing-baseline, duplicate-alert and error behavior.
- [x] Record the `PRELOAD_PRIVILEGED` deferral because current telemetry cannot prove preload origin and privilege context.
- [x] Verify clean and harmless deviation fixtures through the full pipeline.

**Implementation status (2026-10-05):** Merged to `main` in PR #59.
The collector evaluates confirmed loads and symbol bindings against the selected
executable/environment baseline, persists canonical JSON alerts, and counts
duplicate, missing-profile, persistence, and evaluation outcomes. The store
schema includes `MISSING_BASELINE`; `PRELOAD_PRIVILEGED` is explicitly deferred
because current telemetry cannot prove its origin and privilege context.
Focused tests cover clean approved-baseline evaluation, unknown libraries,
missing baselines, duplicate alerts, provider identity, and incomplete records.
The full C-to-Go clean/deviation fixture is now recorded below.

### T07 evidence record

```text
Task ID: T07
Owner / reviewer: Engine + collector / implementation review
Implementation reference: PR #59; internal/collector/processor.go; internal/engine/rules; internal/store/baseline.go; internal/store/sqlite.go; migration 005; docs/contract.md
Environment and toolchain: Linux, Go 1.26.1, SQLite, GCC/glibc integration fixtures
Validation performed and result: go test -race ./..., go vet ./..., and git diff --check passed on the merged branch. Focused tests cover approved-baseline clean evaluation, UNKNOWN_SO and MISSING_BASELINE persistence, duplicate-alert idempotency, provider/requester orientation, truncation filtering, migration history, and real collector integration.
Affected issue IDs and disposition: I01 implemented for connected collector evaluation; I06/I07 implemented for selected executable/environment baselines and provider identity; I08 fixed by canonical path comparison; I11 remains limited to truthful UNKNOWN origin; I21 deferred because PRELOAD_PRIVILEGED evidence is unavailable; I24 updated for T07 behavior.
Remaining limitations: CLI alert/report workflows, sustained-load measurements, and final documentation reconciliation remain T08–T11 work.
Gate status: Passed on 2026-10-05 for the implementation and clean/deviation acceptance fixture; broader integration and performance evidence remains T09.

End-to-end fixture evidence (2026-10-05): built the C audit library and collector
from the checkout, started an isolated collector with environment `production`,
and ran `/bin/true` through the real `LD_AUDIT` Unix-socket path. The initial
unprofiled run persisted 4 `LOAD` events plus lifecycle/search records and
produced four `MISSING_BASELINE` alerts. After profiling, approving, and
selecting `/usr/bin/true` version 1, a clean rerun increased the alert count
from 4 to 4. A harmless run with an empty-constructor `LD_PRELOAD` shared
library persisted the extra library load and increased the alert count from 4
to 5 with exactly one `UNKNOWN_SO`/`HIGH` alert for that library. Collector
shutdown reported 30 persisted events, 5 alerts, zero persistence failures,
zero detection failures, and zero unresolved identities.
```

**Gate:** Passed 2026-10-05. Real telemetry produced expected stored alerts with correct executable identity and canonical fields; a clean approved run remained clean.

## T08 — Build CLI workflows

Owner: CLI. Plan: F08. Issues: I20, I24.

- [x] Add shared database configuration, validation, help and exit-code handling.
- [x] Implement `alerts` and severity filtering.
- [x] Implement approved baseline display.
- [x] Implement live event watching with a stable cursor and process-instance handling.
- [x] Implement `diff` with an explicit observation source.
- [x] Implement JSON report export and validated date filtering.
- [x] Validate against T07-produced data, including empty/error cases.

**Gate:** Passed 2026-10-05. All retained README command promises work without duplicating detection or identity logic.

### T08 implementation evidence

```text
Task ID: T08
Owner / reviewer: CLI / implementation review
Implementation reference: cmd/ldwatch-cli/main.go; cmd/ldwatch-cli/main_test.go; README.md CLI Reference
Environment and toolchain: Linux local checkout; Go 1.26.1; SQLite migrations 001–005; merged T07 collector output
Validation performed and result: `GOCACHE=/tmp/ldwatch-t08-cache go test -race ./...`, `go vet ./...`, and `git diff --check` passed. The CLI was built and run against the real T07-produced database: `alerts --severity HIGH` listed the persisted `MISSING_BASELINE` and `UNKNOWN_SO` alerts; `baseline show` displayed the selected `/usr/bin/true` production profile; `diff --source events` reported the harmless preloaded library as `UNEXPECTED`; `report` emitted valid JSON; and `watch --after 0` streamed stable event IDs and process keys. Empty database, invalid severity/date/range, and database-open error cases are covered by CLI tests.
Affected issue IDs and disposition: I20 fixed with the complete CLI workflows; I24 CLI commands and validation evidence now match the merged T07 schema and pipeline.
Remaining limitations: Sustained-load measurements, CI packaging, demo automation, and final documentation reconciliation remain T09–T11 work.
Gate passed on: 2026-10-05
```

## T09 — Complete integration and performance evidence

Owner: tests, with component owners. Plan: F10. Issue: I22; validates I01–I21.

- [x] Add/complete C-to-Go wire compatibility checks.
- [x] Cover short-lived/threaded processes, executable replacement and object unload/reload.
- [x] Cover absent/slow/restarted collector, idle shutdown and invalid records.
- [x] Cover storage failures and migration/legacy-data behavior.
- [x] Cover clean and harmless controlled deviation outcomes through stored alerts.
- [x] Cover those outcomes through CLI reports after T08 is complete.
- [x] Measure workload-specific overhead, throughput and packet persistence with stated conditions.
- [x] Record evidence and remaining limitations; avoid universal no-loss claims from small tests.

**Implementation status (2026-10-05):** Integration and performance checks are
recorded in [`t09-evidence.md`](t09-evidence.md). The full Go race suite, `go vet`,
Linux audit fixture, and clean/deviation CLI report test passed. Benchmark results
are scoped to the WSL/i5-12450H workload and do not claim a universal loss rate.

**Gate:** Passed locally on 2026-10-05. Component integration, lifecycle,
failure-handling, benchmark, and CLI report evidence are recorded. Failures return
to their owning stage rather than being patched in test wrappers.

## T10 — Enforce CI and package the demo

Owner: tooling + tests. Plans: F09, F10. Issues: I09, I15, I22, I23, I25.

- [x] Build audit library, collector and CLI in CI.
- [x] Run required suites once in clearly named stages; fail if a required suite is missing.
- [x] Verify expected artifacts exist before upload.
- [x] Wire a dedicated demo endpoint/database through the now-stable configuration.
- [x] Demonstrate baseline approval, clean run, harmless deviation, alert query and report export.
- [x] Verify repeatable setup/cleanup without modifying unrelated data.

**Gate:** Passed 2026-10-06. A fresh Linux checkout produces deliverables and a repeatable isolated demo.

**Implementation status (2026-10-06):** CI now pins Go 1.26.1, builds all three
deliverables, verifies artifact presence, runs race tests, runs `go vet`, runs
the C audit fixture suite, and uploads build outputs. `scripts/demo_t10.sh` now
uses a dedicated database/socket, approves a real `/bin/true` baseline, checks
a clean rerun, injects one harmless `UNKNOWN_SO` deviation, queries alerts, and
exports a report. Compose test services use read-only roots with tmpfs workspaces.

## T11 — Reconcile documentation and close the review

Owner: documentation + all reviewers. Plan: F10. Issue: I24.

- [ ] Update README tree, wire example, phase checklist and working commands.
- [ ] Add architecture, protocol and threat-model documents matching implementation.
- [ ] State actual coverage, secure-execution limits, integrity limits and detection-versus-prevention distinction.
- [ ] Update demo instructions and include verified report output.
- [ ] Verify academic references and remote CI/branch settings separately.
- [ ] Record each issue as fixed, accepted limitation or deferred, with evidence links.
- [ ] Keep deferred bonus/future work visible rather than checking it off as implemented.

**Gate:** Every advertised capability has evidence, and every unresolved issue has an explicit disposition.

## Evidence record template

### T01 evidence record

```text
Task ID: T01
Owner / reviewer: Project owner / implementation review pending at each downstream stage
Implementation reference: contract.md (LD-Watch v1 shared contract)
Environment and toolchain: Documentation decision; no runtime behavior changed
Validation performed and result: Contract includes a fixed wire layout, valid examples, event lifecycle, persistence mapping, baseline policy, alert vocabulary, and incompatible-record rejection policy.
Affected issue IDs and disposition: I05, I06, I07, I08, I11, I14, I15, I17, I21, I24 — implementation deferred to T03–T11 under the agreed contract.
Remaining limitations: Protocol and schema implementation, end-to-end validation, and documentation reconciliation remain pending.
Gate passed on: 2026-10-01
```

### T02 evidence record

```text
Task ID: T02
Owner / reviewer: Tooling + audit / project owner
Implementation reference: commit 680eace (fix: harden development safety checks)
Environment and toolchain: Linux local checkout; Go 1.26.1 module target
Validation performed and result: audit hook suite passed 11/11; full Go suite (including integration) passed; make all passed; docker compose config passed.
Affected issue IDs and disposition: I09, I13 fixed; I23 and I25 partially addressed by aligned toolchain/safe Compose defaults and remain open for T10 delivery/CI evidence.
Remaining limitations: Dedicated configurable demo endpoint, complete CI enforcement, and broader container evidence remain pending.
Gate passed on: 2026-10-01
```

### T03 evidence record

```text
Task ID: T03
Owner / reviewer: Audit / project owner
Implementation reference: audit/include/audit.h, audit/src/ipc.c, audit/src/hooks.c, audit/src/audit.c, tests/fixtures/wire_receiver.c
Environment and toolchain: Linux local checkout; GCC and glibc loader audit interface
Validation performed and result: C audit library built; controlled receiver validated magic/version/length/event/PID/TID over configured SOCK_SEQPACKET; audit suite passed 12/12 with verbose and endpoint checks.
Affected issue IDs and disposition: I02 fixed in sender scope; I05 partially fixed at source identity/lifecycle; I11 fixed for truthful unknown origin; I12 fixed with close cleanup/capacity reporting; I15 fixed for sender endpoint override; I17 fixed at wire-source scope. Collector and cross-component compatibility remain T04.
Remaining limitations: Concurrent stress, sustained-loss measurement, and collector decoding/peer policy remain T04/T09 evidence.
Gate passed on: 2026-10-01
```

### T04 evidence record

```text
Task ID: T04
Owner / reviewer: Collector / project owner
Implementation reference: internal/proto/event.go, internal/socket/listener.go, cmd/collector/main.go, internal/collector/processor.go
Environment and toolchain: Linux local checkout; Go 1.26.1, Unix SOCK_SEQPACKET, SQLite
Validation performed and result: Full Go suite passed; socket tests cover unsafe paths, peer credentials, concurrent connections, and idle shutdown; actual C audit traffic persisted 4 load events through the Go collector; invalid/legacy packet decoding is unit-tested.
Affected issue IDs and disposition: I03 fixed; I04 fixed in ingress scope; I05 remains partial pending T05 process-instance enrichment; I10 fixed; I16 fixed; I17 fixed at ingress/decode scope.
Remaining limitations: Schema migration, durable lifecycle attribution, retention/health policy, and full sustained-load evidence remain T05/T09.
Gate passed on: 2026-10-01
```

### T05 evidence record

```text
Task ID: T05
Owner / reviewer: Store + collector / independent review pending
Implementation reference: internal/store/migrations, schema.sql, queries.sql and generated sqlc output; internal/store/persistence.go; internal/collector/processor.go; docs/persistence.md
Environment and toolchain: Linux via WSL, Go 1.26.1 runtime checks, GCC/glibc, SQLite; pinned sqlc v1.31.1 generated with its selected Go 1.26.8 toolchain
Validation performed and result: go test -race ./... and go vet ./... passed. Real C audit source through Unix socket and four workers persisted 9 records including 4 confirmed loads for /usr/bin/true with process lifetime and peer identity. Tests cover fresh/unversioned migrations, legacy preservation, repeat migration, migration rollback, initialization cleanup, restart persistence, atomic event failure, bounded busy waits, SQLite disk-full behavior, retention, lifetime/PID reuse, exec replacement, searches/closes, full unsigned values, canonical alerts and scoped baseline queries.
Affected issue IDs and disposition: I05 fixed in attribution/persistence scope; I14, I18, I19 fixed; I06/I07 schema and query prerequisites delivered, baseline workflow remains T06; I24 storage documentation updated, overall reconciliation remains T11.
Remaining limitations: Independent review pending. Unresolved records are not guessed or coalesced; counters reset on restart; retention is explicit and disabled by default; no durable overflow spool. Baseline approval, rule evaluation, CLI workflows and sustained-load evidence remain T06–T09.
Gate passed on: 2026-10-01 (local acceptance)
```

Use this for each completed task in the team's issue tracker or appended records:

```text
Task ID:
Owner / reviewer:
Implementation reference:
Environment and toolchain:
Validation performed and result:
Affected issue IDs and disposition:
Remaining limitations:
Gate passed on:
```

## Follow-up issue #64 — Bound audit diagnostic output

- [x] Reproduce the default logger hanging with a full, undrained stderr pipe.
- [x] Make diagnostics silent by default and explicitly opt-in.
- [x] Permit only already nonblocking pipes, drop failed fragments without retry,
  preserve descriptor flags, and suppress only newly generated diagnostic SIGPIPE.
- [x] Cover default/full/closed-pipe behavior and preserve hook/formatter checks.
- [x] Document the [bounded logging policy](audit-logging.md).

Validation: pre-fix reproduction timed out with exit 124. The C audit suite
passed 17/17, including logging regressions. Race-enabled collector/integration
tests passed, and shell syntax/whitespace checks passed. This is separate from
the still-open follow-ups #65–#68.

## Future scope: not required for the initial completion gate

- Static-binary/system-wide coverage through a separately designed telemetry source.
- Stronger content-integrity verification if added to the threat model.
- Additional platforms, architectures and loaders.
- Additional critical symbols with documented coverage and overhead.
- Privileged-preload detection if explicitly deferred in T01.

Do not begin these extensions before the dependable core path is complete: approved baseline → audited program → attributed events → persisted alert → CLI report.
