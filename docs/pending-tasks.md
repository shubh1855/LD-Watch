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

- [ ] Decode and validate the T03 protocol; reject incompatible versions.
- [ ] Validate configuration before creating resources.
- [ ] Add safe socket ownership, active-instance protection and peer attribution.
- [ ] Bound connection/resource use.
- [ ] Implement active-connection tracking, cancellation and bounded shutdown.
- [ ] Validate actual C-source records and idle-client shutdown.

**Gate:** Valid source records reach the processing boundary; invalid records are counted/rejected; shutdown is bounded. Persistence migration follows in T05.

## T05 — Implement schema, enrichment and persistence

Owner: store + collector. Plan: F05. Issues: I05, I06, I07, I14, I18, I19, I24.

- [ ] Create versioned migrations for events, process instances, baselines and alerts agreed in T01.
- [ ] Implement lifecycle-aware executable enrichment and replace the forever PID cache.
- [ ] Preserve searches distinctly and uncertainty explicitly.
- [ ] Remove executable placeholders from storage helpers.
- [ ] Implement shared queries and regenerate sqlc code.
- [ ] Add justified indexes, bounded failure handling and health counters.
- [ ] Close resources on initialization failures; define retention and disk-full behavior.
- [ ] Verify fresh/existing database migration and real-source telemetry persistence.

**Gate:** Correctly attributed telemetry persists through the real C/collector path. Stable queries are ready for baselines, rules and CLI.

## T06 — Complete baseline learning and approval

Owner: engine/baseline. Plan: F06. Issues: I06, I07.

- [ ] Implement executable-scoped candidate learning from confirmed events.
- [ ] Implement inspection, approval, version selection and reload.
- [ ] Implement expected-library and symbol-provider retrieval using shared identity rules.
- [ ] Define and implement optional-library and missing-baseline policy.
- [ ] Provide a profiling entry point without duplicating collector/store logic.
- [ ] Verify cross-executable isolation and persistence across restart.

**Gate:** Approved profiles can be retrieved deterministically; normal detection cannot change them.

## T07 — Repair rules and connect alerts

Owner: engine + collector. Plan: F07. Issues: I01, I06, I08, I11, I21, I24.

- [ ] Restrict loaded-library deviation checks to confirmed loads.
- [ ] Use approved executable-specific baselines and verified provider identity.
- [ ] Connect enriched events to rule evaluation and JSON alert persistence.
- [ ] Implement explicit missing-baseline, duplicate-alert and error behavior.
- [ ] Implement privileged-preload detection only if approved in T01 and supported by verified metadata; otherwise record its deferral and remove unsupported promises.
- [ ] Verify clean and harmless deviation fixtures through the full pipeline.

**Gate:** Real telemetry produces expected stored alerts with correct executable identity and canonical fields. A clean approved run remains clean.

## T08 — Build CLI workflows

Owner: CLI. Plan: F08. Issues: I20, I24.

- [ ] Add shared database configuration, validation, help and exit-code handling.
- [ ] Implement `alerts` and severity filtering.
- [ ] Implement approved baseline display.
- [ ] Implement live event watching with a stable cursor and process-instance handling.
- [ ] Implement `diff` with an explicit observation source.
- [ ] Implement JSON report export and validated date filtering.
- [ ] Validate against T07-produced data, including empty/error cases.

**Gate:** All retained README command promises work without duplicating detection or identity logic.

## T09 — Complete integration and performance evidence

Owner: tests, with component owners. Plan: F10. Issue: I22; validates I01–I21.

- [ ] Add/complete C-to-Go wire compatibility checks.
- [ ] Cover short-lived/threaded processes, executable replacement and object unload/reload.
- [ ] Cover absent/slow/restarted collector, idle shutdown and invalid records.
- [ ] Cover storage failures and migration/legacy-data behavior.
- [ ] Cover clean and harmless controlled deviation outcomes through stored alerts and CLI reports.
- [ ] Measure workload-specific overhead, throughput and loss with stated conditions.
- [ ] Record evidence and remaining limitations; avoid universal no-loss claims from small tests.

**Gate:** Required functional checks pass and performance limitations are documented. Failures return to their owning stage rather than being patched in test wrappers.

## T10 — Enforce CI and package the demo

Owner: tooling + tests. Plans: F09, F10. Issues: I09, I15, I22, I23, I25.

- [ ] Build audit library, collector and CLI in CI.
- [ ] Run required suites once in clearly named stages; fail if a required suite is missing.
- [ ] Verify expected artifacts exist before upload.
- [ ] Wire a dedicated demo endpoint/database through the now-stable configuration.
- [ ] Demonstrate baseline approval, clean run, harmless deviation, alert query and report export.
- [ ] Verify repeatable setup/cleanup without modifying unrelated data.

**Gate:** A fresh Linux checkout produces deliverables and a repeatable isolated demo.

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

## Future scope: not required for the initial completion gate

- Static-binary/system-wide coverage through a separately designed telemetry source.
- Stronger content-integrity verification if added to the threat model.
- Additional platforms, architectures and loaders.
- Additional critical symbols with documented coverage and overhead.
- Privileged-preload detection if explicitly deferred in T01.

Do not begin these extensions before the dependable core path is complete: approved baseline → audited program → attributed events → persisted alert → CLI report.
