# LD-Watch issue register

Review date: 2026-09-29. Findings describe that historical checkout. Current
dispositions below were reconciled 2026-10-07 and supersede intermediate notes.
GitHub closure is separate from implementation status.

This is a source-review baseline, not runtime certification. Linux builds and tests were not run during the review: Go was unavailable on the Windows host PATH and WSL enumeration returned access denied. Findings describe the reviewed implementation; environment-dependent outcomes still require Linux validation.

Read [fix plans](fixes.md) for remediation and [ordered pending tasks](pending-tasks.md) for execution order. Issue IDs are stable across all three files. This document owns the problem descriptions; the task checklist owns completion status.

## Current dispositions (T11)

| ID | Disposition | Implementation / evidence |
| --- | --- | --- |
| I01 | Fixed | Connected detection and persisted alerts; [T07](pending-tasks.md#t07--repair-rules-and-connect-alerts), [demo](collector_demo.md) |
| I02 | Fixed bounded transport; drops accepted | Nonblocking seqpacket, reconnect/fork, no SIGPIPE; [T09](t09-evidence.md) |
| I03 | Fixed | Bounded shutdown and idle-client tests; T04 |
| I04 | Fixed ingress; record trust limit accepted | 0660 socket, peer metadata, connection limits; [threat model](threat-model.md) |
| I05 | Fixed attribution; uncertainty retained | Process lifetime/source identity; [persistence](persistence.md) |
| I06 | Fixed | Searches excluded from load learning/rules; T06/T07 |
| I07 | Fixed | Executable/environment approval, versions, optional loads; T06 |
| I08 | Fixed | Shared canonical provider/path comparison; T07 |
| I09 | Fixed | Guarded setup; isolated demo refuses existing DB/socket; [demo](collector_demo.md) |
| I10 | Fixed | Active endpoint and file/symlink validation; T04 |
| I11 | Fixed truthful origin; preload certainty deferred | UNKNOWN loads; [protocol](protocol.md) |
| I12 | Fixed | Unload cleanup/capacity degradation; T03/T09 |
| I13 | Fixed | Full uint64 formatter fixture; T02/T03 |
| I14 | Fixed | Shared executable resolver in helpers; [persistence](persistence.md) |
| I15 | Fixed | Absolute endpoint override and real isolated demo; T03/T10 |
| I16 | Fixed | Worker validation before resource setup; T04 |
| I17 | Fixed v1; legacy intentionally rejected | Explicit encoding and real C decode tests; [protocol](protocol.md) |
| I18 | Fixed failure policy; durable recovery deferred | Busy/full rollback, counters, explicit retention; [persistence](persistence.md) |
| I19 | Fixed | Initialization cleanup/migration rollback tests; T05 |
| I20 | Fixed | alerts/baseline/watch/diff/report and validation; T08 |
| I21 | Deferred | PRELOAD_PRIVILEGED lacks origin/privilege evidence; [threat model](threat-model.md) |
| I22 | Fixed scoped evidence; universal performance/no-loss excluded | Real source/lifecycle, CLI integration and measurements; [T09](t09-evidence.md) |
| I23 | Fixed CI delivery | Artifact checks, race/vet/C fixtures, aligned Go; [live CI](https://github.com/shubh1855/LD-Watch/actions/runs/37483536116) |
| I24 | Reconciled T11 | README, architecture, protocol, demo/report and [review evidence](t11-evidence.md) |
| I25 | Fixed routine configuration | Read-only source/root, tmpfs, no ptrace/seccomp exceptions; [review evidence](t11-evidence.md) |

[Pending tasks](pending-tasks.md) records implementation/test details for T01–T10.
Disabled branch protection, manual IEEE metadata checks and fresh container
runtime evidence remain explicit follow-ups in [T11 evidence](t11-evidence.md).

## Historical priorities

- **P1:** Resolve before claiming reliable end-to-end detection.
- **P2:** Resolve before broader use; some are prerequisites for P1 work.
- **Delivery:** Missing functionality or evidence needed for project completion.

## Issues

| ID | Priority | Finding and evidence | Impact |
| --- | --- | --- | --- |
| I01 | P1 | `cmd/collector/main.go` and `internal/collector/processor.go` only persist telemetry; they do not construct or invoke the engine. | Real collector events cannot automatically generate stored alerts. |
| I02 | P1 | `audit/src/ipc.c` uses blocking stream sockets and writes, has no local SIGPIPE suppression, and permanently disables sending after connection failure. It lacks close-on-exec and explicit fork/concurrent-writer handling. `audit/src/audit.c` writes synchronously to stderr. | Monitoring can stall applications, terminate them under applicable signal conditions, or silently lose events. Record integrity and reconnection require validation. |
| I03 | P1 | `internal/socket/listener.go:Stop` waits for handlers without closing existing connections or setting a drain deadline. | Idle connected processes can prevent shutdown indefinitely. |
| I04 | P1 | `internal/socket/listener.go` makes the socket world-writable and trusts record metadata without peer attribution or connection limits. | Telemetry is not authenticated evidence; client resource use is unbounded. |
| I05 | P1 | `audit/src/hooks.c` uses TID for symbol events but PID for other events. `internal/collector/processor.go` caches executable paths indefinitely by PID; `internal/store/queries.sql` inserts processes using `INSERT OR IGNORE`. | Thread events, PID reuse, executable replacement and short-lived processes can be attributed incorrectly. |
| I06 | P1 | Both load rules accept search events. The processor writes selected searches to `so_events` without retaining their type. | Failed search candidates can be mistaken for loaded libraries and contaminate learning or alerts. |
| I07 | P1 | `internal/engine/baseline/profiler.go` has no executable key and returns paths across all observed event types. | Baselines are global, lack approval/versioning, and do not implement the documented optional-library policy. |
| I08 | P1 | `internal/engine/rules/symbol_interpose.go:sameSharedObject` accepts matching basenames. | Different objects with identical filenames are treated as the expected symbol provider. Other rules do not make this comparison correct. |
| I09 | P1 | `scripts/demo_collector_setup.sh` unconditionally removes the database and socket. | Repeating setup can erase telemetry and disrupt an active collector. |
| I10 | P2 | `internal/socket/listener.go:New` removes the configured path without checking file type or whether a collector is active. | Startup can remove an unrelated file or detach an active collector endpoint. |
| I11 | P2 | `audit/src/hooks.c` always labels loads as standard; no C sender path emits the preload mechanism. | Stored mechanism values overstate what the audit source actually knows. Synthetic Go tests do not validate real classification. |
| I12 | P2 | The object map in `audit/src/hooks.c` only grows, has 256 slots, and has no unload cleanup. | Long-running load/unload activity can exhaust tracking or leave stale attribution. |
| I13 | P2 | `audit/src/audit.c` uses 20 bytes for decimal uint64 formatting and 18 for prefixed hexadecimal. | Full-range values exceed the available space including terminators. Ordinary current PID/address values may not reach these bounds. |
| I14 | P2 | `internal/store/sqlite.go` writes `SOPath` into the executable field in its high-level event helpers. | Helper callers persist incorrect executable identity. The collector currently uses its separate resolver. |
| I15 | P2 | The collector supports a custom socket flag but `audit/include/audit.h` fixes the sender endpoint. | A supported-looking configuration can produce no telemetry. |
| I16 | P2 | `cmd/collector/main.go` accepts zero or negative worker counts. | The process can exit without consuming telemetry instead of rejecting invalid configuration. |
| I17 | P2 | The wire contract has fixed-length strings without truncation indicators or version negotiation. Go decodes little-endian records while C sends native layout. | Incomplete identities and incompatible records can be interpreted as valid. The Go size test does not prove C interoperability. |
| I18 | P2 | Worker persistence failures are logged and events are discarded. Storage lacks an explicit retention, retry, disk-full and health policy. | Operators cannot reliably quantify data loss or degraded detection. |
| I19 | P2 | Storage initialization paths in `internal/store/open.go` and `internal/store/sqlite.go` do not close handles on every failure. | Failed initialization can leak resources. |
| I20 | Delivery | `cmd/ldwatch-cli/main.go` only prints a banner. | All advertised CLI workflows remain unavailable. |
| I21 | Delivery | `PRELOAD_PRIVILEGED` is absent, and telemetry lacks sufficient privilege/origin context. | The bonus rule cannot be implemented truthfully by merely adding a condition to current events. |
| I22 | Delivery | Tests largely use synthetic Go events, mocked executable resolution and small workloads. Hook tests inspect stderr. Full real-source detection tests are absent. | Existing tests do not establish the complete detection path, lifecycle correctness or performance. |
| I23 | Delivery | CI explicitly builds only the audit library; missing shell integration tests do not fail the runner. Setup, Docker and module Go versions differ. | Passing CI does not establish full deliverables or required end-to-end coverage. Setup may require an additional toolchain download. |
| I24 | Delivery | README tree, wire struct, completion checklist, baseline claims and commands differ from implementation. Rule names, severity casing and alert representations are inconsistent. | Users and assessors can infer functionality or guarantees that are not implemented. |
| I25 | P2 | Docker test services mount the repository writable and relax seccomp/add ptrace capability without a documented per-test need. | The demonstration environment has more host-file access and capability than routine fixtures need. |

## T03 dispositions (2026-10-01)

- **I02 — fixed in audit-source scope.** The sender now uses explicit v1 `SOCK_SEQPACKET` records, `MSG_NOSIGNAL`, nonblocking bounded sends, close-on-exec, one-second reconnect backoff, fork detection, and drop/reconnect counters. Collector-side handling remains T04.
- **I05 — partially fixed.** Audit records now carry PID consistently, separate TID, process start ticks, namespace, and object lifecycle cleanup. Collector executable/process-instance enrichment remains T05.
- **I11 — fixed in audit-source scope.** Loads default to `UNKNOWN`; origin values are emitted only from loader flags, and no unsupported preload certainty is invented.
- **I12 — fixed.** Object entries are removed on `la_objclose`; capacity exhaustion is counted and marked degraded.
- **I13 — fixed.** Formatter buffers cover full uint64 decimal and hexadecimal ranges with regression coverage.
- **I15 — fixed in sender scope.** `LDWATCH_SOCKET` supports an absolute endpoint override; collector policy remains T04.
- **I17 — partially fixed.** The source now emits versioned, explicit little-endian records with lengths and truncation/degraded flags. Go decoding and incompatible-record rejection remain T04.

## T04 dispositions (2026-10-01)

- **I03 — fixed.** Listener shutdown stops accepting, drains briefly, closes idle/remaining connections, and closes the event channel once.
- **I04 — fixed in ingress scope.** Socket paths are protected, access is `0660`, peer credentials are captured, and connections are bounded. Record trust and process attribution remain explicit contract limitations.
- **I05 — partial.** The collector now receives peer/process/thread/lifetime metadata, but durable process-instance enrichment and PID reuse handling remain T05.
- **I10 — fixed.** Existing paths are validated as sockets and active endpoints are rejected; unrelated files and symlinks are never removed.
- **I16 — fixed.** Non-positive worker counts are rejected before database/socket resources are created.
- **I17 — fixed at ingress scope.** Go decodes explicit v1 records, rejects legacy 408-byte packets and invalid flags/reserved bytes, and the real C-to-Go path has been exercised.

## Scope limitations, not automatically bugs

- LD-Watch uses `LD_AUDIT` to observe selected dynamically linked programs. It does not currently monitor every program system-wide.
- Static binaries and unsupported loaders/platforms require separate approaches.
- Secure-execution behavior restricts environment-based instrumentation. Do not equate root execution with setuid execution or claim universal coverage.
- Asynchronous monitoring is not a guarantee of prevention before damage.
- Path identity alone does not prove file-content integrity. A content-integrity claim requires a separately designed identity and verification policy.
- In-process telemetry cannot be described as tamper-proof merely because the collector checks peer credentials.
- Remote branch protection, live CI results and bibliography accuracy were not verified in this review.

## Technical references

## Follow-up #64 — Diagnostic logging can block stderr

The original I02 transport fix did not bound its separate synchronous stderr
logging path. A prefilled blocking pipe with default diagnostics reproduced an
application timeout (exit 124). The follow-up changes diagnostics to opt-in,
permits writes only to already nonblocking pipes, drops full-pipe fragments,
and handles newly generated SIGPIPE without changing application descriptor
flags or signal disposition. Normal socket telemetry remains independent.

Evidence: C suite passed 17/17; collector/integration race tests passed.
See [logging policy](audit-logging.md). GitHub #64 was fixed in merged PR #69;
#65–#68 have separate dispositions below.

## Current follow-up dispositions after main synchronization

| GitHub issue | Status and evidence |
| --- | --- |
| #64 | Fixed by PR #69: silent default and bounded opt-in diagnostics; audit regression suite |
| #65 | Connected-parent immediate fork delivery fixed by PR #70; failed-initial-connection edge remains documented in the PR review |
| #66 | Fixed by PR #73: SQL severity/date filtering and one unbounded snapshot read prevent truncation and concurrent-insert duplicates; `cmd/ldwatch-cli/report_test.go` covers large, historical, filtered and concurrent exports |
| #67 | Fixed by PR #71: optional-library absence excluded from MISSING; required/unexpected cases retained |
| #68 | Fixed by PR #72: all approved providers per symbol accepted; sorted provider-set alert detail and regression coverage |

## Technical reference links

- [Linux audit API](https://man7.org/linux/man-pages/man7/rtld-audit.7.html): search callbacks describe candidates; object-open callbacks describe loads; object-close callbacks support lifecycle tracking.
- [Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html): peer credentials and stream/signal behavior.
- [Dynamic loader](https://man7.org/linux/man-pages/man8/ld.so.8.html): instrumentation and secure-execution scope.

## T05 dispositions (2026-10-01)

- **I05 — fixed in persistence scope.** Process lifetime keys, source executable snapshots, explicit unresolved identity, and per-event peer/TID/namespace metadata are persisted atomically. PID reuse and exec replacement are tested; no PID-only cache or delayed executable lookup remains.
- **I06/I07 — shared schema/query prerequisites implemented.** Candidates, numbered approval-state versions, entries, and executable/environment/version queries are supplied. Workflow and engine integration remain T06/T07; old global profiler evidence stays legacy.
- **I14 — fixed.** High-level storage helpers use the shared executable resolver and require a complete source executable or explicit uncertainty. They never substitute a library path. Searches, loads, symbols and closes remain distinct.
- **I18 — fixed.** SQLite lock waits and high-level processor writes are bounded; storage failures roll back, count, and report without being presented as success. Actual SQLite full and busy paths are tested.
- **I19 — fixed.** Failed initialization closes database connections; migrations and version markers roll back together. Retention defaults, explicit batch API and disk-full behavior are documented in [persistence.md](persistence.md).
- **I24 — storage documentation reconciled.** Collector query examples and T05 policy/evidence now match the canonical tables. Full README, baseline, rule and CLI reconciliation remains T11.
