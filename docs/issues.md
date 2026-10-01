# LD-Watch issue register

Review date: 2026-09-29. Status: open unless explicitly updated after implementation and validation.

This is a source-review baseline, not runtime certification. Linux builds and tests were not run during the review: Go was unavailable on the Windows host PATH and WSL enumeration returned access denied. Findings describe the reviewed implementation; environment-dependent outcomes still require Linux validation.

Read [fix plans](fixes.md) for remediation and [ordered pending tasks](pending-tasks.md) for execution order. Issue IDs are stable across all three files. This document owns the problem descriptions; the task checklist owns completion status.

## Priority

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

## Scope limitations, not automatically bugs

- LD-Watch uses `LD_AUDIT` to observe selected dynamically linked programs. It does not currently monitor every program system-wide.
- Static binaries and unsupported loaders/platforms require separate approaches.
- Secure-execution behavior restricts environment-based instrumentation. Do not equate root execution with setuid execution or claim universal coverage.
- Asynchronous monitoring is not a guarantee of prevention before damage.
- Path identity alone does not prove file-content integrity. A content-integrity claim requires a separately designed identity and verification policy.
- In-process telemetry cannot be described as tamper-proof merely because the collector checks peer credentials.
- Remote branch protection, live CI results and bibliography accuracy were not verified in this review.

## Technical references

- [Linux audit API](https://man7.org/linux/man-pages/man7/rtld-audit.7.html): search callbacks describe candidates; object-open callbacks describe loads; object-close callbacks support lifecycle tracking.
- [Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html): peer credentials and stream/signal behavior.
- [Dynamic loader](https://man7.org/linux/man-pages/man8/ld.so.8.html): instrumentation and secure-execution scope.
