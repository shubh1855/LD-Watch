# LD-Watch v1 shared contract

Status: accepted implementation contract for T01, 2026-10-01.

This is the single contract for the audit library, collector, store, engine,
and CLI. It replaces the undocumented native-layout 408-byte record. It is
intentionally incompatible: an old record must be rejected, never decoded as
v1.

## Scope and trust boundary

LD-Watch v1 supports x86_64 Linux with the glibc dynamic loader and
`LD_AUDIT`. It observes only processes explicitly started with the audit
library. It does not claim system-wide, static-binary, secure-execution, or
tamper-proof coverage. Telemetry is process-supplied evidence: peer
credentials identify a connection, but do not make an adversary-controlled
process's records trustworthy.

The default endpoint is `/run/ldwatch/ldwatch.sock`. The collector `--socket`
flag and a non-secure sender's absolute `LDWATCH_SOCKET` value select another
endpoint; an empty or relative value is ignored. The collector owns this
endpoint. T04 must reject a non-socket path and an active collector, set
group-based (not world-writable) access, and retain `SO_PEERCRED` as
attribution metadata.

## Transport and compatibility

Use `AF_UNIX` + `SOCK_SEQPACKET`: one v1 record is one complete packet. The C
sender opens a close-on-exec socket and reconnects after an error or a detected
post-`fork` PID change. It fails open: a failed, absent, or slow collector may
drop telemetry but must not block loader execution indefinitely.

All multi-byte fields are explicitly little-endian. C serializes a byte
buffer; Go decodes that buffer, rather than either side reading a native C
struct. The collector rejects and counts an invalid magic, version, length,
enum, reserved byte, or required-field combination. A 408-byte legacy packet
is counted as `legacy_wire_v0` and rejected.

The record length is exactly 1,024 bytes. Text fields are byte strings. A
non-full field is NUL-terminated; a full field has no terminator and sets its
truncation flag. Transport neither resolves symlinks nor compares basenames.

## Wire record

| Offset | Size | Field | Meaning |
| ---: | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `LDW1` |
| 4 | 2 | `version` | little-endian `1` |
| 6 | 2 | `record_len` | little-endian `1024` |
| 8 | 1 | `event_type` | enum below |
| 9 | 1 | `origin` | enum below |
| 10 | 2 | `flags` | little-endian bitset |
| 12 | 4 | `pid` | sender process ID |
| 16 | 4 | `tid` | callback Linux thread ID |
| 20 | 8 | `process_start_ticks` | `/proc/self/stat` start time; `0` if unknown |
| 28 | 8 | `namespace_id` | glibc `Lmid_t`, or `0` |
| 36 | 8 | `timestamp_ns` | Unix nanoseconds, or `0` if unavailable |
| 44 | 8 | `resolved_addr` | symbol address; otherwise `0` |
| 52 | 12 | `reserved` | all zero in v1 |
| 64 | 256 | `exe_path` | executable path observed at initialization |
| 320 | 384 | `subject_path` | candidate, loaded object, or symbol provider |
| 704 | 256 | `related_path` | requesting object for search/symbol events |
| 960 | 64 | `symbol` | symbol name for a symbol binding |

An empty `exe_path` is uncertain identity, not permission to substitute a
library path or a later PID-only lookup.

For the main executable, whose `la_objopen` name is empty, the audit source
uses the literal subject sentinel `<main>`; the executable identity remains in
`exe_path`.

### Event types

| Value | Name | Subject | Related | Symbol |
| ---: | --- | --- | --- | --- |
| 1 | `SEARCH` | candidate considered by loader | requester if known | empty |
| 2 | `LOAD` | confirmed object from `la_objopen` | empty | empty |
| 3 | `SYMBOL_BIND` | provider object | requester object | resolved symbol |
| 4 | `OBJECT_CLOSE` | object closed by `la_objclose` | empty | empty |

Only `LOAD` proves a library loaded. Searches remain diagnostic observations;
they may never train a baseline or trigger a loaded-library deviation rule.
`OBJECT_CLOSE` updates lifecycle state only.

### Origin values

| Value | Name | Evidence |
| ---: | --- | --- |
| 0 | `UNKNOWN` | source cannot establish an origin |
| 1 | `STANDARD` | loader reported standard/default resolution |
| 2 | `PRELOAD` | affirmative preload evidence |
| 3 | `LIBRARY_PATH` | loader reported `LD_LIBRARY_PATH` |
| 4 | `RUNPATH` | loader reported RUNPATH/RPATH |
| 5 | `LOADER_CONFIG` | loader reported cache/config resolution |
| 6 | `SECURE_PATH` | loader reported secure-path resolution |

A search origin never automatically becomes a load origin. A load is
`UNKNOWN` without a one-to-one confirmed correlation. The current audit source
has no affirmative preload signal and therefore must emit `UNKNOWN`, not
`PRELOAD`, until T03 adds real evidence.

### Flags

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `EXE_TRUNCATED` | `exe_path` filled its field |
| 1 | `SUBJECT_TRUNCATED` | `subject_path` filled its field |
| 2 | `RELATED_TRUNCATED` | `related_path` filled its field |
| 3 | `SYMBOL_TRUNCATED` | `symbol` filled its field |
| 4 | `EXE_UNRESOLVED` | executable identity was unavailable |
| 5 | `PROCESS_START_UNRESOLVED` | start ticks were unavailable |
| 6 | `OBJECT_UNRESOLVED` | object attribution was unavailable or capacity was exhausted |

Unknown bits and non-zero reserved bytes are invalid in v1.

### Valid examples

| Event | Required populated fields | Required zero/empty fields |
| --- | --- | --- |
| `SEARCH` | `pid`, `tid`, `subject_path` | `symbol`, `resolved_addr` |
| `LOAD` | `pid`, `tid`, `subject_path` | `related_path`, `symbol`, `resolved_addr` |
| `SYMBOL_BIND` | `pid`, `tid`, `subject_path`, `related_path`, `symbol`, `resolved_addr` | none of those fields |
| `OBJECT_CLOSE` | `pid`, `tid`, `subject_path` | `related_path`, `symbol`, `resolved_addr` |

For example, a confirmed load of `/lib/x86_64-linux-gnu/libc.so.6` has
`event_type=LOAD`, `subject_path` set to that path, and `origin=UNKNOWN` unless
the source has affirmative correlation evidence. A preceding `SEARCH` for
`libc.so.6` with `origin=LIBRARY_PATH` remains a separate observation; it
cannot make that later load a library-path load.

## Identity and lifecycle

A process instance is `(pid, process_start_ticks)`. If start ticks are zero,
it is persisted as unresolved and may not be merged with a later certain
instance of the same PID. TID is diagnostic callback identity only; all event
kinds contain the process PID.

An object identity is `(process instance, namespace_id, subject_path)`. A
symbol binding records both provider and requester. Baseline comparison never
accepts a matching basename alone. Any approved alias set must be shared by
learning and detection.

```text
process initialization → SEARCH* → LOAD → SYMBOL_BIND* → OBJECT_CLOSE
                                      ↘ SEARCH* / LOAD for more objects
```

Events can be dropped and may precede enrichment. The store retains that
uncertainty. `OBJECT_CLOSE` removes only the matching identity; capacity or
correlation loss becomes an explicit health counter, never a silent alias.

## Persistence and baselines

T05 adds versioned migrations, replacing PID-only processes, the current
`so_events`, and global `baseline_events`. Its logical records are:

| Record | Required fields |
| --- | --- |
| `process_instances` | key, PID, start ticks, executable identity/uncertainty, first/last seen |
| `loader_events` | event ID, process key, type, origin, flags, namespace, subject, related, symbol, address, timestamp, peer credential snapshot |
| `baseline_candidates` | executable identity, environment key, confirmed load/provider identity, observation counts |
| `baseline_versions` | ID, executable identity, environment key, version, approval state, metadata |
| `baseline_entries` | baseline ID, `LOAD` or `SYMBOL_PROVIDER`, approved identity, optionality |
| `alerts` | UUID, canonical severity/rule, process key, executable identity, JSON detail, timestamp, deduplication key |

`environment_key` begins as an explicitly supplied profile label; it is never
inferred from PID, cwd, or arbitrary environment variables. Old rows migrate
as legacy/unresolved and are never relabelled as confirmed loads.

Learning consumes only confirmed `LOAD` and `SYMBOL_BIND` events with an
identified executable and produces candidates scoped to `(executable,
environment_key)`. It never changes an approved baseline. An operator promotes
candidates into a numbered approved version; detection reads one selected
version. Optional approved loads may be absent without alerting, but are
checked when present. Missing profiles yield `MISSING_BASELINE`, not a
fabricated clean result.

## Alerts and implementation handoff

Canonical rules are `UNKNOWN_SO`, `PATH_HIJACK`, `SYMBOL_INTERPOSITION`, and
`MISSING_BASELINE`. The last is a coverage alert and means the event could not
be evaluated against an approved profile; it is never a clean result.
`PRELOAD_PRIVILEGED` is deferred until affirmative preload and privilege
evidence exists. Severities are uppercase `LOW`, `MEDIUM`, `HIGH`, and
`CRITICAL`. Alert IDs are lowercase RFC 4122 UUIDs; timestamps are Unix
nanoseconds.

`detail` is UTF-8 JSON with stable `event_type`, `process_instance`,
`executable`, `observed`, `baseline`, `origin`, and `flags` keys. T07 derives a
deduplication key from the rule, process instance, baseline version, and
observed identity; storage failure is recorded as a health failure, not a
stored alert.

- T03 implements v1 serialization, endpoint selection, bounded seqpacket
  transport, fork handling, and object lifecycle.
- T04 validates the v1 packet, captures peer credentials, and enforces ingress
  limits.
- T05 performs the migrations and attribution persistence.
- T06 learns and approves executable-scoped baselines.
- T07 evaluates confirmed events and persists canonical alerts.
- T08 exposes this model without duplicating its rules.

Any incompatible change requires a new wire version and a migration decision.
