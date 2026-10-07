# Implemented architecture

Reviewed 2026-10-07. The [contract](contract.md) owns compatibility rules.

## Components and ownership

| Component | Responsibility | Source |
| --- | --- | --- |
| Audit library | glibc callbacks, source identity, object lifecycle, bounded sends | `audit/src/` |
| Codec/listener | validate v1 packets, constrain connections, retain peer credentials | `internal/proto/`, `internal/socket/` |
| Processor | atomic event persistence, approved-profile lookup, rule evaluation, alerts | `internal/collector/processor.go` |
| Baselines | executable/environment candidates, approval, version selection | `internal/engine/baseline/`, `internal/store/baseline.go` |
| Store | migrations, queries, bounded SQLite writes, explicit retention | `internal/store/` |
| CLI | query alerts/events/baselines and export reports | `cmd/ldwatch-cli/` |

```text
glibc SEARCH / LOAD / SYMBOL_BIND / OBJECT_CLOSE
  -> C explicit v1 serialization
  -> bounded SOCK_SEQPACKET send
  -> listener validation + SO_PEERCRED
  -> worker -> event transaction -> selected approved baseline -> alert insert
  -> SQLite queries -> CLI
```

There is no CGo boundary between the audit source and collector. The CLI uses
Go's standard `flag` package, not Cobra, and accesses SQLite directly.

## Identity and evaluation

PID and process start ticks identify process instances; TID is callback
metadata. Source executable snapshots avoid delayed PID-only lookup. Unknown
identity stays uncertain. Full-path canonical library identity is shared by
learning and detection; equal basenames are not equal objects.

SEARCH remains diagnostic and OBJECT_CLOSE supports lifecycle. Complete LOAD
and SYMBOL_BIND records can train an executable/environment candidate.
Approval freezes a numbered version; explicit selection activates it. An
operator must ensure candidate observations came from a trusted workload.

The collector persists observations before detection. Missing selected
profiles generate MISSING_BASELINE for evaluable events. Unknown executable
identity and relevant truncation/unresolved flags suppress unsafe comparison;
absence of an alert for those records does not establish a clean execution.

Same-name/different-path loads produce PATH_HIJACK only with one unambiguous
approved path; otherwise unapproved paths produce UNKNOWN_SO. Symbol providers
are checked only when the profile has an expectation for a tracked symbol.
Each tracked symbol accepts all approved provider identities in the selected
executable/environment version, independent of requester. Outside providers
produce SYMBOL_INTERPOSITION with a sorted `baseline.value.providers` array.
CLI diff reports absent required loads but skips absent optional loads; optional
loads remain allowed when present. Alert deduplication includes process
instance, rule, profile and observation.

## Failure boundaries

Audit sends are nonblocking, fail open and reconnect after failure/fork.
Tracking capacity, absent/slow collectors and overload can lose telemetry.
Listener connections and queues are bounded; shutdown closes idle clients.
SQLite failures roll back event writes and increment health counters; alert
write/detection failure is not counted as a successfully stored alert.
Counters are process-local and reset after restart; there is no durable spool.
See [persistence policy](persistence.md) and [T09 measurements](t09-evidence.md).

## Delivery

`make all` produces `audit/audit.so`, `bin/collector`, `bin/ldwatch-cli`.
CI runs builds/artifact checks, Go race tests, vet and audit fixtures.
Compose copies read-only source into tmpfs and requests no extra ptrace or
seccomp privileges. The isolated demo demonstrates a real audited program and
report path; benchmarks and synthetic rule tests have separate evidence limits.
