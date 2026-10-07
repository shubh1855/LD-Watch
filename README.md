# LD-Watch

Dynamic-linker telemetry and baseline deviation detection for selected x86_64
Linux programs using the glibc loader. BE Computer Engineering major project,
Mumbai University.

## Overview

Start a program with `LD_AUDIT=audit/audit.so` to observe loader searches,
confirmed loads, selected symbol bindings and closes. The C library sends
packets to a Go collector, which persists events in SQLite and evaluates
complete observations against an approved executable/environment baseline.
The CLI queries evidence and exports reports.

This is asynchronous detection, not prevention or system-wide monitoring.
Static binaries, unsupported loaders and secure-execution instrumentation are
outside supported coverage. See [threat model](docs/threat-model.md).

## Quick start

Requirements: Linux amd64 with glibc, GCC, Make, Go 1.26.1 and `sqlite3` for
the demo. `jq` is optional. The Ubuntu setup script is
`bash scripts/setup.sh`; review its package/system changes before running it.

```bash
git clone https://github.com/shubh1855/LD-Watch.git
cd LD-Watch
make all
bash scripts/demo_t10.sh
```

The demo uses a unique temporary database/socket, records `/bin/true`, approves
its baseline, checks a clean run, preloads a harmless library, verifies one
additional `UNKNOWN_SO`, and exports JSON. Default output is removed on exit.
To retain results:

```bash
LDWATCH_DEMO_DIR=/tmp/ldwatch-demo-review bash scripts/demo_t10.sh
bin/ldwatch-cli alerts --db /tmp/ldwatch-demo-review/events.db
bin/ldwatch-cli baseline show --db /tmp/ldwatch-demo-review/events.db \
  --exe /usr/bin/true --environment-key production
jq 'length' /tmp/ldwatch-demo-review/report.json
```

Choose a fresh directory for each retained run; an existing database/socket is
rejected. See [demo guide](docs/collector_demo.md) for live collection and output.

## Architecture and protocol

```text
instrumented glibc process
  audit.so callbacks
    -> 1,024-byte v1 little-endian AF_UNIX/SOCK_SEQPACKET packets
    -> bounded listener + peer credentials
    -> collector workers -> SQLite events -> approved-baseline evaluation
    -> persisted alerts -> ldwatch-cli
```

Wire header: `LDW1`, version `1`, length `1024`. Event enums:
`SEARCH=1`, `LOAD=2`, `SYMBOL_BIND=3`, `OBJECT_CLOSE=4`. This is an explicitly
serialized buffer, not a native C struct. Legacy 408-byte records are rejected.
See [protocol](docs/protocol.md), [contract](docs/contract.md) and
[architecture](docs/architecture.md) for offsets, identity and failure policy.

## Repository structure

```text
audit/                  C callbacks, wire serialization, bounded IPC sender
cmd/collector/          Go collector entry point
cmd/ldwatch-cli/         Go CLI using standard flag package
internal/collector/     persistence and connected detection processor
internal/engine/        alerts, baselines and rules
internal/identity/      shared identity resolver
internal/proto/         v1 codec and validation
internal/socket/        bounded seqpacket listener
internal/store/         migrations, SQLite policy, SQL/sqlc queries
tests/fixtures/         controlled C source/receiver/lifecycle probes
tests/integration/      Go integration tests and benchmarks
scripts/                setup, test runners, isolated demo
docker/Dockerfile       Ubuntu 24.04 / Go 1.26.1 image
docker-compose.yml     read-only source/root, tmpfs workspaces
.github/workflows/      CI validation and artifact upload
docs/                   contracts, evidence, issues and task tracking
```

## Building and testing

```bash
make all                 # audit/audit.so, bin/collector, bin/ldwatch-cli
make audit
make collector
make cli
go test -race ./...       # includes Go integration and CLI tests
go vet ./...
bash scripts/test_audit.sh
make test                # wrapper: C fixtures and Go suite
docker compose config
```

`make test` includes Go integration via `go test ./...`. Its legacy
optional-shell-test stage says no shell integration tests exist; the Go
integration package still runs.

CI builds all deliverables, checks artifacts, runs race tests, vet and C
fixtures, then uploads outputs. It triggers on PRs targeting `main`/`dev` and
pushes to those branches. The demo is validated locally, not in a separate CI
stage. [T11 evidence](docs/t11-evidence.md) records live CI and branch settings.

For a disposable container workspace:

```bash
docker compose build dev
docker compose run --rm dev
# Inside container:
make all
LDWATCH_DEMO_DIR=/tmp/demo bash scripts/demo_t10.sh
```

Read-only `/src` is copied into tmpfs `/ld-watch`; container changes disappear
on exit. Compose requests no ptrace capability or seccomp exception. Compose
parsing is verified; a fresh full container build/run is not claimed here.

## Running and CLI reference

For manual collection, use [the two-terminal guide](docs/collector_demo.md).
Collector flags: `--db`, `--socket`, `--workers` (positive, default 4),
`--environment` (nonempty, default `default`). Sender `LDWATCH_SOCKET` must
match the absolute endpoint; `LDWATCH_VERBOSE=0` suppresses logs.

Each CLI command accepts `--db PATH` after its command/subcommand (default
`/var/ldwatch/events.db`). Use the same environment label as the collector.

```bash
bin/ldwatch-cli --help
bin/ldwatch-cli alerts --db /tmp/ldwatch-demo-review/events.db --severity HIGH
bin/ldwatch-cli baseline inspect --db /tmp/ldwatch-demo-review/events.db \
  --exe /usr/bin/true --environment-key production
bin/ldwatch-cli baseline show --db /tmp/ldwatch-demo-review/events.db \
  --exe /usr/bin/true --environment-key production
bin/ldwatch-cli watch --db /tmp/ldwatch-demo-review/events.db --after 0
bin/ldwatch-cli diff --db /tmp/ldwatch-demo-review/events.db \
  --source events --exe /usr/bin/true --environment-key production
bin/ldwatch-cli report --db /tmp/ldwatch-demo-review/events.db \
  --output /tmp/ldwatch-demo-review/report.json --severity HIGH
```

For a trusted manual run: `baseline profile`, `inspect`, `approve`, then
`use --version N`, each with `--db`, `--exe` and `--environment-key`.
Approval prints the version; select that version rather than assuming `1`.
Reprofiling the retained deviation demo includes the injected library in
candidates: do not approve those observations as production normality.
Optional loads use `approve --library /absolute/path.so --optional`.
Searches do not train baselines, and learning never changes approved versions.

`watch` polls stored rows; resume with `--after ID`, filter with `--pid PID`.
`diff` compares recorded loads, supports `--since-id ID`, and does not execute
the target. Severity filters: CRITICAL, HIGH, MEDIUM, LOW.
Report dates: YYYY-MM-DD or RFC3339; `--since` inclusive, `--until` exclusive.
Reports select at most the newest 10,000 matching severity rows before date
filtering; they are not unlimited archival exports.

## Detection and evidence

| Rule | Trigger with an approved baseline | Severity |
| --- | --- | --- |
| UNKNOWN_SO | Confirmed load has an unapproved canonical path | HIGH |
| PATH_HIJACK | Different path from the single same-name approved object | CRITICAL |
| SYMBOL_INTERPOSITION | Tracked symbol has a different approved provider | CRITICAL |
| MISSING_BASELINE | Complete evaluable event has no selected approved profile | HIGH |

Ambiguous same-name loads remain UNKNOWN_SO. Basename equality is not identity.
Load origin is normally unknown: injection can create a path deviation without
proving preload origin. PRELOAD_PRIVILEGED remains deferred.

The isolated demo establishes real-source clean/deviation behavior.
Rule/processor tests cover path and symbol deviations; three packaged live
attack scenarios are not claimed. Lifecycle, bounded-failure checks and
environment-specific measurements are in [T09 evidence](docs/t09-evidence.md).

## Database and report format

Canonical tables: `process_instances`, `loader_events`, `baseline_candidates`,
`baseline_versions`, `baseline_entries`, `alerts`. Legacy tables preserve
migration evidence. See [persistence](docs/persistence.md) and store migrations.

```bash
sqlite3 /tmp/ldwatch-demo-review/events.db \
  'SELECT id,process_key,event_type,subject_path FROM loader_events ORDER BY id LIMIT 10;'
jq 'map(.Rule) | group_by(.) | map({rule: .[0], count: length})' \
  /tmp/ldwatch-demo-review/report.json
jq '.[] | select(.Rule == "UNKNOWN_SO") | .Detail | fromjson' \
  /tmp/ldwatch-demo-review/report.json
```

Reports are top-level arrays, not objects with an `alerts` key. Current fields:
`ID`, `Severity`, `Rule`, `ProcessKey`, `Pid`, `Exe`, `Detail`, `Timestamp`,
`DeduplicationKey`. Detail is a JSON-encoded string; Timestamp is Unix
nanoseconds. Empty output is `[]`. See the verified example in the demo guide.

## Project status and team workflow

- [x] Audit v1 source and bounded IPC (T03)
- [x] Bounded ingress and attribution persistence (T04–T05)
- [x] Approved baselines and connected detection (T06–T07)
- [x] CLI and integration/performance evidence (T08–T09)
- [x] CI delivery and isolated demonstration (T10)
- [x] Documentation and issue dispositions (T11; evidence limits remain explicit)
- [ ] Future: privileged preload, system-wide/static monitoring, content hashes,
  additional loaders/architectures/symbols

[Pending tasks](docs/pending-tasks.md) owns the detailed checklist;
[issues](docs/issues.md) owns historical findings and current dispositions.
Component responsibilities: audit; collector/socket/store; engine/baselines;
CLI/tests. Request teammate review, use feature branches and passing CI.
Branch protection is a remote setting; inspection on 2026-10-07 found it
disabled on main. Enabling it remains a repository-owner decision.

## Known limitations and references

Coverage is opt-in glibc processes. Secure-execution mode restricts loader
environment variables; root execution alone is not equivalent to secure
execution. Compromised processes can omit/forge telemetry. Peer credentials do
not authenticate contents. Paths do not prove file-content integrity.
Drops, storage errors and incomplete identities prevent a universal clean or
no-loss guarantee. See [threat model](docs/threat-model.md).

Loader references: [rtld-audit(7)](https://man7.org/linux/man-pages/man7/rtld-audit.7.html)
and [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html).
[Academic references](docs/references.md) records verified metadata and pending
bibliography checks. Publications are background, not LD-Watch implementation
evidence.
